"""SetuGuard -- static-extract and score the verified banking corpus. NON-FROZEN.

NOT one of the six frozen PS1 files and not part of batch_baseline.py's suite. Does NOT modify
the scorer, per instruction -- in particular does not reinstate self_signed. Static extraction
and rule-based scoring only: no RAG, no Ollama, no LLM call anywhere in this file.

Extraction uses setuguard_ps1.static_analysis.analyze_apk() -- the frozen file, imported
unmodified, same function harness/extract_features_pool.py and harness/rescore_from_cache.py
already use for the 668-sample cache. Scoring uses a PINNED COPY of
setuguard_app/backend/app.py:_rule_based_verdict()'s score-relevant lines, taken byte-for-byte
from harness/rescore_from_cache.py's already-verified `_score_new` (that file's own provenance
note diffs it against app.py directly). Not importing app.py itself: app.py has import-time side
effects (loads the PS2 model artifact, starts building a Flask app) that this measurement doesn't
need and that the "no edits to setuguard_app/" constraint makes safer to avoid entirely --
importing a file is not editing it, but this repo's own established convention
(rescore_from_cache.py, threshold_sweep.py) is a pinned copy for exactly this situation, and this
script follows that precedent rather than inventing a new one.

Verified byte-for-byte against setuguard_app/backend/app.py at commit 81c73ab (this session's
starting HEAD for setuguard_app/) by direct read, same as rescore_from_cache.py's own provenance
note. If app.py's scorer changes, this copy must be re-synced by hand -- it will silently drift
otherwise, same risk rescore_from_cache.py already carries and documents.

Only scores APKs with status "pass" in BANKING_CORPUS_VERIFICATION.json (verify_banking_corpus.py's
output) -- rejected and quarantined APKs are recorded as such but never static-analyzed, since
androguard was already invoked once during verification and a "reject" status (debug cert, no
cert, AOSP test key, package mismatch, corrupt download) makes the sample unusable regardless of
what the scorer would say about it.

Idempotent / resumable: on each run, only sha256 values not already present in
harness/results_banking_legit.csv are (re-)scored, so this can be re-invoked as new APKs pass
verification -- pipelining against the download+verify cycle rather than waiting for the full
corpus to finish (per instruction).

Emits harness/results_banking_legit.csv (schema below) and prints an extraction-failure summary
by reason and package to stderr -- committed separately as an appendix if the failure rate is
material.

Usage:
    python3 score_banking_corpus.py --verification harness/BANKING_CORPUS_VERIFICATION.json \\
        --corpus-dir harness/banking_legit_corpus --out harness/results_banking_legit.csv
"""
import argparse
import csv
import ipaddress
import json
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "setuguard_ps1"))

RESULTS_FIELDNAMES = ["sha256", "tier", "pkg_name", "arm", "vt_scan_date", "apk_size",
                       "score", "verdict", "extraction_ok", "extraction_error"]


# ---------------------------------------------------------------------------
# PINNED scorer copy -- see module docstring. Must match
# setuguard_app/backend/app.py:_rule_based_verdict()'s score computation
# exactly; verified byte-for-byte at commit 81c73ab.
# ---------------------------------------------------------------------------

def _url_host_is_bare_ip(url: str) -> bool:
    try:
        host = urlparse(url).hostname
    except ValueError:
        return False
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _url_has_nonstandard_port(url: str) -> bool:
    try:
        port = urlparse(url).port
    except ValueError:
        return False
    return port is not None and port not in (80, 443)


def score(features: dict) -> float:
    s = 0.0
    dp = features["dangerous_permissions"]
    if dp:
        s += min(len(dp) * 0.06, 0.30)

    sapis = features["suspicious_apis"]
    weight_by_cat = {
        "dynamic_code_loading": 0.20, "sms_control": 0.20, "device_admin": 0.15,
        "accessibility_service": 0.20, "installed_app_discovery": 0.10,
    }
    seen_cats = {api["category"] for api in sapis if api["category"] != "reflection"}
    for cat in seen_cats:
        s += weight_by_cat.get(cat, 0.08)

    strs = features["suspicious_strings"]
    bare_ips = [x for x in strs if x["kind"] == "ip"]
    flagged_urls = [
        x for x in strs
        if x["kind"] == "url" and (_url_host_is_bare_ip(x["value"]) or _url_has_nonstandard_port(x["value"]))
    ]
    ip_url = bare_ips + flagged_urls
    if ip_url:
        s += min(len(ip_url) * 0.05, 0.20)

    cert = features["certificate"]
    if cert.get("is_debug"):
        s += 0.05

    return max(0.0, min(s, 1.0))


def verdict_for(s: float) -> str:
    if s >= 0.65:
        return "malicious"
    elif s >= 0.30:
        return "suspicious"
    return "benign"


# ---------------------------------------------------------------------------


def already_scored(out_csv: Path) -> set:
    done = set()
    if out_csv.exists() and out_csv.stat().st_size > 0:
        with open(out_csv, newline="") as f:
            for row in csv.DictReader(f):
                done.add(row["sha256"])
    return done


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verification", type=Path, required=True)
    ap.add_argument("--corpus-dir", type=Path, default=Path(__file__).parent / "banking_legit_corpus")
    ap.add_argument("--out", type=Path, default=Path(__file__).parent / "results_banking_legit.csv")
    args = ap.parse_args()

    import static_analysis  # frozen file, imported unmodified, post-sys.path-insert

    ver = json.loads(args.verification.read_text())
    todo_rows = [r for r in ver["results"]]

    done_shas = already_scored(args.out)
    print(f"[score] {len(done_shas)} already scored, {len(todo_rows)} in verification report",
          file=sys.stderr)

    write_header = not args.out.exists() or args.out.stat().st_size == 0
    out_f = open(args.out, "a", newline="")
    writer = csv.DictWriter(out_f, fieldnames=RESULTS_FIELDNAMES)
    if write_header:
        writer.writeheader()
        out_f.flush()

    n_scored, n_skipped_not_pass, n_extract_fail = 0, 0, 0
    fail_reasons = {}  # (pkg_name, reason) -> count
    t0 = time.perf_counter()

    for r in todo_rows:
        sha = r["sha256"]
        if sha in done_shas:
            continue
        if r["status"] != "pass":
            n_skipped_not_pass += 1
            continue

        apk_path = args.corpus_dir / f"{sha}.apk"
        row = {
            "sha256": sha, "tier": r["tier"], "pkg_name": r.get("manifest_pkg_name") or r.get("expected_pkg_name"),
            "arm": r["arm"], "vt_scan_date": r.get("vt_scan_date"), "apk_size": r["actual_size_bytes"],
        }
        try:
            features = static_analysis.analyze_apk(str(apk_path))
            s = score(features)
            row["score"] = round(s, 4)
            row["verdict"] = verdict_for(s)
            row["extraction_ok"] = True
            row["extraction_error"] = ""
            n_scored += 1
            print(f"[score] {sha[:12]}… {row['pkg_name']:40s} score={s:.3f} verdict={row['verdict']}",
                  file=sys.stderr)
        except Exception as e:
            row["score"] = ""
            row["verdict"] = ""
            row["extraction_ok"] = False
            row["extraction_error"] = f"{type(e).__name__}: {e}"
            n_extract_fail += 1
            key = (row["pkg_name"], type(e).__name__)
            fail_reasons[key] = fail_reasons.get(key, 0) + 1
            print(f"[score] {sha[:12]}… {row['pkg_name']:40s} EXTRACTION FAILED: "
                  f"{row['extraction_error']}", file=sys.stderr)

        writer.writerow(row)
        out_f.flush()

    out_f.close()
    elapsed = time.perf_counter() - t0
    total_attempted = n_scored + n_extract_fail
    fail_rate = (n_extract_fail / total_attempted * 100) if total_attempted else 0.0

    print(f"\n[score] done: {n_scored} scored, {n_extract_fail} extraction failures, "
          f"{n_skipped_not_pass} skipped (not status=pass), {elapsed:.0f}s", file=sys.stderr)
    if total_attempted:
        print(f"[score] extraction failure rate: {n_extract_fail}/{total_attempted} = {fail_rate:.1f}%",
              file=sys.stderr)
        if fail_rate > 20:
            print(f"[score] *** failure rate exceeds 20% -- this is itself a finding about what "
                  f"static analysis can see in production banking software, not a nuisance ***",
                  file=sys.stderr)
    if fail_reasons:
        print(f"[score] failure reasons:", file=sys.stderr)
        for (pkg, reason), n in sorted(fail_reasons.items(), key=lambda kv: -kv[1]):
            print(f"    {n}x {pkg}: {reason}", file=sys.stderr)
    print(f"[score] wrote {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
