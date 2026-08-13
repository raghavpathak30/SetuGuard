"""SetuGuard -- verify the downloaded banking corpus is what it claims to be. NON-FROZEN.

NOT one of the six frozen PS1 files and not part of batch_baseline.py's suite. Read-only over
harness/banking_legit_corpus/*.apk (never modifies an APK). This gate exists because
banking_holdout_16/ never had one -- see harness/BANKING_HOLDOUT_16_PROVENANCE.md. Every check
below is a check that, applied in July, would have rejected all sixteen of that directory:

  - package name mismatch between the manifest and what was requested        -> quarantine
  - debug-signed, AOSP public test key, or no certificate at all             -> reject
  - sha256 collision against an existing corpus                             -> reported first,
    loudly, before anything else, because a collision means this exact error has recurred

Ordinary self-signing is NOT grounds for rejection -- nearly every Android APK, including
legitimate Play Store apps, is self-signed in the X.509 sense (there is no CA-issued cert chain
for app-signing certs). Only debug keys, the AOSP test key, and a missing certificate are
rejected.

Also writes BANKING_CORPUS_VERIFICATION.json (same basename, .json suffix) -- a machine-readable
companion consumed by score_banking_corpus.py, which scores only APKs with status "pass" here.

Usage:
    python3 verify_banking_corpus.py --candidates harness/banking_candidates.json \\
        --corpus-dir harness/banking_legit_corpus --out harness/BANKING_CORPUS_VERIFICATION.md
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from loguru import logger

logger.disable("androguard")

from androguard.core.apk import APK  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
TIER_A_SURVIVOR_GATE = 30

AOSP_TEST_KEY_MARKERS = ("android@android.com",)
DEBUG_KEY_MARKERS = ("android debug", "android-debug")


def sha256_of_file(path: Path, chunk=1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(chunk), b""):
            h.update(c)
    return h.hexdigest()


def cert_fields(apk: APK):
    try:
        certs = apk.get_certificates()
    except Exception as e:
        return None, None, None, f"{type(e).__name__}: {e}"
    if not certs:
        return None, None, None, "unsigned / no certificate recovered"
    c = certs[0]
    try:
        return c.subject.human_friendly, c.issuer.human_friendly, c.sha256.hex(), None
    except Exception as e:
        return None, None, None, f"{type(e).__name__}: {e}"


def cert_disposition(subject: str, issuer: str, cert_sha: str, cert_err: str):
    """Returns (status, reason). status in {"ok", "reject"}."""
    if cert_sha is None:
        return "reject", f"no certificate ({cert_err or 'no signer'})"
    subj_l = (subject or "").lower()
    for marker in AOSP_TEST_KEY_MARKERS:
        if marker in subj_l:
            return "reject", f"AOSP public test key (subject contains '{marker}')"
    for marker in DEBUG_KEY_MARKERS:
        if marker in subj_l:
            return "reject", f"debug-signed (subject contains '{marker}')"
    self_signed = subject == issuer
    return "ok", "self-signed (ordinary, not rejected)" if self_signed else "CA-adjacent chain present"


def load_expected(candidates_path: Path):
    """sha256 -> {pkg_name, tier, arm, vt_scan_date, apk_size} from
    filter_banking_candidates.py's output."""
    d = json.loads(candidates_path.read_text())
    tier_of = {pkg: p["tier"] for pkg, p in d["per_package"].items()}
    expected = {}
    for arm_name, picks in (("era_matched", d["era_matched_picks"]), ("current", d["current_picks"])):
        for pkg, row in picks.items():
            expected[row["sha256"]] = {
                "pkg_name": pkg, "tier": tier_of[pkg], "arm": arm_name,
                "vt_scan_date": row.get("vt_scan_date"), "apk_size": row.get("apk_size"),
            }
    return expected


def existing_sha256_sets():
    """The three corpora a collision must never occur against."""
    archive_manifest = {}
    p = REPO_ROOT / "harness" / "BANKING_ARCHIVE_MANIFEST.tsv"
    if p.exists():
        for line in p.read_text().splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 2:
                sha = parts[1].removesuffix(".apk")
                archive_manifest[sha] = parts[2] if len(parts) > 2 else "?"

    cic_dir = {f.stem for f in (REPO_ROOT / "cicmaldroid_banking").glob("*.apk")} \
        if (REPO_ROOT / "cicmaldroid_banking").exists() else set()

    sample_716 = set()
    p716 = REPO_ROOT / "harness" / "sample_set_716.txt"
    if p716.exists():
        for line in p716.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            path_str = line.rsplit(",", 1)[0]
            sample_716.add(Path(path_str).stem)

    return archive_manifest, cic_dir, sample_716


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidates", type=Path, required=True)
    ap.add_argument("--corpus-dir", type=Path, default=Path(__file__).parent / "banking_legit_corpus")
    ap.add_argument("--out", type=Path,
                     default=Path(__file__).parent / "BANKING_CORPUS_VERIFICATION.md")
    args = ap.parse_args()

    expected = load_expected(args.candidates)
    archive_manifest, cic_dir, sample_716 = existing_sha256_sets()
    print(f"[verify] collision check universe: {len(archive_manifest)} in archive manifest, "
          f"{len(cic_dir)} in cicmaldroid_banking/, {len(sample_716)} in sample_set_716.txt",
          file=sys.stderr)

    apks = sorted(args.corpus_dir.glob("*.apk")) if args.corpus_dir.exists() else []
    print(f"[verify] {len(apks)} APKs on disk in {args.corpus_dir}", file=sys.stderr)

    collisions = []
    results = []

    for p in apks:
        sha = p.stem
        row = {"sha256": sha, "filename": p.name}

        for label, universe in (("BANKING_ARCHIVE_MANIFEST.tsv", archive_manifest),
                                  ("cicmaldroid_banking/", cic_dir),
                                  ("sample_set_716.txt", sample_716)):
            if sha in universe:
                collisions.append({"sha256": sha, "collides_with": label})

        exp = expected.get(sha)
        row["expected_pkg_name"] = exp["pkg_name"] if exp else None
        row["tier"] = exp["tier"] if exp else "UNKNOWN (sha256 not in candidates.json)"
        row["arm"] = exp["arm"] if exp else None
        row["vt_scan_date"] = exp["vt_scan_date"] if exp else None
        row["expected_apk_size"] = exp["apk_size"] if exp else None
        row["actual_size_bytes"] = p.stat().st_size

        try:
            actual_file_sha = sha256_of_file(p)
        except OSError as e:
            row["status"] = "reject"
            row["reason"] = f"unreadable: {e}"
            results.append(row)
            continue
        if actual_file_sha != sha:
            row["status"] = "reject"
            row["reason"] = "filename does not match file content sha256 -- corrupt/truncated download"
            results.append(row)
            continue

        try:
            apk = APK(str(p))
            manifest_pkg = apk.get_package()
            row["app_label"] = _safe_app_name(apk)
            row["version_name"] = apk.get_androidversion_name()
            row["version_code"] = apk.get_androidversion_code()
        except Exception as e:
            row["status"] = "reject"
            row["reason"] = f"androguard could not parse: {type(e).__name__}: {e}"
            results.append(row)
            continue

        row["manifest_pkg_name"] = manifest_pkg
        if exp and manifest_pkg != exp["pkg_name"]:
            row["status"] = "quarantine"
            row["reason"] = (f"package name mismatch: requested '{exp['pkg_name']}', "
                              f"manifest says '{manifest_pkg}' -- repackaging signal")
            results.append(row)
            continue

        subject, issuer, cert_sha, cert_err = cert_fields(apk)
        row["cert_subject"] = subject
        row["cert_issuer"] = issuer
        row["cert_sha256"] = cert_sha
        cert_status, cert_reason = cert_disposition(subject, issuer, cert_sha, cert_err)
        if cert_status == "reject":
            row["status"] = "reject"
            row["reason"] = cert_reason
            results.append(row)
            continue

        row["status"] = "pass"
        row["reason"] = cert_reason
        results.append(row)

    tier_pass = {}
    for r in results:
        if r["status"] == "pass":
            tier_pass[r["tier"]] = tier_pass.get(r["tier"], 0) + 1
    tier_a_survivors = tier_pass.get("A", 0)
    gate_ok = tier_a_survivors >= TIER_A_SURVIVOR_GATE

    args.out.write_text(render(results, collisions, tier_pass, tier_a_survivors, gate_ok, args.corpus_dir))
    json_out = args.out.with_suffix(".json")
    json_out.write_text(json.dumps({
        "collisions": collisions, "tier_pass": tier_pass,
        "tier_a_survivors": tier_a_survivors, "gate_ok": gate_ok,
        "results": results,
    }, indent=2))
    print(f"[verify] wrote {json_out} (machine-readable companion, consumed by score_banking_corpus.py)",
          file=sys.stderr)
    print(f"\n[verify] status counts: "
          f"{ {s: sum(1 for r in results if r['status']==s) for s in ('pass','reject','quarantine')} }",
          file=sys.stderr)
    print(f"[verify] Tier A survivors: {tier_a_survivors} "
          f"(gate {'PASSED' if gate_ok else 'FAILED'}, need >= {TIER_A_SURVIVOR_GATE})",
          file=sys.stderr)
    if collisions:
        print(f"[verify] *** {len(collisions)} SHA-256 COLLISION(S) -- reported first in the "
              f"output file, this repeats the banking_holdout_16 error class ***", file=sys.stderr)
    print(f"[verify] wrote {args.out}", file=sys.stderr)


def _safe_app_name(apk):
    try:
        return apk.get_app_name()
    except Exception as e:
        return f"<unreadable: {type(e).__name__}>"


def render(results, collisions, tier_pass, tier_a_survivors, gate_ok, corpus_dir) -> str:
    def esc(s):
        return (str(s) if s is not None else "—").replace("|", "\\|")

    L = ["# Banking corpus verification\n",
         f"Generated by `harness/verify_banking_corpus.py` over `{corpus_dir}`. "
         f"Read-only; no APK modified.\n"]

    L.append("## SHA-256 collisions against existing corpora — checked first\n")
    if collisions:
        L.append(f"**{len(collisions)} COLLISION(S) FOUND.** This means the same corpus-identity "
                 "error that produced `banking_holdout_16/` has recurred. Stop and investigate "
                 "before reading anything else in this file.\n")
        for c in collisions:
            L.append(f"- `{c['sha256']}` also present in **{c['collides_with']}**")
    else:
        L.append("**None.** Every downloaded APK's sha256 is absent from "
                 "`BANKING_ARCHIVE_MANIFEST.tsv`, `cicmaldroid_banking/`, and "
                 "`sample_set_716.txt`.\n")
    L.append("")

    L.append("## Gate\n")
    L.append(f"**Tier A survivors: {tier_a_survivors}** (threshold: ≥{TIER_A_SURVIVOR_GATE}) — "
             f"**{'PASSED' if gate_ok else 'FAILED'}**.\n")
    if not gate_ok:
        L.append("Below threshold. Reporting and continuing per instruction, but every "
                 f"downstream number in `RESULTS_CLEAN_GATE.md` must be labelled underpowered "
                 f"with n={tier_a_survivors} stated in the same sentence.\n")
    L.append("| Tier | Pass |")
    L.append("|---|---|")
    for t in sorted(tier_pass):
        L.append(f"| {t} | {tier_pass[t]} |")
    L.append("")

    counts = {s: sum(1 for r in results if r["status"] == s) for s in ("pass", "reject", "quarantine")}
    L.append(f"## Summary — {len(results)} APKs on disk\n")
    L.append(f"- **pass**: {counts['pass']}")
    L.append(f"- **reject**: {counts['reject']}")
    L.append(f"- **quarantine** (package mismatch): {counts['quarantine']}\n")

    L.append("### Rejections and quarantines, with reasons\n")
    bad = [r for r in results if r["status"] != "pass"]
    if not bad:
        L.append("None.\n")
    else:
        L.append("| sha256 | tier | pkg (expected) | status | reason |")
        L.append("|---|---|---|---|---|")
        for r in bad:
            L.append(f"| `{r['sha256'][:16]}…` | {esc(r['tier'])} | "
                     f"`{esc(r['expected_pkg_name'])}` | {r['status']} | {esc(r['reason'])} |")
        L.append("")

    L.append("### Full table\n")
    L.append("| sha256 | tier | arm | pkg | app label | version | cert org/CN | vt_scan_date | size | status |")
    L.append("|---|---|---|---|---|---|---|---|---|---|")
    for r in sorted(results, key=lambda r: (r["tier"] != "A", r["tier"], r["status"] != "pass")):
        org = _org_of(r.get("cert_subject"))
        ver = f"{esc(r.get('version_name'))} ({esc(r.get('version_code'))})"
        L.append(f"| `{r['sha256'][:16]}…` | {esc(r['tier'])} | {esc(r['arm'])} | "
                 f"`{esc(r.get('manifest_pkg_name') or r['expected_pkg_name'])}` | "
                 f"{esc(r.get('app_label'))} | {ver} | {esc(org)} | {esc(r['vt_scan_date'])} | "
                 f"{r['actual_size_bytes']/1024:.0f}KB | {r['status']} |")
    L.append("")
    return "\n".join(L) + "\n"


def _org_of(subject):
    if not subject:
        return ""
    m = re.search(r"Organization:\s*([^,]+)", subject)
    if m and m.group(1).strip():
        return m.group(1).strip()
    m = re.search(r"Common Name:\s*([^,]+)", subject)
    if m and m.group(1).strip():
        return m.group(1).strip()
    return subject


if __name__ == "__main__":
    main()
