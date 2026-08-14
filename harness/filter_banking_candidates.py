"""SetuGuard -- filter AndroZoo latest.csv.gz for the pre-registered banking corpus. NON-FROZEN.

NOT one of the six frozen PS1 files and not part of batch_baseline.py's suite. Read-only over
latest.csv.gz; never decompresses to disk (streams zcat | grep -F into this process's stdin) and
never writes into an existing output directory.

Implements exactly the rule pre-registered in harness/BANKING_CORPUS_INCLUSION_RULE.md, committed
BEFORE this script was run against a real file:
  - pkg_name matched EXACTLY (never substring) against harness/banking_packages.csv column 1
  - markets must contain play.google.com
  - vt_detection literally "0" (empty means never-scanned, not clean -- excluded)
  - vt_scan_date non-empty
  - the malformed comma-bearing AndroZoo row is excluded by literal substring, per instruction
  - era-matched arm: highest vercode among rows with vt_scan_date <= 2019-12-31 (inclusive)
  - current arm: highest vercode among all filter-passing rows, any date
  - ties on vercode within a package broken by lowest sha256 (lexical), for determinism

Column indexing is BY NAME from the header row, not by position -- AndroZoo's column order has
changed historically and positional indexing is how this breaks silently.

Coarse pre-filter is `zcat latest.csv.gz | grep -F -f <packages>` (fast, C-level literal
matching) so Python only ever parses the small candidate subset, not the full multi-gigabyte
file. grep -F can match a package name as a SUBSTRING of some other field, so every candidate
line is still re-parsed as CSV and pkg_name is compared for EXACT equality before it counts.

Usage:
    python3 filter_banking_candidates.py --csv-gz ~/latest.csv.gz \\
        --packages harness/banking_packages.csv --out harness/banking_candidates.json
    python3 filter_banking_candidates.py --csv-gz harness/fixtures/fake_latest.csv \\
        --packages harness/banking_packages.csv --out /tmp/candidates_dryrun.json --plain-text
"""
import argparse
import csv
import hashlib
import json
import subprocess
import sys
from collections import defaultdict
from datetime import date
from pathlib import Path

ERA_CUTOFF = date(2019, 12, 31)
MALFORMED_ROW_EXCLUDE = ",snaggamea"  # literal, per instruction -- not a general CSV repair


def load_packages(path: Path):
    rows = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            rows.append(row)
    return rows


def sha256_of_file(path: Path, chunk=1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(chunk), b""):
            h.update(c)
    return h.hexdigest()


def read_header_line(csv_gz: Path, plain_text: bool) -> str:
    """The header row ("sha256,sha1,md5,...") never contains any target package
    name as a substring, so it can never be yielded by the grep -F pre-filter in
    stream_candidate_lines() -- confirmed against the fixture, not assumed.
    Read it directly via `zcat | head -1` (stops early; never decompresses the
    whole file just to see the first line)."""
    cat_cmd = ["cat", str(csv_gz)] if plain_text else ["zcat", str(csv_gz)]
    cat = subprocess.Popen(cat_cmd, stdout=subprocess.PIPE)
    head = subprocess.run(["head", "-1"], stdin=cat.stdout, stdout=subprocess.PIPE, text=True)
    cat.stdout.close()
    cat.terminate()
    return head.stdout.rstrip("\n")


def stream_candidate_lines(csv_gz: Path, target_pkgs: list, plain_text: bool):
    """Yields raw candidate lines (header excluded -- see read_header_line()
    above, the header can never appear here) that grep -F matched against any
    target package name. plain_text=True reads csv_gz as an already-plain
    (uncompressed) CSV file -- used for the fixture dry run, which is not gzipped."""
    pattern_file = csv_gz.parent / ".grep_patterns.tmp"
    pattern_file.write_text("\n".join(target_pkgs) + "\n")
    try:
        if plain_text:
            cat_cmd = ["cat", str(csv_gz)]
        else:
            cat_cmd = ["zcat", str(csv_gz)]
        cat = subprocess.Popen(cat_cmd, stdout=subprocess.PIPE)
        grep = subprocess.Popen(
            ["grep", "-F", "-f", str(pattern_file)],
            stdin=cat.stdout, stdout=subprocess.PIPE, text=True,
        )
        cat.stdout.close()
        for line in grep.stdout:
            if MALFORMED_ROW_EXCLUDE in line:
                continue
            yield line.rstrip("\n")
        grep.wait()
        cat.wait()
    finally:
        pattern_file.unlink(missing_ok=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv-gz", type=Path, required=True)
    ap.add_argument("--packages", type=Path, default=Path(__file__).parent / "banking_packages.csv")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--plain-text", action="store_true",
                     help="csv-gz argument is already-decompressed plain CSV (fixture dry runs)")
    args = ap.parse_args()

    pkg_rows = load_packages(args.packages)
    target_pkgs = [r["pkg_name"] for r in pkg_rows]
    tier_of = {r["pkg_name"]: r["tier"] for r in pkg_rows}
    hint_of = {r["pkg_name"]: r["issuer"] for r in pkg_rows}

    print(f"[filter] {len(target_pkgs)} target packages, "
          f"{sum(1 for t in tier_of.values() if t=='A')} Tier A", file=sys.stderr)

    header_line = read_header_line(args.csv_gz, args.plain_text)
    if not header_line:
        print("[filter] FATAL: could not read a header line from csv-gz "
              "(check the file exists and zcat/head are on PATH)", file=sys.stderr)
        sys.exit(1)
    header = next(csv.reader([header_line]))
    col = {name: i for i, name in enumerate(header)}
    required = {"sha256", "pkg_name", "vercode", "vt_detection", "vt_scan_date", "markets", "apk_size"}
    missing = required - set(col)
    if missing:
        print(f"[filter] FATAL: expected columns missing from header: {missing}. "
              f"AndroZoo's schema may have changed -- refusing to index positionally.",
              file=sys.stderr)
        sys.exit(1)
    print(f"[filter] header OK, {len(header)} columns: {header}", file=sys.stderr)

    matched = defaultdict(list)  # pkg_name -> list of row dicts
    any_seen = set()
    n_candidate_lines = 0

    for line in stream_candidate_lines(args.csv_gz, target_pkgs, args.plain_text):
        n_candidate_lines += 1
        try:
            fields = next(csv.reader([line]))
        except Exception:
            continue
        if len(fields) <= max(col.values()):
            continue
        pkg = fields[col["pkg_name"]]
        if pkg not in tier_of:
            continue  # grep -F substring hit, not an exact target -- discard
        any_seen.add(pkg)
        matched[pkg].append({
            "sha256": fields[col["sha256"]],
            "pkg_name": pkg,
            "vercode": fields[col["vercode"]],
            "apk_size": fields[col["apk_size"]],
            "vt_detection": fields[col["vt_detection"]],
            "vt_scan_date": fields[col["vt_scan_date"]],
            "markets": fields[col["markets"]],
        })

    def passes_filters(r):
        if "play.google.com" not in r["markets"]:
            return False
        if r["vt_detection"] != "0":
            return False
        if not r["vt_scan_date"].strip():
            return False
        return True

    def vercode_key(r):
        try:
            return int(r["vercode"])
        except ValueError:
            return -1

    def pick_best(rows):
        """Highest vercode; ties broken by lowest sha256, for determinism."""
        if not rows:
            return None
        return sorted(rows, key=lambda r: (-vercode_key(r), r["sha256"]))[0]

    era_picks, current_picks = {}, {}
    per_pkg_report = {}
    for pkg, rows in matched.items():
        passing = [r for r in rows if passes_filters(r)]
        era_candidates = [r for r in passing if _parse_date(r["vt_scan_date"]) is not None
                           and _parse_date(r["vt_scan_date"]) <= ERA_CUTOFF]
        era_best = pick_best(era_candidates)
        current_best = pick_best(passing)
        if era_best:
            era_picks[pkg] = era_best
        if current_best:
            current_picks[pkg] = current_best
        per_pkg_report[pkg] = {
            "tier": tier_of[pkg], "app_hint": hint_of[pkg],
            "raw_rows_from_grep": len(rows), "rows_passing_filters": len(passing),
            "has_era_matched_version": era_best is not None,
            "era_matched_sha256": era_best["sha256"] if era_best else None,
            "era_matched_vercode": era_best["vercode"] if era_best else None,
            "current_sha256": current_best["sha256"] if current_best else None,
            "current_vercode": current_best["vercode"] if current_best else None,
        }

    zero_hit = [p for p in target_pkgs if p not in any_seen]

    tier_summary = defaultdict(lambda: {"requested": 0, "found_in_latest_csv": 0,
                                          "passed_filters_any_row": 0, "has_era_matched": 0,
                                          "era_picks": 0, "current_picks": 0})
    for pkg in target_pkgs:
        t = tier_summary[tier_of[pkg]]
        t["requested"] += 1
        if pkg in any_seen:
            t["found_in_latest_csv"] += 1
        pr = per_pkg_report.get(pkg)
        if pr and pr["rows_passing_filters"] > 0:
            t["passed_filters_any_row"] += 1
        if pr and pr["has_era_matched_version"]:
            t["has_era_matched"] += 1
        if pkg in era_picks:
            t["era_picks"] += 1
        if pkg in current_picks:
            t["current_picks"] += 1

    csv_identity = None if args.plain_text else {
        "path": str(args.csv_gz),
        "sha256": sha256_of_file(args.csv_gz),
        "size_bytes": args.csv_gz.stat().st_size,
        "recorded_at_utc": __import__("datetime").datetime.utcnow().isoformat(),
    }

    out = {
        "source_csv_identity": csv_identity,
        "inclusion_rule": "harness/BANKING_CORPUS_INCLUSION_RULE.md",
        "n_candidate_lines_from_grep": n_candidate_lines,
        "zero_hit_packages": zero_hit,
        "tier_summary": {k: v for k, v in sorted(tier_summary.items())},
        "era_matched_picks": era_picks,
        "current_picks": current_picks,
        "per_package": per_pkg_report,
    }
    args.out.write_text(json.dumps(out, indent=2))

    print(f"\n[filter] candidate lines from grep: {n_candidate_lines}", file=sys.stderr)
    print(f"[filter] zero-hit packages (need Raghav's correction): {len(zero_hit)}", file=sys.stderr)
    for p in zero_hit:
        print(f"    ZERO HITS: {p} ({tier_of[p]}, {hint_of[p]})", file=sys.stderr)
    print(f"\n[filter] per-tier summary:", file=sys.stderr)
    for tier, s in sorted(tier_summary.items()):
        print(f"  Tier {tier}: requested={s['requested']} found={s['found_in_latest_csv']} "
              f"passed_filters={s['passed_filters_any_row']} has_era_match={s['has_era_matched']} "
              f"-> era_picks={s['era_picks']} current_picks={s['current_picks']}", file=sys.stderr)
    print(f"\n[filter] wrote {args.out}", file=sys.stderr)


def _parse_date(s: str):
    s = s.strip()
    if not s:
        return None
    try:
        return date.fromisoformat(s.split(" ")[0])
    except ValueError:
        return None


if __name__ == "__main__":
    main()
