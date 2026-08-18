"""SetuGuard -- banking-corpus composition manifest. NON-FROZEN.

NOT one of the six frozen PS1 files. Read-only over harness/banking_legit_corpus/*.apk
(manifest parse only, via androguard.core.apk.APK -- never AnalyzeAPK, never modifies
an APK) and over harness/banking_candidates.json / harness/banking_packages.csv.

Why this exists: harness/verify_banking_corpus.py reported "effective n = nominal n = 95"
and that phrase is correct about collision exclusion and wrong as a sample-size claim.
95 is a FILE count (current-arm builds + era-matched builds of the same packages). The
independent-unit count -- distinct packages, and above that distinct issuer clusters --
is what every confidence interval on this corpus must resample over, per
harness/PREREGISTERED_BANKING_AUC_CLAIMS.md.

Usage:
    python3 harness/build_corpus_manifest.py
"""
import json
import sys
from pathlib import Path

from loguru import logger

logger.disable("androguard")

from androguard.core.apk import APK  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_DIR = REPO_ROOT / "harness" / "banking_legit_corpus"
CANDIDATES = REPO_ROOT / "harness" / "banking_candidates.json"
PACKAGES_CSV = REPO_ROOT / "harness" / "banking_packages.csv"
OUT_TSV = REPO_ROOT / "harness" / "BANKING_CORPUS_MANIFEST.tsv"

COLUMNS = ["sha256", "pkg_name", "declared_pkg", "version_code", "version_name",
           "tier", "arm", "issuer", "size_bytes", "parse_ok"]


def norm_sha(value: str) -> str:
    """Canonical in-memory form for every sha256 in this script: UPPERCASE hex.
    Same rule as verify_banking_corpus.py / CONTEXT.md §5 -- normalise at every
    READ boundary, never rewrite a stored cache."""
    return value.strip().upper()


def load_expected(candidates_path: Path) -> dict:
    """sha256 -> {pkg_name, tier, arm, vercode, apk_size} joined from
    banking_candidates.json's current_picks/era_matched_picks + per_package."""
    d = json.loads(candidates_path.read_text())
    per_pkg = d["per_package"]
    expected = {}
    for arm_name, picks in (("current", d["current_picks"]), ("era_matched", d["era_matched_picks"])):
        for pkg, row in picks.items():
            sha = norm_sha(row["sha256"])
            expected[sha] = {
                "pkg_name": pkg,
                "tier": per_pkg[pkg]["tier"],
                "arm": arm_name,
                "vercode": row["vercode"],
                "apk_size": row["apk_size"],
            }
    return expected


def load_issuers(packages_csv: Path) -> dict:
    """pkg_name -> {issuer, source, note} from banking_packages.csv."""
    import csv
    out = {}
    with open(packages_csv, newline="") as f:
        for row in csv.DictReader(f):
            out[row["pkg_name"]] = {
                "issuer": row["issuer"], "source": row["source"], "note": row["note"],
            }
    return out


def main():
    expected = load_expected(CANDIDATES)
    issuers = load_issuers(PACKAGES_CSV)

    apks = sorted(CORPUS_DIR.glob("*.apk"))
    print(f"[manifest] {len(apks)} files on disk in {CORPUS_DIR}", file=sys.stderr)

    # --- Step 2 GATE: every file must join to a pkg_name and an issuer ---
    join_failures = []
    joined = []
    for p in apks:
        sha = norm_sha(p.stem)
        exp = expected.get(sha)
        if exp is None:
            join_failures.append((sha, "no match in banking_candidates.json"))
            continue
        iss = issuers.get(exp["pkg_name"])
        if iss is None:
            join_failures.append((sha, f"pkg_name '{exp['pkg_name']}' not in banking_packages.csv"))
            continue
        joined.append((p, sha, exp, iss))

    if join_failures:
        print(f"[manifest] STOP: {len(join_failures)} file(s) failed to join", file=sys.stderr)
        for sha, reason in join_failures:
            print(f"  {sha}: {reason}", file=sys.stderr)
        sys.exit(1)

    print(f"[manifest] all {len(joined)} files joined to pkg_name and issuer", file=sys.stderr)

    # --- Step 3: verify declared package against actual APK ---
    mismatches = []
    parse_failed = []
    rows = []
    for p, sha, exp, iss in joined:
        row = {
            "sha256": sha, "pkg_name": exp["pkg_name"], "declared_pkg": None,
            "version_code": None, "version_name": None,
            "tier": exp["tier"], "arm": exp["arm"], "issuer": iss["issuer"],
            "size_bytes": p.stat().st_size, "parse_ok": False,
        }
        try:
            a = APK(str(p))
            declared = a.get_package()
            row["declared_pkg"] = declared
            row["version_code"] = a.get_androidversion_code()
            row["version_name"] = a.get_androidversion_name()
            row["parse_ok"] = True
        except Exception as e:
            parse_failed.append((sha, exp["pkg_name"], f"{type(e).__name__}: {e}"))
            rows.append(row)
            continue

        if declared != exp["pkg_name"]:
            mismatches.append((sha, exp["pkg_name"], declared))

        rows.append(row)

    if parse_failed:
        print(f"[manifest] {len(parse_failed)} file(s) androguard could not parse "
              f"-- excluded from downstream n, flagged parse_ok=False:", file=sys.stderr)
        for sha, pkg, err in parse_failed:
            print(f"  {sha} ({pkg}): {err}", file=sys.stderr)

    if mismatches:
        print(f"[manifest] STOP: {len(mismatches)} declared-vs-actual package mismatch(es)",
              file=sys.stderr)
        for sha, expected_pkg, actual_pkg in mismatches:
            print(f"  {sha}: expected '{expected_pkg}', androguard says '{actual_pkg}'",
                  file=sys.stderr)
        sys.exit(1)

    print(f"[manifest] all {len(rows) - len(parse_failed)} parsed files match their "
          f"declared package name", file=sys.stderr)

    # --- Step 4: write manifest ---
    with open(OUT_TSV, "w") as f:
        f.write("\t".join(COLUMNS) + "\n")
        for r in rows:
            f.write("\t".join(str(r[c]) for c in COLUMNS) + "\n")
    print(f"[manifest] wrote {OUT_TSV} ({len(rows)} rows)", file=sys.stderr)

    print_composition_table(rows)
    run_step4_checks(rows)


def print_composition_table(rows):
    ok = [r for r in rows if r["parse_ok"]]
    print("\n=== Composition table ===")
    print(f"files total: {len(rows)}")
    print(f"files parse_ok: {len(ok)}")

    def distinct_pkgs(rs):
        return sorted({r["pkg_name"] for r in rs})

    def distinct_issuers(rs):
        return sorted({r["issuer"] for r in rs})

    print(f"distinct pkg_name overall: {len(distinct_pkgs(ok))}")
    print(f"distinct issuer overall: {len(distinct_issuers(ok))}")

    print("\nper arm:")
    for arm in ("current", "era_matched"):
        rs = [r for r in ok if r["arm"] == arm]
        print(f"  {arm}: files={len(rs)} distinct_packages={len(distinct_pkgs(rs))} "
              f"distinct_issuers={len(distinct_issuers(rs))}")

    print("\nper tier:")
    for tier in ("A", "B", "C", "D"):
        rs = [r for r in ok if r["tier"] == tier]
        print(f"  {tier}: files={len(rs)} distinct_packages={len(distinct_pkgs(rs))} "
              f"distinct_issuers={len(distinct_issuers(rs))}")

    tier_a_current = [r for r in ok if r["tier"] == "A" and r["arm"] == "current"]
    print(f"\nTier A current arm: files={len(tier_a_current)} "
          f"distinct_packages={len(distinct_pkgs(tier_a_current))} "
          f"distinct_issuers={len(distinct_issuers(tier_a_current))}")

    current_pkgs = set(distinct_pkgs([r for r in ok if r["arm"] == "current"]))
    era_pkgs = set(distinct_pkgs([r for r in ok if r["arm"] == "era_matched"]))
    era_also_current = sorted(era_pkgs & current_pkgs)
    era_only = sorted(era_pkgs - current_pkgs)
    print(f"\nera-matched packages ALSO in current arm ({len(era_also_current)}): {era_also_current}")
    print(f"era-matched packages ONLY in era-matched arm ({len(era_only)}): {era_only}")

    from collections import defaultdict
    pkg_versions = defaultdict(list)
    for r in ok:
        pkg_versions[r["pkg_name"]].append(r["version_code"])
    multi_file_pkgs = {pkg: vs for pkg, vs in pkg_versions.items() if len(vs) > 1}
    print(f"\npackages contributing >1 file ({len(multi_file_pkgs)}):")
    for pkg, vs in sorted(multi_file_pkgs.items()):
        print(f"  {pkg}: version_codes={vs}")

    issuer_pkgs = defaultdict(set)
    for r in ok:
        issuer_pkgs[r["issuer"]].add(r["pkg_name"])
    multi_pkg_issuers = {iss: pkgs for iss, pkgs in issuer_pkgs.items() if len(pkgs) > 1}
    print(f"\nissuers contributing >1 package ({len(multi_pkg_issuers)}):")
    for iss, pkgs in sorted(multi_pkg_issuers.items()):
        print(f"  {iss}: {len(pkgs)} packages -- {sorted(pkgs)}")


def run_step4_checks(rows):
    ok = [r for r in rows if r["parse_ok"]]
    print("\n=== Step 4 checks ===")

    era_files = [r for r in ok if r["arm"] == "era_matched"]
    era_a = sum(1 for r in era_files if r["tier"] == "A")
    era_b = sum(1 for r in era_files if r["tier"] == "B")
    era_d = sum(1 for r in era_files if r["tier"] == "D")
    check1 = len(era_files) == 26
    print(f"CHECK 1 -- era_matched files == 26 (20 A + 1 B + 5 D): "
          f"{'PASS' if check1 else 'FAIL'} "
          f"(actual: {len(era_files)} total = {era_a} A + {era_b} B + {era_d} D "
          f"+ {len(era_files) - era_a - era_b - era_d} other)")

    tier_a = [r for r in ok if r["tier"] == "A"]
    tier_a_current = sum(1 for r in tier_a if r["arm"] == "current")
    tier_a_era = sum(1 for r in tier_a if r["arm"] == "era_matched")
    check2 = len(tier_a) == 73 and tier_a_current == 53 and tier_a_era == 20
    print(f"CHECK 2 -- Tier A files == 73 (53 current + 20 era-matched): "
          f"{'PASS' if check2 else 'FAIL'} "
          f"(actual: {len(tier_a)} total = {tier_a_current} current + {tier_a_era} era-matched)")

    from collections import defaultdict
    by_pkg_arm = defaultdict(dict)
    for r in ok:
        by_pkg_arm[r["pkg_name"]][r["arm"]] = r["version_code"]
    not_older = []
    for pkg, arms in by_pkg_arm.items():
        if "era_matched" in arms and "current" in arms:
            try:
                era_vc = int(arms["era_matched"])
                cur_vc = int(arms["current"])
            except (TypeError, ValueError):
                not_older.append((pkg, arms["era_matched"], arms["current"], "non-integer vercode"))
                continue
            if not (era_vc < cur_vc):
                not_older.append((pkg, arms["era_matched"], arms["current"], "era >= current"))
    check3 = len(not_older) == 0
    print(f"CHECK 3 -- every era-matched version_code < current-arm version_code for same package: "
          f"{'PASS' if check3 else 'FAIL'}")
    if not_older:
        for pkg, era_vc, cur_vc, reason in not_older:
            print(f"  FAIL: {pkg}: era_matched vercode={era_vc}, current vercode={cur_vc} ({reason})")


if __name__ == "__main__":
    main()
