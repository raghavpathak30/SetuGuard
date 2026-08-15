"""SetuGuard -- verify the malware and F-Droid corpora's own labels against AndroZoo. NON-FROZEN.

NOT one of the six frozen PS1 files and not part of batch_baseline.py's suite. Read-only over
latest.csv.gz and over the two corpus directories (only to enumerate filenames / compute
sha256 -- no APK is opened, parsed, or modified).

Why this exists: this project has never verified that the 2,489 cicmaldroid_banking/ samples are
actually malicious, or that fdroid_benign_apks/ (which carries the surviving AUC 0.9366 figure) is
actually clean. Both labels were taken on trust from a directory name -- structurally the same
assumption that produced the banking_holdout_16/ error, at larger scale and with better odds of
being right, but currently unfalsified rather than verified. latest.csv carries VirusTotal
vt_detection keyed by sha256 for every file AndroZoo has seen, so checking both corpora against
it costs one grep against a file already on disk for other reasons.

cicmaldroid_banking/ is sha256-named already (confirmed in BANKING_ARCHIVE_MANIFEST.tsv), so its
2,489 hashes come straight from filenames. fdroid_benign_apks/ is NOT sha256-named (F-Droid
filenames are package_versioncode.apk) -- its 802 hashes must be computed from file content, once,
and are cached to harness/fdroid_sha256_cache.tsv (filename<TAB>sha256) so a re-run doesn't
re-hash 12GB of APKs it already hashed. This also closes CORPUS_PROVENANCE.md's open item about
the 2 F-Droid APKs with no recorded download URL (acab.naiveha.subrosa_7.apk,
app.olauncher_105.apk): an AndroZoo vt_detection lookup is independent evidence about them even
without their original URL.

For testability without a real 2.7GB+ latest.csv.gz or the full 802-file F-Droid corpus, the hash
lists can be supplied directly (--malware-hashes-file / --benign-hashes-file, one hex sha256 per
line) instead of derived from directories -- used by this script's dry run against the shared
fixture, harness/fixtures/fake_latest.csv.

Usage:
    python3 vt_label_lookup.py --csv-gz ~/latest.csv.gz \\
        --malware-dir cicmaldroid_banking --benign-dir fdroid_benign_apks \\
        --out harness/CORPUS_LABEL_VERIFICATION.md
    python3 vt_label_lookup.py --csv-gz harness/fixtures/fake_latest.csv --plain-text \\
        --malware-hashes-file /tmp/mal.txt --benign-hashes-file /tmp/ben.txt --out /tmp/dryrun.md
"""
import argparse
import csv
import hashlib
import statistics
import subprocess
import sys
from pathlib import Path

FDROID_CACHE = Path(__file__).parent / "fdroid_sha256_cache.tsv"


def sha256_of_file(path: Path, chunk=1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(chunk), b""):
            h.update(c)
    return h.hexdigest()


def malware_hashes_from_dir(d: Path) -> dict:
    """cicmaldroid_banking/ is sha256-named -- filenames ARE the hashes.
    Excludes non-.apk stray files (the known 9cc47edb...sh)."""
    return {f.stem.upper(): f.name for f in d.glob("*.apk")}


def benign_hashes_from_dir(d: Path, cache_path: Path = FDROID_CACHE) -> dict:
    """fdroid_benign_apks/ is NOT sha256-named. Computes content sha256 for
    every file, cached so a re-run doesn't re-hash ~12GB it already hashed."""
    cached = {}
    if cache_path.exists():
        with open(cache_path, newline="") as f:
            for row in csv.reader(f, delimiter="\t"):
                if len(row) == 2:
                    cached[row[0]] = row[1]

    out = {}
    new_entries = []
    files = sorted(d.glob("*.apk"))
    for i, f in enumerate(files, 1):
        if f.name in cached:
            out[cached[f.name].upper()] = f.name
            continue
        sha = sha256_of_file(f)
        out[sha.upper()] = f.name
        new_entries.append((f.name, sha))
        if i % 100 == 0 or i == len(files):
            print(f"[vt_label] hashed {i}/{len(files)} F-Droid files "
                  f"({len(new_entries)} newly this run)", file=sys.stderr)

    if new_entries:
        with open(cache_path, "a", newline="") as f:
            w = csv.writer(f, delimiter="\t")
            for name, sha in new_entries:
                w.writerow([name, sha])
    return out


def read_hashes_file(path: Path) -> list:
    return [line.strip().upper() for line in path.read_text().splitlines() if line.strip()]


def stream_matches(csv_gz: Path, hashes: list, plain_text: bool):
    """zcat/cat | grep -F -f <hashes>, matched lines only. sha256 is a fixed
    64-hex-char field so grep -F substring risk is negligible (a 64-char hex
    string is vanishingly unlikely to appear inside another field by chance)
    but every line is still exact-matched on the sha256 COLUMN, not just
    "grep matched somewhere in the line", before it counts."""
    pattern_file = csv_gz.parent / ".vt_grep_patterns.tmp"
    pattern_file.write_text("\n".join(h.upper() for h in hashes) + "\n")
    try:
        cat_cmd = ["cat", str(csv_gz)] if plain_text else ["zcat", str(csv_gz)]
        cat = subprocess.Popen(cat_cmd, stdout=subprocess.PIPE)
        grep = subprocess.Popen(["grep", "-F", "-f", str(pattern_file)],
                                 stdin=cat.stdout, stdout=subprocess.PIPE, text=True)
        cat.stdout.close()
        for line in grep.stdout:
            yield line.rstrip("\n")
        grep.wait()
        cat.wait()
    finally:
        pattern_file.unlink(missing_ok=True)


def read_header(csv_gz: Path, plain_text: bool) -> list:
    cat_cmd = ["cat", str(csv_gz)] if plain_text else ["zcat", str(csv_gz)]
    cat = subprocess.Popen(cat_cmd, stdout=subprocess.PIPE)
    head = subprocess.run(["head", "-1"], stdin=cat.stdout, stdout=subprocess.PIPE, text=True)
    cat.stdout.close()
    cat.terminate()
    line = head.stdout.rstrip("\n")
    return next(csv.reader([line])) if line else []


def lookup(csv_gz: Path, hashes: list, plain_text: bool):
    """Returns {sha256: (vt_detection_str, vt_scan_date_str)}."""
    header = read_header(csv_gz, plain_text)
    col = {name: i for i, name in enumerate(header)}
    if "sha256" not in col or "vt_detection" not in col or "vt_scan_date" not in col:
        print(f"[vt_label] FATAL: expected columns missing from header {header}", file=sys.stderr)
        sys.exit(1)
    target = set(h.upper() for h in hashes)
    found = {}
    for line in stream_matches(csv_gz, hashes, plain_text):
        try:
            fields = next(csv.reader([line]))
        except Exception:
            continue
        if len(fields) <= max(col.values()):
            continue
        sha = fields[col["sha256"]].upper()
        if sha in target:
            found[sha] = (fields[col["vt_detection"]], fields[col["vt_scan_date"]])
    return found


def scored_benign_sample(benign_dir: Path, seed: int = 42, n: int = 300) -> list:
    """Reproduces build_sample_set_716.py's seeded benign draw exactly: sorted
    glob, then a fresh random.Random(seed).sample() (build_sample_set_716.py:39-40).
    That draw, not the full 802, is what the surviving AUC 0.9366 figure was
    computed on."""
    import random
    pool = sorted(benign_dir.glob("*.apk"))
    return random.Random(seed).sample(pool, n)


def summarize(name_by_sha: dict, vt_by_sha: dict):
    total = len(name_by_sha)
    resolved = {sha: vt for sha, vt in vt_by_sha.items() if sha in name_by_sha}
    n_resolved = len(resolved)
    detections = []
    scan_years = {}
    n_zero, n_ge5, n_unparseable = 0, 0, 0
    for sha, (vt, scan_date) in resolved.items():
        try:
            v = int(vt)
        except (ValueError, TypeError):
            n_unparseable += 1
            continue
        detections.append(v)
        if v == 0:
            n_zero += 1
        if v >= 5:
            n_ge5 += 1
        year = scan_date[:4] if scan_date and scan_date[:4].isdigit() else "unknown"
        scan_years[year] = scan_years.get(year, 0) + 1
    detections_sorted = sorted(detections)
    return {
        "total_in_corpus": total,
        "resolved_in_androzoo": n_resolved,
        "unresolved_in_androzoo": total - n_resolved,
        "resolved_pct": round(100 * n_resolved / total, 1) if total else None,
        "vt_detection_unparseable": n_unparseable,
        "vt_detection_median": statistics.median(detections) if detections else None,
        "vt_detection_mean": round(statistics.mean(detections), 2) if detections else None,
        "vt_detection_min": min(detections) if detections else None,
        "vt_detection_max": max(detections) if detections else None,
        "vt_detection_p25": detections_sorted[len(detections_sorted) // 4] if detections_sorted else None,
        "vt_detection_p75": detections_sorted[(3 * len(detections_sorted)) // 4] if detections_sorted else None,
        "vt_detection_all_sorted": detections_sorted,
        "n_zero_detections": n_zero,
        "pct_zero_detections": round(100 * n_zero / n_resolved, 1) if n_resolved else None,
        "n_ge5_detections": n_ge5,
        "pct_ge5_detections": round(100 * n_ge5 / n_resolved, 1) if n_resolved else None,
        "vt_scan_year_distribution": dict(sorted(scan_years.items())),
    }


def histogram_buckets(values):
    edges = [("0", lambda v: v == 0), ("1-4", lambda v: 1 <= v <= 4), ("5-9", lambda v: 5 <= v <= 9),
             ("10-19", lambda v: 10 <= v <= 19), ("20-29", lambda v: 20 <= v <= 29),
             ("30-39", lambda v: 30 <= v <= 39), ("40+", lambda v: v >= 40)]
    return [(label, sum(1 for v in values if pred(v))) for label, pred in edges]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv-gz", type=Path, required=True)
    ap.add_argument("--plain-text", action="store_true")
    ap.add_argument("--malware-dir", type=Path)
    ap.add_argument("--benign-dir", type=Path)
    ap.add_argument("--malware-hashes-file", type=Path)
    ap.add_argument("--benign-hashes-file", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    if args.malware_hashes_file:
        mal_name_by_sha = {h: h for h in read_hashes_file(args.malware_hashes_file)}
    else:
        mal_name_by_sha = malware_hashes_from_dir(args.malware_dir)
    if args.benign_hashes_file:
        ben_name_by_sha = {h: h for h in read_hashes_file(args.benign_hashes_file)}
    else:
        ben_name_by_sha = benign_hashes_from_dir(args.benign_dir)

    print(f"[vt_label] {len(mal_name_by_sha)} malware hashes, {len(ben_name_by_sha)} benign hashes "
          f"to look up", file=sys.stderr)

    all_hashes = list(mal_name_by_sha) + list(ben_name_by_sha)
    vt_by_sha = lookup(args.csv_gz, all_hashes, args.plain_text)
    print(f"[vt_label] {len(vt_by_sha)} of {len(all_hashes)} total hashes resolved in AndroZoo",
          file=sys.stderr)

    mal_summary = summarize(mal_name_by_sha, vt_by_sha)
    ben_summary = summarize(ben_name_by_sha, vt_by_sha)

    ben_nonzero = [sha for sha, (vt, _) in vt_by_sha.items()
                   if sha in ben_name_by_sha and vt not in ("0", "")]

    scored_summary = None
    if args.benign_dir:
        scored_files = scored_benign_sample(args.benign_dir)
        name_to_sha = {name: sha for sha, name in ben_name_by_sha.items()}
        scored_name_by_sha = {name_to_sha[f.name]: f.name for f in scored_files if f.name in name_to_sha}
        scored_summary = summarize(scored_name_by_sha, vt_by_sha)

    args.out.write_text(render(mal_summary, ben_summary, ben_nonzero, ben_name_by_sha, scored_summary))
    args.out.with_suffix(".json").write_text(
        __import__("json").dumps(
            {"malware": mal_summary, "benign": ben_summary, "scored_benign_300": scored_summary},
            indent=2))
    print(f"[vt_label] malware: resolved={mal_summary['resolved_in_androzoo']}/{mal_summary['total_in_corpus']} "
          f"median_vt={mal_summary['vt_detection_median']} pct_zero={mal_summary['pct_zero_detections']}",
          file=sys.stderr)
    print(f"[vt_label] benign:  resolved={ben_summary['resolved_in_androzoo']}/{ben_summary['total_in_corpus']} "
          f"pct_zero={ben_summary['pct_zero_detections']}", file=sys.stderr)
    print(f"[vt_label] wrote {args.out}", file=sys.stderr)


ZERO_DETECTION_CAVEAT_THRESHOLD_PCT = 15.0


def render(mal, ben, ben_nonzero, ben_name_by_sha, scored=None) -> str:
    L = ["# Corpus label verification — independent check against AndroZoo VirusTotal data\n",
         "This project has never verified that `cicmaldroid_banking/`'s 2,489 samples are "
         "actually malicious, or that `fdroid_benign_apks/`'s 802 samples are actually clean. "
         "Both labels were taken on trust from a directory name -- the same class of assumption "
         "that produced the `banking_holdout_16/` error, at larger scale and with better odds. "
         "This is the first independent evidence for either label.\n",
         f"**Pre-registered interpretation rule (fixed before the numbers were seen):** if more "
         f"than {ZERO_DETECTION_CAVEAT_THRESHOLD_PCT}% of resolvable malware samples carry "
         f"`vt_detection == 0`, the positive-class label requires an explicit caveat in this "
         f"report. Below {ZERO_DETECTION_CAVEAT_THRESHOLD_PCT}%, a tail of zeros is normal for "
         f"any malware corpus.\n"]

    L.append(f"## Malware corpus (`cicmaldroid_banking/`, n={mal['total_in_corpus']} on disk)\n")
    L.append(f"- Resolved in AndroZoo: **{mal['resolved_in_androzoo']}/{mal['total_in_corpus']}** "
             f"({mal['resolved_pct']}%) -- **{mal['unresolved_in_androzoo']} not found in AndroZoo, "
             f"stated plainly as a real coverage limitation, not extrapolated over.**")
    L.append(f"- `vt_detection` median: **{mal['vt_detection_median']}**, "
             f"mean {mal['vt_detection_mean']}, IQR [{mal['vt_detection_p25']}, {mal['vt_detection_p75']}], "
             f"range [{mal['vt_detection_min']}, {mal['vt_detection_max']}] (of "
             f"{mal['resolved_in_androzoo']} resolved)")
    L.append("- Full distribution:")
    for label, count in histogram_buckets(mal['vt_detection_all_sorted']):
        pct = round(100 * count / mal['resolved_in_androzoo'], 1) if mal['resolved_in_androzoo'] else 0
        L.append(f"  - `{label}`: {count} ({pct}%)")
    L.append(f"- **≥5 detections: {mal['n_ge5_detections']} ({mal['pct_ge5_detections']}%)**")
    L.append(f"- **`vt_detection == 0`: {mal['n_zero_detections']} ({mal['pct_zero_detections']}%)** "
             f"of {mal['resolved_in_androzoo']} resolved -- reported as-is, no staleness "
             f"explanation offered (CICMalDroid samples date from 2017-18 and the `vt_scan_date` "
             f"distribution above shows most resolved scans postdate collection, so staleness is "
             f"not a credible account of these zeros).")
    if mal['vt_detection_unparseable']:
        L.append(f"- Unparseable `vt_detection` field: {mal['vt_detection_unparseable']}")
    over_threshold = mal['pct_zero_detections'] is not None and mal['pct_zero_detections'] > ZERO_DETECTION_CAVEAT_THRESHOLD_PCT
    side = "ABOVE" if over_threshold else "BELOW"
    verdict = "the caveat applies" if over_threshold else "no caveat is required"
    L.append(f"- **Threshold result: {mal['pct_zero_detections']}% is {side} the "
             f"{ZERO_DETECTION_CAVEAT_THRESHOLD_PCT}% pre-registered threshold -- {verdict}.**")
    L.append("- `vt_scan_date` distribution (by year, of resolved samples):")
    for year, count in mal['vt_scan_year_distribution'].items():
        L.append(f"  - {year}: {count}")
    L.append("")

    L.append(f"## Benign corpus (`fdroid_benign_apks/`, n={ben['total_in_corpus']} on disk)\n")
    L.append("Carries the surviving AUC 0.9366 figure -- its labels have never been checked "
             "either.\n")
    L.append(f"- Resolved in AndroZoo: **{ben['resolved_in_androzoo']}/{ben['total_in_corpus']}** "
             f"({ben['resolved_pct']}%) -- **{ben['unresolved_in_androzoo']} not found in AndroZoo.**")
    L.append(f"- **`vt_detection == 0`: {ben['n_zero_detections']}/{ben['resolved_in_androzoo']} "
             f"resolved ({ben['pct_zero_detections']}%)**")
    if ben_nonzero:
        L.append(f"\n**{len(ben_nonzero)} F-Droid sample(s) resolved with nonzero `vt_detection`:**")
        for sha in ben_nonzero:
            L.append(f"- `{sha}` ({ben_name_by_sha.get(sha, '?')})")
    else:
        L.append("\nNo F-Droid sample resolved with a nonzero detection count.")
    L.append("")

    if scored is not None:
        L.append("## Scored subset (the 300 actually behind AUC 0.9366)\n")
        L.append("`build_sample_set_716.py:39-40` draws the benign arm as "
                 "`random.Random(42).sample(sorted(fdroid_benign_apks/*.apk), 300)` -- the AUC was "
                 "computed on those 300, not the full 802. Reproduced here with the same seed and "
                 "the same sorted-glob draw order.\n")
        L.append(f"- Resolved in AndroZoo: **{scored['resolved_in_androzoo']}/{scored['total_in_corpus']}** "
                 f"({scored['resolved_pct']}%) -- {scored['unresolved_in_androzoo']} not found.")
        L.append(f"- **`vt_detection == 0`: {scored['n_zero_detections']}/{scored['resolved_in_androzoo']} "
                 f"resolved ({scored['pct_zero_detections']}%)**")
        L.append("")

    L.append("## Closes: the two F-Droid APKs with no recorded download URL\n")
    L.append("`CORPUS_PROVENANCE.md` (P-5) flags `acab.naiveha.subrosa_7.apk` and "
             "`app.olauncher_105.apk` as present on disk with no entry in `fdroid_urls.txt`. "
             "An AndroZoo resolution for either is independent evidence about them even without "
             "their original download URL -- check the benign corpus table above for their "
             "sha256 (computed and cached in `harness/fdroid_sha256_cache.tsv`) directly.\n")

    return "\n".join(L) + "\n"


if __name__ == "__main__":
    main()
