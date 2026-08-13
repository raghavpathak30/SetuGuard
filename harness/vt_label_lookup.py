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
    return {f.stem: f.name for f in d.glob("*.apk")}


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
            out[cached[f.name]] = f.name
            continue
        sha = sha256_of_file(f)
        out[sha] = f.name
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
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]


def stream_matches(csv_gz: Path, hashes: list, plain_text: bool):
    """zcat/cat | grep -F -f <hashes>, matched lines only. sha256 is a fixed
    64-hex-char field so grep -F substring risk is negligible (a 64-char hex
    string is vanishingly unlikely to appear inside another field by chance)
    but every line is still exact-matched on the sha256 COLUMN, not just
    "grep matched somewhere in the line", before it counts."""
    pattern_file = csv_gz.parent / ".vt_grep_patterns.tmp"
    pattern_file.write_text("\n".join(hashes) + "\n")
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
    """Returns {sha256: vt_detection_str_or_None}."""
    header = read_header(csv_gz, plain_text)
    col = {name: i for i, name in enumerate(header)}
    if "sha256" not in col or "vt_detection" not in col:
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
            found[fields[col["sha256"]]] = fields[col["vt_detection"]]
    return found


def summarize(name_by_sha: dict, vt_by_sha: dict):
    total = len(name_by_sha)
    resolved = {sha: vt for sha, vt in vt_by_sha.items() if sha in name_by_sha}
    n_resolved = len(resolved)
    detections = []
    n_zero, n_ge5, n_unparseable = 0, 0, 0
    for sha, vt in resolved.items():
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
    return {
        "total_in_corpus": total,
        "resolved_in_androzoo": n_resolved,
        "resolved_pct": round(100 * n_resolved / total, 1) if total else None,
        "vt_detection_unparseable": n_unparseable,
        "vt_detection_median": statistics.median(detections) if detections else None,
        "vt_detection_mean": round(statistics.mean(detections), 2) if detections else None,
        "vt_detection_min": min(detections) if detections else None,
        "vt_detection_max": max(detections) if detections else None,
        "n_zero_detections": n_zero,
        "pct_zero_detections": round(100 * n_zero / n_resolved, 1) if n_resolved else None,
        "n_ge5_detections": n_ge5,
        "pct_ge5_detections": round(100 * n_ge5 / n_resolved, 1) if n_resolved else None,
    }


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

    ben_nonzero = [sha for sha, vt in vt_by_sha.items()
                   if sha in ben_name_by_sha and vt not in ("0", "")]

    args.out.write_text(render(mal_summary, ben_summary, ben_nonzero, ben_name_by_sha))
    args.out.with_suffix(".json").write_text(
        __import__("json").dumps({"malware": mal_summary, "benign": ben_summary}, indent=2))
    print(f"[vt_label] malware: resolved={mal_summary['resolved_in_androzoo']}/{mal_summary['total_in_corpus']} "
          f"median_vt={mal_summary['vt_detection_median']} pct_zero={mal_summary['pct_zero_detections']}",
          file=sys.stderr)
    print(f"[vt_label] benign:  resolved={ben_summary['resolved_in_androzoo']}/{ben_summary['total_in_corpus']} "
          f"pct_zero={ben_summary['pct_zero_detections']}", file=sys.stderr)
    print(f"[vt_label] wrote {args.out}", file=sys.stderr)


def render(mal, ben, ben_nonzero, ben_name_by_sha) -> str:
    L = ["# Corpus label verification — independent check against AndroZoo VirusTotal data\n",
         "This project has never verified that `cicmaldroid_banking/`'s 2,489 samples are "
         "actually malicious, or that `fdroid_benign_apks/`'s 802 samples are actually clean. "
         "Both labels were taken on trust from a directory name -- the same class of assumption "
         "that produced the `banking_holdout_16/` error, at larger scale and with better odds. "
         "This is the first independent evidence for either label.\n"]

    L.append(f"## Malware corpus (`cicmaldroid_banking/`, n={mal['total_in_corpus']} on disk)\n")
    L.append(f"- Resolved in AndroZoo: **{mal['resolved_in_androzoo']}/{mal['total_in_corpus']}** "
             f"({mal['resolved_pct']}%)")
    L.append(f"- `vt_detection` median: **{mal['vt_detection_median']}**, "
             f"mean {mal['vt_detection_mean']}, range [{mal['vt_detection_min']}, {mal['vt_detection_max']}]")
    L.append(f"- **≥5 detections: {mal['n_ge5_detections']} ({mal['pct_ge5_detections']}%)**")
    L.append(f"- **`vt_detection == 0`: {mal['n_zero_detections']} ({mal['pct_zero_detections']}%)** "
             f"-- reported loudly: this is either AndroZoo staleness (scanned before signatures "
             f"existed) or a mislabelled sample, and this file does not distinguish which.")
    if mal['vt_detection_unparseable']:
        L.append(f"- Unparseable `vt_detection` field: {mal['vt_detection_unparseable']}")
    L.append("")

    L.append(f"## Benign corpus (`fdroid_benign_apks/`, n={ben['total_in_corpus']} on disk)\n")
    L.append("Carries the surviving AUC 0.9366 figure -- its labels have never been checked "
             "either.\n")
    L.append(f"- Resolved in AndroZoo: **{ben['resolved_in_androzoo']}/{ben['total_in_corpus']}** "
             f"({ben['resolved_pct']}%)")
    L.append(f"- **`vt_detection == 0`: {ben['n_zero_detections']}/{ben['resolved_in_androzoo']} "
             f"resolved ({ben['pct_zero_detections']}%)**")
    if ben_nonzero:
        L.append(f"\n**{len(ben_nonzero)} F-Droid sample(s) resolved with nonzero `vt_detection`:**")
        for sha in ben_nonzero:
            L.append(f"- `{sha}` ({ben_name_by_sha.get(sha, '?')})")
    else:
        L.append("\nNo F-Droid sample resolved with a nonzero detection count.")
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
