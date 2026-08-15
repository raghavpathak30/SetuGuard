"""SetuGuard -- resumable downloader for the pre-registered banking corpus. NON-FROZEN.

NOT one of the six frozen PS1 files and not part of batch_baseline.py's suite. Downloads only
the exact (sha256, tier, arm) set chosen by filter_banking_candidates.py
(harness/banking_candidates.json), against the rule pre-registered in
harness/BANKING_CORPUS_INCLUSION_RULE.md, committed before this script ever ran against a real
candidate list.

APKs never enter git -- *.apk is already gitignored repo-wide (.gitignore line 6). Output
directory: harness/banking_legit_corpus/ (created on demand).

Priority order (hard-coded, per PLAN A4 -- NOT a CLI flag, because getting this wrong silently
degrades which arm finishes first, and a complete primary arm at n=55 is worth more than two
half-built arms at n=110):
  1. Tier A, era-matched
  2. Tier B, era-matched
  3. Tiers C and D, era-matched
  4. Tier A, current
  5. everything else, current
Within each band: ascending apk_size (small files first maximises n per hour of transfer).

Resumability follows harness/extract_features_pool.py's precedent, not a separate progress log:
on startup this script re-derives "already done" by scanning the output directory and verifying
each <sha256>.apk file's ACTUAL sha256 against its filename -- not by trusting a state file that
could disagree with reality if a prior run was killed mid-write. A mismatching file is deleted
and re-queued rather than trusted.

Concurrency: 4-6 connections max (--workers, clamped). Each completed transfer is SHA-256
verified against the manifest's expected hash before being counted done; on mismatch the file is
deleted and re-queued once (MAX_RETRIES), then given up on and logged to
harness/banking_download_failures.csv.

Requires an AndroZoo API key in $AZ_KEY or ~/.az (first non-blank line). Refuses to start
without one rather than silently doing nothing.

Usage:
    python3 download_banking_corpus.py --candidates harness/banking_candidates.json \\
        --out-dir harness/banking_legit_corpus --workers 5 --stop-at 2026-08-15T12:00:00
    python3 download_banking_corpus.py --candidates harness/banking_candidates.json --dry-run
"""
import argparse
import csv
import hashlib
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import requests

API_URL = "https://androzoo.uni.lu/api/download"
MAX_RETRIES = 1
MIN_WORKERS, MAX_WORKERS, DEFAULT_WORKERS = 4, 6, 5


def get_api_key() -> str:
    key = os.environ.get("AZ_KEY", "").strip()
    if key:
        return key
    az_file = Path.home() / ".az"
    if az_file.exists():
        for line in az_file.read_text().splitlines():
            line = line.strip()
            if line:
                return line
    print("[download] FATAL: no AndroZoo API key found. Set $AZ_KEY or put it as the first "
          "non-blank line of ~/.az. Refusing to start rather than silently doing nothing.",
          file=sys.stderr)
    sys.exit(1)


def sha256_of_file(path: Path, chunk=1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(chunk), b""):
            h.update(c)
    return h.hexdigest()


def build_priority_queue(candidates: dict):
    """Returns an ordered list of (sha256, tier, arm, apk_size, pkg_name) per
    the hard-coded A4 priority order. era_matched_picks / current_picks are
    keyed by pkg_name -> row dict (from filter_banking_candidates.py)."""
    tier_of = {pkg: p["tier"] for pkg, p in candidates["per_package"].items()}
    era = candidates["era_matched_picks"]
    cur = candidates["current_picks"]

    def entries(picks, arm):
        out = []
        for pkg, row in picks.items():
            try:
                size = int(row["apk_size"])
            except (KeyError, ValueError):
                size = 0
            out.append({
                "sha256": row["sha256"], "pkg_name": pkg, "tier": tier_of[pkg],
                "arm": arm, "apk_size": size,
            })
        return out

    era_entries = entries(era, "era_matched")
    cur_entries = entries(cur, "current")

    bands = [
        [e for e in era_entries if e["tier"] == "A"],
        [e for e in era_entries if e["tier"] == "B"],
        [e for e in era_entries if e["tier"] in ("C", "D")],
        [e for e in cur_entries if e["tier"] == "A"],
        [e for e in cur_entries if e["tier"] != "A"],
    ]
    queue = []
    for band in bands:
        queue.extend(sorted(band, key=lambda e: e["apk_size"]))
    return queue


def scan_existing(out_dir: Path) -> dict:
    """Verifies every <sha256>.apk already on disk against its own filename.
    A mismatch means a prior run was killed mid-write -- delete and re-queue
    rather than trust it. Returns {sha256: True} for verified-good files."""
    good = {}
    for f in out_dir.glob("*.apk"):
        expected = f.stem
        try:
            actual = sha256_of_file(f)
        except OSError:
            continue
        if actual.lower() == expected.lower():
            good[expected] = True
        else:
            print(f"[download] {f.name}: on-disk hash mismatch "
                  f"(expected {expected[:12]}…, got {actual[:12]}…) -- deleting, will re-queue",
                  file=sys.stderr)
            f.unlink()
    return good


def download_one(sha256: str, api_key: str, out_dir: Path, timeout=180):
    dest = out_dir / f"{sha256}.apk"
    tmp = out_dir / f"{sha256}.apk.part"
    t0 = time.perf_counter()
    try:
        resp = requests.get(API_URL, params={"apikey": api_key, "sha256": sha256},
                             stream=True, timeout=timeout)
        resp.raise_for_status()
        n_bytes = 0
        with open(tmp, "wb") as f:
            for chunk in resp.iter_content(chunk_size=1 << 16):
                f.write(chunk)
                n_bytes += len(chunk)
        actual = sha256_of_file(tmp)
        if actual.lower() != sha256.lower():
            tmp.unlink(missing_ok=True)
            return {"sha256": sha256, "ok": False, "reason": f"sha_mismatch got={actual[:12]}",
                    "bytes": n_bytes, "elapsed_s": time.perf_counter() - t0}
        tmp.rename(dest)
        return {"sha256": sha256, "ok": True, "bytes": n_bytes,
                 "elapsed_s": time.perf_counter() - t0}
    except Exception as e:
        tmp.unlink(missing_ok=True)
        return {"sha256": sha256, "ok": False, "reason": f"{type(e).__name__}: {e}",
                "bytes": 0, "elapsed_s": time.perf_counter() - t0}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidates", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, default=Path(__file__).parent / "banking_legit_corpus")
    ap.add_argument("--failures-csv", type=Path,
                     default=Path(__file__).parent / "banking_download_failures.csv")
    ap.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    ap.add_argument("--stop-at", type=str, default=None,
                     help="ISO timestamp; stop launching new downloads at or after this time")
    ap.add_argument("--dry-run", action="store_true",
                     help="build and print the priority queue, download nothing")
    args = ap.parse_args()

    workers = max(MIN_WORKERS, min(MAX_WORKERS, args.workers))
    candidates = json.loads(args.candidates.read_text())
    queue = build_priority_queue(candidates)

    print(f"[download] priority queue: {len(queue)} targets "
          f"(workers={workers}, capped to [{MIN_WORKERS},{MAX_WORKERS}])", file=sys.stderr)
    band_counts = {}
    for e in queue:
        key = (e["arm"], e["tier"])
        band_counts[key] = band_counts.get(key, 0) + 1
    for (arm, tier), n in sorted(band_counts.items(), key=lambda kv: -len(str(kv[0]))):
        print(f"  {arm:12s} tier {tier}: {n}", file=sys.stderr)

    if args.dry_run:
        for e in queue:
            print(f"  {e['arm']:12s} {e['tier']} {e['apk_size']:>10d}B {e['pkg_name']} {e['sha256'][:16]}…",
                  file=sys.stderr)
        return

    args.out_dir.mkdir(exist_ok=True)
    api_key = get_api_key()

    already_good = scan_existing(args.out_dir)
    todo = [e for e in queue if e["sha256"] not in already_good]
    print(f"[download] {len(already_good)} already on disk and verified, "
          f"{len(todo)} to fetch", file=sys.stderr)

    stop_at = datetime.fromisoformat(args.stop_at) if args.stop_at else None

    write_header = not args.failures_csv.exists() or args.failures_csv.stat().st_size == 0
    fail_f = open(args.failures_csv, "a", newline="")
    fail_w = csv.DictWriter(fail_f, fieldnames=["sha256", "pkg_name", "tier", "arm", "reason"])
    if write_header:
        fail_w.writeheader()
        fail_f.flush()

    t_start = time.perf_counter()
    cumulative_bytes = 0
    n_ok, n_failed = 0, 0
    retries_used = {}

    def submit(entry):
        return download_one(entry["sha256"], api_key, args.out_dir)

    pending = list(todo)
    try:
        while pending:
            if stop_at and datetime.now() >= stop_at:
                print(f"[download] stop-at reached ({args.stop_at}); "
                      f"{len(pending)} targets not started", file=sys.stderr)
                break
            batch = pending[:workers]
            pending = pending[workers:]
            entry_by_sha = {e["sha256"]: e for e in batch}
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(submit, e): e for e in batch}
                for fut in as_completed(futures):
                    r = fut.result()
                    entry = entry_by_sha[r["sha256"]]
                    cumulative_bytes += r["bytes"]
                    elapsed = time.perf_counter() - t_start
                    rate_kb_s = (cumulative_bytes / 1024) / elapsed if elapsed > 0 else 0
                    if r["ok"]:
                        n_ok += 1
                        print(f"[download] OK  {entry['arm']:12s} {entry['tier']} "
                              f"{entry['pkg_name']:45s} {r['bytes']/1024:8.0f}KB "
                              f"{r['elapsed_s']:5.1f}s | cumulative {cumulative_bytes/1e6:.1f}MB "
                              f"in {elapsed:.0f}s ({rate_kb_s:.0f} KB/s avg) | "
                              f"{n_ok} ok / {n_failed} failed / {len(pending)} queued",
                              file=sys.stderr)
                    else:
                        retries = retries_used.get(r["sha256"], 0)
                        if retries < MAX_RETRIES:
                            retries_used[r["sha256"]] = retries + 1
                            pending.append(entry)
                            print(f"[download] RETRY {entry['pkg_name']}: {r['reason']}",
                                  file=sys.stderr)
                        else:
                            n_failed += 1
                            fail_w.writerow({"sha256": r["sha256"], "pkg_name": entry["pkg_name"],
                                              "tier": entry["tier"], "arm": entry["arm"],
                                              "reason": r["reason"]})
                            fail_f.flush()
                            print(f"[download] GIVE UP {entry['pkg_name']}: {r['reason']}",
                                  file=sys.stderr)
    finally:
        fail_f.close()

    elapsed = time.perf_counter() - t_start
    print(f"\n[download] done this invocation: {n_ok} ok, {n_failed} gave up, "
          f"{cumulative_bytes/1e6:.1f}MB in {elapsed:.0f}s", file=sys.stderr)
    print(f"[download] re-run to resume -- already-good files are re-verified and skipped, "
          f"not re-fetched", file=sys.stderr)


if __name__ == "__main__":
    main()
