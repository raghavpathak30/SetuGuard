"""SetuGuard — parallel feature-extraction cache builder.

NOT one of the six frozen PS1 files. Read-only consumer of the frozen
static_analysis.analyze_apk() (imported, never modified) — runs it over a
multiprocessing pool and caches the RAW FEATURES dict per APK to disk, keyed
by sha256. The point of the cache: after this runs once, rescoring (old
formula, new formula, any future weight change) reads cached JSON only and
never re-invokes Androguard. Written 2026-08-12 for the scorer-v2 pruning
measurement (Step 2/4).

maxtasksperchild=1 so each APK gets a fresh worker process — keeps per-task
peak RSS measurement clean (no accumulation across tasks) and bounds
steady-state memory growth over a long run.

Modes:
  --benchmark N_APKS N_WORKERS   Run N_APKS through a pool of N_WORKERS,
                                  report per-process peak RSS (max, mean,
                                  min) via resource.getrusage in each worker.
                                  Does not write to the feature cache.
  (default)                      Full run over --sample-list, writing
                                  harness/feature_cache/<sha256>.json and
                                  harness/feature_cache_skips.csv. Resume is
                                  derived from those two outputs' recorded
                                  source paths (not a separate progress log),
                                  so a run killed mid-flight (OOM, etc.) can
                                  always be safely re-invoked without losing
                                  or duplicating work.

Usage:
    python3 extract_features_pool.py --benchmark --n 20 --workers 4
    python3 extract_features_pool.py --sample-list sample_set_716.txt --workers 8
"""
import argparse
import csv
import json
import resource
import sys
import time
from datetime import datetime, timezone
from multiprocessing import Pool
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "setuguard_ps1"))

CACHE_DIR = Path(__file__).parent / "feature_cache"
SKIPS_CSV = Path(__file__).parent / "feature_cache_skips.csv"
MAX_WORKERS = 8  # hard cap per instruction -- do not saturate the 20-core box


def _worker(args):
    """Runs in a fresh subprocess (maxtasksperchild=1). Returns a result dict,
    never raises -- exceptions are caught and reported as a skip."""
    path, corpus = args
    t0 = time.perf_counter()
    try:
        import static_analysis  # imported inside the worker, post-fork
        features = static_analysis.analyze_apk(path)
        elapsed = time.perf_counter() - t0
        peak_rss_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return {
            "ok": True,
            "path": path,
            "corpus": corpus,
            "sha256": features["sha256"],
            "features": features,
            "elapsed_s": elapsed,
            "peak_rss_kb": peak_rss_kb,
        }
    except Exception as e:
        elapsed = time.perf_counter() - t0
        peak_rss_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return {
            "ok": False,
            "path": path,
            "corpus": corpus,
            "exception_type": type(e).__name__,
            "exception_msg": str(e)[:300],
            "elapsed_s": elapsed,
            "peak_rss_kb": peak_rss_kb,
        }


def _read_sample_list(path: Path):
    entries = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        p, label = line.rsplit(",", 1)
        entries.append((p, label))
    return entries


def run_benchmark(n_apks: int, n_workers: int, sample_list: Path):
    entries = _read_sample_list(sample_list)[:n_apks]
    print(f"[benchmark] {len(entries)} APKs, {n_workers} workers, maxtasksperchild=1")
    t0 = time.perf_counter()
    with Pool(processes=n_workers, maxtasksperchild=1) as pool:
        results = pool.map(_worker, entries)
    elapsed = time.perf_counter() - t0

    rss_vals = [r["peak_rss_kb"] / 1024 for r in results]  # -> MB (Linux ru_maxrss is KB)
    ok = sum(1 for r in results if r["ok"])
    print(f"[benchmark] wall time: {elapsed:.1f}s for {len(entries)} APKs "
          f"({elapsed / len(entries):.2f}s/APK effective, {n_workers}x parallel)")
    print(f"[benchmark] ok={ok}/{len(entries)}")
    print(f"[benchmark] per-process peak RSS (MB): "
          f"min={min(rss_vals):.0f} mean={sum(rss_vals) / len(rss_vals):.0f} max={max(rss_vals):.0f}")
    print(f"[benchmark] projected RSS at N workers (max-observed * N): "
          f"4w={max(rss_vals) * 4:.0f}MB  8w={max(rss_vals) * 8:.0f}MB")
    for r in results:
        if not r["ok"]:
            print(f"[benchmark] FAILED {r['path']}: {r['exception_type']}: {r['exception_msg']}")


def _already_done_paths():
    """Ground truth of what's already been handled: source_path recorded
    inside each cache/*.json (verified successes) union path recorded in
    SKIPS_CSV (verified failures). Deliberately does NOT trust any separate
    progress log -- a log written by a process that gets killed (e.g. OOM)
    can silently disagree with what's actually on disk. Mirrors
    fix3_fp_harness.py's _already_processed_filenames(), which derives its
    done-set from results.csv + skips.csv, not a side log."""
    done = set()
    for f in CACHE_DIR.glob("*.json"):
        try:
            done.add(json.loads(f.read_text())["source_path"])
        except Exception:
            continue  # truncated/corrupt cache file: NOT done, will be retried
    if SKIPS_CSV.exists() and SKIPS_CSV.stat().st_size > 0:
        with open(SKIPS_CSV, newline="") as f:
            for row in csv.DictReader(f):
                if row.get("path"):
                    done.add(row["path"])
    return done


def run_full(sample_list: Path, n_workers: int):
    if n_workers > MAX_WORKERS:
        print(f"[extract] requested {n_workers} workers > cap {MAX_WORKERS}; clamping.")
        n_workers = MAX_WORKERS

    CACHE_DIR.mkdir(exist_ok=True)
    entries = _read_sample_list(sample_list)

    already_done = _already_done_paths()
    todo = [(p, c) for p, c in entries if p not in already_done]

    print(f"[extract] {len(entries)} total in sample list, {len(entries) - len(todo)} already done "
          f"(verified via cache dir + skips.csv), {len(todo)} to process, "
          f"{n_workers} workers, cap={MAX_WORKERS}")

    # Skips CSV is opened in append mode and each row is written+flushed
    # immediately as it happens (not batched to the end of the run) --
    # a run killed mid-flight must not lose the failures it already saw.
    write_header = not SKIPS_CSV.exists() or SKIPS_CSV.stat().st_size == 0
    skips_f = open(SKIPS_CSV, "a", newline="")
    skips_writer = csv.DictWriter(skips_f, fieldnames=["path", "corpus", "exception_type", "exception_msg"])
    if write_header:
        skips_writer.writeheader()
        skips_f.flush()

    n_ok = 0
    n_skip = 0
    corpus_skip_counts = {}
    t0 = time.perf_counter()

    try:
        with Pool(processes=n_workers, maxtasksperchild=1) as pool:
            for i, r in enumerate(pool.imap_unordered(_worker, todo), 1):
                if r["ok"]:
                    n_ok += 1
                    out = CACHE_DIR / f"{r['sha256']}.json"
                    payload = {
                        "sha256": r["sha256"],
                        "corpus": r["corpus"],
                        "source_path": r["path"],
                        "analyzed_at": datetime.now(timezone.utc).isoformat(),
                        "elapsed_s": round(r["elapsed_s"], 3),
                        "features": r["features"],
                    }
                    out.write_text(json.dumps(payload, default=str))
                else:
                    n_skip += 1
                    corpus_skip_counts[r["corpus"]] = corpus_skip_counts.get(r["corpus"], 0) + 1
                    skips_writer.writerow({
                        "path": r["path"], "corpus": r["corpus"],
                        "exception_type": r["exception_type"], "exception_msg": r["exception_msg"],
                    })
                    skips_f.flush()
                if i % 50 == 0 or i == len(todo):
                    elapsed = time.perf_counter() - t0
                    print(f"[extract] {i}/{len(todo)} done ({elapsed:.0f}s elapsed, "
                          f"{elapsed / i:.2f}s/APK effective)")
    finally:
        skips_f.close()

    print(f"[extract] done. ok={n_ok} skipped={n_skip} "
          f"(this run; see {SKIPS_CSV} for cumulative)")
    print(f"[extract] skip counts by corpus (this run): {corpus_skip_counts}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample-list", type=Path, default=Path(__file__).parent / "sample_set_716.txt")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--benchmark", action="store_true")
    ap.add_argument("--n", type=int, default=20, help="benchmark: number of APKs")
    args = ap.parse_args()

    if args.benchmark:
        run_benchmark(args.n, args.workers, args.sample_list)
    else:
        run_full(args.sample_list, args.workers)
