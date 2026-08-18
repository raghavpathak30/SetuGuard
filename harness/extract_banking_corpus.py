"""SetuGuard -- feature extraction for the banking-legit corpus, priority-ordered. NON-FROZEN.

NOT one of the six frozen PS1 files. Read-only consumer of the frozen
static_analysis.analyze_apk() (imported, never modified) -- same function
extract_features_pool.py uses for the 668-sample malware/F-Droid cache.

Why a separate script rather than reusing extract_features_pool.py: that script's
CACHE_DIR/SKIPS_CSV are hardcoded module constants pointing at harness/feature_cache/,
not parameterised, and its worklist format (--sample-list, comma-separated path,label)
doesn't carry tier/arm/size_bytes for priority ordering. Per instruction, it is reused
AS IS for the 668-sample cache and NOT modified; this script adds only what the banking
run needs on top of the same core pattern (subprocess-per-APK, frozen analyze_apk import,
resumable via what's already on disk):

  - a SEPARATE cache dir, harness/banking_feature_cache/, so feature_cache/ stays
    byte-identical
  - work order read from BANKING_CORPUS_MANIFEST.tsv: Tier A current arm (53, primary)
    -> Tier A era-matched (20, confound check) -> everything else (22), ascending
    size_bytes within each group
  - a real per-file wall-clock timeout (600s) that can actually kill a stuck worker --
    built on multiprocessing.Process + terminate(), not Pool.imap, because Pool has no
    way to kill an individual stuck task without tearing down the whole pool
  - exit-code-based skip classification (timeout / memory / androguard_parse_error /
    other:<ExceptionClass>) so an OOM-killed worker (SIGKILL, exitcode -9) is
    distinguishable from a normal Python exception

sha256 case: static_analysis.analyze_apk() computes its own sha256 via hashlib
(lowercase, static_analysis.py:228) -- frozen, not modified. This script never keys or
compares on that field; the canonical UPPERCASE sha256 from BANKING_CORPUS_MANIFEST.tsv
(already verified against on-disk file content in the prior task) is what's used for the
cache filename and the top-level "sha256" field in each payload. The frozen function's
own (lowercase) value is preserved unmodified inside payload["features"]["sha256"] for
fidelity, never used as a lookup key.

Usage:
    python3 extract_banking_corpus.py                      # full priority-ordered run
    python3 extract_banking_corpus.py --limit 10            # stop after N files (checkpoint)
"""
import argparse
import csv
import json
import resource
import signal
import sys
import time
from datetime import datetime, timezone
from multiprocessing import Process, Queue
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "setuguard_ps1"))

CORPUS_DIR = REPO_ROOT / "harness" / "banking_legit_corpus"
MANIFEST = REPO_ROOT / "harness" / "BANKING_CORPUS_MANIFEST.tsv"
CACHE_DIR = REPO_ROOT / "harness" / "banking_feature_cache"
SKIPS_CSV = REPO_ROOT / "harness" / "banking_extract_skips.csv"

TIMEOUT_S = 600
PARALLELISM = 2
SKIP_FIELDS = ["sha256", "pkg_name", "tier", "arm", "size_bytes", "reason", "elapsed_s"]


def norm_sha(value: str) -> str:
    return value.strip().upper()


def load_worklist(order: str = "asc", tier_a_only: bool = False):
    """Priority order: (Tier A, current) -> (Tier A, era_matched) -> everything else.
    order="asc": cheap wins first. order="desc": largest-first within each group --
    the 10-12GB headroom-gate fallback, so a failure on the biggest file surfaces in
    ~90s rather than 30 minutes into the run. tier_a_only=True excludes group 2
    (Tier B/C/D) entirely -- used when that group is deferred by decision."""
    rows = []
    with open(MANIFEST, newline="") as f:
        for row in csv.DictReader(f, delimiter="\t"):
            if row["parse_ok"] != "True":
                continue  # excluded upstream too; defensive, not expected to fire
            row["sha256"] = norm_sha(row["sha256"])
            row["size_bytes"] = int(row["size_bytes"])
            rows.append(row)

    def group(r):
        if r["tier"] == "A" and r["arm"] == "current":
            return 0
        if r["tier"] == "A" and r["arm"] == "era_matched":
            return 1
        return 2

    if tier_a_only:
        rows = [r for r in rows if group(r) in (0, 1)]

    size_sign = -1 if order == "desc" else 1
    rows.sort(key=lambda r: (group(r), size_sign * r["size_bytes"]))
    return rows


def _read_vmstat_swap():
    """(pswpin, pswpout) cumulative page counters from /proc/vmstat."""
    pswpin = pswpout = 0
    with open("/proc/vmstat") as f:
        for line in f:
            if line.startswith("pswpin "):
                pswpin = int(line.split()[1])
            elif line.startswith("pswpout "):
                pswpout = int(line.split()[1])
    return pswpin, pswpout


def _read_mem_available_bytes():
    with open("/proc/meminfo") as f:
        for line in f:
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) * 1024  # kB -> bytes
    return None


def _already_cached():
    done = set()
    if CACHE_DIR.exists():
        for f in CACHE_DIR.glob("*.json"):
            done.add(f.stem)  # filename stem IS the normalised sha256
    if SKIPS_CSV.exists() and SKIPS_CSV.stat().st_size > 0:
        with open(SKIPS_CSV, newline="") as f:
            for row in csv.DictReader(f):
                if row.get("sha256"):
                    done.add(row["sha256"])
    return done


def _worker_entry(path: str, out_q: Queue):
    """Runs in its own subprocess. Never left to raise past this frame --
    on success or on a caught exception, exactly one dict goes on the queue.
    An OOM-kill or segfault means this frame never runs to completion and
    nothing is queued; the parent detects that via join()/exitcode."""
    from loguru import logger
    logger.disable("androguard")
    t0 = time.perf_counter()
    try:
        import static_analysis  # frozen; imported post-fork, same pattern as
                                 # extract_features_pool.py's _worker()
        features = static_analysis.analyze_apk(path)
        elapsed = time.perf_counter() - t0
        peak_rss_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        out_q.put({"ok": True, "features": features, "elapsed_s": elapsed, "peak_rss_kb": peak_rss_kb})
    except MemoryError as e:
        elapsed = time.perf_counter() - t0
        out_q.put({"ok": False, "reason": "memory", "exception_type": type(e).__name__,
                   "exception_msg": str(e)[:300], "elapsed_s": elapsed})
    except Exception as e:
        elapsed = time.perf_counter() - t0
        out_q.put({"ok": False, "reason": "androguard_parse_error", "exception_type": type(e).__name__,
                   "exception_msg": str(e)[:300], "elapsed_s": elapsed})


def run_one(row: dict) -> dict:
    """Spawns one subprocess for one APK, enforces TIMEOUT_S, classifies the
    outcome. Returns a result dict; never raises."""
    path = str(CORPUS_DIR / f"{row['sha256']}.apk")
    q = Queue()
    p = Process(target=_worker_entry, args=(path, q))
    t0 = time.perf_counter()
    p.start()
    p.join(TIMEOUT_S)

    if p.is_alive():
        p.terminate()
        p.join(5)
        if p.is_alive():
            p.kill()
            p.join()
        return {"ok": False, "reason": "timeout", "elapsed_s": time.perf_counter() - t0,
                "peak_rss_kb": None}

    elapsed = time.perf_counter() - t0
    try:
        result = q.get(timeout=1)
    except Exception:
        result = None

    if result is not None:
        result.setdefault("elapsed_s", elapsed)
        return result

    # Process exited without queuing a result: killed by signal or crashed
    # before reaching the try/except (e.g. import-time segfault in a native
    # androguard/zip dependency).
    code = p.exitcode
    if code is not None and code < 0:
        sig = -code
        reason = "memory" if sig == signal.SIGKILL else f"other:Signal-{sig}"
    else:
        reason = f"other:ExitCode-{code}"
    return {"ok": False, "reason": reason, "elapsed_s": elapsed, "peak_rss_kb": None}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=None,
                     help="stop after N files processed this run (checkpoint mode)")
    ap.add_argument("--only", type=str, default=None,
                     help="process exactly one file by sha256 (probe mode), ignoring priority order")
    ap.add_argument("--workers", type=int, default=PARALLELISM,
                     help=f"override parallelism (default {PARALLELISM})")
    ap.add_argument("--order", choices=["asc", "desc"], default="asc",
                     help="size ordering within each priority group")
    ap.add_argument("--tier-a-only", action="store_true",
                     help="restrict worklist to Tier A current + era_matched; excludes B/C/D")
    args = ap.parse_args()
    parallelism = args.workers

    CACHE_DIR.mkdir(exist_ok=True)
    worklist = load_worklist(order=args.order, tier_a_only=args.tier_a_only)
    done = _already_cached()

    if args.only:
        target = norm_sha(args.only)
        todo = [r for r in worklist if r["sha256"] == target]
        if not todo:
            print(f"[extract] --only {target}: not found in manifest (parse_ok Tier-eligible rows)",
                  file=sys.stderr)
            sys.exit(1)
        if todo[0]["sha256"] in done:
            print(f"[extract] --only {target}: already cached/skipped, forcing re-run", file=sys.stderr)
        print(f"[extract] --only {target}: single-file probe, parallelism={parallelism}",
              file=sys.stderr)
    else:
        todo = [r for r in worklist if r["sha256"] not in done]
        print(f"[extract] {len(worklist)} total in priority worklist, {len(worklist) - len(todo)} "
              f"already cached, {len(todo)} to process, parallelism={parallelism}, "
              f"timeout={TIMEOUT_S}s, cache={CACHE_DIR}", file=sys.stderr)
        if args.limit:
            todo = todo[:args.limit]
            print(f"[extract] --limit {args.limit}: processing at most {len(todo)} files this run",
                  file=sys.stderr)

    write_header = not SKIPS_CSV.exists() or SKIPS_CSV.stat().st_size == 0
    skips_f = open(SKIPS_CSV, "a", newline="")
    skips_writer = csv.DictWriter(skips_f, fieldnames=SKIP_FIELDS)
    if write_header:
        skips_writer.writeheader()
        skips_f.flush()

    # PARALLELISM=2, run_one() is synchronous per call (spawns, waits up to
    # TIMEOUT_S, returns) -- so a 2-wide pipeline is: kick off two run_one()
    # calls concurrently via a tiny process-pair, not Pool. Sequential-with-
    # two-in-flight, implemented as a fixed-size sliding window.
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results_summary = []
    t0 = time.perf_counter()
    idx_lock_counter = {"i": 0}
    peak_rss_so_far_mb = 0.0
    over_12gb = []

    def process_one(row):
        swap_before = _read_vmstat_swap()
        mem_avail_before = _read_mem_available_bytes()
        r = run_one(row)
        swap_after = _read_vmstat_swap()
        r["swap_in_bytes"] = (swap_after[0] - swap_before[0]) * 4096
        r["swap_out_bytes"] = (swap_after[1] - swap_before[1]) * 4096
        r["mem_available_at_start_bytes"] = mem_avail_before
        return row, r

    with ThreadPoolExecutor(max_workers=parallelism) as ex:
        futures = {ex.submit(process_one, row): row for row in todo}
        for fut in as_completed(futures):
            row, r = fut.result()
            idx_lock_counter["i"] += 1
            i = idx_lock_counter["i"]
            sha = row["sha256"]
            size_mb = row["size_bytes"] / 1_000_000

            if r["ok"]:
                payload = {
                    "sha256": sha,
                    "pkg_name": row["pkg_name"],
                    "tier": row["tier"],
                    "arm": row["arm"],
                    "source_path": str(CORPUS_DIR / f"{sha}.apk"),
                    "analyzed_at": datetime.now(timezone.utc).isoformat(),
                    "elapsed_s": round(r["elapsed_s"], 3),
                    "features": r["features"],
                }
                (CACHE_DIR / f"{sha}.json").write_text(json.dumps(payload, default=str))
                status = "ok"
            else:
                skips_writer.writerow({
                    "sha256": sha, "pkg_name": row["pkg_name"], "tier": row["tier"],
                    "arm": row["arm"], "size_bytes": row["size_bytes"],
                    "reason": r["reason"], "elapsed_s": round(r["elapsed_s"], 3),
                })
                skips_f.flush()
                status = f"SKIP:{r['reason']}"

            rss_mb = (r.get("peak_rss_kb") or 0) / 1024
            peak_rss_so_far_mb = max(peak_rss_so_far_mb, rss_mb)
            rss_str = f"{rss_mb:.0f}MB" if rss_mb else "n/a"

            swap_out_mb = r["swap_out_bytes"] / (1024 * 1024)
            swap_flag = f" SWAP_OUT={swap_out_mb:.0f}MB" if r["swap_out_bytes"] > 0 else ""

            print(f"[extract] {i}/{len(todo)} {sha[:16]} {row['pkg_name']:<45s} "
                  f"{size_mb:6.1f}MB {r['elapsed_s']:7.1f}s rss={rss_str:>8s} "
                  f"peak_so_far={peak_rss_so_far_mb:.0f}MB {status}{swap_flag}",
                  flush=True)

            if rss_mb > 12 * 1024:
                over_12gb.append((row, rss_mb))
                print(f"[extract] *** {sha[:16]} ({row['pkg_name']}) exceeded 12GB RSS: "
                      f"{rss_mb:.0f}MB ***", file=sys.stderr, flush=True)

            results_summary.append((row, r))

    skips_f.close()
    elapsed_total = time.perf_counter() - t0
    n_ok = sum(1 for _, r in results_summary if r["ok"])
    n_skip = len(results_summary) - n_ok
    n_swap_dirty = sum(1 for _, r in results_summary if r["swap_out_bytes"] > 0)
    print(f"[extract] this run: {len(results_summary)} attempted, ok={n_ok} skipped={n_skip}, "
          f"{elapsed_total:.0f}s wall, peak_rss={peak_rss_so_far_mb:.0f}MB, "
          f"swap_dirty_files={n_swap_dirty}", file=sys.stderr)
    if over_12gb:
        print(f"[extract] *** {len(over_12gb)} file(s) exceeded 12GB RSS: "
              f"{[(row['pkg_name'], f'{mb:.0f}MB') for row, mb in over_12gb]} ***", file=sys.stderr)


if __name__ == "__main__":
    main()
