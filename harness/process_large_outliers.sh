#!/bin/bash
# One-off driver, not part of the harness proper: processes the 15 APKs >50MB
# in harness/sample_set_716_large.txt one at a time, each in its own
# systemd-run scope with a generous dedicated memory budget (nothing else
# competing since it's the only thing running), and a hard wall-clock
# timeout so a memory-throttle stall can't hang forever. Any file that
# doesn't finish within the timeout is killed and logged to
# feature_cache_skips.csv as a manual skip, same schema as the harness's
# own skip rows, so rescore_from_cache.py's provenance accounting stays
# exact (cache + skips == sample list).
set -u
cd /home/raghavp/BOIhackathon
LARGE_LIST=harness/sample_set_716_large.txt
SKIPS_CSV=harness/feature_cache_skips.csv
PER_FILE_TIMEOUT=300

i=0
total=$(wc -l < "$LARGE_LIST")
while IFS=, read -r path corpus; do
  i=$((i+1))
  echo "[large $i/$total] $path ($corpus)"
  onefile=$(mktemp)
  echo "${path},${corpus}" > "$onefile"

  systemd-run --user --scope -p MemoryMax=10G -p MemoryHigh=8G -p MemorySwapMax=2G \
    python3 harness/extract_features_pool.py --sample-list "$onefile" --workers 1 \
    > "harness/extract_run_large_${i}.log" 2>&1 &
  runner_pid=$!

  waited=0
  while kill -0 "$runner_pid" 2>/dev/null && [ "$waited" -lt "$PER_FILE_TIMEOUT" ]; do
    sleep 5
    waited=$((waited+5))
  done

  if kill -0 "$runner_pid" 2>/dev/null; then
    echo "[large $i/$total] TIMEOUT after ${PER_FILE_TIMEOUT}s -- stopping scope, logging manual skip"
    scope=$(systemctl --user list-units --type=scope --no-legend 2>/dev/null | awk -v p="$runner_pid" '{print $1}' | tail -1)
    # find the scope owning runner_pid's children more reliably via cgroup
    pkill -TERM -P "$runner_pid" 2>/dev/null
    sleep 2
    pkill -KILL -P "$runner_pid" 2>/dev/null
    kill -KILL "$runner_pid" 2>/dev/null
    # also sweep any leftover extract_features_pool.py workers from this scope
    pkill -KILL -f "extract_features_pool.py --sample-list $onefile" 2>/dev/null
    python3 - "$path" "$corpus" "$SKIPS_CSV" <<'PYEOF'
import csv, sys, pathlib
path, corpus, skips_csv = sys.argv[1], sys.argv[2], sys.argv[3]
p = pathlib.Path(skips_csv)
write_header = not p.exists() or p.stat().st_size == 0
with open(p, "a", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["path", "corpus", "exception_type", "exception_msg"])
    if write_header:
        w.writeheader()
    w.writerow({"path": path, "corpus": corpus, "exception_type": "ManualTimeout",
                "exception_msg": "killed after 300s wall-clock under dedicated 10G/8G/2G cgroup; "
                                  "did not complete (see FROZEN_FILE_FINDINGS / evidence doc for detail)"})
PYEOF
  else
    echo "[large $i/$total] finished within ${waited}s"
  fi
  rm -f "$onefile"
  free -h
done < "$LARGE_LIST"

echo "=== all large files processed ==="
ls harness/feature_cache/*.json | wc -l
