"""SetuGuard -- Day 6 scaling/timing harness. NON-FROZEN.

Built 21 Aug 2026 per FINALE_PLAN_AND_AUDIT.md Day 6 and the Day 6 harness
requirements logged in SESSION_LOG.md's 20 Aug entry. BUILD ONLY in this
session -- not run here. Intended to be run by the operator on a clean
machine (nothing else open) once Ollama, both llama-server models and the
Flask backend are already warm, per the pre-flight checklist this script
itself prints and enforces.

Answers three separate questions, each with its own mode:

  latency       n>=30 full-pipeline runs against real banking-app APKs
                (harness/banking_legit_corpus/), through the LIVE
                /api/analyze_apk HTTP endpoint (measures Flask + the real
                serving path, not a bypass). Reports median and IQR of
                wall-clock latency, and of RSS/VmSwap for all three
                processes. NEVER a single figure, NEVER "p50" (see
                CONTEXT.md U1). Restricted to files <= MAX_APK_UPLOAD_MB
                (the live endpoint's own cap) since anything larger is
                rejected by the endpoint itself before analysis starts --
                see the size-sweep mode for the larger files.

  size-sweep    Analysis time and peak memory as a function of APK size,
                across the FULL corpus size range (up to the 269.4MB max),
                INCLUDING files above the current 50MB cap. Necessarily
                bypasses the capped HTTP endpoint -- calls the same
                pipeline functions app.py calls (imported from
                setuguard_app.backend.app, never reimplemented), matching
                the existing convention in harness/extract_features_pool.py
                and harness/extract_banking_corpus.py. This produces the
                evidence needed to set MAX_APK_UPLOAD_MB from data; it does
                NOT change the cap itself.

  demo-footprint  A separate, narrower measurement: Flask + both models +
                one browser tab, nothing else running, driving the exact
                three-call demo sequence (analyze_apk -> analyze_dataset ->
                bridge) that harness/browser_smoke.js also drives. Reports
                peak TOTAL memory (Flask + embedding llama-server +
                Mistral-7B llama-server, summed at each sampled instant)
                against the 15GB stage-machine ceiling. This is the number
                that matters for the stage machine, not the corpus-wide
                figures above.

  preflight     Runs the pre-flight checks alone and exits. Also run
                automatically, and enforced, at the start of every other
                mode.

VOID CONDITION (latency and size-sweep modes): any run during which the
Mistral-7B llama-server process shows non-zero VmSwap at ANY sampled point
is EXCLUDED from that mode's reported medians/IQRs and logged in the
"excluded_runs" list with the reason. keep_alive=-1 (set unconditionally in
rag_report.py, a frozen file, verified by reading -- not edited here)
prevents Ollama from unloading the model; it does NOT prevent the kernel
from paging it out under memory pressure. A latency median computed over
partially-swapped runs would not measure the post-residency-fix system --
see SESSION_LOG.md's 20 Aug memory finding for the incident that established
this.

PID RESOLUTION: both llama-server processes are resolved BY MODEL --
inspecting each candidate process's full /proc/<pid>/cmdline for
'--embedding' (the embedding server) vs its absence together with a chatml
chat-template flag (the Mistral-7B server) -- never by `pgrep | head -1`,
which silently selects the embedding server every time and was the root
cause of a real prior confusion (SESSION_LOG.md, 20 Aug: a malformed
/proc/<two PIDs>/status path from exactly this bug was misread as a process
having been killed).

Usage:
    python3 harness/day6_scaling_harness.py preflight
    python3 harness/day6_scaling_harness.py latency [--n 30]
    python3 harness/day6_scaling_harness.py size-sweep
    python3 harness/day6_scaling_harness.py demo-footprint --i-have-one-tab-open
    python3 harness/day6_scaling_harness.py all [--n 30]

Writes harness/DAY6_SCALING_RESULTS.json, in the same provenance-heavy style
as harness/BANKING_AUC_RESULTS.json and harness/BANKING_PROBE_TIMINGS.json.
"""
import argparse
import json
import os
import platform
import random
import re
import shutil
import signal
import statistics
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_DIR = REPO_ROOT / "harness" / "banking_legit_corpus"
BACKEND_DIR = REPO_ROOT / "setuguard_app" / "backend"
API_BASE = "http://127.0.0.1:5000"
OUTPUT_PATH = REPO_ROOT / "harness" / "DAY6_SCALING_RESULTS.json"

DEMO_MATCHING_APK = (
    REPO_ROOT / "cicmaldroid_banking"
    / "007556ca146f4b2e9ac6bd51dc66be5130538d514f5aa04d60c1a0b079585ef3.apk"
)
DEMO_DATASET_CSV = REPO_ROOT / "DataSet.csv"

STAGE_MACHINE_CEILING_BYTES = 15 * 1024 * 1024 * 1024  # 15GB, per instruction
SWAP_TRIVIAL_THRESHOLD_KB = 1024  # 1MB -- anything above this is not "trivial"


# ===========================================================================
# /proc helpers -- PID resolution BY MODEL, never by first-match.
# ===========================================================================

def _iter_proc_cmdlines():
    """Yield (pid:int, cmdline:str) for every readable process. Processes
    that vanish mid-scan or aren't ours to read are skipped silently --
    this is a best-effort system scan, not a targeted lookup."""
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                raw = f.read()
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        cmdline = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        if cmdline:
            yield pid, cmdline


def find_llama_server_pids():
    """Resolve the embedding and Mistral-7B llama-server PIDs by inspecting
    each candidate's full command line, never by `pgrep | head -1` (which
    silently selects the embedding server -- see module docstring).

    Returns {"embedding": pid_or_None, "mistral": pid_or_None}. Raises if
    more than one process matches either role -- an ambiguous match is
    refused, not guessed at.
    """
    embedding_pids = []
    mistral_pids = []
    for pid, cmdline in _iter_proc_cmdlines():
        if "llama-server" not in cmdline:
            continue
        if "--embedding" in cmdline:
            embedding_pids.append(pid)
        elif "chatml" in cmdline or "-c 4096" in cmdline:
            mistral_pids.append(pid)
    if len(embedding_pids) > 1:
        raise RuntimeError(
            f"Ambiguous: {len(embedding_pids)} embedding llama-server processes found "
            f"({embedding_pids}). Refusing to guess -- resolve manually."
        )
    if len(mistral_pids) > 1:
        raise RuntimeError(
            f"Ambiguous: {len(mistral_pids)} Mistral-7B llama-server processes found "
            f"({mistral_pids}). Refusing to guess -- resolve manually."
        )
    return {
        "embedding": embedding_pids[0] if embedding_pids else None,
        "mistral": mistral_pids[0] if mistral_pids else None,
    }


def find_flask_pid():
    """Resolve the live Flask backend PID by matching its known entry-point
    path in the command line. Returns None if not running (or if more than
    one candidate matches, in which case it refuses to guess)."""
    candidates = [
        pid for pid, cmdline in _iter_proc_cmdlines()
        if "backend/app.py" in cmdline or "backend" + os.sep + "app.py" in cmdline
    ]
    if len(candidates) > 1:
        raise RuntimeError(
            f"Ambiguous: {len(candidates)} Flask backend processes found ({candidates})."
        )
    return candidates[0] if candidates else None


def read_proc_status(pid):
    """Return {'vm_rss_kb': int, 'vm_swap_kb': int} for a PID, or None if
    the process is gone by the time we read it (process death between
    resolution and read is a real race on a live system, not an error)."""
    try:
        with open(f"/proc/{pid}/status", "r") as f:
            text = f.read()
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None
    rss_match = re.search(r"^VmRSS:\s+(\d+)\s*kB", text, re.MULTILINE)
    swap_match = re.search(r"^VmSwap:\s+(\d+)\s*kB", text, re.MULTILINE)
    return {
        "vm_rss_kb": int(rss_match.group(1)) if rss_match else 0,
        "vm_swap_kb": int(swap_match.group(1)) if swap_match else 0,
    }


# ===========================================================================
# Pre-flight -- printed and enforced before every mode.
# ===========================================================================

def _run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
    except Exception as e:
        return f"<failed to run {cmd}: {e}>"


def preflight(refuse_on_swap=True):
    print("=" * 70)
    print("PRE-FLIGHT")
    print("=" * 70)

    print("\n--- free -h ---")
    free_out = _run(["free", "-h"])
    print(free_out)

    free_kb_out = _run(["free"])
    swap_used_kb = None
    for line in free_kb_out.splitlines():
        if line.lower().startswith("swap:"):
            parts = line.split()
            if len(parts) >= 3:
                swap_used_kb = int(parts[2])

    pids = find_llama_server_pids()
    print(f"--- llama-server PIDs (resolved by model, not by first match) ---")
    print(f"embedding: {pids['embedding']}   mistral: {pids['mistral']}")

    swap_report = {}
    for role, pid in pids.items():
        if pid is None:
            swap_report[role] = None
            print(f"{role}: NOT RUNNING -- warm it before proceeding")
            continue
        status = read_proc_status(pid)
        swap_report[role] = status
        print(f"{role} (pid {pid}): VmRSS={status['vm_rss_kb']}kB  VmSwap={status['vm_swap_kb']}kB")

    swappiness_out = _run(["sysctl", "vm.swappiness"]).strip()
    print(f"\n--- vm.swappiness ---\n{swappiness_out}")

    print("=" * 70)

    problems = []
    if swap_used_kb is not None and swap_used_kb > SWAP_TRIVIAL_THRESHOLD_KB:
        problems.append(
            f"System swap use is {swap_used_kb}kB, above the "
            f"{SWAP_TRIVIAL_THRESHOLD_KB}kB trivial threshold."
        )
    for role, status in swap_report.items():
        if status and status["vm_swap_kb"] > 0:
            problems.append(f"{role} llama-server has non-zero VmSwap: {status['vm_swap_kb']}kB.")
    if pids["mistral"] is None or pids["embedding"] is None:
        problems.append("One or both llama-server processes are not running -- warm both first.")

    result = {
        "free_h": free_out,
        "llama_server_pids": pids,
        "llama_server_swap": swap_report,
        "system_swap_used_kb": swap_used_kb,
        "vm_swappiness": swappiness_out,
        "problems": problems,
        "passed": len(problems) == 0,
    }

    if problems:
        print("\nREFUSING TO PROCEED:")
        for p in problems:
            print(f"  - {p}")
        print(
            "\nFix: close other applications, run `sudo sysctl vm.swappiness=10`, "
            "`swapoff -a && swapon -a` to force pages back to RAM, warm both "
            "models with one throwaway analysis, then re-run."
        )
        if refuse_on_swap:
            raise SystemExit(1)
    else:
        print("\nPre-flight PASSED. Proceeding.")

    return result


# ===========================================================================
# Kernel OOM check -- run after every mode, not just at the end of Phase 2.
# ===========================================================================

def check_kernel_oom():
    """Best-effort scan for kernel OOM-kill events. Multiple sources tried;
    a failure to read any of them (commonly a permissions issue for a
    non-root user reading dmesg) is reported as a limitation, not silently
    swallowed -- per this project's convention of reporting negative
    results, not just positive ones."""
    findings = {"sources_tried": [], "oom_events_found": [], "errors": []}

    for cmd in (["dmesg", "-T"], ["journalctl", "-k", "--no-pager"]):
        name = cmd[0]
        findings["sources_tried"].append(name)
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if out.returncode != 0:
                findings["errors"].append(
                    f"{name} exited {out.returncode}: {out.stderr.strip()[:300]}"
                )
                continue
            hits = [
                line for line in out.stdout.splitlines()
                if re.search(r"out of memory|oom-kill|killed process", line, re.IGNORECASE)
            ]
            findings["oom_events_found"].extend(hits)
        except FileNotFoundError:
            findings["errors"].append(f"{name} not available on this system.")
        except Exception as e:
            findings["errors"].append(f"{name} failed: {e}")

    findings["oom_events_found"] = sorted(set(findings["oom_events_found"]))
    findings["clean"] = len(findings["oom_events_found"]) == 0 and len(findings["errors"]) == 0
    return findings


# ===========================================================================
# Background memory sampler -- shared by latency, size-sweep, demo-footprint.
# ===========================================================================

class MemorySampler:
    """Polls /proc/<pid>/status for a fixed set of PIDs on a background
    thread at a fixed interval, for the duration of a `with` block. Records
    every sample so peak and swap-ever-nonzero can be computed afterward."""

    def __init__(self, pids: dict, interval_s=1.0):
        self.pids = pids  # {"embedding": pid, "mistral": pid, "flask": pid}
        self.interval_s = interval_s
        self.samples = []  # list of {"t": float, role: {"vm_rss_kb", "vm_swap_kb"}}
        self._stop = threading.Event()
        self._thread = None

    def _loop(self):
        t0 = time.monotonic()
        while not self._stop.is_set():
            sample = {"t": time.monotonic() - t0}
            for role, pid in self.pids.items():
                sample[role] = read_proc_status(pid) if pid else None
            self.samples.append(sample)
            self._stop.wait(self.interval_s)

    def __enter__(self):
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def mistral_ever_swapped(self):
        return any(
            s.get("mistral") and s["mistral"]["vm_swap_kb"] > 0 for s in self.samples
        )

    def peak_rss_kb(self, role):
        vals = [s[role]["vm_rss_kb"] for s in self.samples if s.get(role)]
        return max(vals) if vals else None

    def peak_total_rss_kb(self):
        """Peak of the SUM across all tracked roles at each sampled instant
        -- the figure that matters for a shared-memory ceiling, not the max
        of each process's own peak (which may occur at different times)."""
        totals = []
        for s in self.samples:
            parts = [s[role]["vm_rss_kb"] for role in self.pids if s.get(role)]
            if len(parts) == len(self.pids):
                totals.append(sum(parts))
        return max(totals) if totals else None


def median_iqr(values):
    if not values:
        return {"median": None, "iqr_25": None, "iqr_75": None, "n": 0}
    s = sorted(values)
    return {
        "median": statistics.median(s),
        "iqr_25": statistics.quantiles(s, n=4)[0] if len(s) >= 2 else s[0],
        "iqr_75": statistics.quantiles(s, n=4)[2] if len(s) >= 2 else s[0],
        "min": min(s),
        "max": max(s),
        "n": len(s),
    }


# ===========================================================================
# Mode: latency -- n>=30 real APKs through the LIVE HTTP endpoint.
# ===========================================================================

def mode_latency(n=30):
    pids = find_llama_server_pids()
    flask_pid = find_flask_pid()
    if flask_pid is None:
        raise SystemExit(
            "Flask backend not running (no process matching backend/app.py in "
            "its cmdline). Start it first -- this mode measures the live "
            "serving path, not an in-process bypass."
        )
    track_pids = {"embedding": pids["embedding"], "mistral": pids["mistral"], "flask": flask_pid}

    max_bytes = 50 * 1024 * 1024  # live endpoint's own cap, read from app.py; not modified here
    candidates = sorted(
        p for p in CORPUS_DIR.glob("*.apk") if p.stat().st_size <= max_bytes
    )
    if len(candidates) < n:
        print(
            f"WARNING: only {len(candidates)} corpus files are <= the live "
            f"{max_bytes // (1024*1024)}MB cap; requested n={n}. Using all of them."
        )
    rng = random.Random(42)  # matches this repo's determinism convention
    sample = candidates if len(candidates) <= n else rng.sample(candidates, n)

    records = []
    excluded_runs = []

    for apk_path in sample:
        with MemorySampler(track_pids, interval_s=1.0) as sampler:
            t0 = time.perf_counter()
            try:
                with open(apk_path, "rb") as f:
                    resp = requests.post(
                        f"{API_BASE}/api/analyze_apk",
                        files={"apk": (apk_path.name, f, "application/octet-stream")},
                        timeout=600,
                    )
                elapsed_s = time.perf_counter() - t0
                outcome = "ok" if resp.status_code == 200 else f"http_{resp.status_code}"
            except requests.exceptions.Timeout:
                elapsed_s = time.perf_counter() - t0
                outcome = "timeout"
            except Exception as e:
                elapsed_s = time.perf_counter() - t0
                outcome = f"error:{type(e).__name__}"

        voided = sampler.mistral_ever_swapped()
        record = {
            "file": apk_path.name,
            "size_bytes": apk_path.stat().st_size,
            "elapsed_s": round(elapsed_s, 3),
            "outcome": outcome,
            "peak_rss_kb": {
                "embedding": sampler.peak_rss_kb("embedding"),
                "mistral": sampler.peak_rss_kb("mistral"),
                "flask": sampler.peak_rss_kb("flask"),
            },
            "mistral_ever_swapped_during_run": voided,
            "voided": voided or outcome != "ok",
        }
        records.append(record)
        if record["voided"]:
            reason = "non-zero VmSwap on Mistral-7B during this run" if voided else f"outcome={outcome}"
            excluded_runs.append({"file": apk_path.name, "reason": reason})
        print(f"  {apk_path.name}: {elapsed_s:.1f}s outcome={outcome} voided={record['voided']}")

    valid = [r for r in records if not r["voided"]]
    return {
        "n_requested": n,
        "n_sampled": len(sample),
        "n_valid": len(valid),
        "n_excluded": len(excluded_runs),
        "excluded_runs": excluded_runs,
        "latency_s": median_iqr([r["elapsed_s"] for r in valid]),
        "peak_rss_kb_embedding": median_iqr([r["peak_rss_kb"]["embedding"] for r in valid if r["peak_rss_kb"]["embedding"]]),
        "peak_rss_kb_mistral": median_iqr([r["peak_rss_kb"]["mistral"] for r in valid if r["peak_rss_kb"]["mistral"]]),
        "peak_rss_kb_flask": median_iqr([r["peak_rss_kb"]["flask"] for r in valid if r["peak_rss_kb"]["flask"]]),
        "records": records,
        "note": (
            "Restricted to corpus files <= the live endpoint's 50MB cap "
            "(MAX_APK_UPLOAD_MB in setuguard_app/backend/app.py) -- files "
            "above it are rejected by the endpoint before analysis starts, "
            "by design (D-5). See the size-sweep section for the full range."
        ),
    }


# ===========================================================================
# Mode: size-sweep -- full corpus range, in-process (bypasses the HTTP cap).
# ===========================================================================

class _TimeoutError(Exception):
    pass


def _alarm_handler(signum, frame):
    raise _TimeoutError()


def mode_size_sweep(per_file_timeout_s=600):
    """Calls the SAME pipeline functions app.py's /api/analyze_apk calls --
    imported from setuguard_app.backend.app, never reimplemented -- so this
    measures the real pipeline, just without the HTTP-layer size cap that
    would otherwise make measuring files above it impossible. Necessary
    because the whole point of this section is producing evidence to set
    that cap; you cannot measure what the cap already rejects.
    """
    sys.path.insert(0, str(BACKEND_DIR))
    import app as sg_app  # noqa: E402 -- see module docstring for why this is safe (app.run() is __main__-guarded)

    pids = find_llama_server_pids()
    track_pids = {"embedding": pids["embedding"], "mistral": pids["mistral"]}

    files = sorted(CORPUS_DIR.glob("*.apk"), key=lambda p: p.stat().st_size)
    records = []

    for apk_path in files:
        size_bytes = apk_path.stat().st_size
        with MemorySampler(track_pids, interval_s=1.0) as sampler:
            t0 = time.perf_counter()
            outcome = "ok"
            error_detail = None
            old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
            signal.alarm(per_file_timeout_s)
            try:
                features = sg_app.static_analysis.analyze_apk(str(apk_path))
                rule_report = sg_app._rule_based_verdict(features)
                report = sg_app._try_llm_narrative(features, rule_report)
                if report["verdict"] != "benign":
                    sg_app.yara_gen.generate_yara(features, report)
            except _TimeoutError:
                outcome = "timeout"
            except Exception as e:
                outcome = f"error:{type(e).__name__}"
                error_detail = str(e)[:300]
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)
            elapsed_s = time.perf_counter() - t0

        voided = sampler.mistral_ever_swapped()
        record = {
            "file": apk_path.name,
            "size_bytes": size_bytes,
            "size_mb": round(size_bytes / (1024 * 1024), 1),
            "elapsed_s": round(elapsed_s, 3),
            "outcome": outcome,
            "error_detail": error_detail,
            "peak_rss_kb": {
                "embedding": sampler.peak_rss_kb("embedding"),
                "mistral": sampler.peak_rss_kb("mistral"),
            },
            "mistral_ever_swapped_during_run": voided,
            "above_current_50mb_cap": size_bytes > 50 * 1024 * 1024,
        }
        records.append(record)
        print(
            f"  {apk_path.name} ({record['size_mb']}MB): {elapsed_s:.1f}s "
            f"outcome={outcome} swapped={voided}"
        )

    # Evidence for setting the cap: for a few candidate latency ceilings,
    # the largest size that completed ok with no swap pressure. Deliberately
    # not collapsed to one number -- "acceptable latency" is a business
    # decision this harness does not make.
    clean = [r for r in records if r["outcome"] == "ok" and not r["mistral_ever_swapped_during_run"]]
    cap_evidence = {}
    for ceiling_s in (30, 60, 90, 120, 180, 300):
        under = [r for r in clean if r["elapsed_s"] <= ceiling_s]
        cap_evidence[f"largest_clean_size_mb_under_{ceiling_s}s"] = (
            max(r["size_mb"] for r in under) if under else None
        )

    return {
        "n_files": len(records),
        "n_ok_no_swap": len(clean),
        "n_timeout": sum(1 for r in records if r["outcome"] == "timeout"),
        "n_error": sum(1 for r in records if r["outcome"].startswith("error")),
        "n_swapped": sum(1 for r in records if r["mistral_ever_swapped_during_run"]),
        "cap_setting_evidence": cap_evidence,
        "note": (
            "cap_setting_evidence values are the largest CLEAN (ok, zero Mistral "
            "VmSwap throughout) file size under each latency ceiling. Apply "
            "headroom below that value before choosing MAX_APK_UPLOAD_MB -- this "
            "harness produces the measurement, it does not set the cap."
        ),
        "records": records,
    }


# ===========================================================================
# Mode: demo-footprint -- Flask + both models + one browser tab, 3-call demo.
# ===========================================================================

def mode_demo_footprint(i_have_one_tab_open=False):
    if not i_have_one_tab_open:
        raise SystemExit(
            "This mode measures the exact stage-machine condition: Flask + "
            "both models + ONE browser tab, nothing else running. Close "
            "everything else, open exactly one tab on the dashboard, then "
            "re-run with --i-have-one-tab-open."
        )
    if not DEMO_MATCHING_APK.exists() or not DEMO_DATASET_CSV.exists():
        raise SystemExit(
            f"Demo fixtures missing: {DEMO_MATCHING_APK} / {DEMO_DATASET_CSV} "
            "-- these are the same fixtures harness/browser_smoke.js uses."
        )

    pids = find_llama_server_pids()
    flask_pid = find_flask_pid()
    if flask_pid is None:
        raise SystemExit("Flask backend not running.")
    track_pids = {"embedding": pids["embedding"], "mistral": pids["mistral"], "flask": flask_pid}

    with MemorySampler(track_pids, interval_s=1.0) as sampler:
        t0 = time.perf_counter()
        with open(DEMO_MATCHING_APK, "rb") as f:
            apk_resp = requests.post(
                f"{API_BASE}/api/analyze_apk",
                files={"apk": (DEMO_MATCHING_APK.name, f, "application/octet-stream")},
                timeout=600,
            )
        apk_json = apk_resp.json()
        with open(DEMO_DATASET_CSV, "rb") as f:
            ds_resp = requests.post(
                f"{API_BASE}/api/analyze_dataset",
                files={"dataset": (DEMO_DATASET_CSV.name, f, "text/csv")},
                timeout=120,
            )
        ds_json = ds_resp.json()
        bridge_resp = requests.post(
            f"{API_BASE}/api/bridge",
            json={"apk_id": apk_json.get("analysis_id"), "dataset_id": ds_json.get("analysis_id")},
            timeout=30,
        )
        total_elapsed_s = time.perf_counter() - t0

    peak_total_kb = sampler.peak_total_rss_kb()
    peak_total_bytes = peak_total_kb * 1024 if peak_total_kb else None

    return {
        "sequence": ["analyze_apk", "analyze_dataset", "bridge"],
        "http_status": [apk_resp.status_code, ds_resp.status_code, bridge_resp.status_code],
        "total_elapsed_s": round(total_elapsed_s, 3),
        "peak_rss_kb": {
            "embedding": sampler.peak_rss_kb("embedding"),
            "mistral": sampler.peak_rss_kb("mistral"),
            "flask": sampler.peak_rss_kb("flask"),
        },
        "peak_total_rss_bytes": peak_total_bytes,
        "peak_total_rss_gb": round(peak_total_bytes / (1024 ** 3), 2) if peak_total_bytes else None,
        "stage_machine_ceiling_gb": STAGE_MACHINE_CEILING_BYTES / (1024 ** 3),
        "headroom_gb": (
            round((STAGE_MACHINE_CEILING_BYTES - peak_total_bytes) / (1024 ** 3), 2)
            if peak_total_bytes else None
        ),
        "mistral_ever_swapped_during_run": sampler.mistral_ever_swapped(),
    }


# ===========================================================================
# Main
# ===========================================================================

def machine_info():
    return {
        "cpu_count": os.cpu_count(),
        "platform": platform.platform(),
        "hostname": platform.node(),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["preflight", "latency", "size-sweep", "demo-footprint", "all"])
    ap.add_argument("--n", type=int, default=30, help="n for latency mode (default 30, minimum enforced elsewhere)")
    ap.add_argument("--i-have-one-tab-open", action="store_true", help="required to run demo-footprint mode")
    ap.add_argument("--no-refuse", action="store_true", help="print pre-flight problems but proceed anyway (debug only)")
    args = ap.parse_args()

    if args.n < 30 and args.mode in ("latency", "all"):
        print(f"WARNING: --n {args.n} is below the required n>=30. Proceeding anyway since this was explicitly requested.")

    preflight_result = preflight(refuse_on_swap=not args.no_refuse)

    if args.mode == "preflight":
        return

    results = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "machine": machine_info(),
        "preflight": preflight_result,
    }

    if args.mode in ("latency", "all"):
        print("\n=== LATENCY ===")
        results["latency"] = mode_latency(n=args.n)

    if args.mode in ("size-sweep", "all"):
        print("\n=== SIZE-SWEEP ===")
        results["size_sweep"] = mode_size_sweep()

    if args.mode in ("demo-footprint", "all"):
        print("\n=== DEMO-FOOTPRINT ===")
        results["demo_footprint"] = mode_demo_footprint(i_have_one_tab_open=args.i_have_one_tab_open)

    print("\n=== KERNEL OOM CHECK ===")
    results["kernel_oom_check"] = check_kernel_oom()
    if results["kernel_oom_check"]["oom_events_found"]:
        print("OOM EVENTS FOUND:")
        for line in results["kernel_oom_check"]["oom_events_found"]:
            print(f"  {line}")
    elif results["kernel_oom_check"]["errors"]:
        print("Could not check (see errors field, likely a permissions issue):")
        for e in results["kernel_oom_check"]["errors"]:
            print(f"  {e}")
    else:
        print("Clean -- no OOM-kill events found in the sources checked.")

    OUTPUT_PATH.write_text(json.dumps(results, indent=2, default=str))
    print(f"\nWrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
