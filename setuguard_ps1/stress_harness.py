"""SetuGuard PS1 — Week-2 stress harness for analyze_apk() (and optionally the
full pipeline).

NOT one of the six frozen pipeline files (static_analysis.py, knowledge_base.py,
report_prompt.py, rag_report.py, yara_gen.py, run_pipeline.py). Imports and
calls their functions read-only; never edits them.

Feeds a fixed list of hostile/edge-case inputs to static_analysis.analyze_apk()
(and, only with --with-rag, the full generate_report()/generate_yara() chain)
and records, per case:
  - outcome: "success" | "clean_raise" | "dirty"
  - exception type + message, if any
  - clean vs dirty: "clean_raise" means analyze_apk() raised a Python exception
    that propagated normally (caught by a plain try/except in the calling
    process). "dirty" means the subprocess used to run the case did NOT exit
    with a clean success/exception outcome — it crashed (non-zero exit with no
    parseable result, e.g. a segfault) or hung past the timeout. Each case runs
    in its own subprocess specifically so a crash or hang in one case can't take
    down the harness or be silently absorbed by the parent process.

Synthetic fixtures (zero-byte file, non-APK zip, non-zip binary, directory,
nonexistent path) are created under a tempfile.mkdtemp() directory, NOT inside
this repo, and cleaned up at exit. The two real-corpus fixtures (the known
truncated download, and the corpus APK with the most dangerous permissions per
baseline/results.csv — the only existing per-sample feature data on disk, so no
pipeline re-run was needed to find it) are referenced directly from their
existing corpus paths, read-only.

--with-rag (default off) additionally runs generate_report()+generate_yara()
for cases that reach a valid features dict, so it consumes Ollama/GPU — must
only be used when Hard Rule 9 (one Ollama job at a time) is satisfiable, i.e.
not while a batch job is running.

CLI: python3 stress_harness.py [--with-rag] [--timeout SECONDS]
"""
import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

# ============================== SETTINGS ==============================

REPO_DIR = Path(__file__).parent
HOME = Path.home() / "BOIhackathon"

TRUNCATED_APK = HOME / "fdroid_benign_apks" / "app.fedilab.nitterizeme_35.apk"
# Chosen from baseline/results.csv (existing on-disk measurement data, n=50 —
# num_dangerous_permissions=9 is the max in that file) rather than by scanning
# a full corpus of features.json files, which does not exist on disk (only one
# reference sample, baseline/one_real_sample.features.json, was ever saved).
MOST_PERMISSIONS_APK = (
    HOME / "cicmaldroid_banking" / "007556ca146f4b2e9ac6bd51dc66be5130538d514f5aa04d60c1a0b079585ef3.apk"
)

DEFAULT_TIMEOUT_S = 60

_WORKER_SCRIPT = REPO_DIR / "_stress_worker.py"

# ========================================================================


def _build_fixtures(tmpdir: Path) -> list[tuple[str, str]]:
    """Returns [(case_name, path_or_None), ...]. path is a string; a case with
    a deliberately invalid/missing path still gets a string so the worker can
    try to open it and observe what analyze_apk() does."""
    cases = []

    cases.append(("truncated_real_apk_known_corrupt", str(TRUNCATED_APK)))

    zero_byte = tmpdir / "zero_byte.apk"
    zero_byte.write_bytes(b"")
    cases.append(("zero_byte_file", str(zero_byte)))

    valid_zip_not_apk = tmpdir / "valid_zip_not_apk.apk"
    with zipfile.ZipFile(valid_zip_not_apk, "w") as zf:
        zf.writestr("hello.txt", "this is a valid zip but not an APK")
    cases.append(("valid_zip_not_apk", str(valid_zip_not_apk)))

    non_zip_binary = tmpdir / "non_zip_binary.apk"
    non_zip_binary.write_bytes(bytes(range(256)) * 64)
    cases.append(("non_zip_binary_renamed_apk", str(non_zip_binary)))

    a_directory = tmpdir / "a_directory.apk"
    a_directory.mkdir()
    cases.append(("directory_path", str(a_directory)))

    nonexistent = tmpdir / "does_not_exist_at_all.apk"
    cases.append(("nonexistent_path", str(nonexistent)))

    cases.append(("corpus_apk_most_dangerous_permissions", str(MOST_PERMISSIONS_APK)))

    return cases


def _run_case(path: str, with_rag: bool, timeout_s: int) -> dict:
    """Runs _stress_worker.py in a fresh subprocess so a crash/hang in
    analyze_apk() can't take down this harness or be masked."""
    cmd = [sys.executable, str(_WORKER_SCRIPT), path]
    if with_rag:
        cmd.append("--with-rag")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s, cwd=str(REPO_DIR))
    except subprocess.TimeoutExpired:
        return {"outcome": "dirty", "reason": "hang", "detail": f"exceeded {timeout_s}s timeout"}

    if proc.returncode != 0:
        # Worker is supposed to always exit 0 and report failures as JSON on
        # stdout; a non-zero exit means the worker process itself died
        # (segfault, OOM kill, uncaught fatal error below the try/except).
        return {
            "outcome": "dirty",
            "reason": "nonzero_exit",
            "detail": f"exit={proc.returncode}, stderr_tail={proc.stderr[-2000:]}",
        }

    try:
        result = json.loads(proc.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return {
            "outcome": "dirty",
            "reason": "unparseable_output",
            "detail": f"stdout={proc.stdout[-2000:]!r} stderr_tail={proc.stderr[-2000:]!r}",
        }

    return result


def main():
    parser = argparse.ArgumentParser(description="SetuGuard PS1 stress harness")
    parser.add_argument("--with-rag", action="store_true",
                         help="Also run generate_report()/generate_yara() (consumes Ollama/GPU)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_S, help="Per-case timeout in seconds")
    args = parser.parse_args()

    if not _WORKER_SCRIPT.exists():
        print(f"FATAL: worker script {_WORKER_SCRIPT} not found", file=sys.stderr)
        sys.exit(2)

    tmpdir = Path(tempfile.mkdtemp(prefix="setuguard_stress_"))
    print(f"Fixtures dir (outside repo): {tmpdir}", file=sys.stderr)

    try:
        cases = _build_fixtures(tmpdir)
        results = []
        for name, path in cases:
            print(f"--- {name} ({path}) ---", file=sys.stderr)
            r = _run_case(path, args.with_rag, args.timeout)
            r["case"] = name
            r["path"] = path
            results.append(r)
            print(f"  -> {r.get('outcome')} / {r.get('reason', r.get('exception_type', ''))}", file=sys.stderr)

        print(json.dumps(results, indent=2))

        dirty = [r for r in results if r.get("outcome") == "dirty"]
        if dirty:
            print(f"\n{len(dirty)}/{len(results)} case(s) were DIRTY failures", file=sys.stderr)
            sys.exit(1)
        print(f"\nAll {len(results)} cases resolved cleanly (success or clean_raise)", file=sys.stderr)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
