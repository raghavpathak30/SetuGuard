"""SetuGuard PS1 — standalone baseline measurement harness.

NOT one of the six pipeline files: this is a read-only measurement script that
imports and calls the existing stage functions as-is. It does not tune prompts,
add validation gates, or modify static_analysis.py / rag_report.py / yara_gen.py.

Samples deterministically (sorted filenames, first N) from:
  - ~/BOIhackathon/fdroid_benign_apks/      (benign)
  - ~/BOIhackathon/cicmaldroid_banking/     (malicious)
Never touches ~/BOIhackathon/banking_holdout_16/.

Crash-survivable by design (Week-2 fix for the baseline_v2 run that died with
zero output): every sample's outcome (success -> results.csv, failure ->
skips.csv) is appended and flushed+fsynced immediately, not batched in memory
and written at the end. A heartbeat.log line is appended per sample so a
running process can be monitored externally. A pidfile is written at start.
If results.csv/skips.csv already have rows for a filename, that sample is
skipped on the next invocation (resume-by-skip), so a killed run can simply be
re-launched.

Optional CLI args (2026-08-10, for the D1 before/after comparison harness):
  --sample-list <file>  Read (path,label) pairs from this file instead of
                         glob-sorting BENIGN_DIR/MALICIOUS_DIR. One
                         "path,label" per line; "#"-prefixed lines ignored.
                         Default (omitted): unchanged glob-sort-first-N
                         selection below.
  --out-dir <dir>       Write results.csv/skips.csv/etc. here instead of the
                         default baseline_v2/. Default (omitted): unchanged.

Outputs to ~/BOIhackathon/setuguard_ps1/baseline_v2/ (OUT_DIR, unless
--out-dir overrides it):
  - results.csv                    one row per successfully processed apk
  - skips.csv                      one row per apk that failed a stage, with reason
  - heartbeat.log                  one line per sample attempt (success or skip)
  - batch_baseline.pid             PID of the running process
  - summary.txt                    FP rate, verdict/confidence breakdown, schema
                                    check, skip-list, timing — recomputed from the
                                    full results.csv/skips.csv on disk, so it is
                                    correct even after a resume
  - one_real_sample.features.json  a full features.json from one malicious
                                    sample, for the frozen-schema reference
"""
import argparse
import csv
import json
import os
import statistics
import sys
import time
from pathlib import Path

from static_analysis import analyze_apk
from rag_report import generate_report
from yara_gen import generate_yara

# ============================== SETTINGS ==============================

BENIGN_DIR = Path.home() / "BOIhackathon" / "fdroid_benign_apks"
MALICIOUS_DIR = Path.home() / "BOIhackathon" / "cicmaldroid_banking"
NUM_BENIGN = 40
NUM_MALICIOUS = 50
OUT_DIR = Path(__file__).parent / "baseline_v2"

RESULTS_CSV = OUT_DIR / "results.csv"
SKIPS_CSV = OUT_DIR / "skips.csv"
HEARTBEAT_LOG = OUT_DIR / "heartbeat.log"
PID_FILE = OUT_DIR / "batch_baseline.pid"
SAMPLE_FEATURES_JSON = OUT_DIR / "one_real_sample.features.json"

RESULTS_FIELDNAMES = ["filename", "true_label", "verdict", "confidence", "num_suspicious_apis",
                       "num_suspicious_strings", "num_dangerous_permissions", "rule_written", "time_s"]
SKIPS_FIELDNAMES = ["filename", "true_label", "stage", "exception"]

# The frozen Week-1 schema this run checks samples against.
TOP_LEVEL_KEYS = {
    "apk_path", "sha256", "package_name", "app_name", "target_sdk",
    "permissions", "dangerous_permissions", "exported_components",
    "suspicious_apis", "suspicious_strings", "certificate",
}
SUSPICIOUS_API_SCHEMA = {"category": str, "class": str, "method": str, "call_count": int, "mitre": str}
SUSPICIOUS_STRING_SCHEMA = {"kind": str, "value": str}
EXPORTED_COMPONENT_SCHEMA = {"type": str, "name": str, "intent_actions": list}

# ========================================================================


def _parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--sample-list", type=Path, default=None,
                    help="Path to a 'path,label' file overriding the default glob-sort selection.")
    p.add_argument("--out-dir", type=Path, default=None,
                    help="Override OUT_DIR (default: baseline_v2/ next to this script).")
    return p.parse_args()


def _select_samples(sample_list_path=None):
    if sample_list_path:
        samples = []
        for line in sample_list_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            path_str, label = line.rsplit(",", 1)
            samples.append((Path(path_str), label))
        return samples
    benign = sorted(BENIGN_DIR.glob("*.apk"))[:NUM_BENIGN]
    malicious = sorted(MALICIOUS_DIR.glob("*.apk"))[:NUM_MALICIOUS]
    return [(p, "benign") for p in benign] + [(p, "malicious") for p in malicious]


def _check_element_schema(elements, expected_schema, field_name, filename, anomalies):
    expected_keys = set(expected_schema.keys())
    for i, el in enumerate(elements):
        keys = set(el.keys())
        if keys != expected_keys:
            anomalies.append(
                f"{filename}: {field_name}[{i}] key mismatch — got {sorted(keys)}, expected {sorted(expected_keys)}"
            )
            continue
        for key, expected_type in expected_schema.items():
            val = el[key]
            if val is None or not isinstance(val, expected_type):
                anomalies.append(
                    f"{filename}: {field_name}[{i}].{key} = {val!r} is not {expected_type.__name__}"
                )


def _validate_schema(features, filename, anomalies):
    keys = set(features.keys())
    if keys != TOP_LEVEL_KEYS:
        anomalies.append(
            f"{filename}: top-level key mismatch — got {sorted(keys)}, expected {sorted(TOP_LEVEL_KEYS)}"
        )

    _check_element_schema(features.get("suspicious_apis", []), SUSPICIOUS_API_SCHEMA,
                           "suspicious_apis", filename, anomalies)
    _check_element_schema(features.get("suspicious_strings", []), SUSPICIOUS_STRING_SCHEMA,
                           "suspicious_strings", filename, anomalies)
    _check_element_schema(features.get("exported_components", []), EXPORTED_COMPONENT_SCHEMA,
                           "exported_components", filename, anomalies)

    try:
        json.dumps(features)
    except TypeError as e:
        anomalies.append(f"{filename}: features dict failed json.dumps round-trip: {e}")


def _percentiles(values):
    values = sorted(values)
    if len(values) == 1:
        v = values[0]
        return {"min": v, "p25": v, "median": v, "p75": v, "max": v}
    q1, q2, q3 = statistics.quantiles(values, n=4, method="inclusive")
    return {"min": values[0], "p25": q1, "median": q2, "p75": q3, "max": values[-1]}


def _already_processed_filenames():
    """Filenames with an existing row in results.csv or skips.csv — resume skips these."""
    done = set()
    for path, fieldnames in ((RESULTS_CSV, RESULTS_FIELDNAMES), (SKIPS_CSV, SKIPS_FIELDNAMES)):
        if path.exists() and path.stat().st_size > 0:
            with open(path, newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get("filename"):
                        done.add(row["filename"])
    return done


def _open_append_csv(path, fieldnames):
    """Open a CSV for incremental appends, writing the header only if the file is new/empty."""
    is_new = not path.exists() or path.stat().st_size == 0
    f = open(path, "a", newline="")
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    if is_new:
        writer.writeheader()
        f.flush()
        os.fsync(f.fileno())
    return f, writer


def _heartbeat(hb_file, idx, total, filename, status, elapsed_since_start):
    hb_file.write(f"{idx}/{total}\t{filename}\t{status}\t{elapsed_since_start:.1f}s\n")
    hb_file.flush()
    os.fsync(hb_file.fileno())


def _read_all_results():
    if not RESULTS_CSV.exists():
        return []
    with open(RESULTS_CSV, newline="") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["confidence"] = float(r["confidence"])
        r["time_s"] = float(r["time_s"])
        r["rule_written"] = r["rule_written"] == "True"
    return rows


def _read_all_skips():
    if not SKIPS_CSV.exists():
        return []
    with open(SKIPS_CSV, newline="") as f:
        return list(csv.DictReader(f))


def main():
    global OUT_DIR, RESULTS_CSV, SKIPS_CSV, HEARTBEAT_LOG, PID_FILE, SAMPLE_FEATURES_JSON

    args = _parse_args()
    if args.out_dir:
        OUT_DIR = args.out_dir
        RESULTS_CSV = OUT_DIR / "results.csv"
        SKIPS_CSV = OUT_DIR / "skips.csv"
        HEARTBEAT_LOG = OUT_DIR / "heartbeat.log"
        PID_FILE = OUT_DIR / "batch_baseline.pid"
        SAMPLE_FEATURES_JSON = OUT_DIR / "one_real_sample.features.json"

    OUT_DIR.mkdir(exist_ok=True)
    PID_FILE.write_text(str(os.getpid()))

    all_samples = _select_samples(args.sample_list)
    already_done = _already_processed_filenames()
    remaining = [(p, label) for (p, label) in all_samples if p.name not in already_done]

    print(f"Selected {len(all_samples)} nominal samples "
          f"({sum(1 for _, l in all_samples if l == 'benign')} benign, "
          f"{sum(1 for _, l in all_samples if l == 'malicious')} malicious); "
          f"{len(already_done)} already processed (resume), {len(remaining)} remaining",
          file=sys.stderr)

    results_f, results_writer = _open_append_csv(RESULTS_CSV, RESULTS_FIELDNAMES)
    skips_f, skips_writer = _open_append_csv(SKIPS_CSV, SKIPS_FIELDNAMES)
    hb_f = open(HEARTBEAT_LOG, "a")

    anomalies = []
    wall_start = time.perf_counter()

    def _write_skip(filename, true_label, stage, exc):
        row = {"filename": filename, "true_label": true_label, "stage": stage, "exception": repr(exc)}
        skips_writer.writerow(row)
        skips_f.flush()
        os.fsync(skips_f.fileno())

    for idx, (path, true_label) in enumerate(remaining, start=1):
        filename = path.name
        t0 = time.perf_counter()

        try:
            features = analyze_apk(str(path))
        except Exception as e:
            _write_skip(filename, true_label, "static_analysis", e)
            elapsed = time.perf_counter() - wall_start
            _heartbeat(hb_f, idx, len(remaining), filename, "SKIP:static_analysis", elapsed)
            print(f"  [{idx}/{len(remaining)}] {filename} SKIPPED at static_analysis: {e}", file=sys.stderr)
            continue

        _validate_schema(features, filename, anomalies)

        try:
            report = generate_report(features)
        except Exception as e:
            _write_skip(filename, true_label, "rag_report", e)
            elapsed = time.perf_counter() - wall_start
            _heartbeat(hb_f, idx, len(remaining), filename, "SKIP:rag_report", elapsed)
            print(f"  [{idx}/{len(remaining)}] {filename} SKIPPED at rag_report: {e}", file=sys.stderr)
            continue

        try:
            rule = generate_yara(features, report)
        except Exception as e:
            _write_skip(filename, true_label, "yara_gen", e)
            elapsed = time.perf_counter() - wall_start
            _heartbeat(hb_f, idx, len(remaining), filename, "SKIP:yara_gen", elapsed)
            print(f"  [{idx}/{len(remaining)}] {filename} SKIPPED at yara_gen: {e}", file=sys.stderr)
            continue

        elapsed = time.perf_counter() - t0

        if true_label == "malicious" and not SAMPLE_FEATURES_JSON.exists():
            SAMPLE_FEATURES_JSON.write_text(json.dumps(features, indent=2))

        row = {
            "filename": filename,
            "true_label": true_label,
            "verdict": report["verdict"],
            "confidence": report["confidence"],
            "num_suspicious_apis": len(features["suspicious_apis"]),
            "num_suspicious_strings": len(features["suspicious_strings"]),
            "num_dangerous_permissions": len(features["dangerous_permissions"]),
            "rule_written": rule is not None,
            "time_s": round(elapsed, 3),
        }
        results_writer.writerow(row)
        results_f.flush()
        os.fsync(results_f.fileno())

        elapsed_total = time.perf_counter() - wall_start
        _heartbeat(hb_f, idx, len(remaining), filename, "SUCCESS", elapsed_total)
        print(f"  [{idx}/{len(remaining)}] {filename} ({true_label}) -> "
              f"{report['verdict']} ({report['confidence']:.2f}) {elapsed:.1f}s", file=sys.stderr)

    total_wall_s = time.perf_counter() - wall_start
    results_f.close()
    skips_f.close()
    hb_f.close()

    # ---- summary.txt — recomputed from the full on-disk results.csv/skips.csv,
    # so it is correct whether this run started fresh or resumed a partial one. ----
    results = _read_all_results()
    skips = _read_all_skips()
    true_denominator = len(results) + len(skips)

    lines = []
    lines.append("SetuGuard PS1 — Week 1 baseline measurement (v2: wider malicious sample)")
    lines.append(f"Sampled: {NUM_BENIGN} benign (sorted-first) + {NUM_MALICIOUS} malicious (sorted-first) "
                 f"= {len(all_samples)} nominal")
    lines.append(f"Processed successfully: {len(results)} / {true_denominator} attempted "
                 f"(true denominator; {len(skips)} skipped)")
    lines.append(f"This run: {len(remaining)} samples attempted this invocation "
                 f"({len(already_done)} were already done from a prior run)")
    lines.append("")

    benign_results = [r for r in results if r["true_label"] == "benign"]
    malicious_results = [r for r in results if r["true_label"] == "malicious"]
    benign_skips = [s for s in skips if s["true_label"] == "benign"]
    malicious_skips = [s for s in skips if s["true_label"] == "malicious"]

    if benign_results:
        fp_count = sum(1 for r in benign_results if r["verdict"] != "benign")
        fp_rate = fp_count / len(benign_results)
        lines.append(f"Benign FP rate: {fp_count}/{len(benign_results)} = {fp_rate:.1%} "
                     f"(of {len(benign_results)} successfully processed; {len(benign_skips)} benign skipped)")
    else:
        lines.append("Benign FP rate: N/A (no benign samples processed)")
    lines.append("")

    lines.append(f"Malicious: {len(malicious_results)} successfully processed, "
                 f"{len(malicious_skips)} skipped")
    lines.append("")

    lines.append("Verdict counts by true_label:")
    for label, group in (("benign", benign_results), ("malicious", malicious_results)):
        counts = {}
        for r in group:
            counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        lines.append(f"  {label}: {counts}")
    lines.append("")

    benign_confs = [r["confidence"] for r in benign_results]
    malicious_confs = [r["confidence"] for r in malicious_results]

    lines.append("Malicious confidence distribution:")
    if malicious_confs:
        p = _percentiles(malicious_confs)
        lines.append(f"  min={p['min']:.2f} p25={p['p25']:.2f} median={p['median']:.2f} "
                     f"p75={p['p75']:.2f} max={p['max']:.2f} (n={len(malicious_confs)})")
    else:
        lines.append("  N/A (no malicious samples processed)")
    lines.append("")

    lines.append("Benign confidence distribution:")
    if benign_confs:
        p = _percentiles(benign_confs)
        lines.append(f"  min={p['min']:.2f} p25={p['p25']:.2f} median={p['median']:.2f} "
                     f"p75={p['p75']:.2f} max={p['max']:.2f} (n={len(benign_confs)})")
    else:
        lines.append("  N/A (no benign samples processed)")
    lines.append("")

    lines.append("Overlap check (does confidence actually separate the classes?):")
    if benign_confs and malicious_confs:
        mal_min = min(malicious_confs)
        ben_max = max(benign_confs)
        benign_at_or_above_mal_min = sum(1 for c in benign_confs if c >= mal_min)
        malicious_at_or_below_ben_max = sum(1 for c in malicious_confs if c <= ben_max)
        lines.append(f"  malicious min confidence = {mal_min:.2f} -> "
                     f"{benign_at_or_above_mal_min}/{len(benign_confs)} benign samples score >= this")
        lines.append(f"  benign max confidence = {ben_max:.2f} -> "
                     f"{malicious_at_or_below_ben_max}/{len(malicious_confs)} malicious samples score <= this")
    else:
        lines.append("  N/A (need both benign and malicious samples processed)")
    lines.append("")

    lines.append(f"Schema check (this invocation only, not persisted across resumes): "
                 f"{'PASS' if not anomalies else 'FAIL'}")
    for a in anomalies:
        lines.append(f"  - {a}")
    lines.append("")

    lines.append(f"Skip-list ({len(skips)} skipped, true denominator = {true_denominator}):")
    if skips:
        for s in skips:
            lines.append(f"  - {s['filename']} (true_label={s['true_label']}, stage={s['stage']}): {s['exception']}")
    else:
        lines.append("  - none")
    lines.append("")

    mean_time = statistics.mean(r["time_s"] for r in results) if results else 0.0
    lines.append(f"This invocation's wall time: {total_wall_s:.1f}s over {len(remaining)} attempted samples")
    lines.append(f"Mean per-apk time (all successful results on disk): {mean_time:.1f}s (n={len(results)})")

    summary_text = "\n".join(lines)
    (OUT_DIR / "summary.txt").write_text(summary_text)
    print(summary_text)


if __name__ == "__main__":
    main()
