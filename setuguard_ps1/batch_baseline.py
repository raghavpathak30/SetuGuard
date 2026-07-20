"""SetuGuard PS1 — standalone baseline measurement harness.

NOT one of the six pipeline files: this is a read-only measurement script that
imports and calls the existing stage functions as-is. It does not tune prompts,
add validation gates, or modify static_analysis.py / rag_report.py / yara_gen.py.

Samples deterministically (sorted filenames, first N) from:
  - ~/BOIhackathon/fdroid_benign_apks/      (benign)
  - ~/BOIhackathon/cicmaldroid_banking/     (malicious)
Never touches ~/BOIhackathon/banking_holdout_16/.

Outputs to ~/BOIhackathon/setuguard_ps1/baseline/:
  - results.csv                    one row per successfully processed apk
  - summary.txt                    FP rate, verdict/confidence breakdown, schema
                                    check, skip-list, timing
  - one_real_sample.features.json  a full features.json from one malicious
                                    sample, for the frozen-schema reference
"""
import csv
import json
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


def _select_samples():
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


def main():
    OUT_DIR.mkdir(exist_ok=True)
    samples = _select_samples()
    print(f"Selected {len(samples)} samples "
          f"({sum(1 for _, l in samples if l == 'benign')} benign, "
          f"{sum(1 for _, l in samples if l == 'malicious')} malicious)", file=sys.stderr)

    results = []
    skip_list = []
    anomalies = []
    sample_feature_json = None

    wall_start = time.perf_counter()

    for idx, (path, true_label) in enumerate(samples, start=1):
        filename = path.name
        t0 = time.perf_counter()

        try:
            features = analyze_apk(str(path))
        except Exception as e:
            skip_list.append({"filename": filename, "stage": "static_analysis", "exception": repr(e)})
            print(f"  [{idx}/{len(samples)}] {filename} SKIPPED at static_analysis: {e}", file=sys.stderr)
            continue

        _validate_schema(features, filename, anomalies)

        try:
            report = generate_report(features)
        except Exception as e:
            skip_list.append({"filename": filename, "stage": "rag_report", "exception": repr(e)})
            print(f"  [{idx}/{len(samples)}] {filename} SKIPPED at rag_report: {e}", file=sys.stderr)
            continue

        try:
            rule = generate_yara(features, report)
        except Exception as e:
            skip_list.append({"filename": filename, "stage": "yara_gen", "exception": repr(e)})
            print(f"  [{idx}/{len(samples)}] {filename} SKIPPED at yara_gen: {e}", file=sys.stderr)
            continue

        elapsed = time.perf_counter() - t0

        if true_label == "malicious" and sample_feature_json is None:
            sample_feature_json = features

        results.append({
            "filename": filename,
            "true_label": true_label,
            "verdict": report["verdict"],
            "confidence": report["confidence"],
            "num_suspicious_apis": len(features["suspicious_apis"]),
            "num_suspicious_strings": len(features["suspicious_strings"]),
            "num_dangerous_permissions": len(features["dangerous_permissions"]),
            "rule_written": rule is not None,
            "time_s": round(elapsed, 3),
        })
        print(f"  [{idx}/{len(samples)}] {filename} ({true_label}) -> "
              f"{report['verdict']} ({report['confidence']:.2f}) {elapsed:.1f}s", file=sys.stderr)

    total_wall_s = time.perf_counter() - wall_start

    # ---- results.csv ----
    fieldnames = ["filename", "true_label", "verdict", "confidence", "num_suspicious_apis",
                  "num_suspicious_strings", "num_dangerous_permissions", "rule_written", "time_s"]
    with open(OUT_DIR / "results.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    # ---- one_real_sample.features.json ----
    if sample_feature_json is not None:
        (OUT_DIR / "one_real_sample.features.json").write_text(json.dumps(sample_feature_json, indent=2))

    # ---- summary.txt ----
    lines = []
    lines.append("SetuGuard PS1 — Week 1 baseline measurement (v2: wider malicious sample)")
    lines.append(f"Sampled: {NUM_BENIGN} benign (sorted-first) + {NUM_MALICIOUS} malicious (sorted-first)")
    lines.append(f"Processed successfully: {len(results)} / {len(samples)}")
    lines.append("")

    benign_results = [r for r in results if r["true_label"] == "benign"]
    malicious_results = [r for r in results if r["true_label"] == "malicious"]

    if benign_results:
        fp_count = sum(1 for r in benign_results if r["verdict"] != "benign")
        fp_rate = fp_count / len(benign_results)
        lines.append(f"Benign FP rate: {fp_count}/{len(benign_results)} = {fp_rate:.1%}")
    else:
        lines.append("Benign FP rate: N/A (no benign samples processed)")
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

    lines.append(f"Schema check: {'PASS' if not anomalies else 'FAIL'}")
    for a in anomalies:
        lines.append(f"  - {a}")
    lines.append("")

    lines.append(f"Skip-list ({len(skip_list)} skipped):")
    if skip_list:
        for s in skip_list:
            lines.append(f"  - {s['filename']} (stage={s['stage']}): {s['exception']}")
    else:
        lines.append("  - none")
    lines.append("")

    mean_time = statistics.mean(r["time_s"] for r in results) if results else 0.0
    lines.append(f"Total wall time: {total_wall_s:.1f}s")
    lines.append(f"Mean per-apk time: {mean_time:.1f}s (n={len(results)})")

    summary_text = "\n".join(lines)
    (OUT_DIR / "summary.txt").write_text(summary_text)
    print(summary_text)


if __name__ == "__main__":
    main()
