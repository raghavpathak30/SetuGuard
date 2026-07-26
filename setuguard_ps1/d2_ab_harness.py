"""SetuGuard PS1 — D2 A/B experiment harness.

NOT one of the six frozen pipeline files (static_analysis.py, knowledge_base.py,
report_prompt.py, rag_report.py, yara_gen.py, run_pipeline.py). Does not modify
any of them. Augments rag_report.CHUNKS at runtime via monkeypatch (confirmed
feasible without touching knowledge_base.py, Phase 0.3) — never writes to
knowledge_base.py. d2_negative_chunks.py is a separate, also-non-frozen module.

For each sampled APK, runs rag_report.generate_report() TWICE back-to-back in the
same process on the same features dict, always in the same order:
  - arm A: rag_report.CHUNKS = the real 16 (unaugmented)
  - arm B: rag_report.CHUNKS = the real 16 + the 6 reviewed negative-evidence
    chunks from d2_negative_chunks.NEGATIVE_CHUNKS (22 total)
rag_report.CHUNKS is restored to the real 16 after every sample (in a `finally`),
so one sample's arm B state can never leak into the next sample's arm A.

Compares verdict + confidence ONLY between arms. cited_chunk_ids is deliberately
NOT read as a comparison signal: it is non-deterministic within a single arm even
after the temperature=0/seed=42 pin (FROZEN_FILE_FINDINGS.md Finding 4), so a
cross-arm difference in it is uninterpretable. Full raw report dicts are still
logged to raw_reports.jsonl for audit purposes, just not used as the metric.

This is a coarse go/no-go at a 6:16 (37%) one-directional corpus-size ratio, on a
seeded, stratified sample — not a claim about the true effect size or an ablation
of which chunks matter (see D2_AB_RESULTS.md for that caveat).

CLI: python3 d2_ab_harness.py [--n-benign N] [--n-malicious N] [--seed N]
"""
import argparse
import csv
import json
import random
import sys
import time
from pathlib import Path

import rag_report
from static_analysis import analyze_apk
from d2_negative_chunks import NEGATIVE_CHUNKS

# ============================== SETTINGS ==============================

BENIGN_DIR = Path.home() / "BOIhackathon" / "fdroid_benign_apks"
MALICIOUS_DIR = Path.home() / "BOIhackathon" / "cicmaldroid_banking"
OUT_DIR = Path(__file__).parent / "d2_ab_results"

DEFAULT_N_BENIGN = 20
DEFAULT_N_MALICIOUS = 20
DEFAULT_SEED = 2026

# ========================================================================

REAL_CHUNKS = list(rag_report.CHUNKS)  # snapshot of the real 16 at import time
AUGMENTED_CHUNKS = REAL_CHUNKS + NEGATIVE_CHUNKS


def _sample(n_benign: int, n_malicious: int, seed: int):
    """Seeded random sample (not sorted-first, deliberately distinct from
    batch_baseline.py's sampling so this isn't just re-testing the same
    first-N files already covered by baseline/baseline_v2)."""
    rng = random.Random(seed)
    benign_all = sorted(BENIGN_DIR.glob("*.apk"))
    malicious_all = sorted(MALICIOUS_DIR.glob("*.apk"))
    benign_sample = rng.sample(benign_all, min(n_benign, len(benign_all)))
    malicious_sample = rng.sample(malicious_all, min(n_malicious, len(malicious_all)))
    return [(p, "benign") for p in benign_sample] + [(p, "malicious") for p in malicious_sample]


def main():
    parser = argparse.ArgumentParser(description="SetuGuard PS1 D2 A/B experiment")
    parser.add_argument("--n-benign", type=int, default=DEFAULT_N_BENIGN)
    parser.add_argument("--n-malicious", type=int, default=DEFAULT_N_MALICIOUS)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args()

    OUT_DIR.mkdir(exist_ok=True)
    samples = _sample(args.n_benign, args.n_malicious, args.seed)
    print(f"D2 A/B: seed={args.seed}, requested {args.n_benign} benign + "
          f"{args.n_malicious} malicious = {len(samples)} candidates. "
          f"Arm A = 16 real chunks, Arm B = 16 + {len(NEGATIVE_CHUNKS)} negative chunks "
          f"= {len(AUGMENTED_CHUNKS)}.", file=sys.stderr)

    fieldnames = ["filename", "true_label",
                  "arm_a_verdict", "arm_a_confidence",
                  "arm_b_verdict", "arm_b_confidence",
                  "verdict_changed", "confidence_delta"]
    results_f = open(OUT_DIR / "results.csv", "w", newline="")
    writer = csv.DictWriter(results_f, fieldnames=fieldnames)
    writer.writeheader()

    skip_f = open(OUT_DIR / "skips.csv", "w", newline="")
    skip_writer = csv.DictWriter(skip_f, fieldnames=["filename", "true_label", "stage", "exception"])
    skip_writer.writeheader()

    raw_f = open(OUT_DIR / "raw_reports.jsonl", "w")

    processed = 0
    wall_start = time.perf_counter()

    for idx, (path, true_label) in enumerate(samples, start=1):
        filename = path.name

        try:
            features = analyze_apk(str(path))
        except Exception as e:
            skip_writer.writerow({"filename": filename, "true_label": true_label,
                                   "stage": "static_analysis", "exception": repr(e)})
            skip_f.flush()
            print(f"  [{idx}/{len(samples)}] {filename} SKIPPED at static_analysis: {e}", file=sys.stderr)
            continue

        try:
            rag_report.CHUNKS = REAL_CHUNKS
            t0 = time.perf_counter()
            report_a = rag_report.generate_report(features)
            t_a = time.perf_counter() - t0

            rag_report.CHUNKS = AUGMENTED_CHUNKS
            t0 = time.perf_counter()
            report_b = rag_report.generate_report(features)
            t_b = time.perf_counter() - t0
        except Exception as e:
            skip_writer.writerow({"filename": filename, "true_label": true_label,
                                   "stage": "generate_report", "exception": repr(e)})
            skip_f.flush()
            print(f"  [{idx}/{len(samples)}] {filename} SKIPPED at generate_report: {e}", file=sys.stderr)
            continue
        finally:
            rag_report.CHUNKS = REAL_CHUNKS  # always restore before the next sample's arm A

        row = {
            "filename": filename,
            "true_label": true_label,
            "arm_a_verdict": report_a["verdict"],
            "arm_a_confidence": report_a["confidence"],
            "arm_b_verdict": report_b["verdict"],
            "arm_b_confidence": report_b["confidence"],
            "verdict_changed": report_a["verdict"] != report_b["verdict"],
            "confidence_delta": round(report_b["confidence"] - report_a["confidence"], 4),
        }
        writer.writerow(row)
        results_f.flush()

        raw_f.write(json.dumps({"filename": filename, "true_label": true_label,
                                 "arm_a": report_a, "arm_b": report_b}) + "\n")
        raw_f.flush()

        processed += 1
        print(f"  [{idx}/{len(samples)}] {filename} ({true_label}) "
              f"A={report_a['verdict']}/{report_a['confidence']:.2f} "
              f"B={report_b['verdict']}/{report_b['confidence']:.2f} "
              f"({t_a:.1f}s+{t_b:.1f}s)", file=sys.stderr)

    total_wall_s = time.perf_counter() - wall_start
    results_f.close()
    skip_f.close()
    raw_f.close()

    print(f"\nDone. Processed {processed}/{len(samples)} in {total_wall_s:.1f}s.", file=sys.stderr)


if __name__ == "__main__":
    main()
