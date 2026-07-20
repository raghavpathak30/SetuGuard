"""SetuGuard PS1 — Fix #3 batch YARA false-positive harness.

NOT one of the six frozen pipeline files (static_analysis.py, knowledge_base.py,
report_prompt.py, rag_report.py, yara_gen.py, run_pipeline.py) and does not mutate
any of them. Like batch_baseline.py, this is a read-only measurement harness that
imports and calls the existing stage functions as-is: analyze_apk -> generate_report
-> generate_yara, the same sequence run_pipeline.py chains for a single APK.

For each APK in --corpus-dir, tabulates: whether a YARA rule was generated, whether
that rule (compiled with yara-python) actually matches the APK it was generated
from, the true label, and — the Fix #3 signal — whether a *benign* sample produced
a rule at all (report["verdict"] == "benign" is a hard gate in yara_gen.py, so any
benign rule-generation is evidence the gate's upstream verdict logic let a
false positive through).

TODO(user): --corpus-dir currently defaults to the existing fdroid_benign_apks/
baseline corpus. Once the wider F-Droid pull and the 16 real-bank holdout samples
are sourced, point --corpus-dir at those directories to extend FP-rate coverage.
banking_holdout_16/ is explicitly refused below (see FORBIDDEN_CORPUS_DIRS) — do
not remove that guard without an explicit go-ahead; per CONTEXT.md it is reserved,
untouched-by-any-script holdout data for that eventual validation pass.

CLI: python fix3_fp_harness.py [--corpus-dir DIR] [--true-label {benign,malicious}]
                                [--limit N] [--out-dir DIR]
"""
import argparse
import csv
import sys
from pathlib import Path

import yara

from static_analysis import analyze_apk
from rag_report import generate_report
from yara_gen import generate_yara

# ============================== SETTINGS ==============================

DEFAULT_CORPUS_DIR = Path.home() / "BOIhackathon" / "fdroid_benign_apks"
DEFAULT_TRUE_LABEL = "benign"
DEFAULT_OUT_DIR = Path(__file__).parent / "fix3_fp_baseline"

# Never touch the reserved Fix #3 holdout corpus from this or any harness.
FORBIDDEN_CORPUS_DIRS = {
    (Path.home() / "BOIhackathon" / "banking_holdout_16").resolve(),
}

# ========================================================================


def _select_samples(corpus_dir: Path, limit: int | None):
    apks = sorted(corpus_dir.glob("*.apk"))
    if limit is not None:
        apks = apks[:limit]
    return apks


def _check_rule_match(rule_text: str, apk_path: Path):
    """Compile the generated rule with yara-python and match it against the raw
    .apk bytes it was generated from. Returns (compiles: bool, matches: bool | None)."""
    try:
        compiled = yara.compile(source=rule_text)
    except yara.Error:
        return False, None
    matches = compiled.match(str(apk_path))
    return True, bool(matches)


def main():
    parser = argparse.ArgumentParser(
        description="SetuGuard PS1 Fix #3 batch YARA false-positive harness"
    )
    parser.add_argument("--corpus-dir", default=str(DEFAULT_CORPUS_DIR),
                         help=f"Directory of .apk files to process (default: {DEFAULT_CORPUS_DIR})")
    parser.add_argument("--true-label", choices=["benign", "malicious"], default=DEFAULT_TRUE_LABEL,
                         help="True label to apply to every sample in --corpus-dir (default: benign)")
    parser.add_argument("--limit", type=int, default=None,
                         help="Process at most this many samples (default: all)")
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR),
                         help=f"Where to write results.csv/summary.txt (default: {DEFAULT_OUT_DIR})")
    args = parser.parse_args()

    corpus_dir = Path(args.corpus_dir).resolve()
    if corpus_dir in FORBIDDEN_CORPUS_DIRS:
        print(f"Refusing to run against reserved holdout corpus: {corpus_dir}", file=sys.stderr)
        sys.exit(1)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(exist_ok=True, parents=True)

    samples = _select_samples(corpus_dir, args.limit)
    print(f"Selected {len(samples)} samples from {corpus_dir} (true_label={args.true_label})",
          file=sys.stderr)

    results = []
    skip_list = []

    for idx, path in enumerate(samples, start=1):
        filename = path.name

        try:
            features = analyze_apk(str(path))
        except Exception as e:
            skip_list.append({"filename": filename, "stage": "static_analysis", "exception": repr(e)})
            print(f"  [{idx}/{len(samples)}] {filename} SKIPPED at static_analysis: {e}", file=sys.stderr)
            continue

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

        rule_generated = rule is not None
        rule_compiles = None
        rule_matches_apk = None
        if rule_generated:
            rule_compiles, rule_matches_apk = _check_rule_match(rule, path)

        fp_signal = args.true_label == "benign" and rule_generated

        results.append({
            "filename": filename,
            "true_label": args.true_label,
            "verdict": report["verdict"],
            "confidence": report["confidence"],
            "rule_generated": rule_generated,
            "rule_compiles": rule_compiles,
            "rule_matches_apk": rule_matches_apk,
            "fp_signal": fp_signal,
        })
        print(f"  [{idx}/{len(samples)}] {filename} -> verdict={report['verdict']} "
              f"rule_generated={rule_generated} fp_signal={fp_signal}", file=sys.stderr)

    fieldnames = ["filename", "true_label", "verdict", "confidence", "rule_generated",
                  "rule_compiles", "rule_matches_apk", "fp_signal"]
    with open(out_dir / "results.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    fp_count = sum(1 for r in results if r["fp_signal"])
    rules_generated = sum(1 for r in results if r["rule_generated"])
    rules_matched = sum(1 for r in results if r["rule_matches_apk"])

    lines = []
    lines.append("SetuGuard PS1 — Fix #3 batch YARA false-positive harness")
    lines.append(f"Corpus: {corpus_dir} (true_label={args.true_label})")
    lines.append(f"Processed successfully: {len(results)} / {len(samples)}")
    lines.append(f"Rules generated: {rules_generated} / {len(results)}")
    lines.append(f"Generated rules that compiled AND matched their own APK: {rules_matched} / {rules_generated}"
                  if rules_generated else "Generated rules that compiled AND matched their own APK: N/A (0 rules)")
    if args.true_label == "benign":
        lines.append(f"False-positive signal (benign sample produced a rule): {fp_count} / {len(results)}")
    lines.append("")
    lines.append(f"Skip-list ({len(skip_list)} skipped):")
    if skip_list:
        for s in skip_list:
            lines.append(f"  - {s['filename']} (stage={s['stage']}): {s['exception']}")
    else:
        lines.append("  - none")

    summary_text = "\n".join(lines)
    (out_dir / "summary.txt").write_text(summary_text)
    print(summary_text)


if __name__ == "__main__":
    main()
