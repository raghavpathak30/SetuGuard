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

Crash-survivable by design (same Week-2 treatment as batch_baseline.py): every
sample's outcome (success -> results.csv, failure -> skips.csv) is appended and
flushed+fsynced immediately, not batched in memory and written at the end. A
heartbeat.log line is appended per sample. A pidfile is written at start. If
results.csv/skips.csv already have rows for a filename, that sample is skipped on
the next invocation (resume-by-skip).

--sample-n/--seed give a reproducible seeded RANDOM sample of that size from
--corpus-dir (distinct from the pre-existing sorted-first --limit, kept for
back-compat) — needed for a stratified-feeling, non-first-N slice of a large
corpus like fdroid_benign_apks/ (802 files) without processing all of it.

TODO(user): --corpus-dir currently defaults to the existing fdroid_benign_apks/
baseline corpus. Once the wider F-Droid pull and the 16 real-bank holdout samples
are sourced, point --corpus-dir at those directories to extend FP-rate coverage.
banking_holdout_16/ is explicitly refused below (see FORBIDDEN_CORPUS_DIRS) — do
not remove that guard without an explicit go-ahead; per CONTEXT.md it is reserved,
untouched-by-any-script holdout data for that eventual validation pass.

CLI: python fix3_fp_harness.py [--corpus-dir DIR] [--true-label {benign,malicious}]
                                [--limit N] [--sample-n N --seed N] [--out-dir DIR]
"""
import argparse
import csv
import os
import random
import sys
import time
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

RESULTS_FIELDNAMES = ["filename", "true_label", "verdict", "confidence", "rule_generated",
                       "rule_compiles", "rule_matches_apk", "fp_signal"]
SKIPS_FIELDNAMES = ["filename", "true_label", "stage", "exception"]

# ========================================================================


def _select_samples(corpus_dir: Path, limit: int | None, sample_n: int | None, seed: int | None):
    apks = sorted(corpus_dir.glob("*.apk"))
    if sample_n is not None:
        rng = random.Random(seed)
        return rng.sample(apks, min(sample_n, len(apks)))
    if limit is not None:
        apks = apks[:limit]
    return apks


class RuleCompileFailure(Exception):
    """yara.compile(source=...) failed on a generated rule — e.g. an embedded NUL
    byte from a poisoned indicator string (static_analysis.py's url regex doesn't
    exclude control chars; yara_gen.py's _yara_escape doesn't strip NUL — see
    FROZEN_FILE_FINDINGS.md Finding 5). This is a distinct, expected failure mode,
    not a bug in this harness, and must be tracked as its own skip reason rather
    than folded into a normal 'doesn't compile' result row."""
    def __init__(self, reason: str, detail: str):
        super().__init__(f"{reason}: {detail}")
        self.reason = reason


def _check_rule_match(rule_text: str, apk_path: Path):
    """Compile the generated rule with yara-python and match it against the raw
    .apk bytes it was generated from. Returns (compiles: bool, matches: bool | None)
    on success. Raises RuleCompileFailure — narrowly, only around the compile()
    call itself, never around match() — if compilation fails, classifying the
    known embedded-NUL case separately from any other compile error."""
    try:
        compiled = yara.compile(source=rule_text)
    except (yara.Error, ValueError) as e:
        reason = "embedded_null" if "embedded null" in str(e).lower() else "compile_error"
        raise RuleCompileFailure(reason, str(e)) from e
    matches = compiled.match(str(apk_path))
    return True, bool(matches)


def _already_processed_filenames(out_dir: Path):
    done = set()
    for path in (out_dir / "results.csv", out_dir / "skips.csv"):
        if path.exists() and path.stat().st_size > 0:
            with open(path, newline="") as f:
                for row in csv.DictReader(f):
                    if row.get("filename"):
                        done.add(row["filename"])
    return done


def _open_append_csv(path: Path, fieldnames):
    is_new = not path.exists() or path.stat().st_size == 0
    f = open(path, "a", newline="")
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    if is_new:
        writer.writeheader()
        f.flush()
        os.fsync(f.fileno())
    return f, writer


def _read_all_results(out_dir: Path):
    path = out_dir / "results.csv"
    if not path.exists():
        return []
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["confidence"] = float(r["confidence"])
        r["rule_generated"] = r["rule_generated"] == "True"
        r["rule_matches_apk"] = r["rule_matches_apk"] == "True" if r["rule_matches_apk"] != "" else None
        r["fp_signal"] = r["fp_signal"] == "True"
    return rows


def _read_all_skips(out_dir: Path):
    path = out_dir / "skips.csv"
    if not path.exists():
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def main():
    parser = argparse.ArgumentParser(
        description="SetuGuard PS1 Fix #3 batch YARA false-positive harness"
    )
    parser.add_argument("--corpus-dir", default=str(DEFAULT_CORPUS_DIR),
                         help=f"Directory of .apk files to process (default: {DEFAULT_CORPUS_DIR})")
    parser.add_argument("--true-label", choices=["benign", "malicious"], default=DEFAULT_TRUE_LABEL,
                         help="True label to apply to every sample in --corpus-dir (default: benign)")
    parser.add_argument("--limit", type=int, default=None,
                         help="Process at most this many samples, sorted-first (default: all)")
    parser.add_argument("--sample-n", type=int, default=None,
                         help="Seeded random sample of this size from --corpus-dir (requires --seed)")
    parser.add_argument("--seed", type=int, default=None,
                         help="Random seed for --sample-n (required if --sample-n is given)")
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR),
                         help=f"Where to write results.csv/summary.txt (default: {DEFAULT_OUT_DIR})")
    args = parser.parse_args()

    if args.sample_n is not None and args.seed is None:
        print("--sample-n requires --seed for reproducibility", file=sys.stderr)
        sys.exit(2)

    corpus_dir = Path(args.corpus_dir).resolve()
    if corpus_dir in FORBIDDEN_CORPUS_DIRS:
        print(f"Refusing to run against reserved holdout corpus: {corpus_dir}", file=sys.stderr)
        sys.exit(1)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(exist_ok=True, parents=True)
    (out_dir / "fix3_fp_harness.pid").write_text(str(os.getpid()))

    all_samples = _select_samples(corpus_dir, args.limit, args.sample_n, args.seed)
    already_done = _already_processed_filenames(out_dir)
    samples = [p for p in all_samples if p.name not in already_done]

    print(f"Selected {len(all_samples)} nominal samples from {corpus_dir} "
          f"(true_label={args.true_label}, seed={args.seed}); "
          f"{len(already_done)} already processed (resume), {len(samples)} remaining",
          file=sys.stderr)

    results_f, results_writer = _open_append_csv(out_dir / "results.csv", RESULTS_FIELDNAMES)
    skips_f, skips_writer = _open_append_csv(out_dir / "skips.csv", SKIPS_FIELDNAMES)
    hb_f = open(out_dir / "heartbeat.log", "a")

    wall_start = time.perf_counter()

    def _write_skip(filename, stage, exc):
        skips_writer.writerow({"filename": filename, "true_label": args.true_label,
                                "stage": stage, "exception": repr(exc)})
        skips_f.flush()
        os.fsync(skips_f.fileno())

    def _heartbeat(idx, filename, status):
        elapsed = time.perf_counter() - wall_start
        hb_f.write(f"{idx}/{len(samples)}\t{filename}\t{status}\t{elapsed:.1f}s\n")
        hb_f.flush()
        os.fsync(hb_f.fileno())

    for idx, path in enumerate(samples, start=1):
        filename = path.name

        try:
            features = analyze_apk(str(path))
        except Exception as e:
            _write_skip(filename, "static_analysis", e)
            _heartbeat(idx, filename, "SKIP:static_analysis")
            print(f"  [{idx}/{len(samples)}] {filename} SKIPPED at static_analysis: {e}", file=sys.stderr)
            continue

        try:
            report = generate_report(features)
        except Exception as e:
            _write_skip(filename, "rag_report", e)
            _heartbeat(idx, filename, "SKIP:rag_report")
            print(f"  [{idx}/{len(samples)}] {filename} SKIPPED at rag_report: {e}", file=sys.stderr)
            continue

        try:
            rule = generate_yara(features, report)
        except Exception as e:
            _write_skip(filename, "yara_gen", e)
            _heartbeat(idx, filename, "SKIP:yara_gen")
            print(f"  [{idx}/{len(samples)}] {filename} SKIPPED at yara_gen: {e}", file=sys.stderr)
            continue

        rule_generated = rule is not None
        rule_compiles = None
        rule_matches_apk = None
        if rule_generated:
            try:
                rule_compiles, rule_matches_apk = _check_rule_match(rule, path)
            except RuleCompileFailure as e:
                stage = f"yara_compile:{e.reason}"
                _write_skip(filename, stage, e)
                _heartbeat(idx, filename, f"SKIP:{stage}")
                print(f"  [{idx}/{len(samples)}] {filename} SKIPPED at {stage}: {e}", file=sys.stderr)
                continue

        fp_signal = args.true_label == "benign" and rule_generated

        row = {
            "filename": filename,
            "true_label": args.true_label,
            "verdict": report["verdict"],
            "confidence": report["confidence"],
            "rule_generated": rule_generated,
            "rule_compiles": rule_compiles,
            "rule_matches_apk": rule_matches_apk,
            "fp_signal": fp_signal,
        }
        results_writer.writerow(row)
        results_f.flush()
        os.fsync(results_f.fileno())
        _heartbeat(idx, filename, "SUCCESS")

        print(f"  [{idx}/{len(samples)}] {filename} -> verdict={report['verdict']} "
              f"rule_generated={rule_generated} fp_signal={fp_signal}", file=sys.stderr)

    results_f.close()
    skips_f.close()
    hb_f.close()

    results = _read_all_results(out_dir)
    skips = _read_all_skips(out_dir)
    true_denominator = len(results) + len(skips)

    fp_count = sum(1 for r in results if r["fp_signal"])
    rules_generated = sum(1 for r in results if r["rule_generated"])
    rules_matched = sum(1 for r in results if r["rule_matches_apk"])

    lines = []
    lines.append("SetuGuard PS1 — Fix #3 batch YARA false-positive harness")
    lines.append(f"Corpus: {corpus_dir} (true_label={args.true_label}, seed={args.seed}, "
                 f"sample_n={args.sample_n})")
    lines.append(f"Processed successfully: {len(results)} / {true_denominator} attempted "
                 f"(true denominator; {len(skips)} skipped)")
    lines.append(f"Rules generated: {rules_generated} / {len(results)}")
    lines.append(f"Generated rules that compiled AND matched their own APK: {rules_matched} / {rules_generated}"
                  if rules_generated else "Generated rules that compiled AND matched their own APK: N/A (0 rules)")
    if args.true_label == "benign":
        lines.append(f"False-positive signal (benign sample produced a rule): {fp_count} / {len(results)} "
                     f"= {fp_count / len(results):.1%}" if results else
                     "False-positive signal (benign sample produced a rule): N/A (0 processed)")
    lines.append("")
    lines.append(f"Skip-list ({len(skips)} skipped, true denominator = {true_denominator}):")
    if skips:
        for s in skips:
            lines.append(f"  - {s['filename']} (stage={s['stage']}): {s['exception']}")
    else:
        lines.append("  - none")

    summary_text = "\n".join(lines)
    (out_dir / "summary.txt").write_text(summary_text)
    print(summary_text)


if __name__ == "__main__":
    main()
