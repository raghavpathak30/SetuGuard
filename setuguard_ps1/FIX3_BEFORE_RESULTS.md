# Fix #3 "Before" Measurement — n=150, seed=7

**Rationale (per instruction):** with D1/D2 unresolved, this FP rate is dominated by the
verdict defect — a verdict-keyed gate that never sees "benign" fires on effectively
everything. This is a reproducible BEFORE number for a later paired comparison, not a
result to act on by itself.

**Command run** (recorded in `fix3_fp_baseline/COMMAND.txt` alongside the raw data):
```
python3 fix3_fp_harness.py --corpus-dir ~/BOIhackathon/fdroid_benign_apks \
    --true-label benign --sample-n 150 --seed 7
```
Run under `setsid nohup`, on the now-deterministic pipeline (`temperature=0, seed=42` pin,
Finding 3). Guard confirmed intact before launch: `fix3_fp_harness.py`'s
`FORBIDDEN_CORPUS_DIRS` hard-refuses `banking_holdout_16/` — never pointed at it. Total wall
time: 2255.4s (~37.6 min) for 150 nominal samples.

**Mid-run crash and fix, for the record:** the first attempt at this run (this session)
crashed at sample 4/150 with an uncaught `ValueError: embedded null character` from
`yara.compile()`. Root-caused, fixed narrowly in `fix3_fp_harness.py` (catches the
compile-failure specifically, classifies it as a distinct skip reason, verified against
repeated occurrences), logged as `FROZEN_FILE_FINDINGS.md` Finding 5, and the run was
restarted **from scratch** (not resumed) so all 150 samples ran under one harness version —
resuming would have mixed 3 pre-fix rows with 147 post-fix rows, breaking the clean-seed
reproducibility this measurement exists to have.

## Accounting — verified from raw `results.csv` + `skips.csv`, not the harness's own `summary.txt`

**The harness's own auto-generated `summary.txt` undercounts the FP rate and should not be
used** — it computes `rule_generated` only over `results.csv` (113 rows) and has no way to
know that every `yara_compile:*` skip row is *also* a rule-generated-on-a-benign-sample
event, since those never reach a results.csv row at all. Corrected accounting below, from
the CSVs directly:

| | Count |
|---|---|
| Nominal samples | 150 |
| **Genuine skips** (`static_analysis` stage — EOCD/zip errors, excluded from all metrics) | 5 |
| **NUL-compile skips** (`yara_compile:embedded_null` — rule *was* generated, just couldn't be compile-tested) | **32** |
| Fully processed (`results.csv`, including a successful or failed compile/match test) | 113 |
| Accounting check | 5 + 32 + 113 = 150 ✓ |

### Why the 32 NUL rows count as false positives (not skips, for FP purposes)

`_check_rule_match()` is only ever called after `generate_yara()` already returned non-`None`
rule text — reaching a compile failure is only possible if a rule was already generated for
that (benign) sample. **`rule_generated=True` is certain by construction for all 32 rows**,
even though `skips.csv` doesn't store per-sample verdict/confidence for them (stated
explicitly, not inferred: verdict/confidence for these 32 samples specifically is not
reconstructable from what's on disk — only the boolean fact that a rule was generated is
recoverable).

### PRIMARY metric: false-positive rate

**Denominator: 145** (successfully analyzed — passed `analyze_apk` + `generate_report`;
excludes only the 5 genuine `static_analysis` skips).
**Numerator: 142** (110 `rule_generated=True` rows in `results.csv` + all 32 NUL rows).

**FP rate = 142 / 145 = 97.9%**

### SECONDARY metric: of generated rules, how many compile-and-match — explicitly biased sub-sample

**Denominator: 110** (rules generated that also survived the compile-test step, i.e. **NOT**
NUL-affected — this denominator is systematically biased against apps carrying Adobe XMP
metadata in their image assets, per Finding 5; it is not a random subsample).

- Compiled AND matched their own source APK: **21 / 110 = 19.1%**
- Compiled but did **not** match their own source APK: 89 / 110 = 80.9%
- (0 rows in `results.csv` have `rule_generated=True` with `rule_compiles=False` — confirms
  the harness fix works completely; every compile failure now correctly routes to `skips.csv`
  instead of leaking into a results row.)

### Verdict distribution (n=113, `results.csv` only)

100% `"suspicious"` — every single processed sample, no exceptions. Confidence: min 0.60,
max 0.80, mean 0.689, median 0.70. This is a fourth independent confirmation this session
(after `baseline`, `baseline_v2`, and the D2 A/B's 36 samples) that the verdict never varies
regardless of sample or measurement context.

## The NUL-skip prevalence is itself the headline finding, independent of the FP number

**32 / 145 = 22.1%** of successfully-analyzed benign F-Droid samples in this seeded draw hit
the `static_analysis.py`/`yara_gen.py` NUL-byte defect (Finding 5). This is not a rare edge
case — it's systemic, consistent with Adobe XMP metadata's ubiquity in ordinary image
assets. Any future measurement using this pipeline (Fix #3's eventual AFTER number, any
broader corpus run) will hit this at a similar rate until Finding 5 is resolved by the team.

## What this is and isn't

- **Is:** a reproducible (seed=7, deterministic pipeline) before-number, with the NUL-skip
  defect now handled as a distinct, countable category rather than a crash.
- **Isn't:** evidence about whether Fix #3's eventual tuning work succeeds — per the
  rationale above, this number is dominated by the verdict defect (D1/D2), not by anything
  Fix #3 itself controls yet.
- **A future paired AFTER comparison must apply the same NUL-exclusion logic** to the
  secondary (compile+match) metric, or the two won't be comparable — this run's 110-of-145
  split (24 excluded, 76% survive to compile-test) is a property of this corpus draw, not
  guaranteed to hold on a different sample.

## Full corpus command (NOT run this session, per instruction)

```
python3 fix3_fp_harness.py --corpus-dir ~/BOIhackathon/fdroid_benign_apks \
    --true-label benign --limit 802
```
Estimated wall time at this run's measured rate (15.04 s/sample): **~201 minutes (~3.35
hours)** for all 802 benign samples. Not run — printed here for you to run yourself if
wanted.
