# D2 A/B Experiment Results

Ran by `d2_ab_harness.py` (new, non-frozen; monkeypatches `rag_report.CHUNKS` at runtime;
never touched `knowledge_base.py`). Seed `2026`, requested 20 benign + 20 malicious,
sampled randomly (not sorted-first) from `fdroid_benign_apks/`/`cicmaldroid_banking/`.
Effective n after skips: **20 benign, 16 malicious** (4 malicious skipped — all
`InvalidInstruction` DEX-bytecode errors at the `static_analysis` stage, the same failure
mode already seen in `baseline_v2/skips.csv`; see `d2_ab_results/skips.csv`).

Arm A = `rag_report.CHUNKS` unaugmented (real 16). Arm B = real 16 + the 6 reviewed
negative-evidence chunks from `d2_negative_chunks.py` (22 total). Compared verdict +
confidence only, per instruction — `cited_chunk_ids` was not read as a signal
(non-deterministic within an arm, Finding 4).

## Headline finding: verdict was invariant to the retrieval change — this redirects D1's suspected root cause, away from D2

**0/36 samples changed verdict in either direction, in either arm.** Every one of the 20
benign and 16 malicious samples stayed "suspicious" whether the model saw the real 16
chunks or all 22. This is the experiment's clearest result, and it's a negative one for the
D2 theory specifically:

If D1's "always suspicious" verdict came from retrieval imbalance (D2's theory — a benign
sample retrieves only malware-framing chunks and the model hedges to split the
difference), then changing what gets retrieved should have moved at least some verdicts
toward "benign," especially for the benign samples that got genuinely relevant
counter-evidence in their top-4 for the first time. It moved **zero** verdicts. It only
nudged the confidence float, and not even in the class-selective direction D2 predicts (see
below).

**This substantially weakens D2 as *the* root cause of D1** and redirects suspicion toward
the other candidates the defects doc listed and this test did not touch — all
`report_prompt.py` concerns, not retrieval: `SYSTEM_PROMPT`'s explicit hedging language
("if evidence is weak... say so and lower confidence... instead of defaulting to a severe
verdict"), the complete absence of explicit decision thresholds telling the model when to
cross from "suspicious" into "benign" or "malicious," and the 3-way enum structurally
inviting the safe middle option under any uncertainty. D2 is not disproven — this is one
ratio, one framing, n=36 — but the cleanest, most-likely-to-work version of it got its
clearest shot on the benign arm (mean confidence delta −0.0075, 14/20 samples completely
unmoved) and didn't fire.

## Confidence moved — backwards from D2's prediction, and separation got worse

| | Benign (n=20) | Malicious (n=16) |
|---|---|---|
| Verdict changed (arm A → arm B) | 0/20 | 0/16 |
| Confidence moved down | 3/20 | **9/16** |
| Confidence moved up | 3/20 | 0/16 |
| Confidence unchanged | 14/20 | 7/16 |
| Mean confidence delta (B − A) | −0.0075 | **−0.0281** |
| Arm A confidence (min/max/mean) | 0.60 / 0.75 / 0.685 | 0.70 / 0.85 / 0.781 |
| Arm B confidence (min/max/mean) | 0.60 / 0.75 / 0.677 | 0.70 / 0.80 / 0.753 |

D2's hypothesis was "augmentation pulls benign confidence down (or toward benign) while
leaving malicious confidence unaffected." Instead, **malicious confidence moved down more**
(mean delta −0.0281, more than triple benign's average movement) — 9 of 16 malicious
samples dropped, none rose.

| | Arm A | Arm B |
|---|---|---|
| malicious min / benign max | 0.70 / 0.75 | 0.70 / 0.75 (unchanged) |
| benign samples ≥ malicious min | 15/20 | 13/20 |
| **malicious samples ≤ benign max** | **7/16** | **14/16** |
| gap between class means | 0.096 | 0.076 |

The extremes didn't move, but the malicious distribution's interior compressed downward
toward the benign range — malicious samples at or below the benign max confidence
**doubled** (7/16 → 14/16), and the gap between class means shrank ~20%. Under this
augmentation, the two classes became *harder* to separate by confidence, not easier.

## Why: this ties D2 to D7 — negative chunks can't be tested at fixed TOP_K=4 alone

The mechanical explanation for malicious confidence dropping *more* than benign: at a fixed
`TOP_K=4` (`rag_report.py`), the 6 new chunks compete for the same 4 retrieval slots as the
original 16. For a malicious sample, this means the negative chunks sometimes **displace** a
genuinely relevant malicious-framing chunk out of the top-4, rather than supplementing it —
eroding signal the model already had, rather than adding balancing context. For a benign
sample, the negative chunks are competing to *replace* a malicious-framing chunk that was
never relevant anyway, so there's much less to lose — consistent with benign confidence
barely moving while malicious confidence eroded.

**Consequence for any future D2 revisit:** negative-evidence chunks cannot be fairly tested
at `TOP_K=4` in isolation — they need to travel together with a retrieval-capacity change
(a higher `TOP_K`, or D7's not-yet-built distance-thresholded retrieval that could admit a
variable number of chunks) so that benign chunks *add* context for a benign sample instead
of *displacing* context for a malicious one. **D2 and D7 are coupled**: D2's fair test
depends on D7's fix existing first, or at minimum on `TOP_K` being raised for the test.
Logged here as the reason, not acted on — no frozen-file change implied.

## Interpretation — explicit boundary

**This is a null-to-mildly-negative result for this specific test, not a general verdict on
D2.** The 6 chunks are a purely exculpatory set at a 6:16 (37%) one-directional ratio,
tested at the current fixed `TOP_K=4` — the cleanest version of "does adding benign
evidence help" this session could construct without smuggling a decision rule into the
corpus, but not a test of every version.

**What this does NOT establish:**
- It does not show negative evidence "can't help" — a different `TOP_K`, a different ratio,
  or D7's distance-thresholded retrieval could behave differently (see above).
- It does not isolate which of the 6 chunks (if any) drove the malicious-confidence dip —
  no ablation was run.
- It does not test D1's other candidate causes (`SYSTEM_PROMPT` hedging, no explicit
  decision thresholds, the 3-way enum) — those are now the more likely candidates and remain
  untouched.

**What this DOES establish:** on this specific, cleanly-scoped 6-chunk set, at `TOP_K=4`, on
this seeded n=36 sample — augmenting the knowledge base moved zero verdicts and made
confidence separation slightly worse, not better. Per standing instruction, a positive
result would need an ablation to the minimal effective chunk set before any frozen-file
commit; this result doesn't reach that bar, so no frozen-file action is implied by this
experiment.

## Raw data

- `d2_ab_results/results.csv` — per-sample arm A/B verdict+confidence, verdict_changed,
  confidence_delta.
- `d2_ab_results/skips.csv` — the 4 skipped malicious samples (bytecode-parse failures).
- `d2_ab_results/raw_reports.jsonl` — full report dicts for both arms per sample (rationale,
  cited_chunk_ids included for audit, not used as a metric here).
