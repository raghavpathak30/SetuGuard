# Verdict Gate Proposal — Week 2 (D1)

**Status: PROPOSAL ONLY. No code was changed to produce or act on this document.** D1's
verdict behavior is a team decision, not something this session resolves unilaterally. This
document exists to hand the team measured evidence, candidate options, and their measured
tradeoffs — not a recommendation to merge.

---

## 0. Determinism caveat — read this before the numbers below (D6, Phase 3.0)

**Confirmed non-deterministic.** 3 real samples (1 benign, 2 malicious — including the corpus
sample with the most dangerous permissions) were each run through `generate_report()` twice,
back to back, same features dict, same process:

| Sample | Run 1 | Run 2 | Verdict changed? |
|---|---|---|---|
| malicious (`com.baidu.pay2`) | suspicious / 0.80 | suspicious / 0.85 | confidence only |
| benign (`InfinityLoop...NewPipeEnhanced`) | suspicious / 0.75 | suspicious / 0.65 | confidence only |
| malicious (max dangerous_permissions, 9) | **suspicious** / 0.75 | **malicious** / 0.90 | **yes — verdict itself flipped** |

`rag_report.py` passes no `options` to `ollama.chat()` (confirmed Phase 0.1 — no
`temperature`/`seed`/anything), so this is expected, not a bug in this session's harness.

**Consequence, stated per instruction:** every distribution and separation claim below is
**confounded by generation randomness** and must be treated as provisional — a snapshot of one
noisy run each, not a stable measurement. A different run of the exact same 90 samples could
plausibly produce different verdict counts and a different-shaped confidence distribution.
**Any cutoff chosen from Section 2 below should be re-validated against a second independent
run before being trusted.**

**A second, unplanned finding from the same 6 runs**: `cited_chunk_ids` is itself unstable and,
in 4 of the 6 runs, contained values that don't exist in `knowledge_base.CHUNKS` at all —
things like `'permissions'`, `'exported_components'`, `'suspicious_api_usage'`, and even full
chunk titles like `'(T1426 / T1426) System Information Discovery (Device fingerprinting)'`
instead of the chunk id `'T1426'`. Run through this session's `validate_report_grounding()`
(Phase 2), these 4 runs produced 3–7 grounding violations each; the other 2 runs produced zero.
This is real, live evidence for D4 — not hypothetical — captured from the very first
`--report.json` inputs this session ever ran the gate against outside synthetic test fixtures.

---

## 1. Measured distributions (D1, D10) — n=10 baseline vs n=46 baseline_v2

Both recomputed directly from `results.csv` in each directory, by true label (not by verdict —
the verdict is 100% `"suspicious"` in both runs, so grouping by verdict tells you nothing).

| | `baseline/` benign (n=40) | `baseline/` malicious (n=10) | `baseline_v2/` benign (n=40) | `baseline_v2/` malicious (n=46, effective — see below) |
|---|---|---|---|---|
| min | 0.45 | 0.75 | 0.60 | 0.65 |
| p25 | 0.65 | 0.75 | 0.65 | 0.75 |
| median | 0.70 | 0.775 | 0.70 | 0.75 |
| p75 | 0.75 | 0.8375 | 0.75 | 0.80 |
| max | 0.75 | 0.85 | 0.85 | 0.85 |
| verdict | 100% suspicious | 100% suspicious | 100% suspicious | 100% suspicious |

**Effective vs nominal n (per your instruction):** `baseline_v2` was sampled for 50 malicious
(nominal), but 4 were skipped at the `static_analysis` stage — all 4 with the same failure
mode, androguard's `InvalidInstruction` on malformed DEX bytecode (not the zip-integrity issue
found in Phase 0/STOP 3; a different corpus defect). Source: `baseline_v2/skips.csv`:

```
020509362bbbfffa005a8aa6fee3d64a18db8c50640e2e03a0bbc86d0d280016.apk — InvalidInstruction (opcode 0x65)
022a1f9bdd22c0275e5a28890daf441aca7f79f833500d2a60c3fcf944fafa63.apk — InvalidInstruction (opcode 0xeb, "unused")
0343f9de21b43cfaeb21f7ad11871b43449a31b8da6bfeade1d61ad8bcc44e2d.apk — InvalidInstruction (opcode 0xf8, "unused")
034a3126b9cb2019ffac82e3850fea3349a6606100a8e2ced322450795c1c42f.apk — InvalidInstruction (opcode 0x71)
```

So: **nominal malicious n=50, effective (successfully processed) malicious n=46.** All
distributions and confusion matrices in this document use **n=46**, never n=50. Benign had 0
skips (effective n=40 = nominal n=40).

## 2. Does the n=10 separation survive at n=46? **No — stated plainly, not smoothed.**

At n=10 malicious: malicious min (0.75) touched benign max (0.75) exactly — no overlap, no
crossing.

At n=46 malicious: **malicious min (0.65) is now below benign max (0.85)** — real, measured
overlap, not just "touching":
- 33/40 benign samples score **at or above** the malicious minimum confidence (0.65).
- 46/46 malicious samples score at or below the benign maximum confidence (0.85) — trivially
  true since they're equal at the top end (both distributions max out at 0.85).

**Overlap region: roughly [0.65, 0.85]** — which is most of both distributions' range. The
apparent clean separation at n=10 does not survive at n=46; whether that's because n=10 was too
small a sample to see the true overlap, or because of the D6 nondeterminism confound above
(different random draws on a re-run), **cannot be distinguished from this data alone.**

## 3. Candidate confidence cutoffs — confusion matrices from actual `baseline_v2/results.csv` rows (n=40 benign, n=46 malicious effective)

Treating "confidence ≥ cutoff" as a binary malicious/not-malicious prediction and true_label as
ground truth:

| cutoff | TP | FN | FP | TN | precision | recall | accuracy |
|---|---|---|---|---|---|---|---|
| ≥0.60 | 46 | 0 | 40 | 0 | 0.53 | 1.00 | 0.53 |
| ≥0.65 | 46 | 0 | 33 | 7 | 0.58 | 1.00 | 0.62 |
| ≥0.70 | 45 | 1 | 25 | 15 | 0.64 | 0.98 | 0.70 |
| **≥0.75** | **40** | **6** | **12** | **28** | **0.77** | **0.87** | **0.79** |
| ≥0.80 | 17 | 29 | 2 | 38 | 0.89 | 0.37 | 0.64 |
| ≥0.85 | 6 | 40 | 1 | 39 | 0.86 | 0.13 | 0.52 |

**No cutoff achieves clean separation** — this data does not contain one. The best accuracy in
this sweep is 0.79 at cutoff ≥0.75 (still 12 false positives out of 40 benign, and 6 false
negatives out of 46 malicious). Every other cutoff trades FPs for FNs or vice versa; none reach
zero on both.

**This is measured from one noisy run (Section 0 caveat applies in full).** Treat these numbers
as "what a cutoff would have scored on this particular run," not as the true operating
characteristic of the confidence signal.

## 4. D2 section — retrieval imbalance as suspected root cause

`knowledge_base.py`'s 16 chunks are **100% malicious-behavior descriptions** (confirmed Phase
0.6 — every chunk's text explains a MITRE ATT&CK technique or malicious pattern; none describe
a normal/benign permission profile). Because `_retrieve()` (Phase 0.2) returns top-k
unconditionally with no similarity threshold, **every APK — benign or malicious — gets 4
malware-behavior chunks pasted into its prompt**, just with different chunks depending on which
permissions/APIs it has. A benign app that happens to use `RECEIVE_BOOT_COMPLETED` (e.g., to
restart a background sync job) retrieves the same T1398 "boot persistence" chunk a banking
trojan would.

**What the D2 A/B (gated behind STOP 4) would test:** augment `rag_report.CHUNKS` in-memory at
runtime (confirmed feasible without touching `knowledge_base.py`, Phase 0.3) with a small set of
negative-evidence chunks — "SMS permissions are normal for a messaging app," "boot-completed
receivers are common in sync/backup apps," etc. — then re-run the same sample set through
`generate_report()` with augmented vs unaugmented `CHUNKS`, paired per-sample, and compare
verdict distribution and confidence separation. If the "suspicious" hedge specifically comes
from the model being shown only malicious framing (the defects doc's leading hypothesis), the
augmented condition should show more "benign" verdicts and/or a lower benign-confidence
distribution without moving the malicious distribution much. If it doesn't move at all, D2 is
not the (sole) root cause and D1's other candidate causes (hedging language in `SYSTEM_PROMPT`,
no explicit decision thresholds, 3-way-enum-invites-the-middle) become more likely.

**Not run this session** — this is the Section-4-of-the-original-instructions gate: it needs
your go-ahead in STOP 4.

---

## 5. What this document is NOT

- Not a recommendation on which cutoff to ship, if any.
- Not a resolution of D1 (verdict-from-confidence vs prompt-engineering vs enum-collapse) — that
  remains an explicit team decision per the defects doc.
- Not evidence that a confidence-derived verdict would be *better* than the current
  always-"suspicious" one for a live demo — a judge asking "why does everything say suspicious"
  is a known bad look, but a cutoff with 12/40 false positives on this run is also a bad look if
  a judge asks about a specific benign sample.
- Not a stable number — Section 0's nondeterminism finding means a second run could shift every
  table above.
