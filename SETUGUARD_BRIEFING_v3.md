# SetuGuard — Finale Briefing v3.0

**Written 24 August 2026, end of Day 6 (last build day).**
Grand Finale 27–28 August, IIT Hyderabad. Live stage demo required.

---

## 0. READ THIS FIRST — what this replaces

**`SetuGuard_Manual.pdf` v2.0 (14 August) is superseded and must not be read by anyone.**
It teaches six things that are now false:

| v2.0 says | Current truth |
|---|---|
| AUC **0.9366** and **17.1%** are the headline PS1 numbers | Both excluded by our own submitted report. Void. |
| The banking comparison is unmeasured, corpus being built | Built and measured. PRIMARY AUC **0.1444**, Outcome 3. |
| **Banned:** saying "our detector ranks banking apps above malware" | That is now precisely the finding. The ban is inverted. |
| Bridge ground truth is one entry, account 9072 | 2 distinct ground-truth linkages. |
| `cv_aucpr_mean` / `n_cv_folds` are live response fields | Renamed and dropped. |
| Citation IDs jitter, narrative otherwise deterministic | The **narrative text itself is not deterministic**. |

**Also stale, also in the project folder, also do not read:**
`FINALE_PLAN_AND_AUDIT.md` (18 Aug — instructs quoting the now-void 17.1%) and
`CONTEXT.md` (still says PS2 not started).

**Authoritative as of now:** this file, `ERRATA.md`, `SESSION_LOG.md`, and the
submitted report PDF.

---

## 1. What the system is — one paragraph each

**PS1 — APK evidence extraction.** Androguard static extraction → FAISS retrieval over
a MITRE ATT&CK-for-Mobile knowledge base → Mistral-7B narrative → YARA rule generation →
rule-based verdict. `POST /api/analyze_apk`. **It ships as an evidence extractor, not a
detector.** It carries no threshold and claims no false-positive rate.

**PS2 — mule account scoring.** XGBoost, inference-only against the committed artifact
`models/ps2_xgb_v1.json`, over 18 bank-approved features. `POST /api/analyze_dataset`.

**Bridge — the innovation claim.** Exact-match join on publisher certificate SHA-256 and
normalised C2 host, linking APK indicators to flagged accounts. `POST /api/bridge`.
Neither half alone is novel; the join is the claim.

**The d1-inversion is the architectural guarantee.** `_rule_based_verdict()` is the sole
source of verdict, score and severity. The language model writes narrative only and
cannot reach any decision field on any path. Verified by running with the model server
down and getting identical verdicts. **This is the single strongest engineering answer
in the project — lead with it whenever LLM reliability comes up.**

---

## 2. THE FRAMING RULES — violating one is worse than saying nothing

1. **PS1 is an evidence extractor.** The negative AUC is the contribution, not a bug.
2. **PS1 has no false-positive rate and claims none.** No threshold exists.
3. **PS2 leakage work is AUDIT and QUANTIFICATION, never DISCOVERY.** The bank's own
   18-feature approved list already excluded every leaky column. A judge who opens
   `data/Description.xlsx` breaks a discovery claim in ten seconds.
4. **Bridge confusion matrix is a CORRECTNESS test of join logic, never a detection
   rate.** Lead with: 2 distinct ground-truth linkages, 100 test cases, 20 near-miss
   confounders. **Never a bare "TP=10".**
5. **`confidence` is `round(0.5 + score/2, 2)`.** Never called "confidence" in
   user-facing text anywhere.
6. **Class convergence** (banking apps and banking trojans share a permission surface) is
   an untested **hypothesis** offered to explain the result. Never stated as a finding.
7. **`ps2/06_graph_features.py` contains label leakage.** Excluded from all claims. The
   "mules sit at network bridges" story is dead.
8. **`yessign[.]net` displayed defanged**, with explicit non-attribution language.
9. **Tier counts must never be paired with recall figures.** Tiers are fixed probability
   thresholds; recall is percentile-based. Different selection rules.
10. **File count is never sample count.** Every quantitative claim names its negative
    class.

---

## 3. QUOTABLE NUMBERS — the only ones

### PS1 — the headline negative result

- PRIMARY AUC **0.1444 [0.0905, 0.2081]** vs `harness/banking_legit_corpus/`
  (51 packages / 32 issuer clusters). Pre-registered at commit `be6a15c`. Both CI bounds
  below 0.5 → Outcome 3.
- SECONDARY AUC **0.3190 [0.2202, 0.4290]** (20 packages, nested subset).
- At threshold 0.30, **50 of 51** legitimate banking packages flag (98.0%).
- Allowlist coverage: **23 of 51** PRIMARY packages (45%). Packages, not files.

### PS2

- AUCPR median **0.271** (IQR 0.221–0.362). AUROC median **0.872** [0.851–0.907].
- Top-1% recall **25.0% (4 of 16 positives)**. Top-5% recall **53.1% (8 of 16)**.
  **Always say the fraction alongside the percentage.**
- Random baseline ~0.0089 → ~30× lift.
- Tier distribution on 9,082 accounts: T1 8,490 / T2 380 / T3 110 / T4 102.

**Know this cold:** 16 is the positive count in a 20% stratified holdout; 81 is the
positive count across all 9,082. The baseline 0.0089 = 81/9,082. If a judge asks "16 or
81?", that's the answer — same data, different denominators, one per split.

### Timing

- Static extraction: **58 of 60** completed at parallelism one, mean **20.1s**. Two hit a
  600-second budget without completing. Slowest completion **93.9s**.
- Full served endpoint: median **123.9s**, IQR 107.1–145.7s, n=14 valid of 30 attempted,
  files ≤50 MB.

### Memory

- Largest clean isolated peak **9.68 GiB**. Sizing rule: ~10 GB measured / 16 GB
  provisioned per concurrent application.

---

## 4. VOID — never say these, never replace with estimates

```
0.4113   0.3841   0.4114   0.988   97.9   9.86
~10s/APK   39.6s/APK   1.20s/APK   77.9s (as slowest extraction)
14.85s   162.2s   119.7s   46.57s   46.45s   9.03s   6.66s   7.12s
```

### NEWLY VOID as of 24 August — the important one

**`0.9366` and `17.1% (50 of 292)` are both dead.** They come from the F-Droid general
benign corpus. The submitted report's §IX Limitations states that corpus was available
during scorer term selection, is therefore contaminated by selection, and *appears
nowhere in this report*.

Quoting a number your own report excludes doesn't cost you the number — it costs you the
pre-registration discipline claim, which is the strongest asset in the project.

**Consequence: PS1 has no false-positive rate.** See the scripted answer in §6.

---

## 5. KNOWN DEFECTS — all disclosed in `ERRATA.md`, none hidden

**C1 — Throughput figure mis-scoped.** The report's 39.6 s/app divides 2,374s wall clock
by 60 *attempts*, two of which hit a 600-second budget without completing and contributed
1,200.2s — 50.7% of the wall clock. The 58 completions averaged 20.1s. `77.9s` is the
slowest file in a three-file probe batch, not the run maximum.

**C2 — `0.66s` account-scoring latency has no producing harness.** No script exists
anywhere for the ~9.86 / ~0.66 / ~0.0025 endpoint timings. Not reproducible from a clone.

**C3 — F-Droid corpus excluded.** See §4.

**C4 — TWO DIVERGENT TIER LADDERS.** The most consequential code finding:

```
setuguard_app/backend/app.py  _assign_tier():   T2 ≥0.25   T3 ≥0.50   T4 ≥0.75
ps2/02_baseline_model.py  assign_risk_tier():   T2 >0.25   T3 >0.55   T4 >0.80
```

An account at 0.78 is **T4 (temporary debit freeze)** served, **T3 (enhanced review)**
offline. The served ladder is authoritative and produces the tier counts; verified that
no single bridge response mixes the two. **Not fixed** — aligning them would change tier
counts, invalidate committed figures, and force re-capture of demo JSONs the day before
freeze. Neither ladder is calibrated; both are hardcoded probability cutoffs, not
percentiles, not a triage capacity, not a cost model.

**Bridge `recommended_action` keyed on APK severity alone.** The account tier displays
next to it and contributes nothing. Two accounts in different tiers linked to the same
APK get identical instructions.

**THE MISTRAL NARRATIVE IS NOT DETERMINISTIC.** Re-capturing `nomatch_01` produced
entirely different prose with `narrative_source: ollama_rag` on both runs, under pinned
temperature=0 and seed=42. The older text named T1636.004 and T1398; the newer named only
techniques present in `mitre[]`. **The MITRE-citation defect is intermittent, not fixed**
— it can reappear on any run.

Determinism **does** cover: verdict, risk score, severity, confidence, family verdict,
YARA text. It does **not** cover narrative text.

**Allowlist — this is progress, not an erratum.** The report states in three separate
places that the allowlist is unimplemented. What shipped is display-layer publisher
tagging, which *exceeds* what the report claims.

**`nomatch_01_apk.json` has a genuine certificate extraction failure** — `cert_sha256:
null`, all nested cert fields null. A real no-match case, not constructed: the bridge
loses one of its two join keys and correctly returns nothing. Good story, and honest.

---

## 6. HOSTILE QUESTIONS — rehearse these out loud

**"What's your false-positive rate?"**

> PS1 doesn't have one, and that's deliberate. It has no threshold — our own
> pre-registered measurement says a threshold on this feature set ranks production
> banking applications above confirmed trojans; 50 of 51 legitimate packages flag at
> 0.30. So it ships as evidence extraction, not detection. We did have a favourable
> false-positive figure against a general free-software corpus. It's excluded from the
> report and I won't quote it, because that corpus was available while the scorer terms
> were being chosen and the figure is contaminated by selection. The false-positive load
> that matters for the product is the account model's, and that one has an operating
> point.

**"Your report says 39.6 seconds. I just watched that take two minutes."**
Different spans. The report figure is static extraction; the endpoint adds retrieval and
narrative generation. The narrative isn't the verdict source, so at volume that stage
queues or drops and no verdict changes. Also, 39.6 divides wall clock including two
600-second timeouts by all 60 attempts — the 58 completions averaged 20.1 seconds.

**"An account at 0.78 — freeze or review? Your code says both."**
The served path decides, and it freezes at 0.75. The offline script uses an older ladder
and its tiers don't reach the product. Neither set of boundaries is calibrated; a bank
would set them from its own triage capacity. Disclosed rather than papered over.

**"Your report names T1398. Where is the evidence for T1398?"**
The technique table is the authoritative evidence — deterministic, each row naming the
class and method that triggered it. The narrative is model-generated commentary, labelled
as such on screen, and technique identifiers in prose are not extraction results. They
also vary between runs on identical input, which is why the label is unconditional.

**"You're showing publisher tagging, but your report says the allowlist isn't
implemented."**
Both. Tagging is display-layer, it removes nothing from the scored path, and no AUC has
been re-run with allowlisted packages excluded. The enforced control is still future
work, exactly as the report says.

**"Why do a low-tier and a high-tier account linked to the same APK get the same
instruction?"**
Because the action reflects the APK-side finding, which is what changes urgency. The
account tier is carried alongside for prioritisation among multiple links. A production
version would key the action on the pair. Known and disclosed.

**"98.0% of legitimate banking packages flag, but you also said 17.1%."**
Two different negative classes at two different thresholds. The F-Droid figure is
excluded from the report and I don't quote it. The banking one is the negative result and
it's the headline.

**"Digital payment fraud is falling in the RBI data. Why does this matter?"**
It's falling in the bank-fraud series, which counts frauds of ₹1 lakh and above committed
against banks. Mule-account fraud is high-volume, low-value, and the victim is the
customer, so most of it never enters that series. In the citizen-side data complaints rose
to 21,77,524 in 2025 while total value fell — more cases, each smaller.

**"Column 4 of your spreadsheet has 19 entries, not 18."**
The nineteenth is F3924, `FRAUD_TGT`, described as "Target variable". The bank marked
their target column in the same column they used to mark finalized features. We use 18
predictors and exclude the target. Cross-checked 24 August.

**"Your feature labels contradict each other."** (F2956's name says 14D, description says
14 to 31D; F3043's name says 31D, description says 7 to 14D)
Both strings are verbatim from the bank's data dictionary. We didn't edit them, and
that's deliberate — showing both the variable name and the description means an auditor
can match either back to the source file. Where the source disagrees with itself, that's
visible rather than papered over. We'd raise it with the data owner rather than pick one.

**"Occupation code and age in a fraud model — have you tested for disparate impact?"**
Not measured. These are the bank's own finalized variables; we ran inference on the list
we were given and did not select features. A production deployment would need a fairness
audit we haven't run.
*Don't volunteer this. Have it ready.*

**"Is the alert card showing what just ran?"**
Say this **proactively** when you open the card: *"this is rendering a saved response."*
The nine `demo/*.json` captures carry fixed narrative text, and since the narrative isn't
deterministic it won't match a live run. Discovered by a judge, it looks like a mockup.

---

## 7. BUSINESS POTENTIAL — the framing is counter-intuitive

**Do NOT say digital fraud is rising.** The RBI Annual Report 2025-26 shows the
card/internet/digital-payments category *collapsing*: 293 cases worth ₹29 crore in
2025-26, down from 13,332 cases (₹517 crore) in 2024-25 and 28,836 cases (₹1,452 crore)
in 2023-24. A judge from Bank of India holding their own regulator's report ends the
section on the spot. Note also that FY2024-25 was **restated** between reports.

**Safe headline:** RBI Annual Report 2025-26 — 10,114 fraud cases involving ₹48,021 crore
in 2025-26. Roughly two-thirds of that is reclassified legacy loan fraud (314 cases worth
₹30,199 crore reported afresh after the March 2023 Supreme Court judgement), and the
series only covers frauds of ₹1 lakh and above counted against the *bank*.

**The correct denominator is the citizen-side I4C / NCRP series:**
- 2025: 21,77,524 complaints, ~₹19,812 crore lost
- 2024: 19,18,852 complaints, ~₹22,849 crore lost
- **Volume up ~13%, value down ~13%** — more cases, each smaller. That's the shape that
  breaks manual triage, because assembly cost per alert is roughly constant.

**The strongest single fact:** CFCFRMS, operated by I4C since 2021, had saved more than
**₹7,130 crore across more than 23.02 lakh complaints** as of December 2025 (Lok Sabha
Unstarred Question No. 432, 2 December 2025). A **Cyber Fraud Mitigation Centre** exists
at I4C where major banks, payment aggregators, telecom providers and state law enforcement
already work together (LS UQ No. 344, 22 July 2025). I4C's awareness campaign names
**malware** and **fake loan apps** among its target modus operandi — the APK half of the
pipeline.

**The argument:** the workflow already exists at national scale with humans doing the
assembly. SetuGuard automates the assembly step. Not a new category.

**Load-bearing non-claims:** no queue-capacity claim, no cost-saving figure, no pricing
model, no validation on real linked fraud.

**Caveat:** the CFCFRMS figures came from a search result, not the Lok Sabha PDF itself.
It's the number a DFS judge is most likely to know cold. Verify at source if there's time.

---

## 8. CO-AUTHOR BRIEFING — Amiya, Tanishka, Puneet

**Do not read `SetuGuard_Manual.pdf` v2.0.** It will make you say things that are now
false. This file replaces it.

### Safe to say

- What the three components are (§1), in the words used there.
- "The language model writes the narrative. It cannot set the verdict — that's a
  rule-based function, and we verified it by running with the model server down."
- "PS1 ships as evidence extraction, not detection."
- "The bridge joins on publisher certificate hash and C2 host."
- **"Raghav has the number / Raghav ran that measurement."** This is always a correct
  answer and it costs nothing.

### Never say, under any circumstance

- Any number at all. Not one. Numbers route to Raghav.
- "Our detector catches X%" / "our accuracy is" / anything with a percentage.
- "We discovered leakage in the bank's data." (We audited and quantified. The bank had
  already excluded it.)
- "The graph features show mules sit at network bridges." (Label leakage. Dead.)
- "It's deterministic." (Verdicts are. The narrative isn't.)
- "TP=10" or any bare confusion-matrix cell.
- "Digital fraud is rising."

If a judge asks something not on the safe list: *"Raghav ran that — let him take it."*
That is a complete and professional answer. Guessing is the only failure mode here.

---

## 9. FREEZE DAY — 25 August

- Three full run-throughs, timed, each from a **hard reboot**. Not a Flask restart —
  Flask-restart-only produced 96s latency where a fresh reboot gave 6s.
- Fallback video: exact machine, exact files, unedited, one continuous run. Recorded
  **tomorrow**, not on travel day.
- Hostile Q&A out loud, timed, from §6.
- Freeze in the evening. Nothing merges after, including things that look like
  one-liners.

**Standing discipline:** `git add -A` is prohibited, explicit paths only,
`git status --short` before every commit and read it. Six PS1 files frozen — edits
permitted, logged in `FROZEN_FILE_FINDINGS.md` with a reason. Never cite line numbers in
documentation; function names only. Report measured values only — if something wasn't
measured, say "not measured".

**Do not touch `setuguard_app/frontend/` or `setuguard_app/backend/`.** Live demo path
with committed smoke-test evidence. A crash on stage costs more than any cosmetic
improvement earns.

---

## Revision history

**v3.0 — 24 August 2026.** Supersedes v2.0 (14 August, commit 229156e era).
Changed: 0.9366 and 17.1% moved to the void list following the report's §IX exclusion,
which removes PS1's false-positive claim entirely; the banking measurement moved from
"unmeasured" to the headline finding at AUC 0.1444; the v2.0 ban on saying the detector
ranks banking apps above malware was inverted, since that is now the established result;
bridge ground truth corrected from one entry to 2 distinct linkages; `cv_aucpr_mean` and
`n_cv_folds` removed as live fields; narrative determinism retracted and added as its own
defect entry; four `ERRATA.md` corrections folded in; both tier ladders documented;
Business Potential reframed off the falling RBI digital-payments series onto the I4C
citizen-side series; co-author briefing added.
