> **CORRECTION — 24 August 2026.** This file predates `ERRATA.md`. Two figures
> below are no longer quotable: **AUC 0.9366** and the **17.1% (50 of 292)**
> general-benign flag rate. Both derive from the F-Droid general benign corpus,
> which the submitted report's §IX Limitations excludes as contaminated by
> selection — that corpus was available during scorer term selection, and the
> report states it appears nowhere in the report. PS1 therefore has no
> false-positive rate and claims none.
>
> The current PS1 headline is **PRIMARY AUC 0.1444 [0.0905, 0.2081]** against
> `harness/banking_legit_corpus/` (51 packages / 32 issuer clusters),
> pre-registered at commit `be6a15c`. Both CI bounds below 0.5.
>
> Where this file and `ERRATA.md` or `SETUGUARD_BRIEFING_v3.md` disagree, those
> win. The body below is retained unedited as a record of what was believed on
> its own date. This includes the instruction to "Lead with AUC 0.9366" and every
> scripted judge answer in this file that quotes it. Those scripts are superseded
> by the hostile-question section of `SETUGUARD_BRIEFING_v3.md`.

# SetuGuard — Execution Plan, 12–27 August 2026

Sole contributor: Raghav. Nothing here depends on anyone else.

**Progress Report** due 17 August, submitting **16 August** — missing it cancels candidature, the
only hard failure mode. **Grand Finale** 27–28 August, IIT Hyderabad.

**Judging criteria:** Innovation, Technical Feasibility, Business Potential, Scalability, User
Experience.

Read `CONTEXT.md` §0 and §6 before starting. The plan below is shaped by the 12 August finding
that `banking_holdout_16/` contains malware rather than banking apps.

---

## Phase 0 — 12–16 August. Documentation only.

**No code changes. No `.py` outside `harness/identify_holdout_16.py`, no `.js`, no `.html`, no
`.json` fixtures.** The integrated build is green and is the project's primary evidence. Eleven
known defects are deliberately deferred past 17 August (`CONTEXT.md` §6). Fixing code this week
is the worst outcome available.

### G0 — Progress Report PDF

- **Gate:** submitted **16 August**, not 17.
- **Dies if it fails:** the candidature. Everything below is downstream.
- **Criterion:** all five.
- **Stop rule:** none. Not cuttable, not deferrable. If anything competes with G0 for time, G0
  wins.
- **Content:** write from `REPORT_FACTS.md` only. Lead with AUC 0.9366, the 93.6%/17.1%
  operating point, the PS2 20-seed distribution against its 0.0089 baseline, and the 66.9% IOC
  yield. **Do not quote AUC 0.4113 or any 15/16 figure.** State the corpus finding as a stated
  limitation — the project caught a corpus-integrity error in its own headline result four days
  before submission, which is a better story than the number it replaces.

### G0a — Holdout provenance — **DONE, 12 August**

`harness/identify_holdout_16.py` → `harness/BANKING_HOLDOUT_16_PROVENANCE.md`. All sixteen apps
identified, all sixteen Tier Unknown, all sixteen established as malware from `Banking.tar.gz`.
The tier scheme (A: scheduled commercial bank first-party / B: UPI-PSP / C: NBFC-wallet-fintech /
Unknown) survives as the **pre-registered inclusion rule** for item A below.

### G0b — IOC yield audit — **DONE, 12 August**

`harness/ioc_yield_audit.json`, `harness/IOC_YIELD_RESULTS.md`. **66.9%** of malicious APKs yield
≥1 network host indicator; **60.6%** yield ≥1 host absent from the comparison corpora; **99.4%**
yield a usable certificate hash. Clears the ≥30% gate. Three caveats travel with it always:
right-censoring at 25 strings, only the 10.6% bare-IP subset is matchable today, and the
conservative floor treating obfuscated parse failures as zero-yield is 60.3%.

---

## Item A — Build the real Tier-A holdout. 17–23 August, parallel track.

**This is no longer a corpus *expansion*. It is the first measurement the project will ever have
made of its central claim.** Promoted from the old G4 to the top of the post-report queue.

Pull from AndroZoo by **exact `pkg_name` match against `latest.csv`**, requiring
`vt_detection == 0` **and** `markets` containing Google Play. AndroZoo has no category field;
there is no "banking" query, so exact package-name match is the only mechanism. Both filters are
load-bearing: AndroZoo carries repackaged fake banking apps under near-identical package names,
and `vt_detection == 0` does not exclude a freshly repackaged trojan no engine has seen.

Use the tier scheme in `harness/identify_holdout_16.py:TIER_RULES` **exactly as committed on
12 August** — it is pre-registered, and it was written before any AndroZoo sample was scored.

**Verify every downloaded APK the way the old holdout was not:** run
`harness/identify_holdout_16.py` over the new directory and require a Tier-A assignment from
package namespace or certificate Organization. **Reject any sample whose certificate is
self-signed, debug-signed, or carries the AOSP test key.** All sixteen of the old holdout would
have been rejected by that one rule.

- **Gate: Tier A AUC in [0.35, 0.55] at n ≥ 40.** Not a pooled figure. A pooled sample including
  light-surface Tier-C fintech apps will drag AUC up for reasons unrelated to the hypothesis —
  those apps genuinely have a smaller permission surface, so malware genuinely does rank above
  them. Reading that as a refutation would be a worse error than the original claim.
- Report **per-tier, pooled, and the retired CICMalDroid sixteen** as three separate columns,
  never one.
- **Dies if it fails:** the class-convergence hypothesis stays unmeasured and the report's stated
  limitation stands unchanged through the finale. Survivable — it is what ships today.
- **Criterion:** Innovation, Technical Feasibility.
- **Stop rule: 23 August.** Fall back to "unmeasured, corpus build in progress," which is what
  `REPORT_FACTS.md` already says.
- **Explicitly not doing:** no time-split evaluation. It re-measures the same quantity on more
  data; the hypothesised mechanism is class convergence, not temporal drift.

---

## Post-report repair queue — 17–20 August

Items 1–9 total roughly a day and a half of work plus one re-extraction. They clear the deferred
defect list in `CONTEXT.md` §6.

### 1. Frontend and README truth pass (~2h)

`setuguard_app/README.md` describes the rule-based verdict as the Ollama-unreachable fallback —
the exact inverse of what `d1-inversion` built — plus "trains XGBoost with stratified CV (falls
back to IsolationForest)" and "auto-detects the label column". It is the first file a judge
opens. Frontend: `index.html:157` "real XGBoost + SHAP trained on your data"; `index.html:164`
button "Run Data Audit + Train"; `app.js:164` status "…then training XGBoost + SHAP…";
`app.js:223,489` render "CV AUCPR (0-fold)" over a 20-seed holdout median; `index.html:212-214`
claim bias checking, KS-test drift monitoring and a greedy counterfactual that is `null`.

- **Gate:** every edit is a string replacement, no logic touched; `harness/browser_smoke.js`
  returns a clean console report on first re-run.
- **Dies if it fails:** highest probability of live humiliation in the project.
- **Criterion:** User Experience, Technical Feasibility.
- **Stop rule:** if the smoke test is not clean on the first re-run, revert and leave the
  strings. A green build beats an honest label.

### 2. Matcher host extraction + populate `c2_host` — **DONE, 21 August (Day 4)**

`urlparse` the URL-kind indicators, extract host and IP separately, match against a host set.
Shipped as a single `_normalize_host()` function applied to both sides of the comparison.
`SYNTHETIC_LINKAGE_GROUND_TRUTH` now carries two entries, one per join key — the C2-host entry's
indicator is a hostname extracted from the sample's strings by our own static analysis
(`yessign[.]net`, mimicking the Korean accredited-certificate brand "yessign" in a sample
impersonating KB Kookmin Bank), not fabricated. No claim is made about the domain's current
ownership, registration, or activity; it is not confirmed as live C2. Its account association is
still hand-constructed. **Not done, still open:** re-running the yield
audit counting *matchable* indicators rather than merely present ones — 10.6% vs 66.9% is still
the honest number pending that re-run.

- **Gate (met):** `bridge/confusion_matrix_validation.py` still returns TP=10/FP=0/FN=0/TN=90 —
  2 distinct ground-truth linkages (one cert hash, one C2 indicator) tested against 100
  hand-built cases including 20 near-miss confounders, matcher correct on all. Verified by
  sabotage on both the offline script and the live `/api/bridge` handler, not by reading.
- **Criterion:** Innovation.

### 3. Fail-closed path (~1h)

Catch the parse exception in `app.py`, return HTTP 200 with `status: requires_manual_review`.

- **Gate:** a deliberately corrupt APK returns 200 with the status field and the dashboard
  renders it as a review state, not a red error string.
- **Dies if it fails:** an exception string rendered in a bank UI is a feasibility answer by
  itself. 40 of 716 sample APKs take this path.
- **Criterion:** Technical Feasibility, User Experience.

### 4. Upload cap (~30m)

50 MB via `MAX_CONTENT_LENGTH` plus a client-side check with an explicit message.

- **Gate:** a 60 MB file is rejected client-side with a readable message, and server-side 413 is
  caught and returned as JSON.
- **Dies if it fails:** 26 sample-set APKs exceed 50 MB; one 172 MB file defeated a 300 s timeout
  with a dedicated memory budget. Two memory incidents already traced to large files.
- **Criterion:** Technical Feasibility.

### 5. Commit `results_716.csv` (~15m, blocked on relabelling)

The headline result must survive a clone. Cache stays gitignored; the results table cannot.

- **Blocked on:** the file's `corpus` column labels sixteen rows `banking_holdout`. Relabel to
  `cicmaldroid_banking_holdout` before committing, or the false corpus claim ships in a data
  file.
- **Gate:** a fresh clone can reproduce every quoted PS1 number from committed files alone.
- **Criterion:** Technical Feasibility.

### 6. Strip surviving retractions (~1h)

`bridge/test_fixtures_ps2_sample.json` (202 records, loaded at runtime by
`confusion_matrix_validation.py:240`) and `ps2/ps2_bridge_payload.json` still carry
`generated_rules`, `rule_validated: true`, `counterfactual: "No change needed (Safe)"`,
`model_version: "v2.0.0-xgb-platt-graph"`, and a `graph_betweenness` SHAP driver — a withdrawn
leaky feature still shipping in a runtime-loaded fixture. Also strike `SESSION_LOG.md:430-434`'s
"independently confirmed" framing, and fix `harness/sample_set_banking_holdout_16.txt:2-3`, whose
comment asserts the sixteen are real bank apps.

- **Gate:** `confusion_matrix_validation.py` still returns TP=10/FP=0/FN=0/TN=90 after the
  fixture edit — 2 distinct ground-truth linkages tested against 100 hand-built cases, not
  a bare "TP=10".
- **Criterion:** Technical Feasibility.

### 7. NUL-byte YARA guard — determine scope first (~1h)

22.1% prevalence (32/145 benign F-Droid samples). `run_pipeline.py` is unguarded. **Establish
whether the API path is too** before writing anything: `app.py:317-326` wraps
`yara_engine.compile` in `try/except Exception`, which *should* degrade to `compiles: false`, but
that has never been tested against a NUL-bearing sample.

- **Gate:** a known NUL-bearing APK through `/api/analyze_apk` returns 200. If it does not,
  roughly one demo run in five can throw during YARA generation — guard in `app.py` immediately.
- **Dies if it fails:** a live uncaught `ValueError: embedded null character` on stage.
- **Criterion:** Technical Feasibility.
- Frozen-file root cause (`static_analysis.py:82`, `yara_gen.py:35-39`) stays deferred; guard in
  the non-frozen layer.

### 8. Timing harness (~1h)

20 reps across all three endpoints with real percentiles, plus **stage-split latency — static
extraction, rule scoring, LLM narrative measured separately.**

- **Gate:** three separate latencies, n=20, committed script and committed output.
- **Dies if it fails:** the scalability argument stays unmade and timings stay unquotable.
- **Why the split is the whole point:** the aggregate ~9.86 s is dominated by the 7B call.
  Quoting it alone implies one GPU per ~8.7k APKs/day, which loses. The correct framing is that
  **batch scoring is CPU-only for 100% of ingest volume and the LLM narrative fires on analyst
  open**, so GPU sizing follows analyst case throughput, not APK volume. That is a description
  of what `d1-inversion` already built, not a redesign — measure it and say it.
- **Criterion:** Scalability, Business Potential.

### 9. `MAX_SUSPICIOUS_STRINGS` per-kind — 18–19 August (~1 day including re-run)

Frozen file. Log in `FROZEN_FILE_FINDINGS.md` with a reason and take sign-off first.

- **Gate:** sign-off recorded before the edit; re-extraction of all 668 completes; a
  re-measurement writeup lands.
- **Dies if it fails:** the censoring caveat stays attached to every indicator count.
- **Why after the report, not before:** it invalidates the feature cache and moves every PS1
  number. Worth doing after, because it removes the censoring caveat and raises IP yield — and
  IPs are currently the only match type the bridge can fire on (item 2 widens that, this deepens
  it).
- **Criterion:** Innovation, Technical Feasibility.

---

## Phase 2 — 20–23 August. Runtime capture, parallel with item A.

### G6 — Dynamic analysis, scoped to network IOC yield only

**Malware only, no benign arm.** The question is whether executing a sample reveals hosts static
analysis cannot see; that needs no control group.

Passive `emulator -tcpdump` on a recent API level; extract **A/AAAA DNS queries** and **TLS
ClientHello SNI** from the pcap. Seed the monkey run (`monkey -s 42`) to match the repo
convention.

**Deliberately not doing:** no mitmproxy, no CA installation, no Frida, no root, no API-level
downgrade. Hostnames are cleartext on the wire regardless of pinning — DNS and SNI are both
unencrypted — so none of that machinery helps. And a system proxy or user-installed CA is itself
an evasion trigger that modern banking trojans check for, which would inflate the no-traffic rate
and corrupt the measurement.

**Three outcomes, not two:** hardcoded-IP C2 recorded as an **IP-valued IOC** (also the only shape
today's matcher can join); **DoH-only traffic** as a **distinct** outcome from no-traffic;
no-traffic as its own count.

Measure `hosts_static`, `hosts_runtime`, `hosts_runtime_only`.

- **Gate, hard, 23 August: ≥5 samples yield ≥1 host invisible to static analysis.**
- **Prerequisite: item 2.** Without host extraction, captured hostnames cannot join anything.
- **Dies if it fails:** report the environment as built, the no-traffic count as measured, and
  emulator awareness as the stated next experiment. A presentable negative result.
- **Criterion:** Innovation, Technical Feasibility.
- **Stop rule: hard stop 23 August.** Not demoed live on 27 August under any outcome.

### G5 — PS2 single-record endpoint + MNTH replayer

**Pre-gate, three checks in this order, before any endpoint code:** MNTH cardinality; backward-
window fraud count; forward-window fraud count. If `F2230` takes only three or four values this
is a two-cohort split and calling it temporal generalisation is overclaiming. If either window is
starved of positives — there are only 81 in total — ship the endpoint as a **capability with no
metric**.

`F2230` is in `EXCLUDED_ALERT_DERIVED` and the leakage guard raises on it, so the replayer must
read MNTH **outside** the model's feature path, never through `load_dataset()`.

- **Gate:** all three checks run and recorded before code.
- **Criterion:** User Experience, Scalability.
- **Stop rule:** pre-gate 21 August, endpoint 23 August or drop.

---

## Phase 3 — 24–26 August.

### G7 — Feature freeze, 24 August

Bug fixes only after. A change past the freeze needs a one-line written justification naming the
demo failure it prevents. **Dies if it fails:** the demo. **Never cut.**

### G8 — Offline demo rehearsal

Three consecutive full runs: networking down at the OS level, Ollama pre-warmed and resident, **no
backend restart between runs** (the PS2 artifact and SHAP explainer load once at import —
`app.py:462` — and a restart pays that on stage), timed against the stage slot.

- **Gate:** three consecutive clean runs inside the slot, zero restarts.
- **Dies if it fails:** the finale. A demo that fails live scores zero on all five criteria at
  once.
- **Never cut.**
- **Stop rule:** if run 3 fails, stop adding and start subtracting demo steps.
- Dynamic analysis is **not** demoed live — a recorded capture plus the results table, inside a
  live static demo.

### G9 — Hostile Q&A rehearsal

Every question below answered inside 60 seconds without notes, out loud, against a clock. The
failure mode is not being wrong; it is hedging, or reaching for a number not in
`REPORT_FACTS.md`.

- **Stop rule:** 26 August. Anything unrehearsed gets the fallback: "we measured it, here is the
  number, here is what it does not show."

---

## Cut order

First to go:

1. VT graded-label correlation — already cut.
2. AndroZoo time-split — already cut.
3. **G5, the PS2 replayer.** Dropped below both the runtime capture and item 9. It was already
   the weakest item; with the bridge repair and the censoring fix competing for the same days it
   does not earn a slot unless everything above lands early.
4. Item 9, `MAX_SUSPICIOUS_STRINGS`.
5. G6, runtime capture — below item 9 only because item 9 is a prerequisite for G6 being worth
   much, and above G5 because passive capture is cheap and **both** of its outcome branches are
   presentable, whereas G5's likely outcome is capability-with-no-metric.

**Never cut:** the IOC yield audit (done), the business/workload page, the offline demo
rehearsal. **Item A is not on this list** — it is the only path to evidence for the central
Innovation claim, and if it is cut the claim is withdrawn rather than downgraded.

---

## Hostile question register

### 1. "Which sixteen banks?" ★ rehearse first

None of them. We asked that question of our own corpus on 12 August and the answer was that
`banking_holdout_16/` contains no banking apps — all sixteen are malware samples from the same
CICMalDroid archive as our positive class, which we established by set-differencing the archive
against both directories: 2,489 plus 16 equals 2,505 exactly, with zero overlap. The name meant
"held out from the Banking malware set" and successive sessions read it as "a holdout of banking
apps." So we withdrew the AUC-0.41 result and the false-positive claim before submitting, and the
report states the gap rather than the number. What survives untouched is the separation we can
evidence: AUC 0.9366 against 292 real F-Droid apps. The corpus we should have had is being built
now against a pre-registered inclusion rule, and the rule that would have caught this in July is
one line — reject any sample whose certificate is self-signed, debug-signed, or carries the AOSP
test key. All sixteen fail it.

### 2. "So your headline result was wrong for five weeks."

Yes, and the mechanism matters more than the apology. It was a naming error that propagated
through six documents without anyone re-opening the files, and our own defect list flagged the
corpus as "unsourced" on 10 August — `PS1_Defects_and_Improvements.md`, item D9 — and the number
was computed anyway. What caught it was asking a question we had never asked: not "is the number
reproducible," which it always was, but "what is it a number *about*." We also had a convention
that said "never touch `banking_holdout_16/` in any script," which is exactly what kept sixteen
files unexamined. We struck it. The instrument that found this is committed as
`harness/identify_holdout_16.py` and it runs in ninety seconds.

### 3. "0.41 AUC — why deploy a detector that ranks malware below real banking apps?" — **DEAD, do not answer as scripted**

This question presupposes the retracted result. **Do not defend 0.41.** Redirect to question 1:
the negative class was malware, the number measured malware against malware, and it has been
withdrawn. If pressed on what the system *does* separate: 0.9366 against general benign apps,
93.6% of malware flagged, 17.1% of clean apps sent to an analyst.

*(The previously scripted answer — "invert the score and general-benign AUC goes from 0.9366 to
0.0634, and that impossibility is the convergence finding" — is arithmetically true but
rhetorically fatal now: it defends a number whose corpus was wrong. Delivering it invites exactly
the follow-up in question 1.)*

### 4. "Show me the 0.9366."

Blocked until item 5 — `results_716.csv` is gitignored, so a fresh clone cannot reproduce it
today. Committed now: `docs/evidence/2026-08-12_scorer_v2.{md,json}`, the summary with full
provenance — sample set, seed, commit SHAs for both scorers, per-corpus distributions, the
Mann-Whitney method and its cross-check against a brute-force pairwise implementation. The
per-sample table lands after the report, once its corpus labels are corrected.

### 5. "Your matcher compares raw strings — so a URL never matches a hostname?" — **RESOLVED, item 2, 21 August**

Was correct through 20 August: the matcher compared raw `suspicious_strings` values with no
`urlparse` call, so a `kind == "url"` indicator could never equal a bare hostname. Fixed 21
August (Day 4) with a single normalization function applied to both sides of the comparison.
Both join keys fire now, each against one hand-constructed ground-truth entry; the C2-host
indicator itself is real (extracted from an actual malware sample), not fabricated — only the
account association is constructed.

### 6. "The bridge is exact-match on a certificate hash. Isn't that just a join?"

Yes, deliberately. Anything fuzzier on a cryptographic hash is a bug. The engineering is in
extracting a usable indicator at all — 99.4% cert-hash yield and 66.9% network-indicator yield
across 668 real APKs — in guarding both sides against `None` so an unsigned APK and an empty
account never match on shared emptiness, and in abstaining: most pairs produce zero links and the
API returns 200 with an empty list. The claim is that two systems a bank runs in different
departments now produce one case file. What is genuinely weak is that our linkage ground truth
has two entries, one per join key, because no real device↔account join key exists in any public
dataset — and one of the two indicators (the C2 host) is at least real, extracted from an actual
malware sample, even though the account it links to is constructed.

### 7. "TP=10/FP=0/FN=0/TN=90 is suspiciously perfect."

It is perfect and it should be — it is a unit test of a deterministic exact-match function, and
we never call it accuracy. Lead with the accurate framing, not the bare number: **2 distinct
ground-truth linkages (one cert hash, one C2 indicator) tested against 100 hand-built cases,
matcher correct on all** — the 10 "true positives" are 10 correctly-linked accounts powered by
only those 2 values, not 10 independent matches. The value is in the negative set: ten
same-/24-subnet near misses, ten same-issuer-different-hash, an all-`None` account, and an
unsigned APK against an empty account — the last two because `None == None` is `True` in Python.
Zero false positives across those confounders is the finding. It says nothing about how often a
real link would be found.

### 8. "81 fraud rows. Does this hold at real base rates?"

Random AUCPR at our 0.892% prevalence is 0.0089; our 20-seed median is 0.271, about 30× baseline.
AUCPR scales with prevalence so the absolute figure would fall in a sparser population; the lift
is the more stable quantity. We report a median and IQR across 20 stratified holdouts rather than
a point estimate because 16 positives per holdout means one account is 6.25% of recall — our own
seed-42 run scored 0.4114, which sits at the 80th percentile, and we retired it for that reason.
What 81 events cannot support is any per-subtype or per-segment breakdown.

### 9. "In-sample 0.988 versus holdout 0.271 — what is that gap?"

Substantial overfitting on 81 positives with 200 trees, and we quote it ourselves rather than
waiting to be asked. The trainer records it under a key named
`in_sample_train_metrics_DO_NOT_REPORT_AS_HOLDOUT` and the API never surfaces it. The gap is why
only holdout figures appear anywhere, why the headline is a 20-seed distribution rather than one
split, and why the operational numbers we lead with are recall at 1% and 5% review depth — those
are what an analyst experiences and they degrade more gracefully than a threshold-free metric.
Reducing the gap means more positives, not more regularisation; at 81 events we are sampling-
limited, not model-limited.

### 10. "Your CLI and your API disagree on the verdict."

They do. `d1-inversion` made the rule scorer structurally authoritative in the serving path —
`_try_llm_narrative` starts as a copy of the rule report and assigns only `rationale` and
`cited_chunk_ids`, and `verdict_source` is a string literal, so no code path lets a model output
reach the verdict. `run_pipeline.py` is the original Week-1 CLI, predates the inversion, is one
of six frozen files we do not edit without sign-off, and takes both verdict and confidence from
Mistral. Everything demoed and everything measured runs through the API. We label the CLI a
retained pre-inversion reference; it is a documented inconsistency, not a discovery.

### 11. "You said the holdout was never tuned against, and your own log says it was in the ranking pool."

Survivable only because we say it first. `SESSION_LOG.md:219` records the term ranking as
"malicious sample vs fdroid_benign + holdout16"; thirty-nine lines later the same entry claims the
holdout was not used. Line 219 is accurate, and there is a dated correction appended in place
rather than a deletion. Given the corpus finding it is worse than contamination: those sixteen are
malware that sat in the *negative* pool, so the ranking that justified three scorer-v2 deletions
ran with about 5% label noise in its negatives. Both the deletions and the ranking are being
re-run against a clean negative class.

### 12. "You're replaying data you trained on."

For every reported metric, no — `train_test_split` with `stratify=y`, which shuffles by default,
20 independent splits, model retrained from scratch inside each. On the live demo, uploading the
training CSV returns row prevalence as an explicitly descriptive figure with a disposition field
saying it is not a performance metric; the numbers shown alongside are always the offline holdout
distribution. One specific trap we checked: all 81 fraud rows are contiguous at the file tail, so
row order encodes the label and any positional sampling would be leakage. We verified our splits
shuffle by reading sklearn's source, not by trusting the function name.

### 13. "You captured hostnames only — how do you know the app did anything malicious at runtime?"

We do not and we do not claim it. The experiment answers one question: does executing the sample
reveal hosts static analysis cannot see. The metric is `hosts_runtime_only`; attribution stays
with the static evidence and the analyst. Passive capture was chosen over instrumentation because
DNS and SNI are cleartext regardless of pinning, so a proxy or installed CA buys nothing — and
both are things banking trojans check for and go quiet on, which would have inflated our
no-traffic rate. We record DoH-only traffic as distinct from no-traffic, because an app that
resolved over encrypted DNS produced traffic and evaded observation.

### 14. "No dynamic analysis?"

Correct, and our largest scope gap. Everything comes from the DEX string pool, manifest and
certificate. We can quantify it: 33.1% of malicious samples yield zero network indicators
statically, and another ~10% cannot be parsed at all because their bytecode is obfuscated past
Androguard's disassembler — and those 39 are conditioned out of every PS1 number we report, which
makes all of them optimistic.

### 15. "What happens if I hand you a 200 MB APK, or one you can't parse?"

The large one is a real risk today and we know it — no upload cap, and a 172 MB sample in our own
corpus defeated a 300-second timeout with a dedicated memory budget. A 50 MB cap ships 18 August.
The unparseable one returns HTTP 500 with the exception type, so an analyst sees an error rather
than a report. What it is not is fail-closed routing to a review queue — we have no such queue,
and we would rather say that than describe one that does not exist. 40 of our 716 samples take
that path, 39 of them obfuscated malware, which are the ones most worth analysing.
