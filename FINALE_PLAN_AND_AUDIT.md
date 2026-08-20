# SetuGuard — Finale Plan and Criterion Audit

**Written 18 August 2026. Supersedes the 10-day research brief.**
Grand Finale: 27–28 August 2026, IIT Hyderabad. Nine working days, 18–26 August.
Sole contributor: Raghav Pathak.

Source of truth for repo state is `CONTEXT.md` (as of 15 Aug, with 18 Aug additions).
Where this document and the handoff prompt disagree, `CONTEXT.md` wins and the
disagreement is recorded in Section 0.

---

## 0. Corrections to the established-facts section

Five items in the handoff prompt are stale or wrong against `CONTEXT.md`. Two are
stage-breakers. Fix these before building anything on top of them.

### 0.1 — The 0.4113 ranking-gate result is void, not "failed"

`CONTEXT.md` §0, evidence `harness/BANKING_HOLDOUT_16_PROVENANCE.md`:
`banking_holdout_16/` contains **zero banking apps**. All sixteen are a partition of
`Banking.tar.gz`, the CICMalDroid *Banking malware* archive.

```
tar -tzf Banking.tar.gz | grep -c '\.apk$'   ->  2505
ls -1 cicmaldroid_banking/*.apk | wc -l      ->  2489
ls -1 banking_holdout_16/*.apk  | wc -l      ->    16
```

Set-differenced both ways: zero extras, zero omissions, zero overlap. Every
certificate self-signed, subjects including `sdsdfsdf` and the AOSP public test key.

So AUC(malicious vs `banking_holdout_16`) 0.3841 → 0.4113 measured **malware against
malware from one archive**. It is not a failed gate. It is not evidence of anything.

> **Never say 0.4113 or 0.3841 again, in the PDF or on stage.** If a judge finds a
> slide carrying that number and asks what the negative class was, the room is lost.

The negative result survives through a different measurement:

- PRIMARY AUC **0.1444 [0.0905, 0.2081]**
- SECONDARY AUC **0.3190 [0.2202, 0.4290]**

Both against `harness/banking_legit_corpus/` — 95 real AndroZoo APKs, downloaded and
verified 15 Aug, pre-registered at commit `be6a15c` before any scoring ran. Both CIs
lie entirely below 0.5. **That is the finding, and it stands without the holdout
number.**

Second-order consequence: "classes are convergent by construction" was demoted in §0home/raghavp/downloads/setuguard_report(3).pdf
from a measured ceiling to an **untested hypothesis**. It may be stated as the
hypothesis explaining the result. It may not be stated as the result.

### 0.2 — The 98% false-positive rate is two scorer versions old

97.9% is 142/145 from `FIX3_BEFORE_RESULTS.md`, n=150, seed=7, corrected NUL
accounting. It is explicitly a BEFORE number, dominated by D1's always-"suspicious"
LLM verdict. D1 is now inverted; the rule scorer is authoritative in the API.

Current, valid, v2-scorer figure: **general benign flagged 17.1% (50 of 292)**,
producing script `harness/rescore_from_cache.py`, in the `CONTEXT.md` §4 verified
table.

17.1% is a survivable analyst load. 97.9% is not. Arguing the allowlist against a
false-positive number that no longer describes the system weakens the argument and
hands a judge a discrepancy. **Quote 17.1%, with the negative class named as F-Droid
general benign — not banking.**

### 0.3 — `matcher.py` is wired; that task is already done

The 18 Aug migration (`ANALYSIS_ID_MIGRATION.md`) has `/api/bridge` calling
`bridge_matcher.extract_ioc_from_ps1` at `app.py:839` and
`bridge_matcher.match_account_to_apk` at `app.py:843`, nothing reimplemented inline,
plus an `inputs` block naming which two artifacts were joined. Do not spend a day
re-doing this.

The live bridge defect is different and worse. **The C2 path has never fired.**
`matcher.py:31-34` builds `apk_c2_hosts` from raw `suspicious_strings` values and
never calls `urlparse`, so for `kind == "url"` the value is scheme + host + path and a
hostname-valued ground-truth entry can never match. Only a bare dotted quad can join —
and the single `SYNTHETIC_LINKAGE_GROUND_TRUTH` entry has `c2_host: None`
(`matcher.py:68`). **In the shipped configuration only cert-hash matching can fire at
all.**

Compounded by D-10: `MAX_SUSPICIOUS_STRINGS = 25` with fixed url→ip→shell ordering
zeroes IP extraction on 84 of 668 APKs — suppressing the one join key that works.

### 0.4 — `run_pipeline.py` is not inverted

`CONTEXT.md` §7 C1: the d1-inversion is scoped to `app.py`. `run_pipeline.py:76` does
`report = generate_report(features)` and lines 30–31, 95–96 print and write Mistral's
verdict and confidence. `batch_baseline.py:261,286` likewise.

Demoing the CLI on stage and then claiming "the LLM never touches the verdict" is a
live self-contradiction. **Demo through the API only.** Either guard the CLI on Day 2
or add a one-line banner to its output stating the verdict is LLM-sourced and not the
product path.

### 0.5 — The 68/47 vs 51/32 conflict is probably not a conflict

`CONTEXT.md` §2 records 68 distinct packages / 47 issuer clusters for the corpus;
current arm 68 files / 68 packages; era-matched arm 27 files that are older builds of
packages already in the current arm; **Tier A 73 files / 53 packages / 33 issuers**.

53/33 sitting one or two off 51/32 reads like the scored set after extraction
failures, not a contradiction. Corpus n and scored n are different numbers and both
are legitimately in written artifacts.

Resolve by opening `harness/BANKING_AUC_RESULTS.json` and reading the n the AUC was
actually computed over. That is the only figure allowed to appear next to 0.1444.
One hour, Day 1. Not blocking — a labelling error, not a contradiction.

### 0.6 — Issuer-cluster integrity: checked 19 Aug, a design that anticipated the
attack, not a near-miss

**Hostile question:** *"Google Play App Signing re-signs every app it distributes with
its own key. Doesn't that collapse independent banks into one issuer cluster and
understate your bootstrap CI's uncertainty?"*

**Answer:** "That risk is real, and I checked it directly rather than assuming it away.
27 of the roughly 73 Tier A files do carry Google Inc. as their raw certificate issuer —
Play App Signing re-signing is real in this corpus. But the bootstrap in
`score_banking_corpus.py` never reads that field. It clusters on a manually-researched
bank-identity label from `harness/banking_packages.csv`, built specifically to guard
against exactly this — `BANKING_PACKAGE_TIERING_DECISIONS.md` names 'same-issuer
clustering' as a risk to effective n on 13-14 August, before any scoring ran, which is
the reason issuer-cluster resampling exists in the pre-registration at all. I
reconstructed the actual clustering used: largest cluster is 3 packages, zero clusters
are labelled Google, in both the PRIMARY and SECONDARY populations. That's a design
that anticipated this exact attack on the interval, not a near-miss that happened to
land safely — the decision rule was fixed before I looked, and the finding came in well
inside the no-action threshold."

---

## 1. Nine-day plan, 18–26 August

Assumption: ~6 productive hours/day, 54 hours total. 44 budgeted, 10 left for the
things that always happen. Existing `PLAN.md` items 1–9 are absorbed here rather than
run in parallel.

Each task is marked **SHIP** (goes in the PDF), **DEMO** (runs live on stage), or
**CLAIM** (something said out loud).

### Day 1 — Tue 18 Aug (partial) · 5h · Truth reconciliation · SHIP · **DONE, ran 19 Aug**

Scheduled for 18 Aug; actually ran 19 Aug — the 18 Aug session went to the `CONTEXT.md`
resync and the analysis-ID migration instead (logged at the time as a one-day slip,
absorbed by compressing Day 1 and starting Day 2 the same day rather than the next).
Precise actual-vs-budgeted hours were not tracked minute-by-minute across the two
19 Aug sessions; both ran to task completion, not to a clock. Every task below shipped:
n corrected to 51 packages/32 issuer clusters (sourced from `BANKING_AUC_RESULTS.json`),
void-number purge clean, D-1/D-2 (README + frontend honesty pass) resolved. See
`SESSION_LOG.md`'s 19 Aug entries for the full record.

| Task | h | Criterion | Artifact | Falsification |
|---|---|---|---|---|
| Read `BANKING_AUC_RESULTS.json`, fix the n on every 0.1444 mention | 1 | Feasibility | corrected `REPORT_FACTS.md` | — |
| Void-number purge: grep for `0.4113`, `0.3841`, `97.9`, `banking_holdout`, `independently confirmed`, `graph_betweenness`, `rule_validated`, `v2.0.0-xgb-platt-graph` | 2 | Feasibility | clean grep output, committed | If >40 hits, cut to the four files a judge opens: README, frontend, `SESSION_LOG.md:430-434`, `bridge/test_fixtures_ps2_sample.json` |
| PLAN 1 = D-1 + D-2: `setuguard_app/README.md` inverted architecture description; frontend copy claiming "real XGBoost + SHAP trained on your data", "Run Data Audit + Train", "CV AUCPR (0-fold)", bias-checking, KS-drift, greedy counterfactual | 2 | Feasibility, UX | corrected README + `index.html` | — |

D-7 and C10 are the specific killers. `bridge/test_fixtures_ps2_sample.json` is loaded
at runtime by `confusion_matrix_validation.py:240` and carries a `graph_betweenness`
SHAP driver — a feature publicly withdrawn as leaked. `SESSION_LOG.md:430-434` still
reads "independently confirmed real fraud (F3924=1)… not a coincidence." Both are
greppable and both contradict published retractions. A judge who finds a live artifact
contradicting a retraction concludes the retraction was cosmetic.

### Day 2 — Wed 19 Aug · 6h · Demo survivability, round one · DEMO · NEVER CUT · **DONE, ran 19 Aug (same day as Day 1)**

| Task | h | Criterion | Artifact | Falsification |
|---|---|---|---|---|
| D-4 fail-closed: `app.py:450-452` returns HTTP 500 with the raw exception string rendered in the UI; 40 of 716 APKs hit this. Replace with a structured refusal — `{"status":"unparseable","reason":"...","action":"escalate to manual review"}` | 3 | Feasibility, UX | error envelope + screenshot | If the refusal path itself can throw, it isn't fail-closed — test with a deliberately corrupt zip before shipping |
| D-5 upload cap: no `MAX_CONTENT_LENGTH`, no client check. 26 sample APKs exceed 50 MB; one 172 MB file defeated a 300 s timeout; two live memory incidents recorded | 1.5 | Feasibility | cap + client-side message | — |
| D-8 NUL guard: `static_analysis.py:82` / `yara_gen.py:35-39`, 22.1% prevalence in benign samples, API scope unconfirmed | 1.5 | Feasibility | guard + confirmation the API path is or isn't affected | Confirm scope first. If the API path is clean, this is a 20-minute CLI guard, not 90 minutes |

D-8 alone is roughly one demo run in five throwing during YARA generation. You cannot
rehearse past a one-in-five crash.

**Shipped, with one correction to this table's own premise.** D-4: done as `status:
requires_manual_review` (spec used `"unparseable"`; `PLAN.md` item 3's exact field value,
`requires_manual_review`, is what shipped — the two docs disagreed on the literal string
and the more specific one won). D-5: done, 50MB scoped to the APK endpoint only — a
Flask-wide cap would have broken `/api/analyze_dataset`'s own ~111MB upload, caught before
shipping. **D-8's confirm-scope-first falsification condition fired, and the premise in
this table's own description was wrong**: the API path was never affected —
`app.py:368-377`'s existing try/except already caught the NUL-byte `ValueError` in 8/8
tested cases, both by direct simulation and a real live HTTP call. "One demo run in five"
came from an offline harness (`fix3_fp_harness.py`) that caught a narrower exception class
than `app.py` does; a harness-observed defect was attributed to the product without
checking the live code path first. The actual bug found instead, a UX/traceability defect:
the alert log claimed "New YARA rule generated" even when compilation failed or no rule was
attempted — fixed. Three consecutive `browser_smoke.js` runs, all 5 steps, zero errors.

### Day 3 — Thu 20 Aug · 6h · The allowlist · SHIP + DEMO · NEVER CUT · **DONE, ran on schedule 20 Aug**

**Argued for, and the highest-value build in the nine days.** The reasoning in the
handoff was right; the justification was wrong. It is not there to fix a 98%
false-positive rate. It is there because the pre-registration names it as the
precondition scoping PS1 to untrusted and sideloaded APKs, and an unenforced
precondition is a rationalisation. Enforced, it is a control, and the same sentence
becomes a design decision.

Architectural bonus worth using on stage: the allowlist keys on publisher certificate
SHA-256, **the same key the bridge joins on**. One cert-hash index serves both the
exclusion path and the linkage path.

| Task | h | Criterion | Artifact | Falsification |
|---|---|---|---|---|
| Extract publisher cert SHA-256 from the 95-APK corpus (certs already in `harness/feature_cache/`), collapse to issuer clusters, write `allowlist_publisher_certs.csv` with per-row provenance. Normalise to UPPERCASE via `norm_sha()` — the boundary that has already bitten four scripts | 3 | Innovation, Feasibility | the CSV, committed | **If the 95 APKs do not collapse to a small stable issuer set, or if any CICMalDroid cert hash appears in it, abandon the allowlist entirely and say so.** A collision means the key doesn't separate the populations and the control is fictional |
| Serving path: allowlisted cert → skip scoring, return `{"status":"publisher_verified","scored":false}` plus an audit-trail line naming which allowlist row matched | 2 | UX, Feasibility | working endpoint + screenshot | If a repackaged APK can inherit an allowlisted cert hash the control is defeated — know the answer (it can't; cert hash covers the signature, repackaging breaks it) |
| Re-run PRIMARY AUC scoring with the allowlist active; record what fraction of the 95 is excluded | 1 | Feasibility | one number with production note | If exclusion is below ~90% of the corpus, the allowlist is not doing the job the pre-registration claims — report the actual fraction, don't round up |

Honest framing, to be said plainly: **the allowlist does not improve the AUC. It
removes the population where the ranking is wrong from the scored path.**

**Superseded at build time, not deleted — the plan above describes exclusion (a scorer
input); what shipped is display-layer, a different design chosen deliberately.** The
20 Aug session opened with exactly the question this plan skipped — scorer input or
display-layer suppression — and chose display-layer against this table's own "skip
scoring" / "Re-run PRIMARY AUC scoring" spec, on cost/risk grounds: re-opening the
pre-registered 0.1444/0.3190 interval eight days out for a triage convenience was judged
not worth it while the errata is still open. What shipped: certificate-issuer detection
(`Organization: Google Inc.`, the Play App Signing template — not a cert-hash allowlist
CSV; checked directly that 29 distinct cert SHA-256 values share the identical issuer
string across the corpus, so the string, not a fixed hash list, is the correct signal),
attached to the API response as `play_signing: {detected, note}` computed strictly after
and independently of `_rule_based_verdict()` — structurally cannot reach score, verdict,
confidence, or risk_score. No AUC re-run performed; none was needed, since nothing scored
changed. Population, of the 51 PRIMARY packages: 23 (45%) would be flagged, 28 (55%) fall
outside coverage — self-signed/self-distributed banks are the majority of the corpus, not
the minority, which is a materially different headline than "removes the population
where the ranking is wrong" implied. Verified: two live samples (Play-signed and not),
verdict/confidence/risk_score identical with and without the field present by
construction; rendered in a real browser, zero console/page errors. Full reasoning and
the two honest gaps (self-signed banks outside; Play-distributed malware inside) recorded
in `CONTEXT.md` §8 and `REPORT_FACTS.md`'s new Play-signed allowlist section.

### Day 4 — Fri 21 Aug · 6h · The bridge · DEMO

| Task | h | Criterion | Artifact | Falsification |
|---|---|---|---|---|
| D-3: `urlparse` host normalisation on both sides of `matcher.py:31-34` and `:94-98`; populate a hostname-valued ground-truth entry | 3 | Innovation | matcher with a firing C2 path + unit test | **If after the fix nothing joins on any key other than the one synthetic cert hash, stop.** The bridge is then a mechanism demo, not a result, and the remaining hours roll into Day 5 |
| D-10: `MAX_SUSPICIOUS_STRINGS = 25` with fixed url→ip→shell order zeroes IP extraction on 84/668. Raise the cap or round-robin by kind. **Frozen file** — log in `FROZEN_FILE_FINDINGS.md` with reason. Invalidates the feature cache | 3 | Innovation | edit + re-extraction of the demo set only | If re-extracting the demo set alone takes >2h at parallelism=1, do not re-extract 716. The claim becomes "measured on the demo set, full re-extraction pending" |

Do not re-extract all 716 files. At parallelism=1 with ~12 GB peak that is most of a
day for a number nobody will ask for.

### Day 5 — Sat 22 Aug · 6h · The analyst artifact · SHIP + DEMO

No analyst-facing output currently exists. Weakest criterion, cheapest to move.

| Task | h | Criterion | Artifact | Falsification |
|---|---|---|---|---|
| One-page alert card per APK: verdict → **recommended action** (block / escalate / monitor / no action) → evidence with traceable chunk and rule ids → "what would change this verdict" | 4 | UX, Business | rendered card, 3 screenshots for the PDF | Hand it to someone who is not you and ask what they would do next. If they can't answer in 30 seconds, it's a report, not an alert |
| Same for a bridge link: which account, which key matched, what the analyst does about it | 2 | UX, Innovation | screenshot | — |

The action verb is the whole point. "Suspicious, confidence 0.78" is not an analyst
artifact. "Escalate — publisher cert not in allowlist, 3 accessibility indicators,
cert hash matches account 9072" is.

### Day 6 — Sun 23 Aug · 5h · Scalability evidence · SHIP

| Task | h | Criterion | Artifact | Falsification |
|---|---|---|---|---|
| D-9 / U1: endpoint timings ~9.86 s / ~0.66 s / ~0.0025 s exist only as a hand-written n=3 table at `SESSION_LOG.md:445-450`. Build the harness. n≥30, report median and IQR | 3 | Scalability | timing JSON + script | **Never write "p50."** If n<20 after failures, report the raw distribution and state n |
| Write the honest scaling paragraph: what breaks at 10M accounts and 100k APKs/day | 2 | Scalability | PDF section | — |

The honest paragraph: PS2 is inference-only over 18 features and scales trivially —
a batch scoring job; 10M rows is minutes, not an architecture problem. PS1 does not:
peak memory runs around 12 GB on large files, so throughput is workers times cores,
and the RAG stage detaches behind a queue because Mistral-7B is the bottleneck and is
not the verdict source anyway. **The narrative generator can be dropped or batched
without changing a single verdict, because the verdict is rule-based.** That property
falls straight out of the d1-inversion and most teams will not have an equivalent.

**Void as of 19 Aug, not deferred to Day 6:** this paragraph no longer quotes a
per-APK figure. It previously said "~10s/APK single-threaded" — that number matches
neither real extraction-timing artifact found this session:
`harness/extract_tier_a_run.log` averages 39.6s/APK single-threaded on the real
banking corpus (large production files, two 600s timeouts), and
`SESSION_LOG.md:353`'s 668-file general corpus run reports "1.20s/APK effective"
under 4-worker parallelism, a different measurement entirely under different
conditions. A 33x spread across the three numbers that have existed for this figure
(9.86s, already voided; 1.20s; 39.6s) is not noise to average over — it's an unmeasured
quantity. Build the Day 6 harness before quoting a per-APK number anywhere.

### Day 7 — Mon 24 Aug · 5h · Business Potential + evidence chain · SHIP + CLAIM

| Task | h | Criterion | Artifact | Falsification |
|---|---|---|---|---|
| Cost and buyer model: who signs, what line item it replaces, per-alert triage cost, run cost on the stated hardware | 3 | Business | PDF section | Every figure needs a source or it is marked *estimate* in the text. An unsourced rupee figure is worse than no figure |
| D-6: `results_716.csv` is gitignored (`.gitignore:77`); "show me the 0.9366" has no answer from a fresh clone. Ship a relabelled summary CSV — the `banking_holdout` rows carry the false corpus label and must be renamed before anything is committed | 2 | Feasibility | committed evidence file | — |

Run costs statable honestly today: one machine, no per-call API cost, fully offline
except local Ollama. That is a real procurement argument for a bank and it costs
nothing to make.

### Day 8 — Tue 25 Aug · 6h · Rehearsal + recorded fallback · DEMO · NEVER CUT

Full run-through three times, timed. **Record the fallback video today, not tomorrow**
— recording on the last day means shipping the first take. Record on the exact machine
with the exact files, unedited, one continuous run including the Ollama-down
degradation path.

### Day 9 — Wed 26 Aug · 5h · Q&A drill + freeze

Hostile Q&A against the questions in Section 2, out loud, timed to under 40 seconds
each. **Code freeze at 18:00** — nothing merges after that, no exceptions, including
things that look like one-liners. Pack; verify the video plays off the laptop with no
network; verify the venue cannot break the demo (no CDN, no external model pull, no
live download).

### Demo survivability allocation

Days 8 and 9 entirely, plus Day 2 — **17 of 44 hours, 39%.** That is the right number
for a project whose Technical Feasibility criterion is scored by watching it run. The
brief's single line for rehearsal was badly wrong. A live crash costs more than every
metric in the PDF is worth, and there were three known crash paths (**all three closed
19 Aug, Day 2** — kept here as the reasoning for the allocation, not as a current risk
list): D-4 at 40/716, D-5
with two recorded memory incidents, D-8 at 22.1% prevalence.

### Cut order, first to go

1. Day 7 business model depth — keep run cost and buyer, cut market sizing
2. Day 4 D-10 re-extraction — keep the matcher fix, cut the cap change
3. Day 7 evidence chain (D-6)
4. Day 6 timing harness beyond n=30
5. Day 5 bridge card — keep the APK card

### Never cut

Day 1 void-number purge · Day 2 all three defects · Day 3 allowlist · Day 5 APK alert
card · Day 8 rehearsal and recorded video · Day 9 freeze.

---

## 2. Criterion audit

### Innovation

**Today: thin.** The bridge is one synthetic linkage. Account 9072 is the only key in
`SYNTHETIC_LINKAGE_GROUND_TRUTH` and has no documented selection rationale; the
"independently confirmed fraud" framing is retracted but still live at
`SESSION_LOG.md:430-434`. The unit test TP=10/FP=0/FN=0/TN=90 is over synthetic ground
truth and is not evidence about the world. In the shipped configuration only cert-hash
matching can fire, so the "certificate-hash *and* C2-host" description overstates what
runs by exactly half. The matcher **is** correctly wired into `/api/bridge` (18 Aug
migration) with an `inputs` block — that part is real and worth showing.

**Best case by 26 Aug:** two working join keys, a firing C2 path, an analyst-facing
link card, and an honest statement that the linkage is demonstrated on constructed
data. Not: a bridge validated on real linked fraud. No dataset exists where an APK
cert hash and a mule account are known to be connected, and none can be obtained in
nine days.

**Closes the gap:** Day 4 (D-3, D-10), Day 5 second card.

**Hostile question:** *"Show me a bridge link you didn't construct yourself."*

**Answer:** "I can't. There is no public dataset that links Android malware
certificates to Indian bank account records — that data exists inside banks and
nowhere else. What I've built is the join mechanism and the key space: certificate
SHA-256 and normalised C2 host, both extracted by the static analyser, both matchable
against account-linked indicators. The linkage in the demo is constructed and labelled
as constructed. What a bank supplies is the other side of the join, which they already
have."

### Technical Feasibility

**Today: mixed, and stronger than the handoff assumes.** The d1-inversion is
structurally verified, not conventionally — `_try_llm_narrative()` opens
`report = dict(rule_report)` at `app.py:274`, assigns only `rationale` and
`cited_chunk_ids`, and `verdict_source` is a string literal at `app.py:426`. Verdict
and confidence are identical with Ollama up or down, and the down path is captured in
`harness/browser_evidence/ollama_down/`. Chart.js is vendored. Dashboard shows zero
console errors under Playwright smoke.

**As of 19 Aug, D-4/D-5/D-8 are closed** — a corrupt-zip parse failure now returns a
structured `requires_manual_review` refusal instead of HTTP 500 with a raw exception
string; a 50MB upload cap (scoped to the APK endpoint, not Flask-wide) rejects an
oversized file in 0.16s instead of a 300s timeout; D-8's premise was wrong and the
existing try/except already caught the NUL-byte crash, with the real bug (a misleading
alert-log line) fixed instead. Three consecutive `browser_smoke.js` runs, zero errors.
Still against it: the CLI/API verdict-source contradiction (C1), and the evidence chain
not surviving a clone (D-6).

**Best case:** an error envelope a bank console could show a user (done) plus a fully
offline run demonstrated live including the model-down path (already captured,
`harness/browser_evidence/ollama_down/`).

**Closes the gap:** Day 8 (Day 2 done).

**Hostile question:** *"What happens when your model server is down at 2 a.m.?"*

**Answer:** "Nothing changes. The verdict, the confidence and the risk score come from
a rule scorer that runs on extracted static features. The language model writes the
narrative and the MITRE mapping only — there is no code path where it reaches a
verdict field. With Ollama stopped, the same APK returns the same verdict with the
rationale field marked unavailable. That's captured in the evidence directory and I
can show it live."

**Hostile question:** *"You planned for a one-in-five demo crash from YARA generation.
What happened to that?"*

**Answer:** "I was wrong about where the bug lived, and I want to say that plainly
rather than let the fixed version stand in for it. The underlying defect was real — a
NUL byte from Adobe XMP metadata reaches YARA's compiler and raises a `ValueError`,
reproducible on 8 of 8 known-affected samples. The 'one in five' estimate came from an
offline test harness that only caught a narrower exception class and crashed on this
one. The live API's own error handling already caught it — I checked before building
anything, and confirmed it live over HTTP, not just by reading the code. So the crash
risk I'd budgeted real time against didn't exist on the path judges would actually see.
What I did find instead was smaller: an alert log that claimed a YARA rule was
generated even when it wasn't, which I fixed. The lesson I'm keeping: a defect observed
in a harness is a claim about that harness until the live code path is checked, not a
claim about the product."

### Business Potential

**Today: absent.** No cost figure, no buyer, no replaced line item appears in the
Progress Report. Weakest criterion on documented evidence, and the cheapest to move,
because the answer is mostly writing.

**Best case:** a named buyer, a named replaced cost, honest run economics, one sourced
market figure. Not: a validated pricing model.

**Closes the gap:** Day 7.

**Hostile question:** *"What does this cost a bank to run, and what does it replace?"*

**Answer:** "It runs on one machine with a GPU, fully offline. No per-call API cost, no
data leaving the bank. What it replaces is the analyst minutes spent assembling
context for an alert — pulling the APK indicators, mapping them to techniques,
checking whether the account has a device-side link. That assembly is the cost, not
the detection. The system does the assembly and hands the analyst a decision."

Get one RBI-sourced fraud figure into the PDF on Day 7 and cite it. One sourced number
beats three estimated ones.

### Scalability

**Today: unsupported.** `CONTEXT.md` §7 U1 is explicit — the endpoint timings exist
only as a hand-written n=3 table at `SESSION_LOG.md:445-450`. No script POSTs all
three endpoints, no percentile is computed anywhere, `measure_app_verdicts.py` times
only `/api/analyze_apk`. There is currently no measured basis for any throughput
claim.

**Best case:** a real distribution at n≥30, plus a specific honest account of what
breaks where.

**Closes the gap:** Day 6.

**Hostile question:** *"9,082 accounts and a handful of APKs. What happens at 10
million accounts?"*

**Answer:** "PS2 is the easy half — inference-only against a committed model artifact
over 18 features, so 10 million accounts is a batch job, not an architecture change.
PS1 is the constraint: peak memory around 12 GB on large files, so throughput is
workers times cores — the exact per-APK figure is pending Day 6's real timing
harness, and I won't quote a spot number here. The useful property is the language
model's role, and I want to be precise about two different things it means: it is
not on the **correctness** path — verdict, confidence and risk score never depend on
it, evidenced with Ollama stopped entirely — but it is currently on the **latency**
path, since the endpoint waits for the narrative before returning. Detaching that
behind a queue is the scaling change, not something already shipped. At volume you
queue it or drop it and every verdict stays unchanged; today, every request pays its
cost."

### User Experience

**As of 20 Aug: stronger than the handoff assumed, one gap open.** D-2's four false
frontend claims are resolved. D-4's raw-exception-string parse failure is resolved —
`requires_manual_review`, structured, HTTP 200, a dedicated card. D-8's alert-log
UX/traceability bug (claiming a YARA rule was generated when it wasn't) is resolved.
The Play-signed allowlist ships as a clearly-separated triage-prior badge, not as queue
exclusion — no analyst-facing artifact exists in the *report* yet, but the live app now
has more honest UX than this section originally credited it for. False-positive load is
17.1% on general benign under the v2 scorer — survivable — but on the legitimate
banking population the ranking is inverted, and the allowlist demotes analyst priority
for the Play-signed 45% of that population without hiding or changing the verdict.

**Best case:** an alert card with an action verb and traceable evidence ids — Day 5's
remaining scope.

**Closes the gap:** Day 5 (Days 2 and 3 done).

**Hostile question:** *"An analyst gets your verdict. What do they do next?"*

**Answer:** "The card names the action: block, escalate, monitor, or no action. Under
it is the evidence that drove it — specific permissions, specific API categories, the
technique ids they map to, each traceable to the knowledge-base chunk it came from.
And a line saying what would change the verdict, so the analyst can disagree with it
on specific grounds rather than just distrusting it."

### Additional prepared answers — added 19 Aug, pre-commit session

**Hostile question:** *"Two of your banking apps failed to extract. Doesn't that just
mean your 0.1444 is missing data, not that it's biased?"*

**Answer:** "Both are 600-second timeouts, confirmed in the extraction log, not crashes
or parse failures. The direction matters: the 51 apps that did score already sit mostly
at or near the maximum score — the median is 1.0, the 25th percentile is 0.94. Any
excluded app is more likely than not to land in that same saturated band. Removing
high-scoring apps from the legitimate side of the comparison makes the two classes look
more similar than they'd otherwise look, which pushes AUC toward 0.5 — the harmless
direction, not the alarming one. So 0.1444 is an upper bound on how bad the ranking is,
not a number inflated by missing data. What I can't yet claim is *why* these two timed
out — it isn't file size, checked directly against same-sized neighbours that extracted
in seconds — so I call it unexplained, not size-driven."

**Hostile question:** *"How long does analysis actually take, and why did it vary so
much when you measured it?"*

**Answer:** "I don't have a defensible per-APK figure yet, and I'd rather say that than
quote one — three different numbers have existed for this at different points (9.86
seconds, 1.20 seconds, 39.6 seconds) and they don't agree closely enough to average.
What I do know precisely: most of that variance was the local language model's
narrative stage reloading into memory after being idle, not the static analysis itself
or genuine unpredictability. Pinning the model to stay resident fixed that — a same-APK
test that previously ranged 71 to 193 seconds now holds at roughly a minute after one
warm-up call at the start of the session. That's why the demo runs the analysis live,
not pre-run — the fix made it fast enough to. The remaining minute is real embedding
and generation compute, not model loading, and it never touches the verdict — that
comes from a deterministic rule scorer, evidenced with the model stopped entirely. A
real per-APK throughput number is Day 6's job, measured properly, not asserted here."

**Report-n discrepancy (T1):** pending. `T1` of this session was blocked — no LaTeX/PDF/
docx source for the submitted 17 Aug Progress Report could be found in this repo or the
home directory tree it was searched against. Cannot state whether the submitted document
pairs 0.1444 with a wrong n until that source is located. Add the prepared answer here
once T1 completes.

---

## 3. The single question most likely to break the presentation

> **"Your own pre-registered measurement says legitimate banking apps rank *above*
> confirmed malware. Why would a bank put this in a pipeline?"**

Most dangerous because it is sourced from your own document, the confidence intervals
lie entirely below 0.5 so there is no measurement-noise escape, and it attacks whether
PS1 works at all rather than whether some claim is overstated. A judge who reads
`PREREGISTERED_BANKING_AUC_CLAIMS.md` will ask it.

**Both halves now exist as of 20 Aug — updated from this section's original framing,
which described a design (enforced exclusion) that was not what shipped.**

Exists: AUC **0.9366** against F-Droid general benign
(`harness/rescore_from_cache.py`), the one genuine PS1 separation figure — the scorer
discriminates strongly against non-banking benign apps. Also exists: the
pre-registration itself, committed at `be6a15c` before any scoring, a stronger
evidence-integrity position than almost anything else in the room.

Built on Day 3, deliberately narrower than this section's original plan: a
**display-layer** Play-signed allowlist, not an enforced exclusion. The original framing
here ("known publishers are excluded upstream by certificate hash before scoring") was
the scorer-input design considered and rejected at Day 3's start — re-opening the
pre-registered 0.1444/0.3190 interval eight days out for a triage convenience was judged
not worth it. What shipped: every APK is still fully scored; a Play-signed one
additionally carries an honest triage tag the analyst sees alongside the verdict, never
in place of it. Population: 23 of 51 PRIMARY packages (45%) would be tagged; 28 (55%)
fall outside its coverage — self-signed and self-distributed banks are the majority of
the corpus, not a residual case.

What to say:

> "That measurement is mine, it was pre-registered before I ran it, and I published it
> because it's the result. It says the scorer's permission and API signals don't
> separate legitimate banking apps from banking trojans — which is what you'd expect,
> since a banking app and a banking trojan are built to do the same things. Against
> general benign apps the same scorer gets 0.9366. So here's the control I built on top
> of that finding: every upload is still fully scored, no exceptions — but if its
> certificate shows Google Play App Signing, the analyst sees that as a triage prior
> alongside the verdict, not instead of it. It doesn't touch the score, and I can show
> you the code path that makes that structurally true. It also doesn't cover
> everything — a self-signed or self-distributed bank isn't flagged by it, and that's
> most of my own corpus, not a small slice. And a malicious app that shipped through
> Play would get the identical tag. It's a triage prior, not a verdict, and it sits
> next to Play Protect, not instead of it. What PS1 ships as is evidence extraction,
> technique-mapped indicators, and rule generation, with a measured statement about
> where its ranking does and doesn't hold, plus one honest control on top of the part
> that doesn't."

**Runner-up, rehearse second:** *"Show me a bridge link you didn't construct."* That
answer cannot be built this week. It can only be given straight — see Innovation
above.
