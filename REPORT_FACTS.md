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
> its own date.

# REPORT_FACTS.md — the only source of quotable numbers

**Authoritative as of 19 August 2026.** For the 27 August Grand Finale. Write from this file
only. If a number is not here, it does not go in.

> **19 Aug update:** the legitimate-banking-app corpus (95 AndroZoo APKs, verified 15 Aug) has
> now been scored. The gap this file described below as "cannot currently be shown" is closed —
> see the new QUOTABLE section immediately below. It is a negative result: both CIs lie entirely
> below 0.5.

Every entry carries: the number, the producing artifact, the corpus, and the caveat it must
always be quoted with.

> ### Read this before anything else
>
> On 12 August, `harness/identify_holdout_16.py` established that **`banking_holdout_16/`
> contains no banking apps.** All sixteen are malware, drawn from the same
> `Banking.tar.gz` (CICMalDroid Banking malware) archive as `cicmaldroid_banking/`. Full
> evidence: `harness/BANKING_HOLDOUT_16_PROVENANCE.md`.
>
> **AUC 0.4113 and the 15/16 false-positive figure are therefore void** and have moved out of
> QUOTABLE. They measured malware against malware. This overrides the plan that produced this
> file, which listed both as quotable-with-caveats. The caveat cannot rescue them; the negative
> class was wrong.
>
> **The report is still strong.** AUC 0.9366 against real F-Droid benign apps is untouched, the
> whole PS2 section is untouched, the IOC yield audit is untouched, and the project now leads
> with a corpus-integrity finding it caught itself, four days before submission, in its own
> headline result. That is a better story than the one it replaces.

---

## QUOTABLE — PS1

### Separation

| Number | Value | Producing artifact | Corpus | Mandatory caveat |
|---|---|---|---|---|
| **AUC(malicious vs general F-Droid benign)** | **0.9366** | `harness/rescore_from_cache.py`, `_score_new` + Mann-Whitney `auc()` | 360 CICMalDroid Banking malware vs 292 F-Droid benign | The negative class is **general-purpose** apps, not banking apps. This does not establish behaviour on the banking vertical — that has never been measured. Re-run reproduces it exactly. |

This is the project's one genuine PS1 separation number. Lead with it.

### Legitimate-banking-app measurement — the surviving negative result

| Number | Value | n | Producing artifact | Caveat |
|---|---|---|---|---|
| **PRIMARY AUC** (malicious vs current-arm legitimate banking apps) | **0.1444** [0.0905, 0.2081] | **51 packages, 32 issuer clusters** | `harness/BANKING_AUC_RESULTS.json` | CI entirely below 0.5. **The only n allowed next to 0.1444.** |
| **SECONDARY AUC** (malicious vs era-matched legitimate banking apps) | **0.3190** [0.2202, 0.4290] | **20 packages, 16 issuer clusters** | same | CI entirely below 0.5. Era-matched arm, all 20 attempted successfully extracted. |

**n, resolved once, from `harness/BANKING_AUC_RESULTS.json` — the sole authority:**
`primary.n_packages = 51`, `primary.n_files = 51`, `primary.n_issuer_clusters = 32`. 53 current-arm
packages / 33 issuer clusters were attempted; 2 timed out during extraction
(`com.Version1`, Punjab National Bank; `com.janabank.mtc`, Jana Small Finance Bank),
dropping PNB's issuer cluster entirely (33 → 32). **51/32 is the scored n and the only figure
that may sit next to 0.1444.**

Two other numbers exist in the repo and describe different populations — never pair either with
0.1444:
- **68 packages / 47 issuer clusters** (`CONTEXT.md` §2) — the full 95-APK downloaded corpus,
  before Tier A subsetting. Not scored.
- **73 files / 53 packages / 33 issuers** (`CONTEXT.md` §2, "Tier A") — the current-arm (53) plus
  era-matched-arm (20) *attempted* sets combined, before the 2 extraction timeouts. This is the
  pre-failure attempt count, not the scored count.

Both CIs computed by 10,000-resample bootstrap, seed 42, resampling by issuer cluster (never by
file) for the negative class, by individual sample for the 360 malicious. Both arms scored by the
same pinned function as the 0.9366 F-Droid figure above — `rescore_from_cache._score_new`,
imported not reimplemented, pinned at commit `89077ef`.

**The 2 extraction-timeout exclusions bias PRIMARY AUC upward (toward 0.5), not
downward — the true value is at or below 0.1444.** Confirmed from
`harness/extract_tier_a_run.log` and `harness/banking_extract_skips.csv`: both current-arm
packages that failed to extract — `com.Version1` (Punjab National Bank, "PNB ONE",
138.7MB) and `com.janabank.mtc` (Jana Small Finance Bank, 37.3MB) — hit the extractor's
600-second wall-clock timeout exactly (600.2s and 600.0s respectively), not a crash or a
parse failure. `com.Version1`'s **era-matched** build (37.7MB, a similar-vintage APK for
the same package) extracted successfully in 5.9s and is scored in SECONDARY, so PNB's
issuer cluster survives in SECONDARY but is absent from PRIMARY (33 → 32 issuer clusters).
Jana SFB has no era-matched counterpart in the corpus, so it is absent from both arms.

The bias-direction argument: `harness/BANKING_AUC_RESULTS.json`'s own quartiles for the 51
already-scored PRIMARY-arm legitimate apps show `q1=0.94, median=1.0, q3=1.0` — the
majority of the *scored* population already sits at or saturates the 1.0 cap. Any excluded
app is a priori more likely to also land in that near-saturated band than not, on the
scored population's own distribution alone. Removing high-scoring members from the
legitimate (negative) class reduces how far the legitimate class's scores sit above the
malicious class's, which mechanically moves AUC toward 0.5 — i.e. **exclusion inflates
AUC away from the true separation**, so 0.1444 is an upper bound, not a point estimate.

**Two things this argument does *not* rest on, and must not be stated as if it did:**
extraction timeout does not track APK size — checked directly against
`extract_tier_a_run.log`'s full 60-file run: `com.janabank.mtc` (37.3MB) timed out while
same-size neighbours (`com.Version1` era-matched 37.7MB: 5.9s; other 35–40MB files: 8–24s)
extracted fine, and `com.Version1`'s 138.7MB current build timed out while 132MB and 142MB
neighbours extracted in 13–22s — both timeouts are outliers against same-sized peers, not
part of a size trend, most likely obfuscation or a pathological control-flow blow-up in
Androguard's DEX analysis rather than raw file size. And no per-app results file exists to
name a specific count of apps "at the cap" (`harness/results_banking_legit.csv` was never
produced, the same evidence-chain gap already documented for the 716-file corpus) — the
argument above uses only the committed quartile summary, not an unverifiable per-app count.

**Say this plainly:** legitimate banking apps rank *above* confirmed malware under this scorer.
The scorer's permission/API-surface signals do not separate a banking app from a banking trojan —
expected, since both are built to request similar capabilities. Class convergence is the
motivating **hypothesis**, not a measured finding — do not state it as the latter. This is why
the Play-signed allowlist (built 19 Aug, Day 3) is the control that makes the PS1 deployment
story coherent, not an optional add-on.

**Correction, 19 Aug: what shipped is narrower than what the submitted report's prose
describes, deliberately.** The report (and the original pre-registration's "Operational
recommendation" section) describes the allowlist as scoped "upstream" — i.e. excluding
Play-signed uploads from scoring entirely, an intake filter. What was actually built is
**display-layer tagging, not exclusion**: every uploaded APK is still fully scored exactly as
before; a Play-signed one additionally carries a `play_signing: {detected, note}` field and a
clearly-separated "Triage Prior — Not Part Of The Verdict Above" UI section, computed strictly
after and independently of the scorer. Chosen deliberately over the intake-filter design
because that design is closer to a scorer input (it changes which APKs a bank's console ever
returns a verdict for, which changes what the pre-registered AUC corpus would represent if
applied there) — re-opening the pre-registered interval eight days from the finale for a
triage convenience was judged not worth it. If a judge has read the report and expects an
upload to be silently skipped when Play-signed, say so directly: that specific behavior is not
what shipped, and explain why in these terms. Population data: of the 51 PRIMARY packages, 23
(45%) carry the Play App Signing issuer and would be tagged; 28 (55%) do not and fall outside
the allowlist's coverage entirely — self-signed and self-distributed banks are the majority of
the corpus, not the minority.

### Operating point — the strongest User Experience numbers the project has

| Number | Value | Corpus | Caveat |
|---|---|---|---|
| Confirmed malware scored **benign** (missed) | **6.4%** (23/360) | `cicmaldroid_banking` seeded sample | Miss rate at the shipping 0.30 threshold |
| General benign apps **flagged** non-benign | **17.1%** (50/292) | `fdroid_benign_apks` seeded sample | Analyst false-positive load |
| Malware **flagged** non-benign | **93.6%** (337/360) | `cicmaldroid_banking` seeded sample | Detection rate at the same threshold |

Frame as analyst load: at the shipping threshold the scorer surfaces 93.6% of malware while
sending roughly one in six clean apps to an analyst. Both numbers come from the same
`harness/feature_cache/` rescore and are recomputable in seconds.

### Held-out malware detection

| Number | Value | Producing artifact | Caveat |
|---|---|---|---|
| Held-out malware flagged non-benign | **15/16 (93.8%)** — 9 malicious, 6 suspicious, 1 missed at score 0.28 | `harness/rescore_from_cache.py` over `harness/feature_cache/` | **These sixteen are malware, not banks** (`BANKING_HOLDOUT_16_PROVENANCE.md`). They are a 16-sample partition of the *same archive* as the 360 — so this is **not an independent holdout**, it is a same-source split. Quote only as "consistent with the 93.6% in-sample-source rate," never as external validation. |

Do **not** present this as a false-positive rate. Do not present it as an improvement on
anything. If in doubt, omit it — the 93.6% row above says the same thing without the corpus
caveat.

### Corpus

| Number | Value | Caveat |
|---|---|---|
| Sample set | **716** APKs: 16 holdout + 400 malicious + 300 benign, seed 42, sorted glob | `harness/build_sample_set_716.py`; independently re-derived byte-for-byte |
| Extracted | **668** | — |
| Skipped | **48** — 39 obfuscated-bytecode parse failures + 1 manifest crash (all malicious), 7 corrupt ZIPs + 1 172 MB manual timeout (both benign) | `harness/feature_cache_skips.csv`, reproduced exactly |

**Selection-bias caveat, attaches to every PS1 number:** the 39 obfuscated parse failures are
~10% of the malicious sample. Obfuscation is itself an adversarial signal, so the 360 that
survived are the more analysable, plausibly less sophisticated tail. **Every PS1 number is
optimistic.**

### Right-censoring — attaches to every indicator count anywhere in the report

`MAX_SUSPICIOUS_STRINGS = 25` with fixed iteration order **url → ip → shell**
(`setuguard_ps1/static_analysis.py:86`). An APK with ≥25 URL matches records **zero** IPs and
zero shell strings by construction — the IP extractor never runs. **84 of 668** sit at the cap.
**IP and shell indicator rates are lower bounds, not measurements.**

---

## QUOTABLE — Play-signed allowlist (built 19 Aug, Day 3)

**Display-layer only, never a scorer input.** Detects Google Play App Signing via the
certificate issuer string (`Organization: Google Inc.` — 29 distinct cert SHA-256 values
share this identical issuer template across `harness/banking_legit_corpus/`, so the string,
not any one hash, is the correct signal). Attached to the `/api/analyze_apk` response as
`play_signing: {detected, note}` after the verdict is already computed — structurally cannot
feed back into score, verdict, confidence, or risk_score. No `PREREGISTERED_BANKING_AUC_CLAIMS.md`
deviation entry needed; the pre-registered AUC is untouched.

**Coverage, of the 51 PRIMARY packages:** 23 (45%) carry the Play App Signing issuer and would
be flagged; 28 (55%) do not. **Self-signed and self-distributed banks are the majority of the
corpus, not the minority.**

**Two gaps, name both before a judge does.** (1) A legitimate bank that self-signs or
self-distributes falls entirely outside the allowlist's coverage — most of the corpus, per the
number above. (2) A malicious app distributed through Google Play would carry the identical
signature and be flagged the same way as a legitimate one. Play-signing means Google signed
it, not that it is safe; the allowlist is a triage prior that sits alongside Google Play
Protect, not a replacement verdict.

**Diverges from the submitted report's prose, deliberately — say so if asked.** The report and
the original pre-registration describe the allowlist as scoped "upstream" (excluding
Play-signed uploads from scoring). What shipped tags instead of excludes. See the correction
entry in the QUOTABLE — scope gaps section below for the full reasoning.

---

## QUOTABLE — Bridge

### IOC yield — `harness/IOC_YIELD_RESULTS.md`, `harness/ioc_yield_audit.json`

| Number | Value | Caveat |
|---|---|---|
| Malicious APKs yielding ≥1 network host indicator | **66.9%** (241/360) | Right-censoring above applies |
| Yielding ≥1 host absent from both the benign and holdout corpora | **60.6%** (218/360) | The holdout half of that exclusion set is malware — see the finding. The benign half (292 F-Droid apps) is genuine and carries the exclusion. |
| Yielding a usable certificate hash | **99.4%** | — |
| Yielding **zero** network indicators | **33.1%** malicious vs **7.9%** benign | Benign apps yield **more**, consistent with the measured **−20.7** backwards separation of that term. Yield and discriminative power are different properties. |

Conservative floor treating all 39 obfuscated failures as zero-yield: **60.3%** (241/400).

### Mandatory adjacent statement — say this whenever linkage is mentioned

**Linkage fires on both keys as of 21 Aug (Day 4).** The C2-host comparison previously used the
raw `suspicious_strings` value with no `urlparse` call, so a `kind == "url"` indicator (the whole
scheme+host+path string) could never equal a bare ground-truth hostname — only a bare `kind ==
"ip"` value ever matched. Fixed with a single normalization function applied to both sides of the
comparison, so neither side can drift out of sync with the other. `SYNTHETIC_LINKAGE_GROUND_TRUTH`
carries two entries, one per join key — each a single hand-constructed linkage, not linkage
observed in the wild. **The C2-host value is a hostname extracted from the sample's strings by
our own static analysis, not independently confirmed as live C2 infrastructure** — a hostname
parsed out of a URL string is evidence the string exists in the APK, not evidence the host is
active or malicious infrastructure. The specific value — display defanged as **yessign[.]net** —
mimics the Korean accredited-certificate brand "yessign," extracted from a sample impersonating
KB Kookmin Bank (package `com.kb`). WHOIS shows the domain is actively registered (created 2015,
renewed to 2028, updated 2025, live nameservers); ownership is redacted. **No claim is made about
the domain's current ownership, registration, or activity — it is not confirmed as live C2.** The
account association is synthetic regardless of which join key fires. Both the offline validation
script and the live `/api/bridge` endpoint were
confirmed to call the real matcher, not a stub, by sabotage: breaking one comparison branch
dropped the expected metric (offline TP, live `match_count`) exactly as predicted, restoring the
file returned it byte-identical. It is now accurate to write "matches on certificate hash or
C2 host" as a present-tense capability.

### Matcher validation

**2 distinct ground-truth linkages (one certificate hash, one C2 indicator), 100 hand-built test
cases, matcher correct on all 100 — not a detection-rate measurement.**
`bridge/confusion_matrix_validation.py` tests the deterministic exact-match function against: 6
accounts sharing the cert-hash linkage, 4 sharing the C2 linkage, 20 hand-built near-miss
confounders (same-/24-subnet and same-issuer-different-hash, 10 each), an all-`None` account, an
unsigned-APK edge case, and 68 true negatives. Confusion-matrix summary: TP=10/FP=0/FN=0/TN=90 —
but those 10 "true positives" are 10 correctly-linked *accounts* powered by only 2 distinct
indicator values, not 10 independent matches. **State the distinct-linkage count (2) alongside
the account count (10) if either is quoted** — "10 true positives" alone overstates how much was
exercised. This is a **correctness test of the join logic against hand-built confounders**, not a
detection-rate or accuracy measurement — no dataset exists where APK-to-account linkage is
independently known, so no detection rate can be measured. **Never "accuracy." Never a performance
metric.**

---

## QUOTABLE — PS2

Untouched by the holdout finding. This section is the most solid material in the report.

| Number | Value | Producing artifact |
|---|---|---|
| AUCPR | **median 0.271**, IQR 0.221–0.362 | `harness/ps2_repeated_splits.py` → `models/ps2_repeated_splits_metrics.json` |
| AUROC | **median 0.872**, IQR 0.851–0.907 | same |
| Recall @ top 1% | **25.0%**, IQR 18.8–37.5 | same |
| Recall @ top 5% | **53.1%**, IQR 43.8–62.5 | same |
| Precision @ top 1% / 5% | 22.2% / 9.4% | same |
| Lift @ top 1% / 5% | 25.2× / 10.6× | same |

Method: **20 repeated stratified 80/20 splits**, seeds 0–19, identical fixed hyperparameters, no
tuning. **1,817 accounts and 16 fraud per holdout.** `train_test_split(..., stratify=y)` shuffles
by default and `stratify` requires it — verified against sklearn's source, not assumed.

**Always state the random baseline in the same sentence:** 81/9,082 = **0.0089**. AUCPR 0.271 is
**≈30× baseline**.

**State the overfit gap yourself, before a judge asks:** in-sample AUCPR **0.988** vs holdout
median **0.271**, on 81 positives. Say plainly that this is why only holdout figures are quoted.
The trainer records it under a key named `in_sample_train_metrics_DO_NOT_REPORT_AS_HOLDOUT` and
the API never surfaces it.

### Dataset

**9,082 rows × 3,925 columns** (`Unnamed: 0` + `F1`…`F3924`; there are 3,924 `F`-columns — do not
write 3,924 for the column count). **81 fraud**, prevalence 0.892%.

**All 81 fraud rows are contiguous at the file tail** — `Unnamed: 0` values **9002–9082**, which
are DataFrame positions **9001–9081**; the two frames differ by one because `Unnamed: 0` is
1-based. No non-fraud row appears in that range, so **row order encodes the target and any
positional sampling of this file is label leakage.**

### Features

**18 bank-finalized features** from column 4 (`Bank_Finalized_Variables`) of
`data/Description.xlsx`, sheet `Data_Dicitionary`: exactly 19 non-empty rows — the 18 plus
`F3924` marked `Target Variable`. Byte-identical to `ps2_features.py:17-36`, to the trained
artifact's `features.bank_finalized`, and to the trainer's `usecols`.

**Framing is audit and quantification only — never discovery.** The bank's own finalized list
already excludes every leaky feature (`F3898`, `F3899`, `F3912`–`F3915`) and every alert-derived
feature (`F2230`, `F3900`–`F3911`, `F3919`–`F3923`). The contribution is a guard that makes the
exclusion structural plus a 4-case negative test proving the guard fires
(`harness/test_leakage_assert.py`, all PASS). A discovery claim is falsifiable by any judge who
opens the same spreadsheet.

---

## QUOTABLE — scope gaps, stated as gaps

**Superseded, kept for provenance — a legitimate-banking-app measurement now exists.** This
paragraph originally read "no legitimate-banking-app measurement exists... unmeasured," true
before 15-16 Aug. It contradicted this file's own PRIMARY/SECONDARY AUC entries above the
moment those were measured, and stood uncorrected until 19 Aug — an internal inconsistency in
this exact file, found and fixed only during this reconciliation pass, not caught earlier.
Current state: PRIMARY AUC 0.1444 [0.0905, 0.2081] over 51 packages/32 issuer clusters,
SECONDARY 0.3190 [0.2202, 0.4290] over 20/16, both pre-registered at `be6a15c`, both CIs
entirely below 0.5 — see the QUOTABLE section above. The class-convergence hypothesis — that a
real banking app needs the same permission set as a banking trojan and is therefore hard to
separate statically — remains **plausible and untested**; the measurement is consistent with
it but does not confirm it. Present it as the motivating hypothesis, never as a finding.

**No dynamic analysis.** Static only: DEX string pool, manifest, certificate. Nothing is
executed. Quantified: 33.1% of malicious samples yield zero network indicators statically and a
further ~10% cannot be parsed at all.

**One static CSV, not real-time feeds.** PS2 scores an uploaded CSV against a fixed 18-column
schema. No streaming ingest, no transaction feed, no NPCI/UPI connection.

**RESOLVED 19 Aug (Day 2) — a fail-closed path now exists on the live API.** Was: parse failure
returned HTTP 500 with the exception string; confirmed live on 4 real corrupt-zip F-Droid
samples before the fix. Now: caught in a try/except scoped to `static_analysis.analyze_apk()`,
returns HTTP 200 `status: requires_manual_review` with `reason`/`action` fields
(`app.py:443-475`), rendered as a dedicated frontend card, per `PLAN.md` item 3. Batch
harnesses' `skips.csv` convention is separate and unchanged — this closed the live-API gap
only. Error-path degradation: the underlying parser still rejects the same files; the failure
is now handled, not eliminated.

**`d1-inversion` is scoped to the serving path only.** `_rule_based_verdict()` is structurally
authoritative in `setuguard_app/backend/app.py` — verified line by line: `_try_llm_narrative()`
opens `report = dict(rule_report)` and assigns only `rationale` and `cited_chunk_ids`, and
`verdict_source` is a string literal. But `run_pipeline.py:76` and `batch_baseline.py:261,286`
take `verdict` and `confidence` straight from Mistral, and the committed
`setuguard_ps1/out/*.report.md` shows an LLM verdict of `suspicious / 0.85`. Describe the CLI as
a **retained pre-inversion reference** and label those artifacts as such.

**RESOLVED 19 Aug (Day 2) — a 50MB upload cap now exists on the APK path.** Was: no
`MAX_CONTENT_LENGTH`, no client-side check; 26 sample-set APKs exceed 50MB, one (172.2MB,
`cash.p.terminal_243.apk`) could not be analysed inside a 300s timeout even with a dedicated
memory budget, and two live memory incidents were traced to large files. Now: rejected in
0.16s via a manual `request.content_length` pre-check plus a post-save size backstop, HTTP
413, plus a client-side check with a readable message. Deliberately **not** Flask-wide
`app.config["MAX_CONTENT_LENGTH"]` — that would have also capped `/api/analyze_dataset`'s own
~111MB `DataSet.csv` upload, a real regression caught by testing against the live dataset path
before shipping, not a hypothetical risk.

---

## BANNED — must not appear in the PDF, the deck, or any document

| Banned | Why |
|---|---|
| **AUC 0.4113 / 0.3841** as a legitimate-banking-app result | The negative class is malware. See the finding. |
| **"15/16 false positives"**, **"16/16"** | Not false positives. They are 15 of 16 malware samples correctly flagged. |
| **"0.688 vs 0.614"** as banking-apps-outscore-malware | Both groups are malware. |
| **"0.816" / "0.720"** | Old scorer, superseded — and same corpus error. |
| **"malware ranks below real banking apps"**, **"convergent by construction"** as a finding | Unmeasured. Permitted only as a stated hypothesis. |
| **"confidence"** as an independent quantity | It is `round(0.5 + score/2, 2)` — a monotone transform of the evidence-weighted score, floored at 0.5, carrying no independent information. Write **evidence-weighted score**, state the transform once. |
| **"0.4114"** and any single-split seed-42 PS2 figure | Retired. It sits at the 80th percentile of the 20-seed distribution — a favourable draw. |
| **"p50"** for endpoint timings | No producing harness. See below. |
| **"accuracy"** applied to the bridge confusion matrix | It is a unit test of an exact-match function. |
| **"mules sit at network bridges"**, any graph-feature uplift | Withdrawn as label leakage — `ps2/06_graph_features.py` assigns top-betweenness nodes to fraud rows using the target. |
| Any **triage-percentile reframe** of the PS1 score | Dead. Proposed once (`SESSION_LOG.md:248-252`), never implemented, does not work for single-APK upload. |
| **"independently confirmed"** applied to account 9072 | It is `F3924==1`, but it is also the **only** key in `SYNTHETIC_LINKAGE_GROUND_TRUTH` — it was chosen. The original claim survives verbatim in `SESSION_LOG.md` (~line 462, "produced exactly 1 link on account 9072... not a coincidence") per the log's no-rewrite convention, but now carries an inline retraction pointer added 19 Aug forwarding to the "2026-08-11 (correction, not a rewrite)" entry. |
| **68 packages / 47 issuer clusters** or **73 files / 53 packages / 33 issuers** next to **0.1444** | Wrong n. The scored n is **51 packages / 32 issuer clusters** — see the QUOTABLE section above. |

---

## CANNOT CURRENTLY BE SHOWN — state the gap, do not quote

**Endpoint timings.** ~9.86 s / ~0.66 s / ~0.0025 s come from a hand-written **n=3** table at
`SESSION_LOG.md:445-450` with no producing harness. `harness/measure_app_verdicts.py` records
`elapsed_s` for `/api/analyze_apk` only and computes no percentile. Either write "spot
measurement, n=3" or omit timings entirely and add them once the harness exists (`PLAN.md`
item 8). **Never write "p50."**

**Ollama-down 1.24 s.** In no committed artifact — checked `console_report.json`,
`backend_stdout_stderr.log`, `03_bridge_match.txt`. The *behaviour* is verified (3 steps, zero
console errors, bridge still matched with Ollama unreachable); the *number* is not.

**The 0.9366 evidence chain does not survive a clone.** `harness/feature_cache/` and
`harness/results_716.csv` are gitignored; only the summary
`docs/evidence/2026-08-12_scorer_v2.{md,json}` is committed. If a judge says "show me," there is
nothing to open. Committing `results_716.csv` is `PLAN.md` item 5 — a post-report item, because
that file's `banking_holdout` rows are mislabelled and must be relabelled first.

---

## The one-paragraph version, for the report's abstract

SetuGuard triages Android banking malware by static analysis and links the result to mule-account
scoring through shared indicators of compromise. Its static scorer separates banking malware from
general-purpose Android apps with **AUC 0.9366** over 652 real APKs, flagging **93.6%** of malware
while sending **17.1%** of clean apps to an analyst. Its mule model reaches **AUCPR 0.271**
(IQR 0.221–0.362) across 20 stratified holdouts — about **30× the 0.0089 random baseline** at a
0.892% fraud rate — catching **53.1%** of fraud in the top 5% of accounts by score. Bridging is
viable: **66.9%** of malware samples yield at least one network indicator and **99.4%** yield a
usable certificate hash. Two limits are stated rather than hidden: the system performs no dynamic
analysis, and its own pre-registered measurement against 51 real legitimate banking apps across
32 issuer clusters shows the static scorer's ranking **inverts** on that population (PRIMARY AUC
**0.1444** [0.0905, 0.2081]) — permission and API-surface signals do not separate a banking app
from a banking trojan built to request similar capabilities. That scopes PS1 to untrusted and
sideloaded APKs. A Play App Signing issuer tag flags known-publisher uploads as a lower-priority
triage prior — every APK is still fully scored, nothing is excluded — covering 45% of the
legitimate corpus (23 of 51 PRIMARY packages); the rest self-sign or self-distribute and fall
outside it.
