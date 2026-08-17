# SetuGuard — Repository Context

**As of 15 August 2026.** Written for a reader with no prior exposure to this
repo. Sections 0 and 4 were verified 12 August and are unchanged; the corpus
rows in §2, the new §5 subsection on sha256 case normalisation, and the first
limitation in §8 were updated 15 August.

This is a description of what the repo *is*. The narrative history lives in `SESSION_LOG.md` and
stays there. Quotable numbers live in `REPORT_FACTS.md`. Forward work lives in `PLAN.md`.

Every claim below is tagged with the file and line range, artifact, or command that proves it.
Claims that could not be traced are in **Section 7**, not here.

---

## 0. The finding of 12 August, first, because everything else depends on it

`banking_holdout_16/` **contains no banking apps.** All sixteen are malware samples — a
sixteen-file partition of `Banking.tar.gz`, the CICMalDroid *Banking malware* archive that
`cicmaldroid_banking/` was also extracted from.

```
tar -tzf Banking.tar.gz | grep -c '\.apk$'   ->  2505
ls -1 cicmaldroid_banking/*.apk | wc -l      ->  2489
ls -1 banking_holdout_16/*.apk  | wc -l      ->    16   (2489 + 16 = 2505, exactly)
```

Set-differenced both ways: zero extras, zero omissions, zero overlap. Every certificate is
self-signed, with subjects including `sdsdfsdf`, `sasasa`, `zxzxzx`, `android-debug`, and the
AOSP public test key. Package names include `com.example.myapp` (the Android Studio default,
which Play rejects) and `zzzzzz.xxxxxx.cccccc`. Full evidence:
`harness/BANKING_HOLDOUT_16_PROVENANCE.md`, produced by `harness/identify_holdout_16.py`.

"Banking holdout" meant *held out from the Banking malware set*. Later sessions read it as *a
holdout of banking apps*. The drift is traceable from
`SetuGuard_Development_Roadmap_v2.md:16` (2026-07-06) through
`harness/sample_set_banking_holdout_16.txt:2-3`, which hardcodes the false reading as a comment.

**Consequences, applied throughout this document:**

| Previously stated | Now |
|---|---|
| AUC 0.4113 = malware does not rank above legitimate banking apps | **Void** — malware vs malware from one archive |
| 15/16 legitimate banking apps false-positive | **Inverted** — 15/16 held-out malware correctly flagged |
| The 0.28 sample was a correct benign call | **A miss** |
| Classes are "convergent by construction" — a measured ceiling | **An untested hypothesis** |
| AUC 0.9366 vs F-Droid benign | **Unaffected.** The one genuine PS1 separation number. |

The repo warned itself and was not heard: `PS1_Defects_and_Improvements.md:144` (D9) recorded
that "the 16 real banking APKs are **unsourced**. Until they exist, the FP number cannot be
measured." It was measured five weeks later anyway.

---

## 1. What this is

A submission to **PSB CyberShield 2026** (Bank of India × IIT Hyderabad × DFS). Raghav Pathak is
the sole contributor.

| Date | What | Failure mode |
|---|---|---|
| **17 Aug 2026** | Progress Report due (submitting 16 Aug) | Missing it **cancels candidature** — the only hard failure mode |
| **27–28 Aug 2026** | Grand Finale, IIT Hyderabad | Judged on Innovation, Technical Feasibility, Business Potential, Scalability, User Experience |

Three components:

- **PS1 — Android banking-malware triage.** Androguard static analysis → FAISS retrieval over a
  16-chunk MITRE ATT&CK knowledge base → Mistral-7B narrative via local Ollama → YARA generation.
- **PS2 — mule-account detection.** XGBoost over the bank's 18 finalized features from a
  9,082-row account dataset, with SHAP attribution and risk tiering.
- **Bridge — IOC linkage.** Joins a PS1 APK's certificate hash to a PS2-scored account.

Deliverable: one Flask backend (`setuguard_app/backend/app.py`) plus a static dashboard
(`setuguard_app/frontend/`), running fully offline except a local Ollama server.

---

## 2. Component state

| Component | Status | Evidence | Provenance |
|---|---|---|---|
| PS1 static extraction | Live | `setuguard_ps1/static_analysis.py:202-242`; 668 cached outputs in `harness/feature_cache/` | frozen file |
| PS1 rule scorer | Live, authoritative in the API | `app.py:194-264` | `d1-inversion`, scorer-v2 (`b3ff83b`) |
| PS1 RAG narrative | Live, narrative-only in the API | `app.py:267-283`; pin at `rag_report.py:78` | frozen; `temperature=0, seed=42` |
| PS1 YARA generation | Live | `yara_gen.py`; compile+match at `app.py:363-377` | frozen |
| PS1 CLI (`run_pipeline.py`) | Live, **not** inverted — LLM supplies the verdict | `run_pipeline.py:15,76,95` | frozen; §7 C1 |
| PS2 offline trainer | Live | `harness/train_ps2_model.py` → `models/ps2_xgb_v1.json` | non-frozen |
| PS2 20-seed study | Live | `harness/ps2_repeated_splits.py` → `models/ps2_repeated_splits_metrics.json` | non-frozen |
| PS2 inference endpoint | Live, inference-only | `app.py:577-761`; artifact loaded once at import, `app.py:512-526` | — |
| PS2 leakage guard + test | Live, 4/4 PASS | `train_ps2_model.py:67-84`; `harness/test_leakage_assert.py` | non-frozen |
| Bridge matcher | Live, exact-match, cert-hash only in practice | `bridge/matcher.py:77-108`; called at `app.py:839,843` | teammate-authored |
| Bridge unit test | Live | `bridge/fix1_confusion_matrix_results.json` | synthetic ground truth |
| Dashboard | Live, zero console errors | `harness/browser_smoke.js`; 5 screenshots + report in `harness/browser_evidence/ollama_up/` | Playwright |
| Ollama-down degradation | Verified | `harness/browser_evidence/ollama_down/` | — |
| Chart.js | Vendored locally | `frontend/chart.umd.js`; `index.html:7-8,249` all-local | — |
| Holdout provenance | **New, 12 Aug** | `harness/identify_holdout_16.py` → `harness/BANKING_HOLDOUT_16_PROVENANCE.md` | non-frozen |
| `ps2/01`–`ps2/07` | Offline research, dead in the live path | zero import hits from `setuguard_app/` or `bridge/` | `ps2/README.md` |
| Legitimate-banking-app corpus | **On disk and verified 15 Aug.** 95 APK files, 5.6 GB, 0 collisions with the CICMalDroid archive (check verified operational for the first time, 15 Aug). **Unscored.** **File count is not sample count**: 68 distinct packages across 47 issuer clusters; current arm 68 files / 68 packages, era-matched arm 27 files which are older builds of packages already in the current arm; Tier A 73 files / 53 packages / 33 issuers. Confidence intervals resample by issuer, never by file. | `harness/download_run.log`; `harness/BANKING_CORPUS_VERIFICATION.json`; `harness/BANKING_CORPUS_MANIFEST.tsv` | `harness/banking_packages.csv`, `harness/BANKING_PACKAGE_TIERING_DECISIONS.md`; inclusion rule pre-registered and committed before any scoring; AUC claims pre-registered at commit be6a15c |
| Dynamic analysis | Not started | no emulator/pcap/Frida code anywhere | — |

**Corpora on disk (gitignored):** `Banking.tar.gz` 3.9 GB / 2,505 APKs, extracted as
`cicmaldroid_banking/` (2,489) + `banking_holdout_16/` (16); `fdroid_benign_apks/` 802 APKs /
12 GB; `DataSet.csv` 117 MB; `harness/banking_legit_corpus/` 95 APKs / 5.6 GB (AndroZoo,
downloaded and verified 15 Aug).

---

## 3. Architecture — traced from code

### `POST /api/analyze_apk` — `app.py:431-454`

```
multipart "apk" → saved to backend/_uploads/
  → static_analysis.analyze_apk(path)          # app.py:440, frozen
  → _rule_based_verdict(features)              # app.py:441  ← verdict, confidence, score
  → _try_llm_narrative(features, rule_report)  # app.py:442  ← rationale, cited_chunk_ids ONLY
  → yara_gen.generate_yara(...)                # app.py:445, skipped when verdict == "benign"
  → _adapt_apk_response(...) → store_analysis("apk", ...) → analysis_id, kind
  → finally: uploaded file deleted             # app.py:453-454
```

**The inversion is structural, not conventional.** `_try_llm_narrative()` opens with
`report = dict(rule_report)` (`app.py:274`), so verdict and confidence hold rule-based values
before Ollama is contacted. Inside the `try`, exactly two keys are assigned — `rationale` and
`cited_chunk_ids` (`app.py:279-280`). The `except` branch assigns only `_narrative_source`.
`verdict_source` is the string literal `"rule_based"` (`app.py:426`), not a variable. There is
no code path — success, failure or partial — on which an LLM value reaches verdict, confidence,
`risk_score` or `severity`. Verified by reading every assignment.

### `POST /api/analyze_dataset` — `app.py:577-761`

Header read → intersect with the 18 bank features → re-read with `usecols` → one-hot F3889/F3891
→ `predict_proba` → SHAP over the top-15 rows only → tiers and audit findings. The model,
metrics and fitted `TreeExplainer` load **once at import** (`app.py:465-526`). No `fit`, no
split, no CV, no explainer construction in any request handler.

### `POST /api/bridge` — `app.py:823-890`

**No longer reads a shared global (2026-08-18 migration, `ANALYSIS_ID_MIGRATION.md`).** Resolves
`apk_id`/`dataset_id` from the request body via `_resolve_bridge_input()` (`app.py:791-820`)
against a lock-guarded, bounded, TTL'd analysis store (`store_analysis`/`get_analysis`/
`latest_analysis`, `app.py:112-155`): explicit ids are validated by prefix (`apk_`/`ds_`) and
resolved by id, wrong-prefix or unknown/expired ids return 400/404 without falling back, and an
omitted id falls back to the most recently stored analysis of that kind (409 if none exists).
The resolved entries then feed the same matching logic as before — calls
`bridge_matcher.extract_ioc_from_ps1` (`app.py:839`) and `bridge_matcher.match_account_to_apk`
(`app.py:843`) directly, nothing reimplemented inline — and the response gains an `inputs` block
(`id`/`label`/`source` for each operand) so which two artifacts were joined is visible in the
response, not just inferred from upload order. Returns HTTP 200 with `"links": []` when nothing
matches.

**The C2 path has never fired.** `matcher.py:94-98` does `linked_c2 in apk_c2_hosts`, and
`apk_c2_hosts` is built at `matcher.py:31-34` from **raw** `suspicious_strings` values — the
matcher never calls `urlparse`. For `kind == "url"` the value is the whole URL including scheme
and path, so a hostname-valued ground-truth entry can never match. Only a bare dotted quad
(`kind == "ip"`, present in 10.6% of malicious APKs) can join. Moreover the single entry in
`SYNTHETIC_LINKAGE_GROUND_TRUTH` has `c2_host: None` (`matcher.py:68`), so in the shipped
configuration **only cert-hash matching can fire at all**.

Consequence for the planned runtime capture: dynamic analysis yields hostnames (DNS, TLS SNI).
Those cannot join through today's matcher. `PLAN.md` item 2 is the prerequisite.

---

## 4. Verified numbers

Full quotable set with caveats: **`REPORT_FACTS.md`**. Summary of what reproduced during the
12 August sweep:

| Number | Value | Producing script | Status |
|---|---|---|---|
| AUC(malicious vs F-Droid benign) | **0.9366** | `harness/rescore_from_cache.py` | **Valid.** The one genuine PS1 separation figure |
| AUC(malicious vs `banking_holdout_16`) | 0.4113 (0.3841 old scorer) | same | **Void** — negative class is malware, §0 |
| Malware flagged / missed | 93.6% / 6.4% (337 and 23 of 360) | same | Valid |
| General benign flagged | 17.1% (50/292) | same | Valid |
| Held-out malware flagged | 15/16 (one missed at 0.28) | same | Valid as a *detection* rate; not an independent holdout — same archive |
| Extraction | 668 cached / 48 skipped of 716 | `harness/extract_features_pool.py` | Valid, reproduced exactly |
| IOC yield, malicious | 66.9% ≥1 host, 99.4% cert hash | `harness/ioc_yield_audit.json` | Valid |
| PS2 AUCPR / AUROC | median **0.271** [0.221–0.362] / **0.872** | `harness/ps2_repeated_splits.py` | Valid |
| PS2 recall @1% / @5% | **25.0%** / **53.1%** | same | Valid |
| Bridge unit test | TP=10 FP=0 FN=0 TN=90 | `bridge/confusion_matrix_validation.py` | Valid, unit-level only |

**PS2 split procedure verified:** `train_test_split(X, y, test_size=0.2, random_state=seed,
stratify=y)` at `ps2_repeated_splits.py:70-72` and `train_ps2_model.py:124-126`. `shuffle`
defaults `True` and `stratify` requires it. No positional slicing exists anywhere in the live
path or either training script — which matters, because all 81 fraud rows are contiguous at the
file tail (`Unnamed: 0` 9002–9082, positional 9001–9081) and row order therefore encodes the
target.

**Dataset shape verified directly:** 9,082 rows × 3,925 columns (`Unnamed: 0` + `F1`…`F3924`),
81 positives.

**The 18 features verified against the spreadsheet:** column 4 of `data/Description.xlsx` has
exactly 19 non-empty rows — 18 features plus `F3924` marked `Target Variable` — byte-identical
to `ps2_features.py:17-36` and to the trained artifact.

**Determinism:** RAG pinned `temperature=0, seed=42` (`rag_report.py:78`); sample set
`random.Random(42)` over a sorted glob; PS2 fixed seed with `n_jobs=1`; scorers are pure
functions over cached dicts.

---

## 5. Conventions

### The six frozen PS1 files

**`static_analysis.py`, `knowledge_base.py`, `report_prompt.py`, `rag_report.py`, `yara_gen.py`,
`run_pipeline.py`** — all in `setuguard_ps1/`.

`FROZEN_FILE_FINDINGS.md` does **not** itself contain this list; it refers to "the six frozen
files" and delegates to `CONTEXT.md §9` (this section's predecessor). Deriving the list from
`FROZEN_FILE_FINDINGS.md` alone recovers only the four it happens to file findings against.

The list is independently confirmed structurally: these are exactly the six `.py` files in
`setuguard_ps1/` whose opening docstring does **not** declare non-frozen status. Every other
`.py` there declares it.

**Rule:** do not modify these six without explicit sign-off. Findings are *reported* in
`FROZEN_FILE_FINDINGS.md`, not fixed; a separate narrowly-scoped follow-up applies exactly the
signed-off fix.

### `FROZEN_FILE_FINDINGS.md` status

| # | Location | Finding | Status |
|---|---|---|---|
| 1 | `static_analysis.py:99-105` | Unguarded `manifest.iter()` on a `None` manifest | **Open** |
| 2 | `static_analysis.py:91-106` | `exported_components[].name` can be `None`, violating the frozen `str` contract | **Open** |
| 3 | `rag_report.py:71-78` | Generation unpinned | **Applied.** Verdict/confidence stable; `cited_chunk_ids` still jitters |
| 4 | `report_prompt.py:36-39` | `cited_chunk_ids` unconstrained | **Applied.** Item schema is now an `enum` of the 16 real IDs |
| 5 | `static_analysis.py:82` + `yara_gen.py:35-39` | NUL byte from Adobe XMP metadata reaches a YARA string literal and crashes `yara.compile()` with `ValueError` | **Open. 22.1% prevalence** (32/145 benign F-Droid samples) |

**Finding 5 is unfixed and `run_pipeline.py` has no guard for it.** `app.py:365-375` wraps
`yara_engine.compile` in `try/except Exception`, so the API degrades to `compiles: false` rather
than crashing — but the CLI and the batch harnesses are unprotected. Scope on the API path is
unconfirmed; establishing it is `PLAN.md` item 7.

### Harness convention

Measurement code is non-frozen, declares that in its own module docstring, never mutates a
frozen file. Offline training writes versioned artifacts to `models/`; the live backend only
loads them. Conforming: `browser_smoke.js`, `build_sample_set_716.py`, `extract_features_pool.py`,
`identify_holdout_16.py`, `measure_app_verdicts.py`, `ps2_repeated_splits.py`,
`rescore_from_cache.py`, `test_leakage_assert.py`, `threshold_sweep.py`, `train_ps2_model.py`,
`verify_chartjs.js`, plus `setuguard_ps1/`'s `batch_baseline.py`, `d2_ab_harness.py`,
`d2_negative_chunks.py`, `fix3_fp_harness.py`, `stress_harness.py`, `_stress_worker.py`,
`validation_gate.py`. One exception: `harness/process_large_outliers.sh` calls itself "a one-off
driver, not part of the harness proper" without using the words *non-frozen*.

### ~~Never touch `banking_holdout_16/` in any script~~ — STRUCK 12 August 2026

The predecessor of this section stated: *"**Never touch `banking_holdout_16/`** in any script.
Every harness in this repo has explicitly excluded it."* Both sentences were false.
`harness/build_sample_set_716.py:33` globs the directory directly and writes all sixteen files
into the scorer's sample set; `harness/rescore_from_cache.py` computes the gate AUC on them;
`harness/sample_set_banking_holdout_16.txt` and `harness/results_banking_holdout.csv` are
committed direct runs. No guard, assertion or refusal exists anywhere.

The rule is struck rather than enforced, for two reasons. It was already universally violated, so
it was a false assurance in a document a judge may read. And it was actively harmful: *"never
open these files"* is precisely what let sixteen malware samples sit unexamined for five weeks
while a headline number was computed on them (§0). The discipline worth keeping is the narrower
one the rule was reaching for — **a holdout must not be used for term selection or threshold
choice** — and on that the repo has a recorded failure (§7 C2).

### sha256 case normalisation — added 15 August 2026

AndroZoo publishes sha256 UPPERCASE. `hashlib` and every local cache in this repo emit lowercase.
Four harness scripts have produced a plausible wrong answer by comparing across that boundary,
each caught only after the wrong answer was believed for some period:

| Script | Failure | Symptom |
|---|---|---|
| `vt_label_lookup.py` | manifest lookup | 0/3,291 resolved |
| `download_banking_corpus.py` | post-download hash check | deleted every good APK for three hours |
| `verify_banking_corpus.py` | collision check vs `universe` | check silently never fired |
| `verify_banking_corpus.py` | content-hash check (found 15 Aug) | reported all 95 good APKs as corrupt/truncated |

**Rule:** every sha256 is normalised to UPPERCASE at the point it is read into memory, via a local
`norm_sha()`. Uppercase is canonical because AndroZoo is the source we cannot change. Stored
caches, manifests and TSVs keep whatever case they were written with and are never rewritten. Any
script that compares two sha256 values from different sources without normalising both is
defective by construction.

### Git workflow

Single branch `main`, PR-into-main with Copilot auto-review. Three stale local branches
(`integration/app-review`, `ps2-merge`, `raghav/week2-ps1`), two with `origin` gone.

### What survives a clone

Gitignored, therefore **not reproducible from a fresh clone**: `harness/feature_cache/`,
`harness/results_716.csv`, `DataSet.csv`, all APK corpora. The PS1 evidence chain survives only
as `docs/evidence/2026-08-12_scorer_v2.{md,json}` — summary statistics with full provenance, no
per-sample data. If a judge says "show me the 0.9366," there is nothing to open.

---

## 6. KNOWN DEFECTS, DEFERRED

**These are deliberate deferrals, not oversights.** Each was found, root-caused and recorded
before 17 August, and each is scheduled. The Progress Report is the only hard failure mode in
this project; a code change that destabilises the green integrated build before submission costs
more than any defect below. Nothing here is fixed during report week. Full schedule: `PLAN.md`.

| # | Defect | File:line | Risk | Scheduled |
|---|---|---|---|---|
| D-1 | `setuguard_app/README.md` describes the rule-based verdict as the Ollama-unreachable *fallback* — the exact inverse of `d1-inversion` — plus "trains XGBoost with stratified CV (falls back to IsolationForest)" and "auto-detects the label column". None is true. | `setuguard_app/README.md` | **High.** First file a judge opens. Contradicts the architecture on its own front page. | 17 Aug, `PLAN.md` 1 |
| D-2 | Frontend claims capabilities that do not exist: "real XGBoost + SHAP trained on your data" (`index.html:157`), button "Run Data Audit + Train" (`:164`), on-screen status "…then training XGBoost + SHAP…" (`app.js:164`), "CV AUCPR (0-fold)" rendered over a 20-seed holdout median (`app.js:223,489`), plus bias-checking, KS-test drift monitoring and a "greedy counterfactual" (`index.html:212-214`) that is `null`. | frontend | **High.** Visible on stage. Zero technical risk to fix. | 17 Aug, `PLAN.md` 1 |
| D-3 | Matcher compares raw URL strings, never parsed hosts; ground-truth `c2_host` is `None`. C2 matching has never fired. | `matcher.py:31-34,94-98`, `:68` | **High.** Blocks runtime-capture experiment entirely. | 17–18 Aug, `PLAN.md` 2 |
| D-4 | No fail-closed path. Parse failure → HTTP 500 with the raw exception string rendered in the UI. | `app.py:450-452` | **Medium-high.** An exception string in a bank console is a feasibility answer by itself. 40 of 716 APKs hit this. | 18 Aug, `PLAN.md` 3 |
| D-5 | No upload size cap — no `MAX_CONTENT_LENGTH`, no client-side check. | `app.py`, `frontend/app.js` | **Medium-high.** 26 sample-set APKs exceed 50 MB; one 172 MB file defeated a 300 s timeout with a dedicated memory budget. Two live memory incidents traced to large files. | 18 Aug, `PLAN.md` 4 |
| D-6 | Evidence chain gitignored — `results_716.csv` does not survive a clone. | `.gitignore:77` | **Medium.** "Show me" has no answer. Must be relabelled first: its `banking_holdout` rows carry the false corpus label. | 18 Aug, `PLAN.md` 5 |
| D-7 | Withdrawn artifacts still shipping: `bridge/test_fixtures_ps2_sample.json` (202 records, loaded at runtime by `confusion_matrix_validation.py:240`) and `ps2/ps2_bridge_payload.json` carry `generated_rules`, `rule_validated: true`, `counterfactual: "No change needed (Safe)"`, `model_version: "v2.0.0-xgb-platt-graph"`, and a `graph_betweenness` SHAP driver — a withdrawn leaky feature. | those two files | **Medium.** Greppable, committed, contradicts three published retractions. | 18 Aug, `PLAN.md` 6 |
| D-8 | Finding 5 NUL-byte YARA crash unfixed; `run_pipeline.py` unguarded, API scope unconfirmed. | `static_analysis.py:82`, `yara_gen.py:35-39` | **Medium.** 22.1% prevalence in benign samples. If the API path is affected, roughly one demo run in five can throw during YARA generation. | 18 Aug, `PLAN.md` 7 |
| D-9 | Endpoint timings have no producing harness (§7 U1). | — | **Medium.** Blocks the scalability argument. | 18 Aug, `PLAN.md` 8 |
| D-10 | `MAX_SUSPICIOUS_STRINGS = 25` with fixed url→ip→shell order right-censors every indicator count and zeroes IP extraction on 84/668 APKs. | `static_analysis.py:86` | **Medium.** IPs are the only match type the bridge can currently fire on, so this suppresses the one working linkage path. **Frozen file** — needs sign-off and invalidates the feature cache. | 18–19 Aug, `PLAN.md` 9 |
| D-11 | `banking_holdout_16/` misnamed; `sample_set_banking_holdout_16.txt:2-3` asserts the false reading in a committed comment. | those paths | **High, but documentation-mitigated.** §0 and `REPORT_FACTS.md` now carry the correction; the rename is a data/code change. | after 17 Aug |
| D-12 | Findings 1 and 2 (`None` manifest, `None` component name) open. | `static_analysis.py:91-106` | **Low.** Both already degrade cleanly at every call site. | unscheduled |

---

## 7. CONTRADICTED and UNVERIFIED

### CONTRADICTED

**C0 — `banking_holdout_16/` is malware, not banks.** §0. The largest of these by a wide margin.

**C1 — `run_pipeline.py` takes verdict *and* confidence straight from the LLM.** The inversion is
scoped to `app.py`. `run_pipeline.py:76` does `report = generate_report(features)` and lines
30–31, 95–96 print and write `report['verdict']` / `report['confidence']` — Mistral's.
`batch_baseline.py:261,286` does the same. The committed
`setuguard_ps1/out/duyskab.txtxorxqlni.nflfnauti.report.md` shows `Verdict: suspicious /
Confidence: 0.85` from the model. Correct framing: the CLI is a **retained pre-inversion
reference**, and those artifacts should be labelled as such.

**C2 — the holdout was in the negative pool during scorer-v2 term selection, and `SESSION_LOG.md`
contradicts itself about it in one entry.** `SESSION_LOG.md:219` records the ranking as
*"malicious sample vs **fdroid_benign+holdout16**"*; `SESSION_LOG.md:258-261` states
*"`banking_holdout_16` was not tuned against… used `cicmaldroid_banking` and `fdroid_benign_apks`
only."* Line 219 is the accurate one — a dated correction is appended in place at
`SESSION_LOG.md`. Given §0 this is worse than contamination: those sixteen are **malware placed
in the negative class**, so the ranking that justified the three scorer-v2 deletions ran with
roughly 5% label noise in its negatives.

**C3 — the "never touch `banking_holdout_16/`" convention was universally violated.** Struck; see
§5.

**C4 — "16/16 false positives" was never a false-positive rate**, and under the shipping scorer
it is 15/16 anyway (9 malicious, 6 suspicious, 1 at 0.28 below the 0.30 threshold). Both the
count and the interpretation were wrong.

**C5 — "0.816 vs 0.720" is the old scorer's** (live: 0.688 vs 0.614), and both pairs compare
malware to malware.

**C6 — there is no fail-closed or manual-review routing.** `grep -rni "manual review|fail.closed|
fail_closed|manual_review"` across every `.py`, `.js`, `.md`, `.html` returns **zero hits**.
Parse failure returns HTTP 500 with the exception string (`app.py:450-452`); batch harnesses
append to `skips.csv`.

**C7 — `setuguard_app/README.md` describes an architecture that does not exist.** D-1 above.

**C8 — the frontend advertises four capabilities that do not exist.** D-2 above.

**C9 — withdrawn artifacts still ship.** D-7 above.

**C10 — the retracted "9072 corroborates the bridge" framing survives.** Commit `0d12997`
retracted it; `SESSION_LOG.md:430-434` still reads *"independently confirmed real fraud
(`F3924=1`)… not a coincidence."* 9072 is `F3924==1`, and is also the **only** key in
`SYNTHETIC_LINKAGE_GROUND_TRUTH` — it was chosen.

**C11 — minor.** `DataSet.csv` has **3,925** columns, not 3,924 (3,924 `F`-columns plus
`Unnamed: 0`). "~15 APKs over 50 MB" was the residual processing queue; the sample set holds
**26**. `ps2/README.md`'s "9002–9082" is the `Unnamed: 0` frame; positional is 9001–9081.

### UNVERIFIED

**U1 — endpoint timings have no producing harness.** ~9.86 s / ~0.66 s / ~0.0025 s exist only as
a hand-written n=3 table at `SESSION_LOG.md:445-450`. Searched for any script POSTing all three
endpoints, any percentile computation under `harness/`, any timing JSON in `docs/evidence/`.
`measure_app_verdicts.py` records `elapsed_s` for `/api/analyze_apk` only and computes no
percentile; `browser_smoke.js` does not time. **Never write "p50."**

**U2 — the Ollama-down "1.24 s"** is in no committed artifact — checked `console_report.json`,
`backend_stdout_stderr.log`, `03_bridge_match.txt`. The behaviour is verified; the number is not.

**U3 — how `fdroid_benign_apks/` was assembled.** `parse_fdroid_index.py`, `index-v2.json`,
`fdroid_urls.txt` and `download_log.txt` document the pull, but no committed script records the
selection or filtering rule. Lower-stakes than U3's predecessor — the holdout question — which
is now answered.

**U4 — representativeness** of the 400/300 draws. The draw is reproducible and was re-derived
byte-for-byte; whether CICMalDroid Banking represents 2026 Indian banking malware, or F-Droid
represents consumer Android, is unestablished either way.

**U5 — hackathon name, team name, venue and dates** appear nowhere in the repo.

---

## 8. Known limitations, stated plainly

**No measurement against legitimate banking apps exists yet.** The corpus was assembled and
verified 15 August (§2) but has not been scored. The class-convergence hypothesis — that a real
banking app needs the same permission set as a banking trojan, making them statically
inseparable — remains **untested**. It may be presented as the motivating hypothesis for the
corpus build; it may not be presented as a finding.

**No dynamic analysis.** DEX string pool, manifest, certificate. Nothing executed. A packed
dropper that resolves its C2 at runtime looks like an app with few permissions and no strings.
Quantified: 33.1% of malicious samples yield zero network indicators statically.

**Sample-selection bias.** 39 of 400 malicious samples (9.75%) were dropped because Androguard's
disassembler rejected obfuscated bytecode. Obfuscation is itself adversarial, so the 360 that
survived are the more analysable tail. Every PS1 number is conditioned on "APKs that parse," and
is therefore optimistic.

**Right-censored indicator counts.** `MAX_SUSPICIOUS_STRINGS = 25`, url→ip→shell order: an APK
with ≥25 URL matches records zero IPs. 84/668 sit at the cap. IP and shell rates are lower
bounds — which matters because IPs are the only indicator the bridge can currently match on.

**One static CSV, not real-time feeds.** No streaming ingest, no transaction feed, no NPCI/UPI
connection.

**Small positive count in PS2.** 81 fraud in 9,082 (0.892%), 16 per holdout — each account is
6.25% of recall. Hence a 20-seed median with IQR rather than a point estimate; AUCPR ranges
0.093–0.600 across seeds. In-sample AUCPR is 0.988 against a 0.271 holdout median.

**Synthetic bridge ground truth, one entry.** No real device↔account join key exists in any
source dataset. TP=10/FP=0/FN=0/TN=90 validates that the matching *function* behaves correctly
on near-miss confounders; it says nothing about how often a real link would be found.

**The bridge's C2 path has never fired.** §3.

---

## Terminology — read once

The field named `confidence` is defined at `app.py:260` as `round(0.5 + score / 2, 2)`: an
affine, strictly monotone transform of the evidence-weighted score, floored at 0.5 by
construction. It carries **no information the score does not carry**. It is not a calibrated
probability and not an uncertainty estimate. Downstream, `risk_score = round(confidence * 100)`
for non-benign verdicts and `round(confidence * 20)` for benign (`app.py:360`) — a further
monotone transform that jumps discontinuously from 13 to 65 at the benign/suspicious boundary.

**Write "evidence-weighted score."** State the transform once, then use one name.

Still presenting it as an independent quantity: `frontend/index.html:119` (a column headed
"Confidence"), `app.py:310` (`_family_guess` appends `"(rule-based triage, confidence {c})"` into
a displayed string), the `confidence` column in `harness/results_*.csv`, and
`PS1_Defects_and_Improvements.md:18-19`, which asserts "Confidence separates the classes
correctly" as though it were a second signal.

## Three things this document will not say

**The bridge confusion matrix is never called accuracy.**

**The PS2 leakage work is never called discovery** — the bank's finalized list already excluded
every leaky feature; SetuGuard audited and quantified.

**The PS1 score is never reframed as a batch-relative triage percentile.** Proposed once
(`SESSION_LOG.md:248-252`), never implemented, does not work for single-APK upload, and converts
a measurement problem into a presentational dodge.
