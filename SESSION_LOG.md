# Session Log

## 2026-08-10

**What changed, by file:**

- `setuguard_ps1/VERDICT_GATE_PROPOSAL.md` — added a header marking it superseded
  (commit `729b9b8` pinned RAG generation after this doc's numbers were measured).
  Not one of the six frozen files (confirmed against `CONTEXT.md` line 782 before
  editing — my own plan initially assumed it was frozen; that was wrong), so no
  `FROZEN_FILE_FINDINGS.md` entry.
- `setuguard_ps1/batch_baseline.py` — added optional `--sample-list <file>` and
  `--out-dir <dir>` CLI args to `_select_samples()`/`main()`. Default (no args)
  behavior unchanged; verified via direct call. Not frozen; docstring updated.
- `setuguard_app/backend/app.py` — D1 inversion. `_rule_based_verdict()` is now
  the sole, structural source of `verdict`/`confidence` for `/api/analyze_apk`;
  `_try_llm_verdict()` was replaced with `_try_llm_narrative(features, rule_report)`,
  which starts as a copy of the rule report and only ever overwrites
  `rationale`/`cited_chunk_ids` on LLM success. Added two new top-level response
  fields, `verdict_source` (always `"rule_based"`) and `narrative_source`
  (`"ollama_rag"` | `"unavailable"`), plus a narrative sentence stating the same.
  `_family_guess()` no longer branches on verdict provenance (verdict is always
  rule-based now). Module docstring and `_rule_based_verdict()`'s docstring
  updated — both previously described the old fallback-only framing.
- New: `harness/sample_set_86.txt` (explicit, deterministic, committed sample
  list — 40 benign + 46 malicious, reproduces `batch_baseline.py`'s selection
  minus 4 permanently-unparseable malicious APKs), `harness/measure_app_verdicts.py`
  (non-frozen harness that POSTs the same 86 samples to `/api/analyze_apk`).
- New (gitignored, not committed): `setuguard_ps1/baseline_v2_pinned/` (fresh
  pinned before-run output), `harness/results_app_path.csv` (after-run output).

**What was measured:**

- **Before** (`batch_baseline.py` → `rag_report.py` directly, pinned
  temperature=0/seed=42, LLM-authoritative verdict), n=86 (40 benign + 46
  malicious, 0 skipped): **86/86 = 100% "suspicious"** — zero separation by
  true label, confirming the documented "always suspicious" behavior on a
  clean, reproducible, pinned run.
- **After** (`/api/analyze_apk`, rule-based-authoritative verdict), n=83
  processed / 86 attempted (3 skipped, see below): **44 malicious / 31
  suspicious / 8 benign**. By true label — benign (n=40): 5 benign / 19
  suspicious / 16 malicious; malicious (n=43 processed): 28 malicious / 12
  suspicious / 3 benign. All 83 responses had `verdict_source: "rule_based"`
  (structurally guaranteed) and `narrative_source: "ollama_rag"` (Ollama was
  reachable throughout). Verdict is no longer monolithic, but the benign
  false-positive rate is high (35/40 flagged suspicious+malicious) — expected
  and untuned, since weight calibration was explicitly out of scope this
  session.
- Ollama-down check: same malicious sample, Ollama unreachable vs reachable —
  identical `verdict`/`confidence` (`malicious`/1.0) both ways, response
  schema key sets identical, complete report returned in both cases
  (`narrative_source` correctly flips to `"unavailable"`).
- `cited_chunk_ids` grounding, one real sample, RAG path, pinned seed, 2
  identical runs: **still broken**. Both runs cited `'T1636'`, which is not a
  legal chunk id (`knowledge_base.CHUNKS` only has `T1636.003`/`T1636.004`) —
  same fabrication, reproducible both times. Matches
  `FROZEN_FILE_FINDINGS.md` Finding 3/4's documented pattern exactly (pinning
  made it reproducible, not correct). Not fixed, per instruction.

**What contradicted CONTEXT.md or a repo doc:**

- Task brief's premise that `bridge/confusion_matrix_validation.py`
  "reimplements matching inline" was **false** — its own docstring says it's
  v2, revised specifically to call the real `match_account_to_apk()` from
  `matcher.py`, and it does (3 call sites, no inline duplication). No file
  renamed; `fix1_confusion_matrix_results.json` stands as valid evidence of
  the real matcher's behavior (ground truth is still synthetic, a separate,
  already-acknowledged caveat).
- `setuguard_ps1/baseline_v2/results.csv` predates commit `729b9b8`'s
  temperature/seed pin by 2 days (2026-07-25 vs 2026-07-27) — unusable as a
  before-number; not used.
- "n=46" in the task brief is not the sample-set size — it's the
  malicious-only successful count. Real reproducible set is 86 (40 benign +
  46 malicious out of 90 nominal; 4 malicious permanently fail
  `static_analysis` on corrupt bytecode, per existing `skips.csv`).
- New, not previously documented anywhere: `app.py`'s `_target_banking_apps()`
  (pre-existing, untouched by this session's edits) crashes with an uncaught
  HTTP 500 on the same 3 filenames `FROZEN_FILE_FINDINGS.md` Finding 2 already
  flags for `exported_components[].name == None` — Finding 2 documented the
  root cause in `static_analysis.py` but not this specific downstream crash
  site in `app.py`. Not fixed this session (out of scope for D1).

**What was not done, and why:**

- `cited_chunk_ids` fix — explicitly out of scope ("no fix this session").
- `_rule_based_verdict()` weight calibration — explicitly out of scope
  ("ship the inversion first").
- `app.py`'s `_target_banking_apps()` None-crash (3/86 samples) — newly
  discovered during measurement, not requested, not fixed; flagged above for
  your decision.
- Nothing committed to git. All changes above are unstaged in the working
  tree; `git status` shows exactly the files listed. Not committed because
  this session was never explicitly told to commit — flagging for you to
  decide when.
- Two backend processes are still running in the background from this
  session's testing: the main instance on port 5000 (PID 100035) and the
  batch-baseline pinned run's now-finished process. You may want to stop the
  port-5000 instance if you're not continuing to use it.

## 2026-08-10 (continued — D1 calibration diagnosis, crash fix, cited_chunk_ids enum, holdout)

Five numbered steps, committed individually for bisection: `fcd2fd4`,
`ee95be4`, `42e9566`, `46ce2ea`, `c99a9b8` (on top of `3c69a17`/`d1-inversion`
from the earlier entry above). Setup: killed the leftover PID 100035 from the
prior entry, confirmed the prior commit/tag already matched the requested
`git add -A`/commit/tag (no-op, working tree was already clean).

**What changed, by file:**

- `setuguard_app/backend/app.py` — four changes across steps 1/3:
  1. `_rule_based_verdict()`'s `suspicious_apis` scoring now adds each
     category's weight once per **distinct category present**, not once per
     call site (was: 15 reflection call sites = 0.75 score on reflection
     alone). No weight values or thresholds changed; rationale still lists
     every individual call site.
  2. `_target_banking_apps()` now filters `None` out of
     `exported_components[].name` before joining — same root cause as
     `FROZEN_FILE_FINDINGS.md` Finding 2, but a different, previously-unfixed
     crash site (guarded in `app.py`, not in the frozen `static_analysis.py`).
  3. New `_safe_field()` wraps `family_verdict`, `target_banking_apps`,
     `c2_candidates`, `api_iocs`, `mitre` in `_adapt_apk_response()` — any one
     raising now degrades that field to a default instead of a 500 for the
     whole request.
- `setuguard_ps1/report_prompt.py` (**frozen file**, logged in
  `FROZEN_FILE_FINDINGS.md` Finding 4, now marked APPLIED) — `cited_chunk_ids`
  item schema gained `"enum": [c["id"] for c in CHUNKS]`, generated from
  `knowledge_base.CHUNKS` at import time (not hardcoded).
- New: `harness/threshold_sweep.py` (mirrors the capped scorer locally, no
  HTTP/Ollama, to sweep cutoff pairs), `harness/sample_set_banking_holdout_16.txt`
  (manifest of the 16 held-out banking APK paths, committed; the APKs
  themselves stay gitignored).
- New, gitignored/untracked (regenerable, not committed): `harness/results_app_path_pre_cap.csv`,
  `results_app_path_capped.csv`, `results_banking_holdout.csv`, `sweep_output.txt`,
  and their `*.log` companions.

**What was measured:**

- **Step 1 — cap fix, 86-sample re-run** (n=83, same 3 crash-skips as before,
  not yet fixed at this point): before `44 malicious / 31 suspicious / 8 benign`
  (benign FP 35/40) → after `25 malicious / 49 suspicious / 9 benign` (benign
  FP 34/40). Malicious verdicts *on benign apps* dropped 16→3; malicious
  recall (non-benign) held at 40/43 both ways. **Answer to "how much of the
  35/40 was this alone": almost none of the count (35→34), but most of the
  severity** — the uncapped call-count bug was inflating false-**malicious**
  severity specifically, not the overall FP rate. Something else is still
  driving the 34/40.
- **Step 2 — threshold sweep**, full 86 (46 malicious here, since this
  bypasses the not-yet-fixed crash entirely): validated against the live
  harness first (susp=0.30/mal=0.65 reproduced benign FP 34/40 exactly).
  Benign FP is **flat at 85% (34/40) for `susp_cut` 0.20–0.30**, first drops
  at 0.35 (67.5%, **zero** malicious-recall cost) and 0.40 (52.5%, ~2-point
  recall cost). Strict "malicious"-label recall depends only on `mal_cut`,
  independent of `susp_cut`: 65.2% (0.55) down to 43.5% (0.75). Full table:
  `harness/sweep_output.txt` (regenerable via the committed script). No
  thresholds changed in code.
- **Step 3 — crash fix verification**: all 3 previously-500ing samples
  (`0297b767...`, `02a3ae0d...`, `04d7ec12...`) now return HTTP 200,
  verdict `malicious`, confidence 1.0, `target_banking_apps: []`.
- **Step 4 — `cited_chunk_ids` enum, same sample that produced the fake
  `T1636`**: re-verified the finding was still live immediately before
  editing (fresh repro, same fabrication). Post-edit, 3 runs on the identical
  pinned input: **0/3 produced an id outside the legal 16** (was 1/4,
  reproducible `'T1636'` truncation, pre-edit) — `T1636.004` (the real id)
  appeared correctly instead. Ollama's structured-output decoding **does**
  honor the item-level enum; no workaround was needed. Citation *jitter*
  among valid ids is not fully gone (run 3 picked a different, still-valid
  subset than runs 1–2) — same residual non-determinism class Finding 3
  already documented for other fields; grounding is the property this
  finding targeted, and it now holds.
- **Step 5 — banking_holdout_16, capped scorer, all fixes applied**:
  **16/16 = 100% non-benign** (12 malicious, 4 suspicious, 0 benign). Every
  single real banking app in the holdout is a false positive. Not tuned
  against; number reported and left alone, per instruction.

**What contradicted CONTEXT.md or a repo doc:** nothing new this round —
all five steps executed as scoped, no premise in the instructions turned out
to be false (unlike the bridge/results.csv/n=46 corrections in the entry
above).

**What was not done, and why:**

- Scorer weights (permission/URL/cert values) were not touched — step 1 was
  scoped as a cap-only diagnosis, not calibration; the 34/40 residual FP
  driver is still unidentified.
- Thresholds (0.30/0.65) were not changed in code — step 2 was measurement
  only, per instruction ("I'll pick the operating point").
- `banking_holdout_16` was not used to tune anything — explicit holdout,
  per instruction.
- `cited_chunk_ids` citation jitter (which valid ids get picked, as opposed
  to whether they're valid) was not addressed — out of scope; the enum fix
  targeted grounding, not exact-match stability.
- `FROZEN_FILE_FINDINGS.md` Finding 1 (`manifest.iter()` on possibly-`None`
  manifest) and Finding 5 (NUL-byte crash) were not touched — not part of
  today's five steps.
- Not pushed to origin — not asked.
- Backend running on port 5000, PID 109314, with all five steps' changes
  live. Left running; kill it if you're done testing.

## 2026-08-10 (continued — D1 calibration diagnosis, investigation only, no code changed)

Investigation-and-planning session per instruction: no file edited, nothing committed. Measured
the 100%-FP-on-`banking_holdout_16` result directly (not reasoned about from code), to verify or
refute the standing hypothesis that a ~0.50 permission+URL floor was the cause. Scratch script
(not committed, scratchpad only) imported the frozen `static_analysis.analyze_apk()` directly —
no HTTP, no Ollama — and recorded per-term score contributions for all 16 `banking_holdout_16`
APKs, a seeded random sample of 400 `cicmaldroid_banking` (360 parsed, `random.Random(42)`), and
150 `fdroid_benign_apks` (146 parsed, same seed).

**What was measured:**

- **Score decomposition**: `banking_holdout_16` mean score **0.816**, *higher* than the actual
  `cicmaldroid_banking` sample's mean (0.720); general `fdroid_benign` mean 0.354. Banking apps
  fire nearly every scoring category (perm 93.8%, sms_control 68.8%, device_admin 50.0%,
  installed_app_discovery 62.5%, reflection 81.2%, url/ip strings 75.0%, self_signed 93.8%,
  device_fingerprinting 87.5% — higher than the malicious sample's 76.7%). Confirmed by reading
  raw permissions on 4 holdout APKs directly: `SEND_SMS`/`RECEIVE_SMS`/`READ_SMS` (OTP autofill),
  `SYSTEM_ALERT_WINDOW` (fraud overlays), `READ_PHONE_STATE`/`READ_CONTACTS`/`CALL_PHONE` — normal
  banking-app functionality, not incidental.
- **Discriminative power per term** (malicious sample vs. fdroid_benign+holdout16, ranked by
  fire-rate separation): `perm_term` +51.9pts (strongest, and largest single contributor to the
  holdout's inflated score), `sms_control` +45.9, `installed_app_discovery` +38.1,
  device_fingerprint/crypto/exec +29.6, `device_admin` +20.6, debug_cert +14.9,
  **`dynamic_code_loading` only +4.7** (second-weakest; fires on just 2/16 holdout apps — refutes
  the standing hypothesis that this term drives the holdout FPs), `self_signed` **+0.1 (dead —
  fires on ~99% of every group regardless of label, contributes a free +0.05 almost everywhere)**,
  `accessibility_service` -1.6 (too rare either direction), **`suspicious_strings` (url/ip) -20.7
  and `reflection` -20.9 (both measurably backwards — fire *more* in benign apps than malware)**.
  `reflection`'s weakness is already documented in `static_analysis.py`'s own code comment; the
  scorer weighs it as a positive signal anyway.
- **Headroom** (extended `threshold_sweep.py`'s susp_cut range past 0.50, isolating
  `banking_holdout_16` alone rather than the combined benign pool): FP never drops below 37.5%
  (6/16) at *any* cut up to 0.98, where malicious flag-recall has already collapsed to 24.7%. Four
  of sixteen legitimate banking apps hit the literal score cap (1.0), same as the top-scoring real
  malware. **No threshold pair achieves benign FP under 15% on the banking population** — this is
  a feature/weight problem, not a threshold problem, confirmed by measurement rather than assumed.
- **Refined the standing hypothesis**: the "~0.50 floor" is real but not universal — general
  `fdroid_benign` apps mostly don't hit it (`perm_term` mean 0.035, fires 40% of the time; overall
  10th-pct score 0.15). It's specific to the banking/fintech vertical, which legitimately needs the
  same permission set (SMS, overlay, phone-state) that the scorer treats as inherently suspicious.

**Remediation plan delivered (not applied — approval pending):** drop/neutralize the two
backwards terms (`reflection`, dead `self_signed`) and narrow the URL/IP term first (cheap,
unambiguous); then redesign `perm_term`/`sms_control`/`installed_app_discovery`/`device_admin` as
named co-occurrence signatures rather than raw counts (highest-leverage single change, per the
discriminative-power ranking) — flagged that `accessibility_service` essentially never fires in
this corpus (0% holdout, <2% general) so any signature built around it needs its own
co-occurrence-rate check before being trusted; deprioritized re-weighting `dynamic_code_loading`
(option c) since measurement shows it isn't the driver. Also proposed reframing the verdict as
batch-relative triage rank (option d), justified specifically by the headroom finding (no
threshold works, not just "thresholds are hard to pick") — mapped onto the existing
`verdict`/`confidence`/`risk_score`/`severity` keys (kept, reinterpreted) plus two new additive
fields (`triage_rank`, `percentile`); flagged single-APK-upload mode (no batch to rank against) as
an unresolved edge case for that option. All four options confirmed implementable entirely in the
non-frozen `setuguard_app/backend/app.py`; none require touching the six frozen PS1 files, since
raw permissions/API categories/strings are already returned by `static_analysis.analyze_apk()`.

**What was not done, and why:**

- No code edited, nothing committed — investigation and planning only, per instruction.
- `banking_holdout_16` was not tuned against — all discriminative-power and decomposition
  measurements used `cicmaldroid_banking` (seeded sample) and `fdroid_benign_apks` (seeded
  sample) only; holdout was scored once, read-only, as the subject of measurement, not as a
  calibration target.
- Permission/API co-occurrence signature design (option b) was scoped and justified by the
  ranking but not specified in detail or calibrated — needs its own before/after measurement
  against the two non-holdout corpora, flagged as next step, not done this session.
- Scratch scoring script and its output CSV live in the session scratchpad only, not committed
  or added under `harness/` — this was ad hoc measurement tooling for the investigation, not a
  reusable harness artifact.

## 2026-08-12 — scorer-v2 pruning: feature cache builder, three deletions, holdout ranking gate

Task brief assumed a fresh start ("no memory of prior sessions"). Disk did not agree: an
interrupted, uncommitted attempt at this exact task was already present (`app.py`'s three
deletions already applied; `harness/build_sample_set_716.py` + `sample_set_716.txt` already
built; `harness/extract_features_pool.py` partially run, 95/716 cached; `harness/rescore_from_cache.py`
already drafted) — evidently OOM-killed mid-extraction the prior day, per instruction to stop
and report rather than guess. Reported the discovery; instructed to verify-then-adopt rather than
rebuild from the literal spec.

**Verification gate (five checks, all passed) before adopting the prior work:**

1. `app.py` deletions — confirmed via live import + unit tests, not just reading: reflection is
   excluded from the `seen_cats` set entirely (does not fall through to the 0.08 "other"
   fallback — the specific trap flagged), `self_signed` block/weight/reason fully removed,
   url/ip narrowed so `https://domain.tld/path` contributes zero while bare-IP-host and
   non-standard-port URLs still fire. Diffed the full function against `HEAD`: nothing else
   changed. Additionally confirmed via `git diff 46ce2ea 9e34c5f -- setuguard_app/backend/app.py`
   (zero output) that `HEAD` and `46ce2ea` are byte-identical for this file, so the "old scorer"
   pinned copy is correctly anchored to both.
2. Cache integrity — all 95 existing JSONs parsed clean, sha256 matched filename and internal
   content, expected feature keys present.
3. Sample set — re-derived `sample_set_716.txt` independently from `build_sample_set_716.py`'s
   seed=42 logic; identical to the committed file, byte-for-byte, 0 diff either direction.
4. Resume-logic bug — root-caused why 7 fdroid_benign failures from the OOM-killed run were
   silently lost: the dead run tracked "already done" via a path-keyed `_done_paths.txt` log
   (not the actual cache/skip outputs) and batched skip-CSV writes to the end of the run, so a
   kill mid-flight lost failures without a trace. Rewrote `run_full()` to derive "already done"
   from the cache dir + `skips.csv` directly (mirrors `fix3_fp_harness.py`'s
   `_already_processed_filenames()`) and to flush each skip row immediately. Deleted the stale
   `_done_paths.txt`.
5. `rescore_from_cache.py` — `_score_old` diffed line-for-line against
   `git show 46ce2ea:setuguard_app/backend/app.py` (exact match); `_score_new` matches the
   working-tree function (per check 1); AUC rank-sum formula verified against synthetic cases
   (positives-higher → 1.0, positives-lower → 0.0, tied → 0.5) and, later, against an independent
   brute-force O(n·m) pairwise cross-check on real data (matched to 4 decimals).

**Extraction (Task 2), with two live operational incidents, both diagnosed and resolved without
losing or corrupting any cached data:**

- Resume attempt 1 (4 workers, `MemoryMax=8G`/`MemoryHigh=6G`, no swap cap) caused system-wide
  swap exhaustion — those settings don't constrain swap without a separate `MemorySwapMax`, so
  the job silently pushed 8GB into swap and starved the desktop (available memory dropped to
  ~1.8GB). Stopped; cache integrity re-verified clean (per-APK immediate-write held up under
  `SIGTERM`).
- Resume attempt 2 (`MemorySwapMax=0`) traded that for a near-total stall — anonymous memory over
  `memory.high` has nowhere to go without swap, so throughput collapsed to ~8% CPU utilization
  with zero new APKs cached in 4+ minutes. Stopped.
- Root-caused both to a small number of atypically large APKs (`fdroid_benign_apks` file sizes
  are heavily skewed: median 0.88MB, but 15 of the 600 remaining files exceed 50MB, one — 172MB —
  exceeds the rest by ~30x) landing in the same concurrent worker window, not a general per-task
  leak. Fix: split the remaining queue into 585 normal-sized files (2 workers,
  `MemoryMax=8G`/`MemoryHigh=6G`/`MemorySwapMax=1G`; completed cleanly, 704s, 1.20s/APK effective)
  and 15 files >50MB, processed one at a time (new script `harness/process_large_outliers.sh`,
  not part of the harness proper) with a dedicated 10G/8G/2G budget and a hard 300s wall-clock
  timeout per file. 14/15 completed in under a minute each in isolation — confirming the earlier
  instability was concurrency-driven, not these files individually. The 15th (`cash.p.terminal_243.apk`,
  172.2MB) still timed out alone with zero contention; logged as a deliberate manual skip.
- Final: 668/716 cached (100% integrity-checked), 48/716 skipped (40 malicious — 39
  `InvalidInstruction` bytecode-parse failures + 1 known Finding-1 `NoneType.iter`; 8 benign — 7
  corrupt-ZIP `EOCD` data-quality failures + the 1 manual timeout above). Accounting exact:
  668 + 48 = 716.

**Task 1 deviation, noted per instruction rather than silently accepted**: the adopted harness
lives at `harness/extract_features_pool.py` with CLI `--sample-list --workers --benchmark --n`,
not the brief's literal `setuguard_ps1/feature_extract.py` with `--corpus-dir --sample-n --seed
--limit --workers --out-dir`. Kept as-is per instruction (verify-then-adopt, don't burn time
rebuilding to spec) — full detail in `docs/evidence/2026-08-12_scorer_v2.md`.

**Task 4 — the gate:**

Old scorer (commit `46ce2ea`, ≡ pre-session `HEAD`): `banking_holdout` mean 0.8156 (n=16),
`malicious` mean 0.7202 (n=360), `benign` mean 0.3649 (n=292) — the holdout mean/malicious mean
closely reproduce the earlier investigation session's numbers (0.816/0.720) on an independent,
larger, seeded sample. New scorer (commit `b3ff83b`, this session's three deletions):
`banking_holdout` mean 0.6881, `malicious` mean 0.6135, `benign` mean 0.1438 — all three corpora's
means dropped, benign by far the most (0.3649 → 0.1438).

AUC(malicious vs `banking_holdout_16`) — **the gate**: old **0.3841**, new **0.4113**.
AUC(malicious vs `fdroid_benign`): old 0.8736, new 0.9366.

**Malware does not rank above legitimate banking apps under either scorer** — both gate AUCs are
≤ 0.5. The three deletions narrow the gap (+0.0272) without closing it. Reported plainly, no
editorializing, per instruction; committed anyway, per instruction, since this result is itself
a deliverable.

Determinism check: one cached feature set, scored 3x with each scorer — old `[0.56, 0.56, 0.56]`,
new `[0.41, 0.41, 0.41]`. Both identical. Pass.

**What was not done, and why:**

- No weight rebalancing, no new features (e.g. permission co-occurrence signatures) — explicitly
  out of scope this session, per instruction ("I want the raw effect of the deletions").
- Task 1 was not rebuilt to the literal file path/CLI spec — explicit instruction to adopt and
  resume instead, given the deadline.
- `banking_holdout_16` was not tuned against at any point — used only as the gate's measurement
  subject, consistent with every prior session.
- Full detail (per-corpus stats, skip reasons, AUC methodology/verification, operational
  incident log) lives in `docs/evidence/2026-08-12_scorer_v2.md` and `.json` rather than being
  duplicated here.

Commits: `89077ef` (harness + sample set), `b3ff83b` (scorer deletions), plus this entry and the
evidence files (commit to follow). Backend process from the 2026-08-10 session was not touched
this session — status unknown, not verified.

## 2026-08-11 — PS2 + Bridge integration into the live API (Tasks 1-4)

Scope per instruction: fix eight established defects in `/api/analyze_dataset` (in-request
training/CV, hardcoded `shap_drivers`/`generated_rules`/`rule_validated`, unconditional bridge
linking, unused `matcher.py`) using a newly-provided data dictionary (`Description.xlsx`, copied
to `data/Description.xlsx` and committed — 140KB exception carved out of the blanket `*.xlsx`
gitignore rule). PS1 (`setuguard_ps1/`), the frontend, and the three API endpoint paths were not
touched, per instruction; `_rule_based_verdict()` untouched and still the sole PS1 score/verdict
source. `ps2/06_graph_features.py` (label-leakage graph features) was not used or referenced.

**Verified against the data dictionary before writing code**: Description.xlsx's
`Bank_Finalized_Variables` column names exactly the 18 features + target (F3924/FRAUD_TGT) the
brief specified, confirmed byte-for-byte against DataSet.csv's actual columns/dtypes (9,082 rows,
81 fraud/9,001 non-fraud — matches brief exactly). Two of the 18 (F3889 ACCT_OPN_DAYS, F3891
CUST_OCCP) are category codes, not numbers, confirmed via dtype inspection, not assumed.

**Task 1** — `setuguard_app/backend/ps2_features.py` defines `BANK_FINALIZED_FEATURES` /
`EXCLUDED_LEAKY_FEATURES` / `EXCLUDED_ALERT_DERIVED` / `CATEGORICAL_FEATURES`, each comment-cited
to the dictionary row it came from; imported by both the trainer and the live backend so they
can't drift apart. `harness/train_ps2_model.py` (non-frozen, docstring says so) loads only the 19
needed columns via `usecols` (never the full 3,925-column/116MB `DataSet.csv`), asserts no
excluded feature is present in the loaded matrix (raises, doesn't silently drop), does a
stratified 80/20 holdout split (train: 65 positive/7,200 negative; holdout: 16 positive/1,801
negative — exact counts, small-positive-class caveat reported per instruction), trains XGBoost,
computes SHAP on the training set (mean(|SHAP|) feature-importance artifact), and writes
`models/ps2_xgb_v1.json` + `models/ps2_xgb_v1_metrics.json` (holdout AUCPR **0.4114**, holdout
AUROC **0.9572** — both HOLDOUT, labeled as such everywhere they're surfaced; in-sample train
AUCPR 0.9885 kept in the metrics file only, under a key literally named
`..._DO_NOT_REPORT_AS_HOLDOUT`, never returned by the API). Determinism verified by running twice
end-to-end and diffing every metric (identical). Peak RSS 400MB, 4s wall clock — small enough that
the `systemd-run` memory-cap wrapper mandated by the brief for long-running jobs wasn't needed;
noted rather than applied blindly.

`/api/analyze_dataset` now loads that artifact once at process import time and never trains,
cross-validates, or fits a SHAP explainer inside a request — the only per-request SHAP work is
running the already-fitted `TreeExplainer` forward over the 15 rows actually returned (inference,
not fitting). Endpoint p50 on a real `DataSet.csv` upload, measured both ways before editing code:
**~7.6s → ~0.66s** (n=4 old / n=4 new), peak RSS **~1.9GB → ~0.66GB** (`VmHWM`) — the RSS drop is
mostly `usecols` no longer parsing all 3,925 columns into a DataFrame just to leakage-audit and
one-hot-encode columns nobody asked for.

**Task 2** — `shap_drivers` was fixed as a side effect of Task 1 (every top_alert now carries its
own real per-record `TreeExplainer` output — confirmed non-identical across records, unlike the
prior hardcoded-fallback defect). `generated_rules`/`rule_validated` were traced to
`ps2/07_ps2_bridge_exporter.py`, which hardcoded `["SetuGuard_YARA_Rule_01.yar"]` / `true`
identically across all 9,082 exported records — a copy-paste of PS1's per-APK YARA concept onto
PS2 accounts, where there's no real per-account "generated rule" to validate. No honest
sub-30-minute way to compute either, so both are now explicit `null` with a `"*_status":
"not_computed"` sibling field on every `top_alert`, never a repeated fabricated constant.

**Task 3** — `/api/bridge` now imports and calls `bridge/matcher.py`'s real
`extract_ioc_from_ps1()` + `match_account_to_apk()` against every scored account, instead of
synthesizing its own `shared_ioc` and linking unconditionally to `top_alerts[0]`. Verified against
real data both directions: analyzing `cicmaldroid_banking/007556ca....apk` (cert_sha256
`d6e80c1de6423814bb8b8e4de46d9eb84d7eaa5cadfd5c8116918e4922e070d6`, matching
`matcher.SYNTHETIC_LINKAGE_GROUND_TRUTH`'s only entry, keyed `"9072"`) against a fresh
`DataSet.csv` scoring produced exactly 1 link on account `"9072"` — independently confirmed real
fraud (`F3924=1`) in the source data and ranked into the model's own top-5 alerts by score, not a
coincidence set up after the fact. A different APK against the same scoring run produced 0 links.
Both paths return HTTP 200; the zero-match response carries `"links": []`, `"matched": false`, and
null-but-safe top-level compat fields for the frontend's existing single-record template — traced
the exact JS template (`app.js`'s bridge handler) and confirmed via a standalone Node
reproduction that it stringifies `null`/`undefined` without throwing, so the empty state renders
rather than erroring. Grepped for the literal phrase "malicious APK indicators" to fix per
instruction; found no occurrence anywhere in the repo. New bridge narrative text uses "matched APK
indicators" throughout.

**Task 4** — full stack exercised against real inputs, backend started fresh each time:

| Endpoint | Input | HTTP | p50 (n=3) | Notes |
|---|---|---|---|---|
| `/api/analyze_apk` | real APK (491KB, cicmaldroid_banking) | 200 | ~9.86s | Ollama reachable this session — real RAG narrative (`narrative_source: ollama_rag`), `verdict_source` stayed `rule_based` (frozen D1 invariant, confirmed) |
| `/api/analyze_dataset` | `DataSet.csv` (9,082 rows) | 200 | ~0.66s | holdout AUCPR/AUROC surfaced, prevalence labeled descriptive-only |
| `/api/bridge` (match) | same APK + dataset run above | 200 | ~0.0025s | 1 link, account "9072", `matched_on: cert_hash` |
| `/api/bridge` (no-match) | different APK, same dataset run | 200 | ~0.0025s | 0 links, `matched: false`, note explains why |

All three response schemas checked field-by-field against what `frontend/app.js` actually reads
(not just "looks plausible") — every field the frontend accesses is present with the expected
type in real responses; the bridge empty-state template was checked by extracting and running the
literal template string, not by inspection alone. Frontend files themselves were not opened in a
browser this session (no browser tool available) — field/type verification stands in for that,
flagged as the one unclosed loop in Task 4's brief ("whether the frontend renders... without
console errors").

**What was not done, and why:**

- The hardcoded `-0.2` counterfactual (established defect #4) was not fixed — not assigned to
  Tasks 1-4, left alone per "no scope creep."
- `models/` is no longer gitignored (was a blanket, comment-flagged-as-unused pattern); the
  artifact itself (276KB) is now committed since the live endpoint depends on it existing.
- The `import matcher as bridge_matcher` line landed in the Task 1 commit (added alongside the
  `ps2_features` import in one edit, before Task 3's usage existed) rather than Task 3's — a minor
  commit-hygiene wrinkle, not a functional issue; noted rather than rewriting history to fix it.
- `ps2/07_ps2_bridge_exporter.py` and `ps2_bridge_payload.json` (the actual source of the
  hardcoded `generated_rules`/`rule_validated`/`shap_drivers` defect, per investigation) were not
  edited — confirmed they're not in the live request path (`/api/bridge` scores from
  `STATE["last_dataset"]`, never calls `matcher.load_ps2_accounts()` against that file), so fixing
  the live schema in `app.py` was the in-scope, load-bearing fix; the offline exporter is dead
  code in the current architecture, consistent with established defect #1's framing of `ps2/` as
  research artifacts separate from the canonical `app.py` implementation.
- Real Ollama latency (~9.9s of the ~9.86s p50) is now the dominant cost on `/api/analyze_apk`,
  unrelated to anything touched this session — flagged for awareness, not fixed (PS1/Ollama stage
  is frozen/out of scope).

Commits: `59603b6` (Description.xlsx), `2581e4a` (Task 1: offline trainer + artifact-loading
endpoint), `752772e` (Task 2: null generated_rules/rule_validated), `d9070c7` (Task 3: real bridge
matching). Backend was started/stopped repeatedly for measurement during this session and is not
left running at session end.
