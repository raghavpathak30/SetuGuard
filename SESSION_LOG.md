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

> **CORRECTION appended 2026-08-12 — the bullet immediately above is wrong, and is retained
> rather than deleted.**
>
> It conflicts with line 219 of this same entry, which records the discriminative-power ranking
> as *"malicious sample vs. **fdroid_benign+holdout16**, ranked by fire-rate separation"*.
> **Line 219 is the accurate one.** The holdout was in the negative pool, so it *was* visible
> during scorer-v2 term selection, and that ranking is what justified the three term deletions
> (`reflection` −20.9, url/ip −20.7, `self_signed` +0.1). The claim of a clean separation
> between measurement corpus and holdout is **retracted**.
>
> Effect on the conclusion, stated so it is not overread in either direction: all three changes
> were **deletions**, and the gate AUC moved 0.3841 → 0.4113. Contamination therefore biased the
> figure **upward** — it worked against the conclusion drawn from it, not for it. The
> quantitative provenance claim is retracted; the direction of the result was not manufactured
> by the leak.
>
> **A second correction, same date, larger.** `harness/identify_holdout_16.py` established that
> `banking_holdout_16/` contains **no banking apps** — all sixteen are malware from
> `Banking.tar.gz`, the same CICMalDroid Banking archive `cicmaldroid_banking/` came from
> (2,489 + 16 = 2,505, zero overlap, every certificate self-signed). See
> `harness/BANKING_HOLDOUT_16_PROVENANCE.md`. This makes the contamination above a **labelling
> error rather than mere leakage**: sixteen malware samples sat in the *negative* class of the
> term ranking, roughly 5% label noise in the negatives. It also voids the gate AUC itself —
> 0.4113 compares malware to malware — and inverts the "16/16 false positives" reading recorded
> at line 172 of this file into 15/16 malware samples correctly detected. `CONTEXT.md` §0 and
> `REPORT_FACTS.md` carry the full consequences.
>
> Both corrections are appended in place. A log that corrects itself is evidence; a log that
> quietly deletes a wrong claim is not.
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

**[RETRACTED — see "2026-08-11 (correction, not a rewrite)" entry below.]** The
"independently confirmed real fraud... not a coincidence" framing above claims account
9072's true fraud label as corroboration. It is not: all 81 fraud rows sit contiguously
at the file tail, so drawing from that region lands on fraud near-certainly regardless of
intent. The label corroborates nothing about match quality. This entry is left as
originally written per the log's own no-rewrite convention; treat the retraction below as
authoritative.

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

## 2026-08-11 (continued) — pre-submission hardening pass (Tasks A-H)

Scope: real-browser verification (the previous entry's frontend check was field/type-checking +
a standalone Node template reproduction, not an actual browser — this session closes that gap),
Ollama-down degradation proof, PS2 variance/operational-recall reporting, killing the last
fabricated number (counterfactual), a leakage-assert negative test, a ps2/ provenance README, a
Chart.js vendoring check, and a provenance question about the bridge's one ground-truth entry.
No PS1 frozen file was touched (confirmed via `git log --name-only` over this session's commits
against `setuguard_ps1/`); no FROZEN_FILE_FINDINGS.md entry needed. No PS2 hyperparameter was
tuned anywhere in this session.

**Task A — headless-browser dashboard smoke test.** Installed Playwright 1.47.2 + Chromium local
to `harness/node_modules` (gitignored) and `~/.cache/ms-playwright` (outside the repo) — no system
packages touched; `--with-deps` needed sudo and wasn't available, but headless Chromium launched
fine without it. `harness/browser_smoke.js` (non-frozen) starts the Flask backend fresh, loads
`setuguard_app/frontend/index.html` via `file://` in headless Chromium, and drives APK analysis →
dataset analysis → bridge (matching APK, expect 1 link) → APK analysis (non-matching APK) →
bridge (expect 0 links), capturing every console message, uncaught page exception, failed
request, and non-2xx response per step, screenshotting each, and exiting non-zero on any console
error or uncaught exception. Run under `systemd-run --user --scope -p MemoryMax=6G -p
MemoryHigh=5G`. Result: **PASS**, zero console errors, zero uncaught exceptions, zero failed/non-
2xx requests across all 5 steps — verbatim `console_report.json` + 5 screenshots + backend log
committed under `harness/browser_evidence/ollama_up/`. The bridge-match screenshot independently
confirms account "9072" / `cert_hash` rendering correctly in an actually-rendered page (not just
the API JSON) — visible in `03_bridge_match.png`.

**Task B — Ollama-down degradation path.** Could not stop the real `ollama.service` — it's a
systemd system service owned by user `ollama`, `sudo -n systemctl stop ollama` failed (password
required, no passwordless sudo), and there's no non-root way to signal a process owned by another
user. Used the `ollama` Python client's documented `OLLAMA_HOST` env var instead, pointed at a
closed local port (`127.0.0.1:19999`, confirmed nothing listening), forwarded to the spawned Flask
child via `systemd-run --setenv`. Verified this is not merely similar to but the *same failure
path* as a stopped service: `OLLAMA_HOST=http://127.0.0.1:19999 python3 -c "import ollama;
ollama.embed(...)"` raises the identical wrapped `ConnectionError` app.py's `_try_llm_narrative()`
catches via a bare `except Exception` — disclosed here rather than asserted silently. Re-ran
`browser_smoke.js --label ollama_down --skip-second-apk`: **PASS**, zero console errors. Confirmed
both visually (screenshot) and via a direct follow-up API call: `verdict_source` stayed
`rule_based`, `narrative_source` became `"unavailable"`, verdict/confidence/severity/risk_score
identical to the Ollama-up run (malicious, 0.88, CRITICAL, 88) since neither depends on the LLM,
narrative visibly degraded to "Note: Ollama/mistral unreachable..." instead of crashing, response
time 1.24s (no hang/retry storm). Real Ollama was never touched, so "restart and confirm normal
operation returns" reduces to Task A's `ollama_up` evidence (same backend/APK, default env,
`narrative_source: ollama_rag`) — not re-run redundantly.

**Task C — PS2 repeated-holdout variance + operational curve.** `harness/ps2_repeated_splits.py`
(non-frozen) runs 20 stratified 80/20 splits, seeds 0-19, identical pipeline and identical fixed
hyperparameters copied verbatim from `train_ps2_model.py` — no hyperparameter search. Only the
split's (and, tied to it, the model's own) `random_state` varies. Result: holdout AUCPR median
**0.271** (IQR 0.221-0.362, min 0.093, max 0.600, n=20); holdout AUROC median **0.872** (IQR
0.851-0.907, min 0.716, max 0.933). Wide, reported as wide.

**Correction to this task's stated premise**: the already-published 0.4114/0.9572 in
`models/ps2_xgb_v1_metrics.json` did **not** come from seed 0 — checked the file directly
(`"seed": 42`); `train_ps2_model.py`'s default `--seed` is 42, not 0. Ran seed 42 explicitly as a
reference point outside the 0-19 range and confirmed it reproduces the published numbers exactly
(byte-identical: 0.4114011947584679 / 0.9571765685730149 — also a correctness check that this
script's pipeline matches the original trainer's). **Seed 42 sits at the 80th percentile of the
seeds-0-19 AUCPR distribution and the 100th percentile (best) of the AUROC distribution** — the
previously reported point estimate is a favorable draw, not a representative one, consistent with
the standing hypothesis that the stricter-eval-scored-higher result was a variance artifact.

Operational curve, seed=0's holdout (1,817 accounts, 16 fraud): reviewing the top 1% by score (18
accounts) catches 3/16 frauds (18.8% recall); top 5% (91 accounts) catches 8/16 (50.0% recall).
Full per-seed table in `models/ps2_repeated_splits_metrics.json`. 21 fits total, 4.8s wall clock,
268MB peak RSS.

**Task D — killed the hardcoded counterfactual.** `"drops_to": round(max(score - 0.2, 0.0), 3)`
was a flat, arbitrary subtraction with no relationship to the model or the specific feature's real
effect size. Nulled using the exact precedent already established for `generated_rules`/
`rule_validated`: value → `null`, sibling `counterfactual_status: "not_computed"`. Verified via
`browser_smoke.js --label ollama_up_taskD` that the frontend's existing null-safe ternary renders
"—" for every row instead of throwing — PASS, confirmed in the screenshot.

Feasibility check (not implemented — decision deferred, per instruction): a real,
non-approximated counterfactual is cheap now that `shap_drivers` is real per-record, since the
trained model is already loaded in-process. The honest version is a literal re-score, not a
SHAP-value subtraction: copy the row, set the top SHAP driver's feature to the dataset median (or
search for the tier-boundary-crossing value), call `model.predict_proba()` on the modified row —
one extra inference call per `top_alert` (15 rows), not an approximation. What it would be
entitled to claim: "if only this one feature had this other value, holding everything else in the
row fixed, the model would output this score" — a real, verifiable statement about the model's own
behavior. What it would **not** be entitled to claim: that the account holder can actually cause
that feature to change (no actionability/plausibility check, unlike DiCE-style counterfactuals);
that it's the minimal or optimal change (only the single top-SHAP feature examined, not jointly
optimized); that the resulting row is internally consistent (changing one ratio feature in
isolation may be incompatible with correlated features held fixed in the same row); or that the
number is stable across model refits — Task C's seed-variance results apply to this model exactly
as much as to its headline metrics.

**Task E — negative test proving the leakage assert fires.** Factored the inline exclusion check
out of `load_dataset()` into a standalone `assert_no_excluded_features(columns)` (no behavior
change — re-ran the trainer post-refactor, byte-identical holdout metrics). This wasn't cosmetic:
`load_dataset()`'s own `df.columns` can never contain a leaky column regardless of the source
CSV's contents, because pandas' `usecols` filters at read time — testing *through* `load_dataset()`
would only prove `usecols` works, not that the guard itself catches a leaky column when
hypothetically handed one. `harness/test_leakage_assert.py` builds hand-constructed column lists
that deliberately include an excluded feature and calls the guard directly. Four cases, all
**PASS**: F3912 (`FRAUD_SUSPECTED`, `EXCLUDED_LEAKY_FEATURES`), F3906 (`STATUS_CHANGE_AFTER_WD`,
one of the 12 `EXCLUDED_ALERT_DERIVED` legacy-rule-engine flags), F2230 (`MNTH`,
`EXCLUDED_ALERT_DERIVED`), and a control (`BANK_FINALIZED_FEATURES` alone, confirms the guard
isn't trigger-happy). Output committed verbatim to `harness/test_leakage_assert_output.txt`.

**Task F — `ps2/README.md`** written (5 short paragraphs): `01-07` are offline research artifacts
behind the leakage audit, produce no number in the report/demo; the shipping model is
`harness/train_ps2_model.py` → `models/ps2_xgb_v1.json`, served inference-only; `06_graph_features.py`
assigns graph features using the target label (cited the exact line —
`fraud_mask = combined_df[target_col] == 1` inside `map_graph_features_to_dataset()`) and the
"mules sit at network bridges" conclusion is withdrawn; `07_ps2_bridge_exporter.py` hardcoded
`shap_drivers`/`generated_rules`/`rule_validated` identically across all 9,082 records and is dead
code in the live path.

**Task G — Chart.js vendoring: premise was stale.** `setuguard_app/frontend/chart.umd.js` (Chart.js
4.4.4, 205KB minified) was already vendored and `index.html` already references it via a local
`<script src="chart.umd.js">` tag, not a CDN URL — traced to commit `5e4d6fe`, predating this
session. No vendoring action taken. What *was* missing: verification that it actually works with
zero network dependency in a real browser — `browser_smoke.js`'s steps all navigate away from the
dashboard before attaching listeners, so none of Task A/B/D's evidence covers the dashboard's
*initial* render, where `renderDashboard()` creates the chart synchronously during page load,
before any step-level listener exists. `harness/verify_chartjs.js` (non-frozen, ad-hoc) closes
that gap: listeners attached before `page.goto()`. Result: **PASS** — `window.Chart` defined
(version "4.4.4"), canvas visibly drawn into, zero console/page errors, and the only non-`file://`
request is the dashboard's own health check to `127.0.0.1:5000` (checked every request's hostname,
not skimmed) — zero requests to any external host. Screenshot + `report.json` in
`harness/browser_evidence/chartjs_vendored/`.

**Task H — provenance of `SYNTHETIC_LINKAGE_GROUND_TRUTH`'s one entry ("9072"). Report only, no
code changed.** Traced via `git log --follow -- bridge/matcher.py` and reading every commit's full
diff:

- The entry (account `"9072"`, `cert_hash` = the real cert SHA-256 of a real analyzed APK) was
  introduced in commit `79e3a39` ("Fix: reproducible test fixture (Raghav's input-path blocker)...").
  `bridge/confusion_matrix_validation.py`'s docstring independently confirms the APK side's
  provenance: `REFERENCE_APK_ANALYSIS` is explicitly "the real analyzed sample Raghav sent" —
  i.e. the PS1 owner supplied a real APK's real static-analysis output to the Bridge author.
- The account-ID side is less clear. The same commit appended exactly two new records to
  `bridge/test_fixtures_ps2_sample.json` — accounts `"9072"` and `"9080"` — on top of an existing
  fixture (from `fdcb1b8`) that was simply the first 200 sequential account IDs ("1".."200"), not
  a curated sample. Only `"9072"` of the two new accounts was then hand-wired into
  `SYNTHETIC_LINKAGE_GROUND_TRUTH`. No comment, docstring, or commit message anywhere states *why*
  `"9072"` (vs. `"9080"`, vs. any other account) was the one chosen.
- **Directly checked both accounts' true fraud label in `DataSet.csv`: both `"9072"` and `"9080"`
  are fraud (`F3924=1`).** Investigating why, found something that reframes the whole question:
  **all 81 fraud rows in `DataSet.csv` are perfectly contiguous at the tail of the file — indices
  9002-9082, no gaps, no interleaving with non-fraud rows anywhere in that range.** (Checked
  directly: `df[df.F3924==1]['idx'].tolist()` is exactly `[9002, 9003, ..., 9082]`.) Since
  `ps2_bridge_payload.json`'s `account_id_raw` is literally `df.index` with no shuffling, *any*
  record grabbed from near the end of that export is fraud with near-certainty — 81 of the last ~82
  rows are fraud. Picking "a couple more accounts past the first 200" from that region of the file
  would land on fraud regardless of whether the fraud label was ever consulted.
- Separately, `bridge/confusion_matrix_validation.py` (a larger, methodologically distinct
  validation exercise, same PR) builds its own 100-account ground truth via
  `random.seed(42); random.shuffle(account_ids)` over real PS2 IDs, assigning the known-good
  cert_hash/C2 to the first few *after* shuffling — explicitly, per its own docstring, "avoids a
  trivially-true-by-construction test." This shows the team's stated practice elsewhere leans
  against label-based cherry-picking, but that script's ground truth is a separate, local
  construction — it does not feed `SYNTHETIC_LINKAGE_GROUND_TRUTH`.
- **Conclusion, stated as a conclusion and not stronger than the evidence supports**: it cannot be
  determined from the repo whether "9072" was chosen because its fraud label was already known, or
  for an unrelated reason (e.g. simply the next two IDs past the original 200-row fixture) with the
  fraud match discovered afterward. The two are not distinguishable from available evidence. What
  *can* be said: given the tail-clustering fact above, landing on a fraud account from that region
  of the file was near-unavoidable regardless of intent, which weakens (without fully resolving)
  the concern that the match is meaningful evidence of anything beyond "the demo fixture was built
  from the tail of a label-sorted file." The prior session's phrase "independently confirmed real
  fraud" is not false — this session verified `F3924=1` for account 9072 by an entirely separate
  method (direct pandas read of `DataSet.csv`, not by reading `matcher.py`) — but it should not be
  read as strong evidence of the bridge matcher's quality, given how easy that outcome was to reach
  by construction. The tail-clustering itself is a new, previously-undocumented data-quality fact
  about `DataSet.csv` worth keeping in mind for any future work that assumes row order carries no
  information.

**Discrepancies flagged against this task's brief, not silently resolved:**
- The brief states data lives at `data/DataSet.csv`; it is still at the repo root
  (`DataSet.csv`), matching `train_ps2_model.py`'s existing default path. Used the actual location;
  did not move the 116MB file.
- The brief assumed Chart.js was still CDN-loaded (Task G) and that the published 0.4114/0.9572
  came from seed 0 (Task C) — both checked against the repo and found otherwise; corrected rather
  than silently complied with.

**What was not done, and why:**
- No PS2 hyperparameter was tuned anywhere in this session, per instruction — Task C's 20-seed
  study exists to characterize variance, not to pick a better-looking seed.
- Task D's real counterfactual was scoped, not implemented, per explicit instruction ("I decide").
- The real `ollama.service` was never stopped (no root) — Task B's degradation proof used an
  env-var redirect verified to hit the identical exception path; disclosed above, not glossed over.

Commits this session (in order): `077ad92` (Task A), `0fabb77` (Task B), `b455d7f` (Task C),
`e060321` (Task D), `581a6c7` (Task E), `bbfa58e` (Task F), `b901014` (Task G). Task H is
report-only, no commit. This entry is the eighth. Backend was started/stopped repeatedly for
measurement and is not left running at session end; the real `ollama.service` was never modified
and is unaffected by anything in this session.

## 2026-08-11 (correction, not a rewrite) — retracting the "9072 corroborates the bridge" framing

This is a correction appended to the record, not an edit of any prior entry — the entries above
this one are left as originally written, per instruction.

**Retracted claim**: the previous entry (Task A, line ~432 above: "produced exactly 1 link on
account `"9072"` — independently confirmed real fraud") and this session's own Task H writeup used
account 9072's true fraud label (`F3924=1`) as if it were meaningful corroboration that the bridge
matcher works. Given Task H's own contiguity finding in that same writeup — all 81 fraud rows in
`DataSet.csv` are contiguous at the file tail (indices 9002-9082) — grabbing almost any record from
that region of the file lands on fraud regardless of intent. The label corroborates nothing about
match quality; it was never independent evidence, because the account was drawn from a region of
the file where a fraud label was the near-certain outcome. The phrasing was not factually false
(the label really is F3924=1, verified by direct read of DataSet.csv) but it was being used as if
it supported a claim it cannot support, which is the part being retracted here.

**What survives, unretracted, because it doesn't depend on account 9072's label at all**:
- `matcher.py` performs exact-match linkage on cert_hash / C2 host (`match_account_to_apk()`,
  `extract_ioc_from_ps1()`) — real code, real matching logic, unaffected by this correction.
- It is unit-tested against near-miss confounders in `bridge/confusion_matrix_validation.py`:
  TP=10, FP=0, FN=0, TN=90 against 100 real PS2 account IDs with a *randomly assigned* (seeded,
  shuffled, independent of true fraud label) synthetic ground truth — this is a unit-level test of
  the matching logic's precision/recall on synthetic linkage, not a measurement of real-world
  accuracy, and is not described as accuracy anywhere in that file (checked directly — the word
  "accuracy" does not appear in `bridge/confusion_matrix_validation.py`).
- One end-to-end demo linkage runs from a genuinely analyzed APK sample (`REFERENCE_APK_ANALYSIS`
  in `confusion_matrix_validation.py`, its own docstring: "the real analyzed sample Raghav sent")
  through the real matcher against a real dataset scoring run, and produces a real (not
  hand-simulated) HTTP response. The account's fraud label is not part of that claim and is
  dropped from it here.

**Scope of the retraction, checked exhaustively**: grepped the full repo (`.py`/`.md`) for "9072",
"independently confirmed", "confirmed real fraud", "coincidence", "corroborat", and "accuracy"
near bridge/confusion-matrix code. The live application code (`setuguard_app/backend/app.py`'s
`/api/bridge` `note` string, `bridge/matcher.py`'s comments, `bridge/confusion_matrix_validation.py`
in full) was already clean — none of them ever claimed 9072's label as evidence; that framing only
existed in this SESSION_LOG's own prior-session narrative text, corrected here. No source file
required a code change for this task. `FROZEN_FILE_FINDINGS.md`, `PS1_Defects_and_Improvements.md`,
`SetuGuard_Development_Roadmap_v2.md`, `CONTEXT.md`, `idea.txt`, and `setuguard_app/README.md` were
also checked and contain no such claim.

## 2026-08-11 (continued) — final evidence pass before the report (Tasks 1-5)

Scope: close the recall@k variance hole the same way the AUCPR/AUROC hole was closed; sweep the
whole repo for positional/row-order leakage given the tail-contiguity finding; retract the
9072-corroborates-the-bridge framing everywhere it actually appears (not just in the SESSION_LOG);
document the contiguity fact where a rebuilder would find it; and make sure the committed metrics
artifacts *and the live API* lead with the distribution, not one favorable seed. No PS1 frozen file
touched (confirmed via `git log --name-only` over this session's commits). No PS2 hyperparameter
tuned, and the seed used to produce the shipped artifact (`train_ps2_model.py`'s default, 42) was
not changed anywhere.

**Task 1 — recall@k across all 20 seeds.** Extended `harness/ps2_repeated_splits.py` so every
seed's own holdout (not just one) yields recall/precision/lift at top-1%/top-5% by score, using the
same fixed hyperparameters as before (copied verbatim from `train_ps2_model.py`; no tuning).
Command: `systemd-run --user --scope -p MemoryMax=4G -p MemoryHigh=3G -- python3
harness/ps2_repeated_splits.py`. Result (median [IQR], n=20 seeds):
top 1% (~18 accounts): recall 25.0% [18.8-37.5], precision 22.2% [16.7-33.3], lift 25.2x
[18.9-37.9]; top 5% (~91 accounts): recall 53.1% [43.8-62.5], precision 9.4% [7.7-11.0], lift 10.6x
[8.7-12.5]. Wide, reported as wide — top-1% recall alone spans 6.2%-62.5% across seeds. seed=42 (the
shipped artifact's actual training seed, fixed before this evaluation, not chosen afterward) located
by percentile in every one of these distributions, not just AUCPR/AUROC: top-1% recall/precision/
lift all sit at the 55th percentile (close to typical); top-5% recall/precision/lift all sit at the
90th percentile (a favorable draw, consistent with the AUCPR/AUROC finding, though less extreme at
top-1%). Full per-seed table with each seed's own operational curve in
`models/ps2_repeated_splits_metrics.json`. 21 fits, 4.7s wall clock, 270MB peak RSS.

**Task 2 — row-order leakage sweep.** Grepped `harness/`, `setuguard_app/`, `ps2/01-07`, `bridge/`
for `.head()`/`.tail()`/`nrows`/`skiprows`/literal `.iloc[]` ranges/bracket `[:n]`/`[-n:]` slicing/
`.sample()` without a seed/`.index` used as a feature or split key/`read_csv` calls that only read
part of the file. Findings, each individually checked (not pattern-matched and assumed):
- `ps2/01_data_audit.py`, `02_baseline_model.py`, `05_ulb_validation.py`, `06_graph_features.py`:
  all `.iloc[train_idx]/.iloc[test_idx]` come from `StratifiedKFold(shuffle=True, random_state=42)`
  — read the actual `skf.split()` call in each file, not assumed from context. Genuinely shuffled,
  not a leak.
- `ps2/06_graph_features.py:109-110`: `sorted_graph_df.iloc[:n_fraud]` assigning top-betweenness
  nodes to fraud rows — this IS the already-documented `map_graph_features_to_dataset()` leak
  (`ps2/README.md`, Task F of the prior session). Not a new finding; cited here for completeness
  since it matched this sweep's `.iloc[]` pattern.
- `ps2/02_baseline_model.py:207`: `"account_id": df.index` — uses row position as an output
  identifier (not a model feature; `X` never includes it). This is the actual mechanism behind Task
  H's finding from the prior session: `df.index` flows unchanged into `baseline_predictions.csv` →
  `ps2_bridge_payload.json` → `test_fixtures_ps2_sample.json` → `matcher.SYNTHETIC_LINKAGE_
  GROUND_TRUTH`'s key space, which is why any account ID drawn from the file's tail is fraud. Not a
  training-time leak (nothing here affects a model's inputs), but it's the structural reason the
  tail-contiguity fact (Task 4) matters downstream. `ps2/` is declared research-only; not fixed,
  per instruction — flagged, not silently passed over.
- `ps2/03_amlworld_risk_spike.py`, `04_dice_counterfactuals.py`: positional-looking calls
  (`.sample(frac=..., random_state=seed)`, `.head(10)` on a score-sorted frame) checked directly —
  operate on the external AMLworld Kaggle dataset or on score-sorted output, not on `DataSet.csv`
  row order. Not a leak.
- `bridge/dice_practice.py:35`: `X.iloc[[1]]` — checked what `X` is: an 8-row hand-typed toy
  dataframe ("fake toy dataset (stand-in for real PS2 data)", the file's own comment), not
  `DataSet.csv`. Not a leak.
- **Live path — confirmed clean, not by assumption**: `harness/train_ps2_model.py` and
  `harness/ps2_repeated_splits.py`'s `train_test_split(X, y, test_size=..., random_state=..., 
  stratify=y)` calls were checked against sklearn's actual source
  (`inspect.getsource`/signature, not the function name): `shuffle` defaults to `True`, and
  the docstring states shuffle must be `True` for `stratify` to be used at all — genuinely
  randomized. `setuguard_app/backend/app.py`'s `/api/analyze_dataset` uses a detected id column
  only as a display label (`account_hash`), never as a model input (`_encode_ps2_features` only
  ever pulls `BANK_FINALIZED_FEATURES`). `bridge/matcher.py`'s matching is IOC-based (cert_hash/
  C2 host), not positional. No `nrows`/`skiprows`/positional-row-limiting read anywhere in the live
  path. **No code change was needed or made in the live path this task — reported as clean, with
  what was checked, not left silent.**

**Task 3 — retraction.** See the dedicated correction entry above ("retracting the '9072
corroborates the bridge' framing") for the full writeup: swept `.py`/`.md` repo-wide for
"independently confirmed", "9072", "coincidence", "corroborat", and "accuracy" near confusion-matrix
code; the only occurrences of the retracted framing were in this SESSION_LOG's own prior entries
(corrected via that new entry, prior entries left unedited, per instruction); the live application
(`app.py`'s `/api/bridge` note, `matcher.py`'s comments, `confusion_matrix_validation.py` in full)
never made the claim in the first place, so no source file needed a change for this task.

**Task 4 — documented in `ps2/README.md`**: all 81 fraud rows occupy indices 9002-9082
contiguously, row order encodes the target, and every reported PS2 result comes from a genuinely
shuffled stratified split (cross-referencing Task 2's sklearn-source check).

**Task 5 — metrics artifacts and the live API now lead with the distribution.**
`models/ps2_repeated_splits_metrics.json` gets a new `"headline"` block (median [IQR] for AUCPR,
AUROC, and all four Task-1 recall/precision/lift figures) positioned first in the file, before the
raw per-seed table and the `seed_42_reference` block. `models/ps2_xgb_v1_metrics.json` (the
single-split artifact) gets a new `"single_split_caveat"` field pointing at the distribution file —
added by editing `train_ps2_model.py` and re-running it; the model artifact itself is confirmed
byte-identical (md5) and `holdout_metrics` numerically unchanged, only the new field was added.

The live API had its own uncaught instance of this exact problem: `/api/analyze_dataset` was
returning the single seed=42 `holdout_aucpr`/`cv_aucpr_mean` (0.4114) with zero distribution
context — literally the number the dashboard's "CV AUCPR" stat tile displays to a judge.
`app.py` now loads the repeated-splits file at startup (optional, falls back with a clear note if
absent) and reports the **20-seed median** as the headline `holdout_aucpr`/`cv_aucpr_mean`, carrying
the full distribution (`holdout_aucpr_distribution`/`holdout_auroc_distribution`) and the
single-split reference (`holdout_single_split_reference`, seed noted explicitly) alongside rather
than dropping them. Verified via `harness/browser_smoke.js --label task5_verify`: PASS, zero console
errors, and the dashboard's CV AUCPR tile now visibly reads "0.271" instead of "0.411"
(`harness/browser_evidence/task5_verify/02_dataset.png`).

Grepped the repo for the literal strings `0.4114` and `0.9572` (all file types, then narrowed to
`.py` after confirming no `.md`/`.js` hits beyond `SESSION_LOG.md` itself). Every occurrence and its
disposition: `setuguard_app/backend/app.py` was a live headline number — fixed, as above.
`models/ps2_xgb_v1_metrics.json` is a legitimate per-seed data point (it IS seed 42's own
`holdout_metrics`) — left in place, now pointing at the distribution via `single_split_caveat`.
`models/ps2_repeated_splits_metrics.json`'s `seed_42_reference` block and
`harness/ps2_repeated_splits.py`'s docstring/note string: legitimate, already correctly labeled as
"this seed's numbers, located by percentile" — left as-is. `SESSION_LOG.md`'s own prior entries
(this session's earlier "Task C" and "Task H" writeups): historical record of what was measured and
reported at the time — per the same not-rewriting-old-entries principle established in Task 3, left
as originally written rather than edited; flagged here as a judgment call applied consistently
across both tasks, not decided differently in each.

**What was not done, and why:**
- `ps2/01-07` were not modified anywhere in this session — declared research-only, checked and
  reported on (Task 2), not fixed, per explicit instruction.
- No hyperparameter was tuned, and `train_ps2_model.py`'s default seed (42, the one that produced
  the shipped artifact) was not changed — the whole point of this session was to characterize its
  variance honestly, not to pick a different, better-looking seed.
- SESSION_LOG.md's own prior entries were not rewritten (Tasks 3 and 5 both touch this) —
  corrections were appended instead, consistent with the instruction given for Task 3 and extended
  to Task 5 by the same reasoning.

Commits this session (in order): `9432612` (Task 1), Task 2 (report-only, no commit), `0d12997`
(Task 3), `1f1ad44` (Task 4), `81c73ab` (Task 5). This entry is the tenth in the file. Backend was
started/stopped repeatedly for measurement during this session and is not left running at session
end; the real `ollama.service` was not touched this session.

## 2026-08-17 / 2026-08-18 — global `STATE` replaced with addressable analysis ids (bridge inputs)

Full design spec: `ANALYSIS_ID_MIGRATION.md`. Summary here for the narrative record.

**Problem, found before writing any spec:** `setuguard_app/backend/app.py:107` held a single
module-level `STATE = {"last_apk": None, "last_dataset": None}`, written by
`/api/analyze_apk`/`/api/analyze_dataset` and read directly by `/api/bridge`, which parsed no
request body at all. The bridge therefore joined whichever two artifacts were uploaded most
recently by anyone, not two named artifacts — unevaluable over a set of pairs, and silently
wrong under either a concurrent request or a stray demo-day upload. Checked, not assumed: Flask
3.1.1's `Flask.run()` does `options.setdefault("threaded", True)` (read directly from the
installed source via `inspect.getsource`), and this app's `app.run(...)` at line 805 sets no
explicit `threaded=`, so the concurrency race is real, not theoretical.

**A spec was written for this migration (2026-08-15 pasted content) before `app.py` had been
read.** Its own Section 0 listed five assumptions to verify first. All five were checked against
the real code on 2026-08-17 and held, with one correction: the file is
`setuguard_app/backend/app.py`, not top-level `app.py` as originally assumed — every path in the
spec was corrected accordingly before any code was written. The corrected spec, with Section 0
replaced by the verified results, was saved as `ANALYSIS_ID_MIGRATION.md` (it hadn't existed as a
file before — the original spec was message text only).

**Split into two batches, deliberately, at the user's instruction — not into one continuous run:**

*Batch A (2026-08-17), additive only:* a lock-guarded, bounded `OrderedDict` store
(`store_analysis`/`get_analysis`/`latest_analysis`, cap 64, TTL 3600s, ids `apk_<8hex>`/
`ds_<8hex>`) added above `STATE`. `/api/analyze_apk` and `/api/analyze_dataset` gained
`analysis_id`/`kind` on their existing responses. `/api/bridge` was rewritten to resolve
`apk_id`/`dataset_id` from the new store (explicit → validate prefix → 400 `malformed_id` if
wrong; well-formed but unknown/expired → 404 `unknown_analysis`; absent → fall back to
`latest_analysis`, 409 `no_analysis_available` if none exists) and to echo an `inputs` block
(`id`, `label`, `source`) in its response. `STATE` and both its writes were deliberately left in
place through this batch, unread by the rewritten bridge, specifically so a bug in the new
resolution logic could be undone by reverting `bridge_endpoint` alone. Verified by live curl
against a running server (five checks: analyze_apk/analyze_dataset carry ids with all prior
fields intact; bridge with `{}` resolves both operands `"source": "fallback"`; bridge with
explicit ids resolves both `"source": "explicit"`) — the human-in-the-loop acceptance check the
user required before authorizing Batch B, run and confirmed by the user, not just reported as
"looks fine" by the assistant.

*Batch B (2026-08-18), the irreversible half:* `STATE` and both remaining writes deleted.
`grep -rn "STATE" setuguard_app --include=*.py` returns zero hits post-edit (the only other
repo-wide hits, in `setuguard_ps1/*.py`, are the unrelated `READ_PHONE_STATE` Android permission
string and were not touched). Server restarted; all five Batch-A checks re-run against the
`STATE`-free code and passed with identical results (`apk_ad66cebd`/`ds_99d11a36` in this run's
ids, fallback/explicit sources correct, swapped ids → 400 `malformed_id` with the expected
detail string).

Frontend (`setuguard_app/frontend/app.js`): all four steps shipped, not just 1-2, since they
landed cleanly against the inherited dashboard. `state.lastApkId`/`state.lastDatasetId` are set
from each analyze response; `/api/bridge` now POSTs a JSON body with both ids when non-null
(previously no body at all); the bridge result panel gets a `linked_inputs` line rendering
`inputs.apk.label`/`inputs.dataset.label` plus `source`; error rendering now prefers the
structured `detail` string over the bare error-code slug. Verified end-to-end through the actual
dashboard, not just by reading the diff: driven with Selenium + headless Chromium
(`chromedriver`) against the real frontend (`python3 -m http.server`) and real backend — uploaded
a real APK and `DataSet.csv` through the UI, captured the live `fetch()` call via an injected
wrapper, confirmed the outgoing `/api/bridge` body was
`{"apk_id":"apk_24653c9a","dataset_id":"ds_c3367af9"}` and the rendered panel showed
`linked_inputs apk=com.sms.google (explicit) dataset=DataSet.csv (explicit)`. Zero links for that
particular APK/dataset pair — expected, per the bridge's own note text, for a synthetic ground
truth that doesn't cover most pairs; not a bug.

**Documentation-scope correction, not silently resolved:** the migration's own §7 said to log the
finding in `FROZEN_FILE_FINDINGS.md`. That file (`setuguard_ps1/FROZEN_FILE_FINDINGS.md`) states
its own scope in its first paragraph: unfixed defects *inside* the six frozen files, held for
team sign-off before anyone touches them. This migration touches no frozen file and was applied,
not sign-off-gated — appending it there would have misrepresented both the finding and the
document. Surfaced to the user rather than guessed past; resolved as: full writeup here (this
entry), plus a one-line, clearly-labeled cross-reference in that file's Status section pointing
back to this entry and to `ANALYSIS_ID_MIGRATION.md`, so a reader of the frozen-file findings
doesn't wonder if the migration was silently dropped.

**Branch discrepancy, also surfaced rather than guessed past:** the Batch-B task brief assumed
work was happening on a branch `fix/analysis-id-store`. It never existed — Batch A and the start
of Batch B were both done directly on `main`, uncommitted, alongside unrelated pre-existing
uncommitted/untracked files in the working tree (`STUDY_GUIDE.md`, `harness/download_run.log`,
etc.) that predate this migration and are not part of it. Handled by branching from the current
`main` HEAD (which carries the uncommitted work forward) and staging only the migration's own
files into the first commit on that branch, leaving the unrelated files uncommitted and untouched
either way.

**Not changed by this migration, restated:** the bridge still rests on one synthetic
cert-hash/C2-host linkage (`matcher.SYNTHETIC_LINKAGE_GROUND_TRUTH`); `shap_drivers`/
`generated_rules`/`rule_validated` hardcoding in the PS2 exporter; the unused `bridge/matcher.py`
surface outside its one real `/api/bridge` call site; the non-functional bridge validation
script; the Play-signed allowlist. Also explicitly out of scope for this session per the task
brief and not touched: `account_hash` being a row ordinal rather than a hash,
`cv_aucpr_mean`/`n_cv_folds: 0` co-reporting, missing-space string-concatenation typos in
rendered text, and the absolute-path leak in `raw_features.apk_path`.

No file under `setuguard_ps1/` was edited to produce or verify this migration. No analysis logic,
scorer behavior, model artifact, or metric was changed — this migration is additive
(`analysis_id`/`kind`/`inputs` fields) plus one deletion (`STATE`), nothing else.

## 2026-08-19 — Day 1 of FINALE_PLAN_AND_AUDIT.md: truth reconciliation

**Schedule note:** the plan dated this Day 1 as 18 Aug. That slot instead went to the
`CONTEXT.md` resync and the analysis-ID migration (`ANALYSIS_ID_MIGRATION.md`). Ran Day 1
compressed today (19 Aug), ahead of tonight's Day 2 defects. Slip absorbed out of Day 1's
own slack, not out of Day 6/7 — see the standing corrections doc for the recommendation.

**Task 1 — resolved n for 0.1444.** From `harness/BANKING_AUC_RESULTS.json`, the sole
authority: PRIMARY AUC 0.1444 [0.0905, 0.2081] was computed over **51 packages / 32 issuer
clusters** (53 current-arm packages / 33 issuer clusters attempted; `com.Version1`, Punjab
National Bank, and `com.janabank.mtc`, Jana Small Finance Bank, timed out during extraction,
dropping PNB's issuer cluster). SECONDARY AUC 0.3190 [0.2202, 0.4290] over **20 packages / 16
issuer clusters** (era-matched arm, no extraction failures). Neither the 68/47 corpus count
nor the 73/53/33 Tier-A-attempted count is the scored n — both are one step removed and must
never sit next to 0.1444. `REPORT_FACTS.md` and `CONTEXT.md` §2/§8 updated to state this once,
consistently.

**Task 2 — void-number purge.** Grepped the repo for the eight banned strings/numbers;
28,527 raw hits across dozens of files, mostly `ps2/raw_graph_features.csv` and
`ps2/ps2_bridge_payload.json` (both dead in the live path — zero import hits from
`setuguard_app/` or `bridge/`, per `CONTEXT.md` §2) plus already-corrected documentation
(`PLAN.md`, `STUDY_GUIDE*.md`, `docs/evidence/`) that carries the void-number explanation
as its own content. Scope gate applied per the plan (>40 hits): fixed the two named
stage-breakers and left the rest as deliberate residue.

- `bridge/test_fixtures_ps2_sample.json`: stripped `model_version`, `shap_drivers`
  (carrying the withdrawn `graph_betweenness` SHAP driver), `counterfactual`,
  `generated_rules`, `rule_validated` from all 202 records. Confirmed via
  `bridge/matcher.py:115-118` (`load_ps2_accounts` returns `payload["records"]` wholesale)
  and `match_account_to_apk` (only ever reads `account_id_raw`) that none of the stripped
  fields were read by any code path — dead weight, safe to delete outright rather than
  estimate a replacement. Re-ran `bridge/confusion_matrix_validation.py` after the edit:
  TP=10/FP=0/FN=0/TN=90, unchanged.
- `SESSION_LOG.md` (this file, ~line 462, Task 3 of the earlier bridge-migration entry):
  the "produced exactly 1 link on account 9072 — independently confirmed real fraud... not
  a coincidence" text is left verbatim per this log's own no-rewrite convention (the
  retraction below it, "2026-08-11 (correction, not a rewrite)", already explains why).
  Added an inline forward-pointer immediately after the risky sentence so a judge reading
  top-to-bottom hits the retraction pointer at the point of risk, not 250 lines later.

Residue, left dirty and named rather than silently skipped: `ps2/raw_graph_features.csv`,
`ps2/ps2_bridge_payload.json`, `ps2/06_graph_features.py`, `ps2/07_ps2_bridge_exporter.py`
(all dead-path, `ps2/README.md` already says so); `harness/*` log/manifest/cache files
containing `97.9`-substring matches that are unrelated numbers, not the false-positive
figure; untracked scratch files `STUDY_GUIDE.md` / `STUDY_GUIDE_GAPS.md` (not committed,
not something a judge browsing the repo would see, not inspected further today).

**Task 3 — README and frontend copy.** `setuguard_app/README.md` fully rewritten: the
"Ollama-down falls back to rule-based" framing (exact inverse of the d1-inversion) and the
"PS2 trains XGBoost with stratified CV, auto-detects the label column" framing (PS2 is
inference-only against a committed artifact) are gone, replaced with the verified
`_try_llm_narrative()`/`verdict_source` mechanics and a stated PRIMARY AUC 0.1444 result.
Frontend: removed "real XGBoost + SHAP trained on your data", "Run Data Audit + Train",
"CV AUCPR (0-fold)" (relabeled "Holdout AUCPR (20-seed median)" — the backend's own comment
at `app.py:735-742` already flagged the label as stale while the underlying value was
honest), the fabricated Compliance-page bias-check/KS-drift/greedy-counterfactual rows, and
the dead `counterfactual` column (always `null` server-side per `app.py:680-681`, dropped
from both `app.js` render calls). Fixed a "Confidence" column header that was actually
rendering `risk_score`, and one backend-side user-facing string
(`app.py`'s `_family_guess`) still calling the evidence-weighted score "confidence".

**Carry-over from 18 Aug, verified already resolved:** `app.py`'s `dict(resp)` copy-before-
store at both `store_analysis` call sites, and `CONTEXT.md` §8's AUC numbers against
`BANKING_AUC_RESULTS.json` — both landed in commit `ad361b2` before this session started.
No action needed; confirmed by reading, not re-done.

**Day 2 tonight:** none of D-4/D-5/D-8 started. Day 1 ran the full ~5h today (schedule
compression absorbed the slip); Day 2's three crash-path defects begin as originally
scheduled, not early.

## 2026-08-19 (continued) — pre-commit gate for Day 1's uncommitted work

Second session same day. Day 1's 8 modified files were sitting uncommitted. This session
gates them: audits, a judge-visible-surface re-sweep at threshold 1, a fixture-consumer
check, browser re-verification, doc updates, then commit.

**T1 — submitted-report n audit: BLOCKED, not silently skipped.** Searched the repo
(including `git log --all --diff-filter=A --name-only` for any `.tex`/`.pdf`/`.docx` ever
tracked) and the home directory tree, including `/home/raghavp/setuguard-incoming/` (a
sibling copy of the pre-integration app zips, not a report). No submitted-report source
exists anywhere searched. Asked the user for the path; not yet supplied as of this entry.
`REPORT_ERRATA.md` not created — nothing to compare against yet. Prepared-answer slot for
this left as "pending" in `FINALE_PLAN_AND_AUDIT.md`'s new hostile-Q&A section.

**T2 — judge-visible surface sweep, threshold 1.** Scoped to `setuguard_app/`, `demo/`,
and every `README.md` in the repo. Found and fixed one real live-code bug beyond the
explicit banned-string list: `app.py`'s `/api/bridge` endpoint hardcoded
`"Matching is on certificate hash / C2 host overlap only"` into the `note` field of
**every** bridge response — a present-tense capability claim `REPORT_FACTS.md` explicitly
bans, baked into the live product (not just prose), rendered verbatim on the frontend
Bridge page (`app.js:282`) and captured in `demo/match_03_bridge.json` /
`demo/nomatch_03_bridge.json`. Fixed at the source (`app.py`'s `note` string and its
module docstring) and in `demo/DEMO_RUNBOOK.md`'s "Honest framing" section, which had the
identical phrase. Re-verified live via browser re-run (T5) — the corrected text now
renders on the actual page, screenshotted. All eight explicitly-listed banned
figures/terms returned zero hits on the judge-visible scope.

**T3 — fixture consumer check.** Grepped the fixture filename repo-wide: two real
consumers, `bridge/matcher.py:147` (its own `__main__` smoke test) and
`bridge/confusion_matrix_validation.py:240`. `bridge/dice_practice.py` does not reference
the fixture at all — standalone toy script, unrelated. Both real consumers re-run clean
after Day 1's field-stripping edit; confusion matrix unchanged: TP=10/FP=0/FN=0/TN=90.

**T4 — untracked scratch files.** `STUDY_GUIDE.md` and `STUDY_GUIDE_GAPS.md` added to
`.gitignore` (not deleted). Confirmed via `git status --ignored`.

**T5 — browser re-verification: blocking, and it found a real pre-existing bug in the
test harness itself.** First two runs both failed the same way: step 1 (`analyze_apk` on
the matching-cert APK) exceeded `browser_smoke.js`'s 60000ms client-side wait, cascading
to step 3's bridge-match failing with a 409 (no APK analysis id yet). Confirmed this is
unrelated to Day 1's edits — full diff review shows nothing touches the `analyze_apk`
code path, and the 60000ms constant is unchanged in git history. Root-caused via direct
timing: this specific APK (`cicmaldroid_banking/007556ca...`, matches
`SYNTHETIC_LINKAGE_GROUND_TRUTH`'s only cert-hash entry) measured 46.47s, 61.47s, 162.2s
(original `DEMO_RUNBOOK.md` figure), and 162.74s across direct measurements taken today —
wide variance driven by Ollama/RAG narrative latency, not file size or DEX-analysis cost.
All four measurements are 5–16x higher than the ~9.86s hand-written spot-check
`SESSION_LOG.md:486` records for this exact file (already flagged unverified, `CONTEXT.md`
§7 U1) — today's evidence sharpens that flag considerably.

Checked for a fixture swap first (smaller APK sharing the same signing cert, so the
harness could pass at the original 60000ms with no edit): wrote a cert-only extraction
scan (`androguard.core.apk.APK`, not the full `AnalyzeAPK` — confirmed ~0.01s/file since
it skips DEX disassembly entirely) across all 2489 `cicmaldroid_banking/` files. Zero
siblings share `007556ca`'s certificate SHA-256. No swap available.

Bumped `harness/browser_smoke.js`'s `APK_ANALYSIS_WAIT_MS` (renamed from a bare 60000
literal used at two call sites) to 250000ms, with an inline comment carrying the
provenance measurements. Also applied it to the previously-passing step 4
(non-matching APK) after that step started failing intermittently once step 1 was
allowed to run to completion — a direct sequential replication (matching apk → dataset →
bridge → non-matching apk, same memory cap) measured the non-matching APK at 46.47s
alone, confirming the same Ollama-latency variance affects it too, just usually staying
under 60s by luck.

Result after the fix, third attempt, label `day1_verify_20260819`: **PASS — zero console
errors, zero uncaught exceptions across all 5 steps.** Verified specifically: the AUCPR
tile reads `0.271` labelled "Holdout AUCPR (20-seed median)" (screenshot,
`02_dataset.png`); the bridge-match note renders the corrected cert-hash-only text live
(`03_bridge_match.txt`/`.png`); zero failed/non-2xx requests across all steps. The
Compliance page is not visited by `browser_smoke.js` at all — verified separately with a
standalone Playwright check (loads `index.html`, clicks Compliance, reads rendered text):
all six rows match Day 1's corrected copy, zero page errors, zero dead columns.
Screenshot taken, not committed (one-off check, not part of the standing evidence set).

Added a "Timing risk" section to `demo/DEMO_RUNBOOK.md` recommending the matching APK be
pre-run before judges arrive, given the 46–163s range is real stage dead-air risk
independent of the harness fix.

**T6 — doc updates.**
- `REPORT_FACTS.md`: added the exclusion-bias entry for the two 600s extraction timeouts
  (`com.Version1`/PNB, `com.janabank.mtc`/Jana SFB — confirmed exact 600.0s/600.2s
  timeouts from `extract_tier_a_run.log`, not crashes). Argued the upward-bias direction
  from the scored population's own quartiles (q1=0.94, median=1.0) rather than the
  originally-proposed "size tracks permission breadth" mechanism, which the extraction
  log actively contradicts: `com.janabank.mtc` (37.3MB) timed out while same-size peers
  (35–40MB) extracted in single-digit-to-tens of seconds, and `com.Version1`'s 138.7MB
  build timed out while 132MB/142MB neighbours took 13–22s. Also could not verify "four
  apps at the score cap" — no per-app results file exists locally
  (`harness/results_banking_legit.csv` was never produced). Wrote the entry on only the
  verifiable parts and said so explicitly rather than asserting the stronger, unverified
  version.
- `FINALE_PLAN_AND_AUDIT.md`: added two hostile-Q&A entries (timeout-exclusion bias
  direction; the 46–163s demo-timing question) in the format Day 9's drill already
  expects. Left the report-n-discrepancy slot marked pending T1.
- `CONTEXT.md`: §2 n-ambiguity note added pointing at the resolved 51/32 and 20/16
  figures; §6 D-1/D-2 marked resolved, D-7 marked partially resolved (live fixture fixed,
  `ps2/` dead-path copy not); §7 C7/C8 marked resolved, C9 partially resolved, C10's line
  reference corrected for drift.
- `ps2/README.md`: `raw_graph_features.csv` and `ps2_bridge_payload.json` were referenced
  only indirectly before; named explicitly now, alongside the scripts that produce them.

**T7 — commit.** See the commit log below this entry for the resulting four commits.

## 2026-08-19 (continued, third session same day) — issuer-cluster integrity + report provenance

**Priority 0 — issuer-cluster integrity: checked, no effect, interval stands.** Full
finding and decision-rule application recorded in `harness/PREREGISTERED_BANKING_AUC_CLAIMS.md`'s
new 2026-08-19 dated section (appended, original text unchanged). Summary: the real risk
was confirmed real at the raw-certificate level — 27 of ~73 Tier A files carry cert
issuer "Google Inc." (Play App Signing) — but `harness/score_banking_corpus.py` (the
actual producing script) never reads that field; it clusters on a manually-researched
bank-identity label from `harness/banking_packages.csv`, built 13-14 Aug specifically
because `harness/BANKING_PACKAGE_TIERING_DECISIONS.md` already flagged same-issuer
clustering as a risk before any scoring ran. Reconstructed the assignment (not stored in
`BANKING_AUC_RESULTS.json`, only the count is) by importing and running
`score_banking_corpus.py`'s own `load_manifest()`/`load_banking_scored()` read-only:
reproduces 51/32 and 20/16 exactly, largest cluster 3 packages, zero Google-labelled
clusters in either scored population. Decision rule's "≤3 packages" branch applies, more
strongly than its own threshold (0 packages, not merely ≤3). No recomputation performed.
Caught and corrected my own error mid-check: an early draft of the pre-registration
amendment claimed none of `BANKING_PACKAGE_TIERING_DECISIONS.md`'s five `VERIFY`-flagged
packages were in the scored sets; checked by name against the cluster tables and found
two are (`com.infra.aryavartupi`, PRIMARY only; `com.lcode.clabmbanking`, both arms) —
both singleton clusters so neither can be merging distinct banks, but corrected before
committing rather than leaving the wrong claim in a pre-registration file.

**Priority 1 — report provenance: partially resolved, portal check still needed.**
`~/Downloads/` holds four `setuguard_report*.pdf` files. `pdfinfo`'s `CreationDate`
(actual TeX compile time) tells a different story than filesystem mtime (download
time): three real compiles exist, not four — 16 Aug 13:33 (6pp, original; `(1)` is a
byte-identical re-download of this same compile, not a new version), 16 Aug 19:19 (6pp,
~500B larger — this is `(2)`'s actual content, downloaded 17 Aug 12:24), and 17 Aug
13:34 (5pp — `(3)`, downloaded immediately). The true gap between the last 6-page
compile and the 5-page one is **~18 hours, not 71 minutes** — the 71-minute figure
compared download times, not compile times, and was misleading.

Extracted text from `(2)` and `(3)` via `pdftotext -layout` and diffed. Initial read
looked alarming (near-total diff, section IV and IX headings missing from `(3)`'s
roman-numeral sequence). On inspection this is a full retypeset into a denser two-column
format (page count dropped 6→5 despite `(3)` having MORE extracted text lines than
`(2)`, 362 vs 334) — not a content cut. Every substantive section's content was found
present in `(3)`, including the full Limitations/Threats-to-Validity section (missed on
first grep due to two-column text-extraction ordering, found on a second, more careful
search) and the full Evaluation Methodology content (merged into section III without
its own heading, rather than deleted). One genuine defect found: `(3)` still reads "the
procedural rules in Section 4 exist" — a dangling reference to a section number that no
longer has its own heading after the merge. Real, fixable, cosmetic; not a missing
claim.

**Not resolved: which of these is what the portal/panel actually holds.** No access to
email or the submission portal from this environment — asked the user to check directly.
Priority 2 (claim inventory) and the errata artifact are blocked on this per their own
stated ordering ("only after Priority 1 resolves"). Session paused here per the time-
discipline instruction protecting Day 2's crash-path defects.

## 2026-08-19 (continued, fourth session same day) — Ollama residency fix + banned-string sweep

**Priority 3 — Ollama residency: confirmed and fixed.** Same-APK three-run test, raw
numbers: cold 157.28s, immediately-after 71.81s, after-6-minute-idle 192.8s.
Slow/fast/slow — the residency signature, not inference variance. Root cause: none of
`rag_report.py`'s three Ollama calls (`ollama.embed()` ×2, `ollama.chat()` ×1) passed
`keep_alive`, so Ollama's ~5-minute default idle-unload applied. Fixed by adding
`keep_alive=-1` to all three calls (chosen over `OLLAMA_KEEP_ALIVE=-1` on the systemd
service, which needs root not available here) — logged as Finding 6 in
`setuguard_ps1/FROZEN_FILE_FINDINGS.md` per the frozen-file discipline. Re-measured
after the fix: fresh backend restart, one warm-up call (77.73s), deliberate 6.5-minute
idle (longer than the window that produced the pre-fix 192.8s), then one more call:
**68.27s, not slow.** The idle-triggered reload penalty is gone. What remains: ~46-80s
of genuine embedding+generation compute per call, unaffected by `keep_alive` — a demo
should expect roughly a minute of wait after a proper warm-up, not "instant."
`demo/DEMO_RUNBOOK.md`'s timing-risk section rewritten to describe this as solved with
a documented mitigation, and a warm-up-call step added to the Preconditions checklist.

**Priority 4 — 9.86 banned-string sweep: clean.** Threshold-1 sweep of
`setuguard_app/`, `demo/`, all `README.md` files for "9.86": one hit, in
`demo/DEMO_RUNBOOK.md`'s own timing-risk section, already correctly framed as a
superseded spot-check with the measured range beside it (written this session). Fixed
the related contradiction in `FINALE_PLAN_AND_AUDIT.md`'s Scalability hostile-answer:
it previously said the language model "isn't on the critical path" without qualifying
that this is true of correctness (verdict/confidence never depend on it) and false of
latency as currently shipped (the endpoint waits for the narrative before returning).
Rewritten to state both halves explicitly, per instruction, rather than the
overclaiming single phrase. Also removed the bare "about ten seconds per APK" figure
from that same answer (declined to quote a spot number pending Day 6's harness) and,
separately, flagged — did not resolve — that Day 6's own planning section still cites
"~10s/APK single-threaded," which matches neither real extraction-timing artifact found
this session: `harness/extract_tier_a_run.log` averages 39.6s/APK single-threaded on
the real banking corpus, and the 668-file general-corpus run
(`SESSION_LOG.md:353`) reports 1.20s/APK effective under 4-worker parallelism — a
different measurement, not single-threaded. Left as a sharpened Day 6 item, not
resolved today.

**Session paused after Priority 4.** Priority 2 (claim inventory) and the errata
artifact remain blocked on the Priority 1 portal check, per their own stated ordering.
Time-discipline instruction (protect Day 2) observed — stopping here to report and ask
about the portal check rather than guessing which report version to build the errata
against.

## 2026-08-19 (Day 2, session start) — D-8 characterisation and fix

**Established before building anything, per this session's own discipline.** Exception:
`ValueError: embedded null character`, raised inside `yara.compile(source=yar_text)` at
`app.py:369`. Root cause unchanged from Finding 5 (`setuguard_ps1/FROZEN_FILE_FINDINGS.md`):
`static_analysis.py`'s URL regex captures a trailing NUL byte from Adobe XMP metadata
strings; `yara_gen.py`'s `_yara_escape()` doesn't strip NUL; the poisoned string reaches
the generated `.yar` rule text unmodified.

**Input-dependent, not nondeterministic — n=31 tested** (32 previously-known-affected
filenames from `fix3_fp_baseline/skips.csv`, 1 missing on disk), via the real
`static_analysis.analyze_apk()` -> `app._rule_based_verdict()` ->
`yara_gen.generate_yara()` -> `yara.compile()` chain, Ollama call skipped (verdict/YARA
never depend on it). Result: 19 now score `benign` under the current live scorer (verdict
has drifted since Finding 5 was found; YARA never attempted), 4 hit a **different**,
uncaught defect (corrupt zip in `static_analysis.analyze_apk()` — D-4's territory, not
D-8's), and **8 reached YARA generation, 8/8 (100%) hit the NUL-byte `ValueError`.** Named:
`app.flicky_940.apk`, `app.plugbrain.android_154.apk`,
`com.carriez.flutter_hbb_104070003.apk`, `com.duckduckgo.mobile.android_52850000.apk`,
`com.calmyjane.spacebeam_11.apk`, `app.pwhs.universalinstaller_31.apk`,
`com.absinthe.libchecker_2671.apk`, `com.bald.uriah.baldphone_102.apk`.

**What actually happens when it fires — this is the finding that matters:** it does not
crash. `app.py:368-377` already wraps `yara.compile()` in `try/except Exception`.
Confirmed three ways: (1) my simulation using the exact try/except code, 8/8 caught
cleanly; (2) a real live HTTP call against `app.flicky_940.apk` — **HTTP 200**,
`verdict: suspicious`, `error: None`, `yara.compiles: false`; (3) the frontend
(`app.js:148`) already renders "❌ compile error" in the results heading when this
happens — analyst-visible, not silent. **The "one demo run in five throws" premise does
not hold for the live API.** It held for the offline `fix3_fp_harness.py`, which caught
only `yara.Error` and missed this `ValueError` — a different program's bug, not app.py's.

**What was actually broken, and fixed:** `app.js:107`'s alert-log line unconditionally
said "New YARA rule generated" regardless of `compiles` status — including for the
benign case where no rule was even attempted (`yar_text` is a placeholder comment, not
a real rule). Fixed: the alert now checks whether a real rule was attempted
(`yar_text` starts with `"rule "`) and whether it compiled, firing "New YARA rule
generated" only on genuine success and "YARA rule generation unavailable for this
sample... failed to compile" (badge-medium, matching the fix bar's exact suggested
wording) otherwise. No alert fires for the benign/no-rule-attempted case, matching prior
behavior there (that case already had no misleading claim to begin with, since no rule
text resembling a real rule existed).

**Falsification condition:** any NUL-byte-affected APK producing an HTTP 500, a blank
panel, or a hang specifically from YARA generation would falsify the "already caught"
finding. The alert-log fix is falsified if the Recent Alerts feed still shows "New YARA
rule generated" unqualified for a sample where `compiles: false`.

**Not yet visually verified in a real browser** (only via curl + JSON inspection) — part
of this session's Task 3 verification pass, though `browser_smoke.js`'s own two demo
APKs are not NUL-byte-affected, so a targeted check is needed separately if full
visual confirmation is wanted.

## 2026-08-19 (Day 2, continued) — D-4 and D-5

**D-4 — fail-closed path. Error-path degradation, not a real correction.** Reproduced
live before touching anything: `app.panoramax_63.apk` (a real F-Droid file, corrupt zip)
through `/api/analyze_apk` returned **HTTP 500**,
`{"error":"ValueError: End of central directory record (EOCD) signature not found"}` —
confirmed as one of the 4 `ANALYZE_APK_RAISED` cases already surfaced during D-8's
characterisation batch, same root code path (`static_analysis.analyze_apk()` raising,
caught previously only by the outer catch-all). Fixed by splitting the endpoint's error
handling: a new inner try/except scoped to just the `analyze_apk()` parse call converts
any exception there into `{"status":"requires_manual_review","kind":"apk","filename":...,
"reason":"static analysis could not parse this file (<ExceptionType>)",
"action":"escalate to manual review"}` at **HTTP 200**, per `PLAN.md` item 3's exact spec.
The outer try/except (verdict/narrative/YARA/store) is unchanged and still returns a
real HTTP 500 for genuine bugs elsewhere — this fix does not mask those. Frontend:
`renderApkResults()` would have thrown on the missing fields (`severity`, `risk_score`,
etc.) a manual-review response doesn't carry, so added a dedicated
`renderManualReviewCard()` and an early branch checking `data.status ===
"requires_manual_review"` before the normal render path.

Verified against all 4 known corrupt samples (`app.panoramax_63.apk`,
`app.michaelwuensch.bitbanana_79.apk`, `app.siftrecipes_8.apk`, `app.pachli_52.apk`):
4/4 now return HTTP 200 with the structured envelope. Regression check: a normal
successful analysis (`com.dmouayad.my_quran_233.apk`) still returns `verdict: benign,
status: None, error: None` — unaffected.

**Falsification condition:** any parse-failing APK still returning HTTP 500 with a raw
exception string, or the frontend throwing/rendering blank on a `requires_manual_review`
response, would falsify this fix.

**D-5 — upload size cap. Error-path degradation (a reject-early guard), not a real
correction.** Characterisation reused from a prior session rather than re-run today:
`cash.p.terminal_243.apk` (172.2MB) measured timing out at a 300s wall-clock even in
isolation with a dedicated 10G/8G/2G memory budget (`SESSION_LOG.md:357-358`) —
well-established, not re-measured, to avoid spending 5+ minutes reproducing an
already-solid result. `MAX_CONTENT_LENGTH` confirmed absent from `app.py` before the fix
(grep, zero hits).

**Caught before shipping, not hypothetical:** the obvious fix — Flask's
`app.config["MAX_CONTENT_LENGTH"]` — is application-wide, and would have rejected
`/api/analyze_dataset`'s own `DataSet.csv` upload (~111MB, real, needed for the demo).
Reverted that approach before testing it against the live dataset path and switched to a
manual check scoped to `analyze_apk_endpoint()` only: `request.content_length` checked
before touching disk (fast-path reject for well-behaved clients), plus a post-`f.save()`
size check as a backstop for chunked-encoding uploads that skip Content-Length, both
returning `{"status":"rejected","reason":"upload is <N>MB, over the 50MB
limit","action":"split or pre-filter the file before resubmitting"}` at HTTP 413.
Client-side: `frontend/app.js`'s file-input change handler now rejects >50MB files
immediately with a readable message and disables the analyze button, before any upload
starts.

Verified: `cash.p.terminal_243.apk` (172.2MB) now rejected in **0.161s** (HTTP 413),
not a 300s timeout. Regression check: `DataSet.csv` (~111MB) through
`/api/analyze_dataset` still returns HTTP 200, `n_rows: 9082`, unaffected. The real demo
APK (`007556ca...`, 492KB) verified end-to-end through the now-combined D-4+D-5+D-8 code
path — result pending at the time of this entry, see the next entry for the outcome.

**Falsification condition:** a >50MB APK upload still reaching the analysis pipeline
(any wall-clock beyond a fast rejection), or a legitimate <111MB dataset upload being
rejected, would falsify this fix.

## 2026-08-19 (Day 2, continued) — verification pass, standing correction, carry-overs

**Task 3 — verification pass.** Three consecutive full `browser_smoke.js` runs (labels
`day2_verify_run1_20260819`, `_run2_`, `_run3_`), all 5 steps each: **PASS — zero console
errors, zero uncaught exceptions across all steps**, all three runs. Neither of
`browser_smoke.js`'s own two demo APKs exercises D-4 (corrupt zip) or D-5 (oversized
file) — both are normal, parseable, under-cap files — so this 3x pass confirms **no
regression** from today's changes on the real demo path, not the new fix paths
themselves. Those were verified separately: a targeted one-off Playwright script
(`harness/_d4_d5_frontend_check.js`, written for this check and deleted after — not part
of the standing harness) drove the real frontend against `app.panoramax_63.apk` (D-4) and
`cash.p.terminal_243.apk` (D-5) directly. Result: zero console errors, zero page errors,
both screenshotted (`harness/browser_evidence/d4_d5_check_20260819/`) — the manual-review
card renders exactly as designed, the oversized-file rejection shows a readable message
and disables the analyze button. Not re-run 3x: D-4/D-5's failure modes are deterministic
(a corrupt zip always raises the same exception; an oversized file always exceeds a fixed
threshold), unlike D-8's Ollama-latency-driven nondeterminism, so a single clean run
against each is the right amount of evidence, not three.

**Standing correction — ~10s/APK voided today, not deferred to Day 6.** Threshold-1
sweep (setuguard_app/, demo/, all READMEs) for "10s/APK" and variants: zero hits, judge-
visible surfaces already clean. Two internal planning-doc occurrences fixed in
`FINALE_PLAN_AND_AUDIT.md`: the Day 6 scaling paragraph no longer states a per-APK
figure at all (previously asserted "~10 s/APK single-threaded" as fact, with a caveat
appended after it — now the number is removed outright, per instruction, rather than
hedged); and a prepared hostile-Q&A answer that both quoted the same void figure and
assumed the demo APK is pre-run (stale given today's residency fix — the demo now runs
live, ~1 minute, after one warm-up call) — rewritten to state plainly that no defensible
per-APK figure exists yet, and to explain the residency finding instead.

**Baseline-comparability note for Day 6, recorded so the harness doesn't inherit a bad
comparison:** `harness/extract_tier_a_run.log`'s 39.6s/APK average was measured before
`keep_alive=-1` landed (today, Finding 6). If that average's underlying per-file timings
included the narrative call (unconfirmed either way from the log alone — it records
wall-clock per extraction, and this session did not check whether `extract_tier_a_run.py`
or whatever produced that log invokes the Ollama stage at all), part of it may be
cold-load tax that no longer exists post-fix. Day 6's harness measures the system as it
exists now, after this session's fixes; it must not be compared against the 39.6s/APK
figure as if both describe the same system.

**Carry-over — Priority 0 (issuer-cluster integrity), for the record, in the framing
that survives a hostile question:** the Play App Signing risk was real at the raw
certificate level (27/~73 Tier A files carry the Google Inc. issuer) and the bootstrap
never used that field — `score_banking_corpus.py` clusters on a manually-researched
bank-identity label built specifically to guard against this
(`BANKING_PACKAGE_TIERING_DECISIONS.md`, 13-14 Aug, before any scoring ran). That is a
design that anticipated the attack, not a near-miss that happened to land safely — say
it that way, not as "we got lucky."

**Carry-over — Priority 1, dangling "Section 4" reference: located precisely, not
fixed.** No LaTeX source exists anywhere searched (repo, home directory tree, confirmed
last session), so the compiled PDFs cannot be edited directly — attempting to patch
binary PDF internals directly was not attempted, it is not a safe or reliable edit path.
Precise finding instead: the sentence "...so the figure is contaminated by selection and
appears nowhere in this report. It is the reason the procedural rules in Section 4
exist." is common to both `(2)` and `(3)`'s underlying content, but is **only wrong in
`(3)`** — `(2)` genuinely has its own numbered "4 Evaluation Methodology" section, so the
reference is accurate there. In `(3)`'s retypeset, that content was merged into "III
Deterministic Verdict Control" without its own heading, so "Section 4" is now dangling.
**Ready-to-paste fix for whenever LaTeX source access exists:** change "Section 4" to
"Section III" in that sentence, in `(3)`'s source only.

**Portal check:** still unresolved as of this entry — the user is doing this separately,
outside this session's scope.

**Not started this session, deliberately:** Priority 2 (claim inventory) and the errata
artifact. The three crash paths closed with room to spare in the session budget, which
per this session's own framing means picking these up is now a live option rather than
foreclosed — deferred to the user's judgment on whether to continue now or hold for a
dedicated evening session, since the errata's target still depends on the unresolved
portal check.
