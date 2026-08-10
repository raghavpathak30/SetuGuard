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
