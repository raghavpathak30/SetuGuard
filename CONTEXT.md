# SetuGuard — Repository Context

_Last written: 2026-07-20, by a Claude Code documentation pass. Everything below was verified
against the actual filesystem/environment on that date unless marked otherwise in the
"UNVERIFIED / TO CONFIRM" section at the end. Read that section before trusting any claim about
identity/dates/venue._

_Updated: 2026-07-20, same day, second Claude Code session. That session (1) initialized git and
pushed to GitHub, (2) ran a dead-code audit across all PS1 files and applied the one signed-off
finding, (3) ran the Week-1 Obfuscapk risk spike (go/no-go — passed) and (4) scaffolded the Fix #3
batch-YARA false-positive harness. Every claim below from that session is traceable to a command
actually run in that session, same standard as the rest of this document. Changed sections: 2, 5,
6, 8, 9._

_Updated: 2026-07-26/27, third Claude Code session (Week 2). Completed the n=50-malicious
`baseline_v2` re-run (D10, now RESOLVED), built `validation_gate.py` (D4) and validated it against
live model output (not just synthetic tests — it caught real grounding-hallucination violations),
built `stress_harness.py` for hostile-input robustness testing, pinned `rag_report.py`'s generation
`options` (temperature=0, seed=42 — D6, PARTIALLY resolved: verdict/confidence now deterministic,
`cited_chunk_ids` is not), ran a paired in-memory D2 A/B experiment (null-to-negative result that
REDIRECTS D1's suspected root cause away from retrieval and toward `SYSTEM_PROMPT`/schema-level
causes), fixed a live crash in `fix3_fp_harness.py` and used it to measure a seeded n=150 Fix #3
"before" FP rate (97.9%, corrected accounting), ran the AutoYara (I2) feasibility spike (NO-GO for
adopting the actual tool; ambiguity flagged, not resolved), corrected a significant D11/corpus-census
undercount (16 unusable benign files, not 1), found and logged five new frozen-file defects
(`FROZEN_FILE_FINDINGS.md`, sign-off-gated, only one applied — the temperature/seed pin), and wrote
`requirements.txt` (D8, now RESOLVED). Every claim below from this session is traceable to a command
actually run in this session. Changed sections: 2, 4, 5, 6, 8, 9._

---

## 1. PROJECT IDENTITY

SetuGuard is a two-sided fraud/malware detection system built for what the user has described as
**PSB CyberShield 2026**, by a team calling itself **Ciphered Four**, with a Grand Finale at
**IIT Hyderabad, Aug 27–28**. None of that name/venue/date information appears anywhere in the
repository's own files (see UNVERIFIED section) — it is recorded here purely on the user's
say-so. What *is* verifiable in-repo is the technical shape of the project: it spans two
problem statements. **PS1** is Android APK threat detection — ingest an `.apk`, statically extract
security-relevant features with Androguard, ground a local-LLM (Mistral, via Ollama) triage
report in a small hand-written MITRE ATT&CK-for-Mobile/OWASP MASTG knowledge base retrieved with
FAISS, and emit a YARA rule when warranted. **PS2** is banking-mule-account detection — planned
(per `SetuGuard_Development_Roadmap_v2.md`) as an XGBoost/SHAP tabular model enriched with graph
features (community detection, betweenness, PageRank, fan-in/out ratios) over a transaction graph
(AMLworld dataset). A **Bridge** component is meant to link the two: take PS1's per-APK IOC output
(package, sha256, verdict, suspicious permissions/APIs) and enrich PS2's mule-account graph with
it, so that "this device/APK is flagged" can influence "this account is a mule." A fourth
component, **Dashboard/Audit**, is meant to visualize all of this and produce compliance-style
audit records. As of this writing, **only PS1 has any code** — see Section 2.

An earlier, more ambitious design (found in `idea.txt`, dated 30 May, called **"FHEGuard"**)
proposed doing account/device linkage under fully homomorphic encryption (CKKS) with private-set-
intersection for cross-bank device matching. `idea.txt` is itself a self-critique of that design
(noise growth, ~100ms+ per-op latency, PSI complexity) and recommends TEEs/model-simplification
instead of raw FHE. `SetuGuard_Development_Roadmap_v2.md` (6 Jul) reads as the resulting, more
grounded plan — no FHE/PSI anywhere in it. Treat `idea.txt` as historical background, not a live
spec.

---

## 2. CURRENT PROJECT STATE

| Component | Status | Evidence |
|---|---|---|
| PS1 `static_analysis.py` | **DONE** (Week-1 baseline) | Runs standalone; tested against real APKs from both corpora; schema held stable (11/11 top-level keys, correct sub-key types) across 50 real samples in `baseline/` run |
| PS1 `knowledge_base.py` | **DONE** | 16 hand-written chunks, `CHUNKS` list, covers 14 MITRE IDs required by the build spec plus 2 more (`T1444`, `T1398`) added to ground fields (certificate, boot receiver) that had no other chunk |
| PS1 `report_prompt.py` | **DONE** | `SYSTEM_PROMPT`, `REPORT_SCHEMA`, `build_user_prompt()` — no pipeline logic, verified |
| PS1 `rag_report.py` | **DONE**, generation now pinned | End-to-end tested against `ollama` (mistral + nomic-embed-text), returns valid JSON matching `REPORT_SCHEMA`. **Week-2 change (sign-off given, one-line edit):** `ollama.chat()` now passes `options={"temperature": 0, "seed": 42}` (Finding 3, `FROZEN_FILE_FINDINGS.md`) — the only edit to any of the six frozen files this session. Verified: verdict+confidence are now bit-for-bit deterministic across repeats; `cited_chunk_ids` is **not** (Finding 4 — that field is schema-unconstrained, see Section 6) |
| PS1 `yara_gen.py` | **DONE** | Rules verified to actually **compile and match** with the real `yara` CLI (`yara-python` 4.5.1) against one malicious and one benign real sample. **Week-2 finding, not applied:** a NUL byte in a `suspicious_strings` value (from Adobe XMP metadata, very common) crashes `yara.compile()` downstream — Finding 5, `FROZEN_FILE_FINDINGS.md`, spans this file and `static_analysis.py` |
| PS1 `run_pipeline.py` | **DONE** | Glue entrypoint; chains the three stages by import (no shelling out); writes `out/<pkg>.{features.json,report.json,report.md,yar}` |
| PS1 `batch_baseline.py` | **DONE for both `baseline/` (n=10 malicious) and `baseline_v2/` (n=50 malicious nominal / n=46 effective)** | Week-2: rewritten for crash-survivability (incremental flush+fsync per sample to `results.csv`/new `skips.csv`, `heartbeat.log`, pidfile, resume-by-skip) after the original run died with zero output. Re-run to completion under `setsid nohup` — see Section 6 for the (now complete) n=46-malicious confidence-separation result |
| Dead-code audit (six frozen files + non-frozen scaffolding) | **DONE, one finding applied** | Full pass (unused-import AST scan, grep-every-symbol-across-repo, commented-code/TODO grep) across `static_analysis.py`, `knowledge_base.py`, `report_prompt.py`, `rag_report.py`, `yara_gen.py`, `run_pipeline.py`, `batch_baseline.py`, `parse_fdroid_index.py`. One finding, in a frozen file: unused DEX-list binding `d` at `static_analysis.py:203` (`a, d, dx = AnalyzeAPK(...)`, `d` never referenced again anywhere in the repo — confirmed by grep before editing). Reported in `setuguard_ps1/DEAD_CODE_REPORT.md`, signed off by the user, applied as `a, _, dx = ...` — the only edit made to any of the six frozen files since Week 1 (superseded as "only edit" by the Week-2 temperature/seed pin, above — that's now the second). Verified with a post-edit CLI+import smoke test against a real malicious-corpus sample (exit 0, correct 11-key schema). Non-frozen files had zero dead code — no changes needed there |
| PS1 `validation_gate.py` (D4) | **NEW, DONE (Week 2)** | Validates-only (never corrects a verdict/rule): `validate_features_schema()`, `validate_report_grounding()` (the D4 grounding-faithfulness check — cited chunk/MITRE ids against `knowledge_base.CHUNKS`' real 16), `validate_indicator_traceability()` (every `$indicator_*` in a rule traces to a real features field). Validated against the one real on-disk artifact (`baseline/one_real_sample.features.json`, PASS) plus synthetic fixtures proving it catches fabricated chunk ids, hallucinated indicators, and schema violations. **Caught real violations from live model output** the same session (see Section 6) — not just synthetic tests. Known gap, not fixed: passes NUL-bearing indicators as "traceable" (provenance-only, no well-formedness check) |
| PS1 `stress_harness.py` + `_stress_worker.py` (Week 2) | **NEW, DONE** | Feeds `analyze_apk()` 7 hostile/edge-case inputs (truncated APK, zero-byte file, valid-zip-not-APK, non-zip binary, directory, nonexistent path, corpus APK with most dangerous_permissions), each isolated in its own subprocess so a crash/hang can't take down the harness. All 7 resolved cleanly (6 clean exceptions, 1 success) — **zero dirty failures**. Also used ad hoc to diagnose the 27-file unzip-integrity discrepancy (see Section 6/8) |
| PS1 `d2_negative_chunks.py` + `d2_ab_harness.py` (Week 2) | **NEW, DONE** | 6 negative-evidence chunks (reviewed/revised twice for framing before running — see Section 6), monkeypatched onto `rag_report.CHUNKS` at runtime by a paired A/B harness; **never edited `knowledge_base.py`**. Full result in Section 6 — a null-to-negative result that **redirects** D1's suspected root cause away from retrieval |
| PS2 (XGBoost/SHAP/graph mule detection) | **NOT STARTED** | Exhaustive `find` for `xgboost`/`mule`/`ps2`/`shap`/`graph`-named files under `~/BOIhackathon` returns nothing but incidental APK filename matches (e.g. `com.eanema.graph89_...apk`, an unrelated F-Droid app) |
| Bridge (PS1↔PS2 IOC enrichment) | **NOT STARTED** | No files found; cannot meaningfully exist without PS2 |
| Dashboard/Audit UI | **NOT STARTED** | No files found |
| Fix #3 (F-Droid + 16-real-bank holdout, FP-rate → 0) | **"Before" number measured (Week 2), still blocked on D1/D2 by design** | `setuguard_ps1/fix3_fp_harness.py`: Week-2 crash-survivability rewrite (same treatment as `batch_baseline.py`) plus `--sample-n`/`--seed` for reproducible seeded sampling. Hard-refuses `banking_holdout_16/` by path check (re-verified intact). A live NUL-byte crash (Finding 5) was hit, fixed narrowly (distinct `yara_compile:embedded_null` skip reason, verified against repeats), and the run restarted clean. **n=150, seed=7 result: FP rate 142/145 = 97.9%** (corrected accounting — see Section 6/`FIX3_BEFORE_RESULTS.md`); this is an explicitly-labeled BEFORE number, not a result to act on, since it's dominated by D1's always-"suspicious" verdict. Still defaults to `fdroid_benign_apks/`; the wider F-Droid pull and the 16 real banking APKs remain a separate, not-yet-done sourcing step |
| Fix #4 (Obfuscapk survival matrix) | **Week-1 risk spike DONE — verdict GO** | The previously-skipped Week-1 spike was run: installed `claudiugeorgiu/obfuscapk` (note: the Docker Hub name is `claudiugeorgiu/obfuscapk`, **not** `obfuscapk/obfuscapk`, which doesn't exist) via `podman pull`, ran it against one real trojan sample from `cicmaldroid_banking/` with the lightest single obfuscation transform (`Nop`) plus the `Rebuild`+`NewAlignment`+`NewSignature` steps Obfuscapk requires you to chain explicitly (it does not auto-rebuild/sign after a transform). Output: a valid signed APK (`unzip -t` clean, `file` confirms an APK Signing Block present) that parses cleanly through `static_analysis.py`'s own `analyze_apk()` — the same androguard call path the pipeline uses. Full result in Section 6. **The survival matrix itself — many samples × multiple transforms, checking whether PS1's verdict/confidence/YARA output survives — is NOT started; this was only the go/no-go gate** |
| AutoYara feasibility spike (I2, Week 2) | **DONE — NO-GO for tool adoption** | `setuguard_ps1/AUTOYARA_SPIKE.md`. Confirmed (fetched, not from memory): Java/Maven, JDK11+ (this machine has JDK 25 already), Apache 2.0, no PyPI package, no Docker image, single 2017-era release — appears abandoned. NO-GO because its input shape (multi-sample, family-labeled, cross-APK biclustering) doesn't fit this pipeline's single-APK shape, not because it's unobtainable. **Unresolved, flagged not resolved:** whether I2 means adopting the actual tool (NO-GO) or building a homegrown single-APK fallback (cheaper, not evaluated) |
| `FROZEN_FILE_FINDINGS.md` (Week 2) | **NEW — 5 findings logged, 1 applied** | Same report-don't-touch precedent as `DEAD_CODE_REPORT.md`, generalized beyond dead code. Finding 1 (unguarded `manifest.iter()` on possibly-`None` manifest), Finding 2 (`exported_components[].name` can be `None`, violating the frozen `str` contract — 3 occurrences in `baseline_v2`), Finding 4 (`cited_chunk_ids` schema-unconstrained — parked research finding), Finding 5 (NUL-byte over-capture/under-sanitization, `static_analysis.py`+`yara_gen.py` — crashes `yara.compile()`, ~22% prevalence in benign F-Droid samples) are all **sign-off-gated, not applied**. Finding 3 (temperature/seed pin) is the one **applied** this session — see `rag_report.py` row above |
| `requirements.txt` (D8) | **RESOLVED (Week 2)** | Generated from `python3 -m pip show` output actually run this session — see Section 5 |
| Version control | **INITIALIZED, pushed** | `.git` exists; remote `origin` = `https://github.com/raghavpathak30/SetuGuard`; branch `main` tracks `origin/main`. 2 commits as of the last push: `aee8497` (initial) and `9695401` (Fix #3 harness + dead-code report). **This session's changes are on branch `raghav/week2-ps1`, not yet committed/pushed as of this documentation pass** — see Section 8/STOP 5 for the staged-file list. `.gitignore` excludes all APK corpora (`*.apk`, `banking_holdout_16/`, `fdroid_benign_apks/`, `cicmaldroid_banking/`, `Banking.tar.gz`), model/embedding/index file patterns, `baseline/`/`baseline_v2/`/`out/`/`fix3_fp_baseline/`/`d2_ab_results/`, the unexplained top-level `logging` binary, and F-Droid scraping data artifacts (`index-v2.json`, `download_log.txt`, the package-list `.txt` files) |

**Known-broken / blunt findings:**

- **The RAG report's categorical verdict has never once been "benign" or "malicious" in any measured run.** Confirmed FOUR times independently now: `baseline/` (n=50), `baseline_v2/` (n=86 effective), the D2 A/B (n=36), and the Fix #3 before-run (n=113 effective) — **100% "suspicious"** across all of them, regardless of true label or measurement context. Confidence separates the classes at small n but the separation **collapses at wider n** (see Section 6) — the 3-way enum carries almost no signal. Week-2's D2 A/B experiment (paired, in-memory, `knowledge_base.py` never touched) **redirects the suspected root cause away from retrieval (D2) and toward `SYSTEM_PROMPT`/schema-level causes** (D1's other candidates) — see Section 6 for the full result. Still not fixed — explicit team decision required, not a silent patch.
- **The wider n=50-malicious confidence-separation re-run is now COMPLETE** (Week 2) — `baseline_v2/` was rewritten for crash-survivability and re-run to completion (n=86 effective: 40 benign, 46 malicious after 4 `InvalidInstruction`-bytecode skips). The separation question is answered: **it does not survive** — see Section 6.
- **Corpus-hygiene correction (Week 2) — CONTEXT.md previously undercounted this by 16x.** The benign corpus does not have "one corrupted file" — it has **16 files that fail `unzip -t`/Python `zipfile`** (only 1 is the known truncated download; the other 15 are structurally-valid-per-`file(1)` APKs that androguard itself also fails to parse for 15/16 of them, raising a clean exception in every case — confirmed via `stress_harness.py`, zero dirty failures). The malicious corpus has 11 similar zip-integrity failures (9/11 of which androguard tolerates fine; 2/11 raise cleanly) **plus a separate, previously-unknown failure mode**: `InvalidInstruction` DEX-bytecode parse errors, hit by 4/50 malicious samples in the `baseline_v2` re-run and again in the D2 A/B and Fix #3 runs. None of this breaks the pipeline (every harness already skip-logs cleanly), but the true unusable-file count across both corpora is materially higher than previously documented.
- **NUL-byte defect (Week 2, Finding 5, `FROZEN_FILE_FINDINGS.md`) — new, high-prevalence.** `static_analysis.py`'s url-string regex doesn't exclude control characters, so Adobe XMP metadata's trailing NUL byte (extremely common in ordinary image assets) ends up in `suspicious_strings`, then in a generated YARA rule's string literal, then crashes `yara.compile()`. Measured prevalence: **22.1% (32/145)** of successfully-analyzed benign F-Droid samples in the Fix #3 seeded n=150 run. Sign-off-gated, not fixed.
- YARA rules are generated assuming indicator strings are byte-present in **decompressed** DEX/AXML content (flagged explicitly in `yara_gen.py`'s module docstring) — most APK zip entries are DEFLATE-compressed, so a raw untouched `.apk` file is not guaranteed to byte-match. Ad hoc verification during this project (2 real samples, one malicious one benign) *did* successfully compile-and-match with the real `yara` CLI against the raw `.apk`, but that is not a general guarantee across build toolchains.
- ~~No `requirements.txt`...~~ **RESOLVED (Week 2)** — see Section 5/8.

---

## 3. ARCHITECTURE

### PS1 (implemented)

```
                         ┌─────────────────────────┐
   <apk file> ─────────► │ static_analysis.py       │
                         │  analyze_apk(path)       │
                         │  → AnalyzeAPK() (a,d,dx) │
                         └────────────┬─────────────┘
                                      │ features dict (11 keys, frozen schema — Section 4)
                                      ▼
                         ┌─────────────────────────────────────────┐
                         │ rag_report.py                            │
                         │  generate_report(features)                │
                         │   1. _build_retrieval_query(features)      │
                         │   2. _retrieve(query, k=4):                │
                         │      ollama.embed(nomic-embed-text) on     │
                         │      CHUNKS (knowledge_base.py) + query,   │
                         │      faiss.IndexFlatIP cosine search       │
                         │   3. build_user_prompt() (report_prompt.py)│
                         │   4. ollama.chat(mistral, format=SCHEMA)   │
                         └────────────┬────────────────────────────┘
                                      │ report dict {verdict, confidence, rationale,
                                      │   cited_chunk_ids, retrieved_chunk_ids, package_name, sha256}
                                      ▼
                         ┌─────────────────────────────────────┐
                         │ yara_gen.py                          │
                         │  generate_yara(features, report)      │
                         │   verdict=="benign" → None            │
                         │   else build indicator strings from   │
                         │   dangerous_permissions + suspicious_  │
                         │   apis classes (deduped) + suspicious_ │
                         │   strings; <2 indicators → None        │
                         └────────────┬──────────────────────────┘
                                      │ .yar text | None
                                      ▼
                         ┌─────────────────────────────────────┐
                         │ run_pipeline.py                       │
                         │  chains all 3 by import (no shell-out) │
                         │  times each stage (time.perf_counter)  │
                         │  writes out/<pkg>.{features.json,       │
                         │    report.json, report.md, yar}         │
                         └─────────────────────────────────────┘
```

`batch_baseline.py` sits alongside these (imports the same three functions) as a **read-only
measurement harness**, deliberately kept separate from the six files above so that "measure" tasks
never risk mutating the frozen pipeline.

### PS2 + Bridge (planned only — no implementation exists)

```
   <transaction data (AMLworld / ULB)>
            │
            ▼
   [PS2: NOT STARTED]
   planned: graph construction → Louvain community / betweenness /
   PageRank / fan-in-out features → XGBoost + SHAP → per-account risk score
            │
            ▼
   [Bridge: NOT STARTED]
   planned: join PS1's {package_name, sha256, verdict, dangerous_permissions,
   suspicious_apis} onto PS2's account-graph nodes via a device↔account link
   (mock initially, later Fix #1's synthetic ground-truth linkage set)
            │
            ▼
   [Dashboard/Audit: NOT STARTED]
   planned: visualize combined PS1+PS2+Bridge output, AuditTrailRecord schema
```

No functions, files, or even stub signatures exist for PS2/Bridge/Dashboard — the diagram above is
reconstructed purely from `SetuGuard_Development_Roadmap_v2.md` prose, not from code.

---

## 4. FULL SPECIFICATIONS

### PS1 — APK ingest & Androguard extraction

- Entry point: `analyze_apk(apk_path: str) -> dict` in `static_analysis.py`.
- Ingest is direct: `from androguard.misc import AnalyzeAPK; a, d, dx = AnalyzeAPK(apk_path)`. No
  pre-validation, no unzip step — trusts androguard even when `file(1)` misidentifies some
  cicmaldroid samples as "Java archive (JAR)" (libmagic false flag; androguard parses them fine).
- **Androguard 4.1.4 quirks handled explicitly** (all confirmed against the installed version,
  not assumed):
  - Androguard 4.x logs XREF resolution at DEBUG via **loguru**, not stdlib `logging`. The
    stdlib `logging.getLogger("androguard").setLevel(WARNING)` idiom is a no-op on 4.x. Fix used:
    `from loguru import logger; logger.disable("androguard")` at module import time
    (`static_analysis.py:12-15`).
  - `AnalyzeAPK()` returns a 3-tuple `(a, d, dx)` — the APK object, DEX list, and Analysis object.
  - `a.get_certificates()` returns a list of **asn1crypto** `x509.Certificate` objects (not
    pyOpenSSL/cryptography). Accessed via `.subject.human_friendly`, `.issuer.human_friendly`,
    `.sha256` (which is `bytes`, hex-encoded with `.hex()`).
  - `dx.find_methods(classname=REGEX, methodname=REGEX)` returns `MethodAnalysis` objects; a
    match is only counted as "actually called" if `list(m.get_xref_from())` is non-empty — a
    hard rule in `_extract_suspicious_apis()` (`static_analysis.py:142-156`) to reject 0-xref
    matches (dead/unreferenced code).
  - `dx.find_strings(REGEX)` returns `StringAnalysis` objects; `.get_value()` gives the string.
  - Manifest namespace is the literal string `"{http://schemas.android.com/apk/res/android}"`
    (`MANIFEST_NS`), used to read `android:name`/`android:exported` off `lxml` Elements returned
    by `a.get_android_manifest_xml()`.

- **Feature set** (the exact, frozen schema — every key below and only these 11 keys):

| Field | Type | Semantics |
|---|---|---|
| `apk_path` | `str` | Input path as given |
| `sha256` | `str` (hex) | SHA-256 of the raw APK file bytes (not the DEX, not a cert) |
| `package_name` | `str` | `a.get_package()` |
| `app_name` | `str` | `a.get_app_name()` |
| `target_sdk` | `str` | `str(a.get_target_sdk_version())` |
| `permissions` | `list[str]` | `a.get_permissions()`, raw |
| `dangerous_permissions` | `list[str]`, sorted | `set(permissions) ∩ DANGEROUS_PERMISSIONS` (12-item set, see catalog below) |
| `exported_components` | `list[{type, name, intent_actions}]` | Only components determined exported (rule below); `type ∈ {activity,service,receiver,provider}`; `name` is fully-qualified (`.Foo` shorthand expanded with package name); `intent_actions: list[str]` |
| `suspicious_apis` | `list[{category, class, method, call_count, mitre}]` | One entry per distinct (class, method) confirmed called (xref-checked); `call_count = len(xrefs)`; includes a synthetic `category="accessibility_service"` entry (`method="<manifest>"`, `call_count=0`) when accessibility abuse is detected declaratively |
| `suspicious_strings` | `list[{kind, value}]`, capped at 25 | `kind ∈ {url, ip, shell}`; deduplicated by value; order-of-first-match across the three regexes |
| `certificate` | `{subject, issuer, sha256, self_signed, is_debug}` | First signer only if multi-signed; all fields `None`/`False` if unsigned (guarded edge case) |

  Exported-component rule (`_extract_exported_components`, `static_analysis.py:99-139`):
  `android:exported=="true"` → exported; `=="false"` → not; attribute **absent** →
  activity/service/receiver exported iff ≥1 `<intent-filter>` child; provider → **not** exported
  (spec-mandated simplification, ignores the real Android targetSdk<17 default).

  Suspicious-API catalog (`SUSPICIOUS_API_CATALOG`, `static_analysis.py:41-72`) — 8 categories,
  each `(class_regex, method_regex, mitre_id)`:

  | category | class regex (partial) | method regex | MITRE |
  |---|---|---|---|
  | `dynamic_code_loading` | `Ldalvik/system/(DexClassLoader\|PathClassLoader\|BaseDexClassLoader);` | `<init>` | T1407 |
  | `reflection` (weak, by design) | `Ljava/lang/reflect/Method;` / `Ljava/lang/Class;` | `invoke` / `forName` | T1406 |
  | `sms_control` | `Landroid/telephony/SmsManager;` | `sendTextMessage\|sendMultipartTextMessage` | T1582 |
  | `device_admin` | `Landroid/app/admin/DevicePolicyManager;` | `lockNow\|wipeData` | T1626 |
  | `installed_app_discovery` | `Landroid/content/pm/PackageManager;` | `getInstalledPackages\|getInstalledApplications` | T1418 |
  | `device_fingerprinting` | `Landroid/telephony/TelephonyManager;` | `getDeviceId\|getImei\|getSubscriberId` | T1426 |
  | `runtime_exec` | `Ljava/lang/Runtime;` | `exec` | T1623 |
  | `crypto_usage` (dual-use, not auto-flagged) | `Ljavax/crypto/Cipher;` / `...SecretKeySpec;` | `doFinal` / `<init>` | T1521 |

  Accessibility abuse (`T1417.001`) is **deliberately not** DEX-matched (benign hello-world apps
  fired 23 `AccessibilityEvent` hits + 41 reflection hits in earlier verification — too noisy).
  Detected instead from the manifest: `BIND_ACCESSIBILITY_SERVICE` permission present, OR a
  `<service>` whose intent-filter action is `android.accessibilityservice.AccessibilityService`.

  `DANGEROUS_PERMISSIONS` (12 items, `static_analysis.py:23-36`): `SEND_SMS`, `RECEIVE_SMS`,
  `READ_SMS`, `READ_CONTACTS`, `READ_PHONE_STATE`, `CALL_PHONE`, `SYSTEM_ALERT_WINDOW`,
  `BIND_ACCESSIBILITY_SERVICE`, `REQUEST_INSTALL_PACKAGES`, `QUERY_ALL_PACKAGES`,
  `RECEIVE_BOOT_COMPLETED`, `WRITE_SETTINGS` (all `android.permission.*`).

  Suspicious-string regexes (`STRING_PATTERNS`, `static_analysis.py:81-85`): `url` =
  `https?://[^\s"']{4,}`; `ip` = standard dotted-quad IPv4; `shell` =
  `/system/(x)?bin/|\bsu\b|chmod\s+777|mount\s+-o`.

### PS1 — FAISS / RAG configuration

- Corpus: `CHUNKS` in `knowledge_base.py` — **16 entries**, each `{id, title, mitre, text}`,
  hand-paraphrased (not scraped) from MITRE ATT&CK-for-Mobile + OWASP MASTG. Covers 14 spec'd
  MITRE IDs (T1407, T1406, T1582, T1417.001, T1417.002, T1626, T1418, T1426, T1623, T1521,
  T1636.003, T1636.004, T1437, T1541) plus 2 extra (T1444 masquerade/cert, T1398 boot-persistence)
  added to ground schema fields (`certificate`, `RECEIVE_BOOT_COMPLETED`) that otherwise had no
  chunk.
- Embedding model: `nomic-embed-text` via Ollama. Per `ollama show nomic-embed-text`:
  architecture `nomic-bert`, 137M params, **768-dim** embeddings, F16 quantization, native context
  length 2048 (served with `num_ctx=8192`).
- Index: `faiss.IndexFlatIP` (exact inner-product search), built **in memory on every call** —
  no persistence, no cache file (corpus is only ~16 chunks, per explicit spec: rebuild-each-run is
  cheap enough). Cosine similarity achieved via `faiss.normalize_L2()` on both corpus and query
  vectors before indexing/search (`rag_report.py:37-54`).
- Retrieval query: `_build_retrieval_query(features)` concatenates `dangerous_permissions` +
  sorted unique `suspicious_apis[].category` + sorted unique `suspicious_apis[].mitre` + sorted
  unique `suspicious_strings[].kind` into one string; falls back to
  `"benign android application no suspicious static indicators"` if all empty.
- `TOP_K = 4` chunks retrieved per report.

### PS1 — Mistral / generation

- Model: `mistral` via Ollama. Per `ollama show mistral`: architecture `llama`, **7.2B params**,
  **Q4_K_M quantization**, **32768-token context**, stop tokens `[INST]`/`[/INST]`.
- Prompt template: `SYSTEM_PROMPT` (constant string) + `build_user_prompt(features,
  retrieved_chunks)` (both in `report_prompt.py`) — both live **only** in that file; no prompt
  logic in `rag_report.py` itself.
- Structured output: `ollama.chat(model="mistral", messages=[system, user],
  format=REPORT_SCHEMA)` — Ollama's JSON-schema-constrained decoding, not a hand-parsed regex.
  `REPORT_SCHEMA` (json-schema dict, `report_prompt.py:21-42`): `verdict` (enum
  benign/suspicious/malicious), `confidence` (number 0–1), `rationale` (string),
  `cited_chunk_ids` (array of string). `generate_report()` adds `retrieved_chunk_ids`,
  `package_name`, `sha256` on top of the model's raw JSON before returning.
- Both `ollama.embed()` and `ollama.chat()` calls are wrapped in `try/except` that **raise
  loudly** (`RuntimeError`) rather than fabricate a verdict if the Ollama server/model is
  unreachable.

### PS1 — YARA rule generation format

- `generate_yara(features: dict, report: dict) -> str | None` in `yara_gen.py`. **Note the
  signature deviates from the literal spec text `generate_yara(features, verdict)`** — see
  Section 7 for why (confidence, required in `meta`, only lives in the report dict).
- Hard gate: `report["verdict"] == "benign"` → `None`, unconditionally (Section 7 explains why
  this is enforced explicitly rather than left to the indicator-count threshold).
- Indicators (three kinds, each becomes one `$indicator_*` string):
  1. `dangerous_permissions` strings, verbatim (plaintext in the AXML string pool) — `ascii wide`.
  2. `suspicious_apis[].class` descriptors, **deduplicated**, class only (NOT the `Lcls;->method`
     arrow form) — `ascii` only.
  3. `suspicious_strings[].value` (url/ip/shell, already capped at 25 upstream) — `ascii wide`.
- If fewer than 2 total indicators → `None`.
- `N = max(2, ceil(0.6 * num_indicators))`.
- Rule text:
  ```
  rule SetuGuard_<sanitized_package_name>
  {
      meta:
          package = "<package_name>"
          sha256 = "<sha256>"
          verdict = "<verdict>"
          confidence = "<confidence>"
          generated_by = "SetuGuard-PS1"
      strings:
          $indicator_perm_0 = "..." ascii wide
          $indicator_api_0  = "..." ascii
          $indicator_str_0  = "..." ascii wide
          ...
      condition:
          uint32(0) == 0x04034b50 and <N> of ($indicator*)
  }
  ```
  (`0x04034b50` is the ZIP/APK local-file-header magic.)
- **Caveat, documented in the file's own module docstring**: this assumes indicator strings are
  byte-present in **decompressed** DEX/AXML content. Most `.apk` zip entries are DEFLATE-compressed,
  so a scanning engine needs to be zip-aware (or the rule needs to run post-extraction) for a
  guaranteed match. Ad hoc testing (this project, 2 samples) showed it *did* match raw `.apk`
  files with the real `yara` CLI, but that's not a general guarantee.

### PS2 — feature engineering, XGBoost, SHAP, graph topology

**No implementation exists.** Everything below is transcribed from
`SetuGuard_Development_Roadmap_v2.md` prose and must not be treated as verified code behavior:

- Baseline (Week 1, per roadmap): "XGBoost/SHAP pipeline running on ULB data with real numbers."
  No hyperparameters, no feature list, no code.
- Fix #2 (Week 2–3, per roadmap): four graph features — Louvain community, betweenness
  centrality, PageRank, fan-in/out ratio — computed on an AMLworld HI-Small subgraph (from
  Kaggle), fed into XGBoost as new columns, checked against AUCPR regression, with a target
  finding that "mule-labeled nodes rank in top-percentile betweenness."
- A Week-1 "Day 5–6 risk spike" was planned ("pull AMLworld HI-Small, load into NetworkX, confirm
  Louvain/betweenness run without choking") — **no evidence in the repo that this happened.**

### Frozen integration schema

The `features` dict schema (Section 4, PS1 table above) **is the frozen contract** other
components (Bridge, PS2 enrichment, Dashboard) are meant to consume. It is reproduced verbatim in
`setuguard_ps1/baseline/one_real_sample.features.json` — a real, pretty-printed example from an
actual malicious APK — explicitly generated as "the frozen-schema reference" for the Bridge owner.
**Breaking this schema (renaming a key, changing a type, adding/removing a field) silently
invalidates that reference file and any downstream code written against it, with no test suite or
schema-validation harness to catch the break automatically** — `batch_baseline.py`'s schema check
is a measurement tool run manually, not a CI gate.

The `report` dict schema (verdict/confidence/rationale/cited_chunk_ids +
retrieved_chunk_ids/package_name/sha256, per `rag_report.py:85-90`) and the YARA `meta` block
format (package/sha256/verdict/confidence/generated_by) are the other two frozen contracts a
Bridge/Dashboard consumer would need.

---

## 5. ENVIRONMENT & REPRODUCIBILITY

Verified directly on the current machine (`cat /etc/os-release`, `uname -a`, `nvidia-smi`,
`python3 --version`, `pip list`, `ollama list`, `ollama show`):

| | |
|---|---|
| OS | Parrot Security 7.1 (echo) |
| Kernel | `6.17.13+2-amd64` (Parrot build, dated 2026-01-08) |
| GPU | NVIDIA GeForce RTX 4060, driver 550.163.01, CUDA 12.4, 8188 MiB VRAM |
| Python | 3.13.5, system interpreter, **no venv** |
| Ollama server | systemd service `ollama`, confirmed `active` |
| Ollama models pulled | `mistral:latest` (4.4GB), `nomic-embed-text:latest` (274MB) |
| Container runtime | `podman` 26.1.5-compat (the `docker` command on this machine is podman under the hood — `docker pull` fails against the podman socket unless invoked as `podman pull`); rootless. Image `docker.io/claudiugeorgiu/obfuscapk:latest` pulled (809MB) for the Fix #4 spike (Section 2/6) |

Pinned dependency versions actually installed (`python3 -m pip list`). **`setuguard_ps1/requirements.txt`
now exists (Week 2, D8 resolved)** — generated from this same `pip show` data, so this table and
that file should stay in sync:

| package | version |
|---|---|
| androguard | 4.1.4 |
| asn1crypto | 1.5.1 |
| faiss-cpu | 1.14.3 |
| loguru | 0.7.3 |
| numpy | 2.2.4 |
| ollama (python client) | 0.6.2 |
| yara-python | 4.5.1 |

_Minor drift noted 2026-07-20 (second session): `python3 -c "import yara; print(yara.__version__)"`
now reports `4.5.2` on this machine — one patch version ahead of the table above. Not re-verified
whether this changes behavior; noted for traceability, not treated as a live bug._

This is a Debian-family "externally managed environment" (PEP 668) — plain `pip install` is
blocked. All of the above were installed with `--break-system-packages` into
`~/.local/lib/python3.13/site-packages` (confirmed via `pip show androguard` pointing there).
**Anyone re-provisioning this machine must use the same flag or a venv.**

**Literal commands to set up and run:**

```bash
# one-time environment setup (Debian/Parrot externally-managed-environment)
python3 -m pip install --break-system-packages androguard==4.1.4 loguru asn1crypto \
    faiss-cpu==1.14.3 ollama==0.6.2 yara-python

# ollama server + models (separate install, not pip)
systemctl status ollama          # must show 'active'
ollama pull mistral
ollama pull nomic-embed-text

# run one APK end-to-end
cd ~/BOIhackathon/setuguard_ps1
python3 run_pipeline.py /path/to/sample.apk
# → out/<package_name>.features.json / .report.json / .report.md / .yar (if a rule was warranted)

# run any single stage standalone
python3 static_analysis.py <apk> [-o feat.json]
python3 rag_report.py <feat.json> [-o report.json]
python3 yara_gen.py <feat.json> <report.json> [-o rule.yar]

# install from the pinned file directly (Week 2)
python3 -m pip install --break-system-packages -r requirements.txt

# re-run the wider measurement batch (baseline_v2/ is now complete — see Section 6 —
# re-running from a clean baseline_v2/ regenerates it; resume-by-skip means a partial
# baseline_v2/ would need clearing first for a truly fresh run)
python3 batch_baseline.py        # writes to baseline_v2/ (NUM_MALICIOUS=50 currently configured)
```

**Corpus locations** (not committed to any repo — raw data on this machine only):

| Directory | Count | Size | Role |
|---|---|---|---|
| `~/BOIhackathon/fdroid_benign_apks/` | 802 apks | 12G | Benign training/eval corpus |
| `~/BOIhackathon/cicmaldroid_banking/` | 2489 apks | 3.9G | Malicious (banking trojan) corpus |
| `~/BOIhackathon/banking_holdout_16/` | 16 apks | 40M | **Reserved holdout — never touched by any script; earmarked for Fix #3** |
| `~/BOIhackathon/fdroid_benign/` | 0 files | 4.0K | Empty — apparent leftover from an earlier, superseded download attempt |
| `~/BOIhackathon/Banking.tar.gz` | — | 3.9G | Presumed source archive for `cicmaldroid_banking/` (not opened/verified) |

**Machine-specific things future sessions should not assume generalize:**
- The measured ~12.6s mean per-APK RAG latency is GPU-accelerated on this specific RTX 4060; a
  CPU-only Ollama install would be substantially slower.
- `batch_baseline.py` hardcodes `Path.home() / "BOIhackathon" / ...` — assumes this exact
  directory layout under whatever user's home it runs as.
- The YARA raw-`.apk`-byte-match caveat (Section 4) was only spot-checked on 2 samples on this
  machine's build of those APKs; don't assume it generalizes to every APK build toolchain.

---

## 6. RESULTS SO FAR

Exactly two measurement artifacts exist, both under `setuguard_ps1/`. **No PS2/Bridge/Dashboard
metrics exist anywhere** — there is no code to produce them.

### `baseline/` — COMPLETE (40 benign + 10 malicious, produced by `batch_baseline.py` before it was
edited to the wider n=50 config)

Source: `setuguard_ps1/baseline/{results.csv,summary.txt}`. Recomputed directly from
`results.csv` for this document (not just copied from the old `summary.txt`, which grouped
confidence by verdict rather than by true label):

| | benign (n=40) | malicious (n=10) |
|---|---|---|
| verdict | 100% `"suspicious"` | 100% `"suspicious"` |
| confidence min/median/max | 0.45 / 0.70 / 0.75 | 0.75 / 0.78 / 0.85 |
| YARA rule written | 36/40 (90%) | 10/10 (100%) |

- Processed: 50/50, **0 skips**.
- Schema check: **PASS**, 0 anomalies (all 11 top-level keys present on every sample; every
  `suspicious_apis`/`suspicious_strings`/`exported_components` element had exactly its expected
  sub-keys with correct types; every features dict round-tripped through `json.dumps` cleanly).
- Total wall time 630.8s; mean 12.6s/apk (this is the Mistral-latency risk-register number).

**The finding and its implication**: confidence scores separate the two classes cleanly (benign
tops out at 0.75; malicious starts at 0.75 — touching exactly at the boundary, not crossing it),
but the **categorical verdict does not** — the model never used `"benign"` or `"malicious"` in
any of the 50 runs, always landing on the middle label. If any downstream consumer (Bridge,
Dashboard) keys off the literal verdict string rather than the confidence float, it will observe
zero variation across the entire corpus. This was recorded as-is, per explicit instruction not to
tune the prompt or add a validation gate to mask it — it is real Week-1 baseline evidence for the
Fix #3 FP-rate work.

### `baseline_v2/` — COMPLETE as of Week 2 (n=40 benign / n=50 malicious nominal, n=46 malicious effective)

Source: `setuguard_ps1/baseline_v2/{results.csv,skips.csv,summary.txt}`, recomputed directly from
the CSVs for this document (not from the harness's own `summary.txt`, which is still accurate for
this particular run but is a general risk pattern worth naming — see the Fix #3 write-up below
for a case where trusting a harness's own summary actively produced a wrong number).
Re-run (Week 2) after a full crash-survivability rewrite of `batch_baseline.py` (incremental
flush+fsync, `skips.csv`, `heartbeat.log`, pidfile, resume-by-skip); ran to completion under
`setsid nohup`, 1055.9s wall time, mean 12.2s/apk (n=86 successful).

| | benign (n=40) | malicious (n=46 effective, 4 skipped) |
|---|---|---|
| verdict | 100% `"suspicious"` | 100% `"suspicious"` |
| confidence min/p25/median/p75/max | 0.60 / 0.65 / 0.70 / 0.75 / 0.85 | 0.65 / 0.75 / 0.75 / 0.80 / 0.85 |

**The n=10 separation does NOT survive at n=46 — answered, not smoothed.** At n=10 malicious
(the `baseline/` run above), malicious min (0.75) exactly touched benign max (0.75) — no overlap.
At n=46, malicious min drops to 0.65, well inside the benign range; benign max (0.85) now equals
malicious max. Overlap region ≈ [0.65, 0.85] — most of both distributions. 33/40 benign score at
or above the malicious minimum. This closes D10 (previously open) and answers the question
CONTEXT.md's prior session left open: **no, confidence separation does not hold at wider n.**

4 malicious samples skipped this run, all `InvalidInstruction` DEX-bytecode parse errors at the
`static_analysis` stage — a distinct failure mode from the zip-integrity issue described below,
first observed this session.

**Schema violation found this run (Finding 2, `FROZEN_FILE_FINDINGS.md`), not seen in `baseline/`'s
n=50:** 3/86 samples had `exported_components[].name = None` (violating the frozen `str`
contract) — all 11 components in each of those 3 manifests lacked an `android:name` attribute.
Traces to `static_analysis.py`'s `_resolve_component_name()` falling through to `return name`
unguarded when the manifest attribute is absent. Sign-off-gated, not fixed — see
`FROZEN_FILE_FINDINGS.md` Finding 2 for the two options.

### D6 determinism — PARTIALLY resolved (Week 2)

`rag_report.py`'s `ollama.chat()` call previously passed no `options` at all. Confirmed via 3 real
samples run twice each through `generate_report()`: **verdict changed on 1/3 pairs, confidence
moved on 3/3** — reproducibility was genuinely broken, not a theoretical risk.

**Fix applied** (sign-off given, one-line edit — the only frozen-file edit this session):
`options={"temperature": 0, "seed": 42}`. Re-verification (same 3 samples, same test):
**verdict and confidence are now bit-for-bit deterministic across all 3 pairs.**
`cited_chunk_ids` is **not** — 1/3 pairs diverged completely (one run cited real MITRE-style ids,
the other cited literal feature-dict key names like `'exported_components'`). Root cause
identified (Finding 4, `FROZEN_FILE_FINDINGS.md`): `REPORT_SCHEMA` content-constrains `verdict`
(enum) and `confidence` (bounded number) via Ollama's schema-guided decoding, but `cited_chunk_ids`
is typed as "array of arbitrary strings" with no such constraint — the same reason it both
jitters and hallucinates. **Verdict/confidence are safe to treat as stable measurements now;
`cited_chunk_ids` is not**, and no downstream measurement this session relied on it.

### D2 A/B experiment — null-to-negative result, REDIRECTS D1's suspected root cause

Full writeup: `setuguard_ps1/D2_AB_RESULTS.md`. Paired, in-memory (`rag_report.CHUNKS`
monkeypatched at runtime; `knowledge_base.py` never edited), seed 2026, n=20 benign + 20
malicious (16 effective after 4 more `InvalidInstruction` skips). Arm A = real 16 chunks; Arm B =
real 16 + 6 reviewed negative-evidence chunks (`d2_negative_chunks.py`) describing normal
permission/API profiles for messaging, fintech, media/utility-boot, package-management, dual-use
APIs, and network strings — written to state only what's normal, with no malicious-co-indicator
language (an earlier draft was rejected on review for smuggling a decision rule this way).

**Headline: verdict never changed — 0/36 samples, either direction, either arm.** This is the
clearest result: if D1's "always suspicious" verdict came from retrieval imbalance (D2's theory),
changing what gets retrieved should have moved at least some verdicts. It moved zero.
**This substantially weakens D2 as *the* root cause of D1** and redirects suspicion toward
`report_prompt.py`-level candidates this test didn't touch: `SYSTEM_PROMPT`'s explicit hedging
language, the absence of explicit decision thresholds, and the 3-way enum inviting the safe middle
option. Confidence moved too, but backwards from D2's prediction — malicious confidence dropped
more than benign (mean Δ −0.028 vs −0.0075), and separation got measurably *worse* (malicious
samples at/below the benign max confidence doubled, 7/16→14/16).

**D2↔D7 coupling, logged as the likely mechanism, not acted on:** at fixed `TOP_K=4`, the 6 new
chunks compete with the original 16 for the same 4 retrieval slots — for a malicious sample this
can displace a genuinely relevant malicious-framing chunk rather than adding balancing context.
**Any future D2 revisit needs to travel with a D7 fix (or at least a higher `TOP_K`)** so negative
chunks add context instead of displacing it. This is a null result for *this specific, cleanly-
scoped test*, not a general verdict on D2 — no ablation was run, and D1's other candidates remain
untouched and now more likely.

### D4 grounding check — now backed by MEASURED evidence, not just synthetic tests

`validation_gate.py`'s `validate_report_grounding()` was run against the same 6 live
`generate_report()` outputs from the D6 determinism check (pre-pin): **4 of 6 runs failed with
3–7 violations each** — real fabricated chunk ids (`'permissions'`, `'exported_components'`,
`'suspicious_api_usage'`, full chunk titles instead of ids) caught on the very first live model
output the gate was ever run against, not a contrived test case. Post-pin, the rate was 5/6 (not
improved by the determinism fix — grounding-hallucination and run-to-run stability are different
properties, see D6 above). **D4 went from a nice-to-have Week-2 deliverable to the barrier between
a hallucinated technique id and a poisoned rule, with real measured evidence it fires in practice.**

### Fix #3 "before" measurement — n=150, seed=7, FP rate 97.9% (corrected)

Full writeup: `setuguard_ps1/FIX3_BEFORE_RESULTS.md`. Explicitly a BEFORE number, not a result —
dominated by D1's always-"suspicious" verdict, per instruction. `fix3_fp_harness.py` rewritten for
crash-survivability plus `--sample-n`/`--seed`; hard-refuses `banking_holdout_16/` (re-verified).

A live crash was hit and fixed mid-session: `com.dmouayad.my_quran_233.apk` (a real, ordinary
F-Droid app) crashed the harness with `ValueError: embedded null character` from
`yara.compile()` — root-caused to a coupled `static_analysis.py`/`yara_gen.py` defect (Finding 5,
below). Fixed narrowly in the harness (distinct `yara_compile:embedded_null` skip reason,
verified against repeated occurrences) and the run **restarted from scratch** (not resumed) so
all 150 samples share one harness version.

**Corrected accounting (the harness's own auto-generated `summary.txt` undercounts and should not
be used — it misses that every `yara_compile:*` skip row is *also* a rule-generated-on-benign
event, since `_check_rule_match()` is only reachable after `generate_yara()` already returned a
rule):**

| | Count |
|---|---|
| Nominal | 150 |
| Genuine skips (`static_analysis`, zip/EOCD errors) | 5 |
| NUL-compile skips (rule generated, couldn't compile-test) | **32** |
| Fully processed | 113 |

**Primary FP rate = 142/145 = 97.9%** (110 `results.csv` rows with `rule_generated=True`, plus all
32 NUL rows, which are `rule_generated=True` by construction — over the 145 samples that made it
through `analyze_apk`+`generate_report`). Secondary sub-metric (of rules that could be
compile-tested, i.e. excluding NUL cases — an explicitly biased subsample): 21/110 = 19.1%
compiled and matched their own source APK.

**The NUL-skip rate itself is the headline, independent of the FP number: 32/145 = 22.1%** of
successfully-analyzed benign F-Droid samples hit this defect — systemic, not incidental, per
Finding 5 below.

Verdict distribution (n=113): 100% `"suspicious"` — the fourth independent confirmation this
session.

### Finding 5 — coupled `static_analysis.py`/`yara_gen.py` defect: NUL bytes crash YARA compilation

Full detail: `FROZEN_FILE_FINDINGS.md` Finding 5. Adobe XMP metadata (near-ubiquitous in ordinary
image assets) embeds a trailing NUL byte; `static_analysis.py:82`'s url regex doesn't exclude
control characters, so it's captured into `suspicious_strings`; `yara_gen.py`'s `_yara_escape()`
strips `\n`/`\r` and escapes backslash/quote but not NUL, so it flows into the generated rule and
crashes `yara.compile()`. Measured prevalence 22.1% in the Fix #3 run above. Also checked:
`validation_gate.validate_indicator_traceability()` passes a NUL-bearing indicator with zero
violations — it validates provenance, not well-formedness. Two options logged for the team
(tighten the regex; harden `_yara_escape()`; likely both needed), neither applied.

### AutoYara (I2) feasibility spike — NO-GO for tool adoption, ambiguity unresolved

Full writeup: `setuguard_ps1/AUTOYARA_SPIKE.md`. `FutureComputing4AI/AutoYara`: Java/Maven, JDK11+
(confirmed available on this machine — JDK 25), Apache 2.0, no PyPI/Docker packaging, appears
abandoned (single 2017-era release). **NO-GO for adopting the tool** — its input shape (multi-
sample, family-labeled, cross-APK biclustering) doesn't fit this pipeline's single-APK
`features → report → rule` shape without a substantial redesign, independent of licensing/
availability. **Flagged, not resolved:** whether I2 means adopting this tool (NO-GO) or building a
much cheaper homegrown single-APK fallback for the `<2 indicators` case (not evaluated) — a team
decision.

### Obfuscapk Fix #4 risk spike — GO (single sample, single transform, not a survival matrix)

Run 2026-07-20 (second session). `claudiugeorgiu/obfuscapk:latest` via `podman run`, against
`cicmaldroid_banking/00049d038a2abc2d5fe3b190d6cf5c1cb1ba63441defdf136be251c7a00727d8.apk`
(94,725 bytes, a real trojan sample, first-sorted from the corpus). Obfuscator chain:
`-o Nop -o Rebuild -o NewAlignment -o NewSignature` — `Nop` is the actual obfuscation transform
(inserts nop instructions in the smali); `Rebuild`/`NewAlignment`/`NewSignature` are required
separate steps to get a valid installable APK back out (Obfuscapk does not rebuild or re-sign
automatically after a transform — that surprised the first attempt, which ran `-o Nop` alone and
silently produced no output file at all, exit 0, no error).

Result: output APK 115,552 bytes. `unzip -t` reports no errors. `file` identifies it as a proper
Android package with an APK Signing Block. `analyze_apk()` (the real PS1 stage-1 function, not a
mock) parses it with no exceptions: `package_name=com.baidu.pay2`, 7 dangerous permissions and 6
suspicious_apis entries recovered — same shape of output as an unobfuscated sample.

**What this proves and doesn't prove**: proves Obfuscapk installs clean in this environment (via
podman, not raw pip — it isn't a PyPI package), completes without erroring on a real sample from
our own malicious corpus, and emits an APK that both `unzip`/`file` and PS1's own androguard-based
ingest accept as valid. Does **not** prove anything about whether obfuscation changes PS1's
*verdict* — nobody has yet run the pre-obfuscation and post-obfuscation APK through the full
`analyze_apk → generate_report → generate_yara` chain and diffed the outputs. That comparison,
across multiple obfuscators and multiple samples, is the actual "survival matrix" and is still
unbuilt (Open Item, Section 8).

---

## 7. DESIGN DECISIONS & RATIONALE

| Decision | Why | What was rejected | What would force a revisit |
|---|---|---|---|
| Accessibility abuse detected from the manifest, not DEX xref-matching | A benign hello-world app fired 23 `AccessibilityEvent` hits + 41 reflection hits — DEX-matching is too noisy | Matching `AccessibilityEvent`-family methods directly like the other 8 categories | If manifest-only detection proves too coarse (misses apps that register accessibility services dynamically at runtime) |
| `reflection` category kept despite being explicitly "weak" | Required by spec (T1406 coverage); dual-use nature stated up front rather than hidden | Dropping reflection entirely to cut noise | If it never contributes to a true positive once wider/holdout data is measured |
| `generate_yara` gates on `report["verdict"] == "benign"` (hard invariant), not just the indicator-count threshold | A real, genuinely benign F-Droid app (`a2dp.Vol`, an audio player) organically racked up 10 indicators (READ_PHONE_STATE + RECEIVE_BOOT_COMPLETED + a GitHub URL, etc.) — proving "benign apps naturally have <2 indicators" false | Relying on the count threshold alone, as the literal spec text implied | This is load-bearing for the "benign apps don't yield malware rules" guarantee — would need explicit team sign-off to relax |
| `generate_yara(features, report)` instead of the literally-specified `generate_yara(features, verdict)` | YARA `meta` requires `confidence`, which only lives in the report dict, not in a bare verdict string | Passing `verdict` and `confidence` as two separate positional args | If a downstream caller needs the exact 2-arg signature for some integration reason |
| FAISS index rebuilt in memory on every `generate_report()` call, no persistence | Corpus is only ~16 chunks — explicit instruction was "no persistence, no cache code" | Precomputing/saving an index file | If the knowledge base grows large enough that per-call embedding cost becomes a real bottleneck |
| YARA strings assume decompressed DEX/AXML content (flagged in the module docstring, not silently handled) | Matches the literal spec's stated assumption; genuinely correct behavior depends on the scanning engine being zip-aware, which this project doesn't control | Adding zip-extraction logic before rule-writing | If a live demo requires generated rules to match against raw, untouched `.apk` files and broader testing shows failures |
| No `requirements.txt`/Dockerfile/Makefile written yet | Every build/measurement task given so far was scoped narrowly (six files, then a measurement harness) — writing project scaffolding was never asked for | Writing one proactively | Arguably now — see Open Items #9 |
| `batch_baseline.py` kept structurally separate from the six frozen pipeline files, even though it imports them | Explicit instruction: "measurement only," must not fold into or modify the six files | Adding a `--batch` mode to `run_pipeline.py` | Never, unless the six-file boundary itself is renegotiated |

---

## 8. OPEN ITEMS

Ordered by risk to the Aug 27–28 demo (per the user's stated date — see UNVERIFIED section):

1. **PS2 (XGBoost/mule detection) has zero code.** This is half of the two-problem-statement
   pitch. Per the project's own roadmap, a baseline should have existed by end of "Week 1
   (1–7 Jul)," and today (per this machine's clock) is 2026-07-20 — well past even
   "Week 3 (15–21 Jul)" in that roadmap's calendar. **Highest risk item in the repo.**
2. **Bridge (PS1↔PS2 linkage) has zero code**, and cannot meaningfully start until PS2 exists.
3. **Dashboard/Audit UI has zero code.**
4. **Fix #3 (F-Droid + 16-real-bank holdout FP-rate tuning): "before" number measured (Week 2),
   still blocked on D1/D2 by design.** `fix3_fp_harness.py` now has a seeded, reproducible n=150
   run (`FIX3_BEFORE_RESULTS.md`, FP rate 142/145 = 97.9%, corrected accounting) — but this number
   is explicitly a BEFORE, not a fix, since it's dominated by D1's always-"suspicious" verdict.
   Still needs: (a) the wider F-Droid pull, (b) the 16 real banking APKs sourced and pointed at via
   `--corpus-dir` (never `banking_holdout_16/` directly — the harness refuses that path itself,
   re-verified intact this session), (c) the actual AFTER run once D1/D2 are addressed by the team,
   applying the same NUL-exclusion accounting so the two are comparable, and (d) the team decision
   on D1 itself.
5. **Fix #4 (Obfuscapk survival matrix): Week-1 risk spike DONE, verdict GO** (Section 2/6). The
   actual survival matrix — running many samples through multiple obfuscation transforms and
   measuring whether PS1's verdict/confidence/YARA output survives — is still **not started**.
   This item is now unblocked, not resolved.
6. ~~The wider (n=50-malicious) confidence-separation re-run is incomplete~~ **RESOLVED (Week 2).**
   `baseline_v2/` re-run to completion (n=86 effective). Answer: **separation does not survive** —
   overlap region ≈[0.65,0.85] at n=46 malicious vs. a clean touch-not-cross at n=10 (Section 6).
7. **The verdict enum still carries near-zero signal — now confirmed FOUR times independently**
   (`baseline`, `baseline_v2`, the D2 A/B, the Fix #3 run — 100% "suspicious" every time, n=50+86+
   36+113). **New this session:** the D2 A/B redirects the suspected root cause away from
   retrieval (D2) and toward `SYSTEM_PROMPT`/schema-level causes (D1's other candidates) — see
   Section 6. Still needs an explicit team decision — not something to silently patch, per
   repeated instruction.
8. ~~No version control exists anywhere in the repository.~~ **RESOLVED 2026-07-20 (second
   session).** `.git` initialized, remote `origin` = `https://github.com/raghavpathak30/SetuGuard`,
   2 commits made and pushed to `main` (`aee8497`, `9695401` — Section 2). `.gitignore` keeps all
   corpora/models/binaries/scraping-data out. Team members can now `git clone` instead of relying
   on Claude Code conversation transcripts for project history. **Week-2 session's work is on
   branch `raghav/week2-ps1`, not yet merged/pushed as of this documentation pass.**
9. ~~No `requirements.txt`/Dockerfile/environment file exists.~~ **RESOLVED (Week 2).**
   `setuguard_ps1/requirements.txt` generated from actual `pip show` output. Ollama+models remain a
   separate, non-pip install (documented in the file's own header).
10. **YARA-vs-compressed-APK caveat is only spot-checked on 2 samples.** Worth a broader
    validation pass (e.g., against the holdout set, once Fix #3 starts using it) before relying on
    generated rules matching raw APKs live in front of judges.
11. ~~One corrupted sample sits in the benign corpus~~ **CORRECTED, WORSE THAN DOCUMENTED (Week
    2).** The benign corpus has **16** files (not 1) that fail `unzip -t`/Python `zipfile` — 15 of
    those also fail androguard parsing (clean exceptions, not dirty failures — confirmed via
    `stress_harness.py`). The malicious corpus has a separate 11 zip-integrity failures (9/11
    androguard-tolerant) **plus** a distinct `InvalidInstruction` DEX-bytecode failure mode hit by
    multiple samples across `baseline_v2`/D2-A/B/Fix#3 runs. None of this breaks the pipeline
    (every harness skip-logs cleanly) but the true unusable-file count is materially higher than
    previously documented — worth a corpus cleanup pass before final numbers are reported to
    judges, so wall-time/sample-count estimates aren't quietly off by ~16-20%.
12. Team/hackathon identity details (name, venue, dates) are asserted by the user but not found
    anywhere in repo text — low risk, noted for traceability only.
13. ~~One dead-code finding in a frozen file~~ **RESOLVED 2026-07-20 (second session).**
    `static_analysis.py:203`'s unused DEX-list binding (`d`) was reported in
    `setuguard_ps1/DEAD_CODE_REPORT.md`, signed off by the user, and fixed
    (`a, d, dx = ...` → `a, _, dx = ...`). No other dead code found anywhere in the six frozen
    files or the two non-frozen scaffolding files (`batch_baseline.py`, `parse_fdroid_index.py`).
    Noted here only for traceability — not an open item.
14. **NEW (Week 2) — five frozen-file findings logged in `FROZEN_FILE_FINDINGS.md`, sign-off-gated,
    only one applied:**
    - Finding 1: `_extract_exported_components()` calls `.iter()` on a possibly-`None` manifest
      (`static_analysis.py`) — 2 observed occurrences, clean `AttributeError`, not fixed.
    - Finding 2: `exported_components[].name` can be `None`, violating the frozen `str` contract —
      3 occurrences in `baseline_v2`, not fixed.
    - Finding 3: `rag_report.py`'s generation was unpinned (D6) — **fixed** (temperature=0,
      seed=42), verdict/confidence now deterministic, `cited_chunk_ids` still isn't.
    - Finding 4: `cited_chunk_ids` is schema-unconstrained in `report_prompt.py`'s `REPORT_SCHEMA`
      — the same reason it both hallucinates and jitters. Parked research finding, not fixed.
    - Finding 5: coupled `static_analysis.py`/`yara_gen.py` NUL-byte defect — crashes
      `yara.compile()`, measured 22.1% prevalence in benign F-Droid samples (Section 6). Not
      fixed. Also: `validation_gate.py`'s indicator-traceability check passes NUL-bearing
      indicators (validates provenance, not well-formedness) — noted, not fixed.
15. **NEW (Week 2) — D2 A/B experiment result redirects D1's suspected root cause.** A clean,
    reviewed, paired in-memory test of D2's hypothesis (retrieval imbalance) moved zero verdicts
    across 36 samples and made confidence separation slightly *worse*. This weakens D2 as *the*
    cause of D1 and points toward `SYSTEM_PROMPT`/schema-level candidates instead. Also
    established: **D2 and D7 are coupled** — a fair retrieval-augmentation test needs a `TOP_K`
    increase or D7's distance-thresholded retrieval fix first, since at fixed `TOP_K=4` new chunks
    displace old ones rather than adding to them. Full detail: `D2_AB_RESULTS.md`.
16. **NEW (Week 2) — AutoYara (I2) ambiguity flagged, not resolved.** The go/no-go spike
    (`AUTOYARA_SPIKE.md`) is a clear NO-GO for adopting the actual `FutureComputing4AI/AutoYara`
    tool (architectural mismatch — multi-sample family-biclustering vs. this pipeline's single-APK
    shape), but I2's original intent is ambiguous between "adopt that tool" and "build a homegrown
    single-APK fallback." Team decision needed on which was meant.

---

## 9. CONVENTIONS FOR FUTURE SESSIONS

- **The six frozen PS1 pipeline files** are: `static_analysis.py`, `knowledge_base.py`,
  `report_prompt.py`, `rag_report.py`, `yara_gen.py`, `run_pipeline.py`. Each is independently
  runnable via CLI (`python3 <file>.py ...`) and importable as a plain module — stages are
  chained by import, never by shelling out to each other. **Do not modify these six without
  explicit user sign-off.** Every task given on this project so far has explicitly separated
  "build/modify the six" from "measure/test, read-only" — preserve that boundary.
- **Measurement/analysis harnesses** (`batch_baseline.py`, `fix3_fp_harness.py`, and now
  `validation_gate.py`, `stress_harness.py`+`_stress_worker.py`, `d2_ab_harness.py`+
  `d2_negative_chunks.py`) live alongside the six files in `setuguard_ps1/` but must say in their
  own module docstring that they are *not* one of the six, and must not mutate them.
- **Any finding in a frozen file — not just dead code — is reported, not fixed, in the same
  session that finds it.** `DEAD_CODE_REPORT.md`'s pattern generalized (Week 2) into
  `FROZEN_FILE_FINDINGS.md`: write up file/line/what/why/options there rather than editing the
  frozen file directly. Once the user signs off on a *specific* finding and its *specific* chosen
  option, a separate, narrowly-scoped follow-up edit applies exactly that fix and nothing else —
  precedent: the `static_analysis.py:203` rename (Section 2, Open Item 13) and the Week-2
  `rag_report.py` temperature/seed pin (Finding 3). Re-verify the finding is still accurate
  immediately before applying (fresh repo-wide grep / re-run the reproduction), since the codebase
  may have changed between the report and the sign-off. **After a crash or unexpected behavior in
  a non-frozen harness, root-cause it before just patching the harness** — Week 2's NUL-byte
  harness crash traced back to a real, previously-unknown frozen-file defect (Finding 5); patching
  only the harness's exception handling would have hidden that.
- **Harness crash-survivability is now the standard, not an exception.** `batch_baseline.py` and
  `fix3_fp_harness.py` both follow the same Week-2 pattern: incremental flush+fsync per sample to
  a results CSV, a separate `skips.csv` (not silently folded into the success rows), a
  `heartbeat.log`, a pidfile, and resume-by-skip. Apply this pattern to any new batch-style
  harness — the original `baseline_v2` disaster (a killed process losing 100% of its output) is
  exactly what this prevents.
- **D2 and D7 are coupled — don't test one without the other.** At fixed `TOP_K` retrieval,
  augmenting `knowledge_base.py`'s chunk corpus (D2) makes new chunks compete with old ones for the
  same slots rather than adding to them, which can erode signal for the class you're *not* trying
  to help. A future D2 revisit needs either a higher `TOP_K` or D7's distance-thresholded retrieval
  fix to be a fair test — see `D2_AB_RESULTS.md`.
- **Settings block convention**: every pipeline file keeps a single
  `# ============================== SETTINGS ==============================` block near the top
  holding all tunable constants (regexes, model names, thresholds, directories). No YAML config,
  no env-var-driven config, no logging framework beyond the one documented loguru workaround, no
  plugin system. Preserve this pattern for any new module.
- **Output directories**: `out/` (per-APK outputs from `run_pipeline.py`, transient/regenerable);
  `baseline/` (the completed n=10-malicious measurement run — **do not overwrite**, it's the
  original wider-than-one-sample evidence); `baseline_v2/` (now **complete**, n=46-malicious-
  effective — regenerable by re-running `batch_baseline.py`, but note it now has real content
  worth keeping, same do-not-carelessly-overwrite caution as `baseline/`); `fix3_fp_baseline/`
  (`fix3_fp_harness.py`'s default output dir, regenerable, but the Week-2 n=150/seed=7 run took
  ~38 min — see `FIX3_BEFORE_RESULTS.md` before blowing it away); `d2_ab_results/`
  (`d2_ab_harness.py`'s output dir, regenerable). All gitignored.
- **Never touch `banking_holdout_16/`** in any script. Every harness in this repo has explicitly
  excluded it; it is reserved for the eventual Fix #3 FP-rate validation. Future sessions must
  preserve that exclusion.
- **New PS2/Bridge/Dashboard modules**: no existing convention, since nothing has been built yet.
  When started, give each its own top-level directory under `~/BOIhackathon/` (e.g.
  `setuguard_ps2/`, `setuguard_bridge/`), mirroring `setuguard_ps1/`'s flat-files +
  settings-block + CLI-`main()` style, unless the team decides otherwise.
- **Updating this file**: whenever a pipeline file's schema changes, a new measurement run
  completes, or a new component (PS2/Bridge/Dashboard) gets its first real code, refresh the
  relevant section of `CONTEXT.md` in the same sitting. Don't let it drift the way the actual
  build has already drifted from the roadmap's own week-by-week calendar.

---

## UNVERIFIED / TO CONFIRM

- **Hackathon name ("PSB CyberShield 2026"), team name ("Ciphered Four"), venue ("IIT
  Hyderabad"), and dates ("Aug 27–28")** — all asserted by the user in the prompt that requested
  this document. Grepping every text file in the repo (`idea.txt`,
  `SetuGuard_Development_Roadmap_v2.md`, all top-level `.txt` files, `index-v2.json`) for these
  terms found **zero genuine matches** (one incidental substring hit on "HIIT," an F-Droid workout
  app, inside `index-v2.json`). Not necessarily wrong — just not traceable to any file in this
  repo.
- **"ULB" dataset** referenced in the roadmap for PS2's baseline — the roadmap text says only
  "ULB benchmark" without elaboration. This document does not assert it is the Université Libre
  de Bruxelles credit-card-fraud dataset; that would be an inference, not a verified fact.
- **Why the `baseline_v2` background process was killed** — inferred from environment evidence
  (process absent from `ps aux`, its log file gone, a ~12-day gap between the last file writes in
  the repo and this documentation session) to be a session/container teardown, but the actual
  termination signal or cause was never directly observed.
- The **`logging` file** at the repo top level (6.5MB, identifies as a PostScript document via
  `file(1)`, oddly named) — purpose unknown. Not examined further since it isn't code; flagged
  here only so a future session doesn't assume it's a log file just because of its name.
- **Whether packages were installed with exactly `--break-system-packages`** vs. some other method
  that produced the same `~/.local` result — inferred from hitting the externally-managed-
  environment error earlier in a related session and androguard's presence in `~/.local` without a
  matching `apt` package, but not confirmed via pip's own install records.
- **Whether the ad hoc YARA-vs-raw-APK match success (Section 4/6) generalizes** beyond the 2
  samples it was checked against — treat as "worked twice," not "proven to always work."
