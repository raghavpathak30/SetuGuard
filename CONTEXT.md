# SetuGuard — Repository Context

_Last written: 2026-07-20, by a Claude Code documentation pass. Everything below was verified
against the actual filesystem/environment on that date unless marked otherwise in the
"UNVERIFIED / TO CONFIRM" section at the end. Read that section before trusting any claim about
identity/dates/venue._

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
| PS1 `rag_report.py` | **DONE** | End-to-end tested against `ollama` (mistral + nomic-embed-text), returns valid JSON matching `REPORT_SCHEMA` |
| PS1 `yara_gen.py` | **DONE** | Rules verified to actually **compile and match** with the real `yara` CLI (`yara-python` 4.5.1) against one malicious and one benign real sample |
| PS1 `run_pipeline.py` | **DONE** | Glue entrypoint; chains the three stages by import (no shelling out); writes `out/<pkg>.{features.json,report.json,report.md,yar}` |
| PS1 `batch_baseline.py` | **DONE** for n=10 malicious + n=40 benign (`baseline/`); **INCOMPLETE** for n=50 malicious + n=40 benign (`baseline_v2/` exists but is **empty** — see below) |
| PS2 (XGBoost/SHAP/graph mule detection) | **NOT STARTED** | Exhaustive `find` for `xgboost`/`mule`/`ps2`/`shap`/`graph`-named files under `~/BOIhackathon` returns nothing but incidental APK filename matches (e.g. `com.eanema.graph89_...apk`, an unrelated F-Droid app) |
| Bridge (PS1↔PS2 IOC enrichment) | **NOT STARTED** | No files found; cannot meaningfully exist without PS2 |
| Dashboard/Audit UI | **NOT STARTED** | No files found |
| Fix #3 (F-Droid + 16-real-bank holdout, FP-rate → 0) | **NOT STARTED** | `banking_holdout_16/` (16 apks) exists and is scrupulously *un-touched* by every script in the repo, but nothing reads it yet; no validation gate exists (explicitly out of scope per every build instruction given so far) |
| Fix #4 (Obfuscapk survival matrix) | **NOT STARTED** | No `obfuscapk` anywhere; not even the Week-1 "Day 5–6 risk spike" (install it, run it once) has any trace in the repo |
| Version control | **MISSING** | `git rev-parse --is-inside-work-tree` fails at the filesystem boundary — there is no `.git` anywhere under `/home/raghavp/BOIhackathon`. No commit history exists at all; all project history lives only in Claude Code conversation transcripts |

**Known-broken / blunt findings:**

- **The RAG report's categorical verdict has never once been "benign" or "malicious" in any measured run.** Across the 50-sample `baseline/` run (40 benign + 10 malicious), **100% of verdicts were the string `"suspicious"`**, regardless of true label. Confidence *does* separate the classes (benign 0.45–0.75, malicious 0.75–0.85 — see Section 6), but the 3-way enum currently carries almost no signal. This was measured, not fixed (explicit instruction: "do not tune prompts, add validation gates" for these measurement tasks).
- **The wider n=50-malicious confidence-separation re-run never finished.** `baseline_v2/` was created (`mkdir`'d) but contains **zero files** — the background process (PID 99102, started via `nohup ... &; disown`) was killed when the working session/container was torn down mid-run (only 2 of 90 samples had logged before the log file itself disappeared). The question "does confidence stay separated past n=10 malicious, or does it bleed into the benign range?" is **still open** and needs a straight re-run of `batch_baseline.py` (already configured for `NUM_MALICIOUS=50`, `OUT_DIR=baseline_v2`).
- One corrupted file exists in the benign corpus: `fdroid_benign_apks/app.fedilab.nitterizeme_35.apk`, truncated at exactly 1,048,576 bytes (a suspiciously round number — almost certainly a cut-off download). `unzip -t` confirms "cannot find zipfile directory." `analyze_apk()` raises cleanly on it (androguard/apkInspector `ValueError: End of central directory record (EOCD) signature not found`); this is bad corpus data, not a pipeline bug, and every harness's try/except-per-stage already logs-and-skips it correctly.
- YARA rules are generated assuming indicator strings are byte-present in **decompressed** DEX/AXML content (flagged explicitly in `yara_gen.py`'s module docstring) — most APK zip entries are DEFLATE-compressed, so a raw untouched `.apk` file is not guaranteed to byte-match. Ad hoc verification during this project (2 real samples, one malicious one benign) *did* successfully compile-and-match with the real `yara` CLI against the raw `.apk`, but that is not a general guarantee across build toolchains.
- **No `requirements.txt`, `pyproject.toml`, `Dockerfile`, `Makefile`, or `.ipynb` exists anywhere in the repository.** Reproducibility currently depends entirely on Section 5 of this document plus the installed state of this one machine.

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

Pinned dependency versions actually installed (`python3 -m pip list`), since **no
requirements.txt exists anywhere in the repo** — this table is the reproducibility record until
one is written:

| package | version |
|---|---|
| androguard | 4.1.4 |
| asn1crypto | 1.5.1 |
| faiss-cpu | 1.14.3 |
| loguru | 0.7.3 |
| numpy | 2.2.4 |
| ollama (python client) | 0.6.2 |
| yara-python | 4.5.1 |

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

# re-run the (currently incomplete) wider measurement batch
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

### `baseline_v2/` — INCOMPLETE (attempted 40 benign + 50 malicious)

Source: directory exists (`setuguard_ps1/baseline_v2/`), confirmed **empty** — no `results.csv`,
no `summary.txt`, no `one_real_sample.features.json`. The background run was started to test
whether the confidence separation above holds past only 10 malicious data points, got at least 2
samples in (per the last-seen log fragment, both benign apps), and was killed when the working
session/container ended before it could write any output. **This question is unanswered and
needs a straight re-run** — the harness is already configured correctly for it
(`NUM_MALICIOUS = 50`, `OUT_DIR = baseline_v2`), so re-running `python3 batch_baseline.py` should
just work; budget ~15–25 minutes wall time based on the v1 run's per-apk rate.

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
4. **Fix #3 (F-Droid + 16-real-bank holdout FP-rate tuning) not started**, despite being the most
   directly relevant fix given the measured 100%-"suspicious" categorical-verdict finding
   (Section 6). The holdout corpus is correctly untouched and ready to use.
5. **Fix #4 (Obfuscapk survival matrix) not started** — not even the Week-1 "install it, run it
   once" risk spike has any trace in the repo.
6. **The wider (n=50-malicious) confidence-separation re-run is incomplete** (`baseline_v2/` is
   empty). Cheap to fix: just re-run `batch_baseline.py`.
7. **The verdict enum currently carries near-zero signal** (100% "suspicious" across all 50
   measured samples). If any planned downstream consumer (Bridge, Dashboard) keys off the literal
   string rather than the confidence float, it will see no variation at all. This needs an
   explicit team decision — not something to silently patch mid-session, per repeated user
   instruction on prior tasks.
8. **No version control exists anywhere in the repository.** No `.git`, no commit history, no
   branches. All project history lives only in Claude Code conversation transcripts. Any
   accidental overwrite or deletion has zero rollback path. For a 4-person team converging on a
   hard deadline, this is a standing operational risk independent of any code issue.
9. **No `requirements.txt`/Dockerfile/environment file exists.** Reproducibility currently depends
   entirely on Section 5 of this document. If the demo machine changes, setup must be redone by
   hand.
10. **YARA-vs-compressed-APK caveat is only spot-checked on 2 samples.** Worth a broader
    validation pass (e.g., against the holdout set, once Fix #3 starts using it) before relying on
    generated rules matching raw APKs live in front of judges.
11. One corrupted sample (`app.fedilab.nitterizeme_35.apk`, truncated at 1,048,576 bytes) sits in
    the benign corpus — harmless (fails cleanly, already skip-logged by every harness) but worth
    deleting/re-downloading so future batch runs don't carry dead weight.
12. Team/hackathon identity details (name, venue, dates) are asserted by the user but not found
    anywhere in repo text — low risk, noted for traceability only.

---

## 9. CONVENTIONS FOR FUTURE SESSIONS

- **The six frozen PS1 pipeline files** are: `static_analysis.py`, `knowledge_base.py`,
  `report_prompt.py`, `rag_report.py`, `yara_gen.py`, `run_pipeline.py`. Each is independently
  runnable via CLI (`python3 <file>.py ...`) and importable as a plain module — stages are
  chained by import, never by shelling out to each other. **Do not modify these six without
  explicit user sign-off.** Every task given on this project so far has explicitly separated
  "build/modify the six" from "measure/test, read-only" — preserve that boundary.
- **Measurement/analysis harnesses** (currently just `batch_baseline.py`) live alongside the six
  files in `setuguard_ps1/` but must say in their own module docstring that they are *not* one of
  the six, and must not mutate them.
- **Settings block convention**: every pipeline file keeps a single
  `# ============================== SETTINGS ==============================` block near the top
  holding all tunable constants (regexes, model names, thresholds, directories). No YAML config,
  no env-var-driven config, no logging framework beyond the one documented loguru workaround, no
  plugin system. Preserve this pattern for any new module.
- **Output directories**: `out/` (per-APK outputs from `run_pipeline.py`, transient/regenerable);
  `baseline/` (the completed n=10-malicious measurement run — **do not overwrite**, it's the only
  complete wider-than-one-sample evidence that exists); `baseline_v2/` (the incomplete n=50
  attempt — currently empty, safe to regenerate by re-running `batch_baseline.py`).
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
