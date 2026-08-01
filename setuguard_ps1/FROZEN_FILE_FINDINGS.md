# Frozen-File Findings — Week 2

Same precedent as `DEAD_CODE_REPORT.md`: findings in the six frozen files are reported
here for team sign-off, not silently fixed. Per `CONTEXT.md` Section 9 / the session's
Hard Rules, none of the six files were edited to produce or investigate this finding.

## Finding 1 — unguarded `manifest.iter()` on a possibly-`None` manifest, `static_analysis.py:99-105`

```python
def _extract_exported_components(manifest, package_name):
    """Returns (exported_components[], accessibility_service_names[])."""
    exported_components = []
    accessibility_service_names = []

    for comp_type in ("activity", "service", "receiver", "provider"):
        for node in manifest.iter(comp_type):          # line 105
```

called from `analyze_apk()` at line 209 as:

```python
manifest = a.get_android_manifest_xml()                # line 207
exported_components, accessibility_service_names = _extract_exported_components(manifest, package_name)
```

`a.get_android_manifest_xml()` (androguard) can return `None` when it cannot recover a
usable `AndroidManifest.xml` from the APK. `_extract_exported_components()` does not
check for that before calling `.iter()` on it, so the failure surfaces as:

```
AttributeError: 'NoneType' object has no attribute 'iter'
```

**Observed, not hypothetical — 2 occurrences this session**, found while diagnosing the
27-file unzip-integrity discrepancy (Phase 0 corpus census / STOP 3 diagnostic, Week-2
session):
- `fdroid_benign_apks/app.onloc.android_124.apk` (benign corpus)
- `cicmaldroid_banking/7491d532cf66c5e0683d3d19f22b4bcb1d41dcc445d6cb6b86c4d5a89d3f08fe.apk` (malicious corpus)

Both files pass `file(1)`'s identification as valid APKs but fail strict zip parsing
(`unzip -t`, Python's `zipfile`) — androguard apparently parses the APK container itself
but can't recover a manifest from it.

**This is not a "dirty" failure** by the stress-harness definition (crash/hang/silent
wrong output) — it's a normal Python exception, caught cleanly by every existing
`try/except Exception` call site (`batch_baseline.py`, and `run_pipeline.py`/
`fix3_fp_harness.py` by the same pattern). Nothing currently breaks silently.

**Why it's still worth a team decision (demo-integrity, not just cosmetics):** if this
ever surfaces live — e.g. a judge hands over an APK with a slightly malformed manifest —
the error message is `AttributeError: 'NoneType' object has no attribute 'iter'`, which
reads like a bug in *our* code, not like "this APK has an unparseable manifest." That's a
bad look to explain live, even though functionally the pipeline already skip-logs it
correctly one level up.

**Two options, deliberately not resolved by this session — pick one before any code changes:**

- **(A) Guard and degrade gracefully.** If `manifest is None`, return `([], [])` —
  no manifest means no exported components (and no accessibility-service detection via the
  manifest path). Cheapest, keeps the schema untouched, but silently discards a signal:
  an APK with a deliberately mangled/absent manifest to evade static analysis is itself
  a mildly suspicious trait, and this option throws that trait away.
- **(B) Treat "unparseable manifest" as a first-class signal.** A legitimately-built app
  submitted through a normal toolchain almost always has a parseable manifest; malware
  and hastily-repackaged APKs are more likely to have a damaged one. Surfacing this (e.g.
  a new boolean field, or folding it into `certificate`-style provenance signals) is more
  informative but **likely touches the frozen `features` schema** (Section 4's 11-key
  contract) — that's a bigger change than a bug-fix and needs the heavier sign-off this
  session isn't authorized to give.

**Proposed next step (for sign-off, not applied):** team picks (A) or (B); a narrowly-scoped
follow-up session applies exactly that fix to `static_analysis.py` and nothing else — same
workflow as the `DEAD_CODE_REPORT.md` → `d`-rename precedent.

## Finding 2 — `exported_components[].name` can be `None`, violating the frozen `str` contract, `static_analysis.py:91-106`

```python
def _resolve_component_name(name, package_name):        # line 91
    """Android allows manifest component names like '.MainActivity' as shorthand
    for '<package>.MainActivity'. Expand it so the report is unambiguous."""
    if name and name.startswith("."):
        return package_name + name
    return name                                          # falls through here if name is None

def _extract_exported_components(manifest, package_name):
    ...
    name = _resolve_component_name(node.get(MANIFEST_NS + "name"), package_name)   # line 106
```

`node.get(MANIFEST_NS + "name")` returns `None` when a manifest `<activity>`/`<service>`/
`<receiver>`/`<provider>` node has no `android:name` attribute. `_resolve_component_name()`'s
`if name and ...` guard is `False` for `None`, so it falls through to `return name`, returning
`None` unchanged. That `None` is then written straight into
`exported_components[i]["name"]` — but `CONTEXT.md` Section 4's frozen `features` schema
(and `batch_baseline.py`'s own `EXPORTED_COMPONENT_SCHEMA`/this session's
`validation_gate.py`'s `EXPORTED_COMPONENT_SCHEMA`) both declare `name` as `str`,
unconditionally.

**Observed, not hypothetical — 3 occurrences in the `baseline_v2` run** (Week-2 session,
`setuguard_ps1/baseline_v2/summary.txt`'s schema-check section, `FAIL`): malicious samples
`0297b767436fc1028cf7400a80a46681a3a7573fe81b86bb49fb48c4ca0a41e1.apk`,
`02a3ae0d4ee42a2b43eb6d73238705e8ed848e454cfb392bd97ea04d562bf038.apk`, and
`04d7ec12ce08dad04e7836fca5fac5b87108ae6a7a137275292df4da9cd5007e.apk` each had **all 11**
of their exported components come back with `name = None` — i.e. every single exported
component in those three manifests lacked an `android:name` attribute, which is unusual
enough to itself be a mild signal (possibly manifest obfuscation/tooling artifact — not
established either way this session).

**Why this matters:** this is a genuine, measured violation of the frozen features
contract — the same contract `baseline/`'s Week-1 run (n=50) reported as a clean PASS with
"0 anomalies" and that `CONTEXT.md` Section 2 describes as "schema held stable... across 50
real samples." That claim held for the specific 50 samples in `baseline/`; it does **not**
generalize to the wider `baseline_v2` sample (n=86 successfully processed) — 3/86 (3.5%)
violate the `name: str` guarantee. Any downstream consumer (Bridge, Dashboard,
`validation_gate.py` itself) that assumes `exported_components[].name` is always a usable
string will break or misbehave on these samples.

**Two options, deliberately not resolved by this session:**

- **(A) Coerce to a placeholder string** (e.g. `""` or `"<unnamed>"`) in
  `_resolve_component_name()` when `name` is `None`. Cheapest, restores the type contract,
  but manufactures a value that wasn't in the manifest — the placeholder itself needs to be
  documented as a sentinel so downstream consumers don't mistake it for a real component name.
- **(B) Loosen the frozen schema** to declare `name: str | None` explicitly, and push the
  "what does a None name mean" question to every consumer. More honest about what androguard
  actually returns, but is a schema-contract change (Section 4) — the same class of change as
  Finding 1's option (B), and needs the same sign-off weight.

**Proposed next step (for sign-off, not applied):** team picks (A) or (B); a narrowly-scoped
follow-up applies exactly that fix to `static_analysis.py` (and, if (B), `CONTEXT.md` Section 4
and every schema-checking file: `batch_baseline.py`, `validation_gate.py`) and nothing else.

## Finding 3 — `ollama.chat()` is called with no `options`, so generation is unpinned and non-deterministic, `rag_report.py:71-78`

```python
resp = ollama.chat(
    model=GEN_MODEL,
    messages=[
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ],
    format=REPORT_SCHEMA,
)
```

No `options={...}` is passed — confirmed by reading this exact call (Phase 0.1, Week-2 session)
and by inspecting the installed `ollama` client's `chat()` signature, where `options` defaults to
`None`. `ollama show mistral --modelfile` has no `PARAMETER temperature` line either, so
whatever temperature/seed Ollama uses is a server-side default not inspectable from anything
installed in this Python environment — not stated here from memory, per this session's rule
against guessing numbers.

**Observed, not hypothetical — measured this session (Phase 3.0, the D6 determinism check):** 3
real samples, each run twice through `generate_report()` with identical input, same process,
back to back:

| Sample | Run 1 verdict/confidence | Run 2 verdict/confidence |
|---|---|---|
| malicious (`com.baidu.pay2`) | suspicious / 0.80 | suspicious / 0.85 |
| benign (`InfinityLoop...NewPipeEnhanced`) | suspicious / 0.75 | suspicious / 0.65 |
| malicious (max dangerous_permissions) | **suspicious** / 0.75 | **malicious** / 0.90 |

Confidence moved on all 3 pairs; the categorical **verdict itself flipped** on one. Every
`cited_chunk_ids` list was also different between the two runs of the same sample, and 4 of the
6 runs cited values that don't exist in `knowledge_base.CHUNKS` at all (caught by this session's
`validation_gate.py`).

**Why this is now the root blocker, not a footnote:** it means the baseline/`baseline_v2`
confidence distributions, the "100% suspicious" verdict finding, and the n=10-vs-n=46 separation
question are all **confounded by generation randomness** — some unknown fraction of what looks
like "the model's classification behavior" is actually run-to-run sampling noise. No downstream
measurement (D1's verdict-derivation proposal, the D2 A/B, Fix #3's FP-rate number) can be
trusted as a stable result until this is closed. See `VERDICT_GATE_PROPOSAL.md` Section 0 for
the full determinism-check writeup.

**Framed honestly — what pinning this would and wouldn't do:**
- It delivers **reproducibility, not correctness.** Pinning `temperature=0` (and a fixed `seed`)
  freezes in whatever prompt-wording bias and retrieval bias (including D2's all-malicious
  knowledge base) currently exist. The team would be locking the model's behavior down in order
  to *study* it deterministically — not fixing the "100% suspicious" problem itself. D1/D2 stay
  open after this fix, just measurable instead of noisy.
- **Sub-choice for the team:** `temperature=0` (fully greedy decoding) vs. a low nonzero value
  (e.g. 0.1–0.2, some determinism while allowing the model a little room). Recommend
  `temperature=0` **and** a fixed `seed` together for a classification task — temperature alone
  is not always sufficient for bit-for-bit reproducibility on every inference stack (some
  llama.cpp-based backends, which Ollama uses, exhibit residual nondeterminism at
  `temperature=0` without an explicit seed pin, due to batching/threading order — **this needs
  empirical verification on this specific installed build**, not assumed from general
  llama.cpp reputation; that verification is exactly step 2 in your instructions below, to run
  after sign-off and the edit).

**Proposed next step (for sign-off, not applied):** team confirms (i) pin, (ii) `temperature=0`
vs. low-nonzero, (iii) whether to also pin `seed` (recommended: yes, alongside `temperature=0`).
A narrowly-scoped follow-up then adds exactly
`options={"temperature": 0, "seed": <fixed_int>}` (or whatever the team picks) to the one
`ollama.chat()` call in `rag_report.py` and nothing else — same precedent as the dead-code
rename. Verification (repeat the 3-sample/2-run determinism check, confirm identical
verdict+confidence+`cited_chunk_ids` across repeats) happens **after** the edit, before this
finding is considered closed.

**APPLIED** (sign-off given, narrow one-line edit): `rag_report.py:78` now reads
`options={"temperature": 0, "seed": 42},` and nothing else in the file changed (diff verified
before and after write). `py_compile` and a live one-sample smoke test both passed post-edit.

**Post-edit verification result (F3.3) — determinism did NOT fully hold:**

| Sample | verdict/confidence across 2 runs | `cited_chunk_ids` across 2 runs |
|---|---|---|
| malicious (`com.baidu.pay2`) | identical (suspicious/0.80) | **identical** |
| benign (`InfinityLoop...NewPipeEnhanced`) | identical (suspicious/0.70) | **identical** |
| malicious (max dangerous_permissions) | identical (suspicious/0.85) | **different** — run 2 replaced 5 real MITRE-style citations with 4 fabricated pseudo-field-names |

Verdict and confidence are now stable across all 3 pairs. `cited_chunk_ids` is stable in 2/3 but
diverged completely in the third — confirming the residual-nondeterminism risk flagged when this
finding was proposed: `temperature=0` + a fixed `seed` does not guarantee bit-for-bit
reproducibility on every field, on this llama.cpp-based Ollama build.

**Grounding-hallucination rate (a separate property from run-to-run stability) — unaffected by
the pin:** 5/6 runs still fail `validate_report_grounding()` post-pin vs. 4/6 pre-pin (noise-level
difference at this sample size, not evidence pinning made it worse). One nuance: two of the
post-pin fabrications were *identical* across both runs of their sample (a truncated MITRE id
`'T1636'`, and a permission name `'RECEIVE_BOOT_COMPLETED'` cited as if it were a chunk id) —
pinning converted some hallucination into a reproducible-but-still-wrong citation rather than
eliminating it.

**Conclusion:** this finding stays open. Verdict/confidence can now be treated as stable;
`cited_chunk_ids` cannot. Per instruction, downstream work (D2 A/B, Fix #3 before-number) is
paused pending your review of this result — see the session transcript for the full report.

---

## Finding 4 — `cited_chunk_ids` is schema-unconstrained, which is why it both hallucinates and jitters, `report_prompt.py:36-39`

```python
"cited_chunk_ids": {
    "type": "array",
    "items": {"type": "string"},
},
```

Parked-research finding, **not acted on** — logged for a future session, per your explicit
instruction. `REPORT_SCHEMA`'s other model-authored fields are content-constrained by Ollama's
schema-guided decoding: `verdict` to a 3-value enum, `confidence` to a bounded number. Those two
fields came back bit-for-bit deterministic post-Finding-3-pin (see above). `cited_chunk_ids` has
no such constraint — it's typed as "array of arbitrary strings," not "array of strings drawn from
the 16 legal chunk ids." That's the same reason it (a) hallucinates non-existent ids
(`validate_report_grounding` catching 4-5/6 runs) and (b) is the one field that still jittered
between identical pinned runs (Finding 3's verification) — an unconstrained free-text field has
no decode-time pressure toward a fixed small vocabulary, with or without a seed.

The one post-pin failing run didn't even attempt a citation-shaped string — it echoed literal
feature-dict key names (`'dangerous_permissions'`, `'exported_components'`,
`'suspicious_api_usage'`, `'retrieved_mitre_attack'`), i.e. the field decoded as if answering "what
sections did you look at" rather than "which of these 16 ids did you cite" — further evidence it's
running effectively unconstrained.

**Not analyzed further, not fixed.** A real fix would schema-constrain `cited_chunk_ids` to an
enum of the 16 legal ids (or a `oneOf`/`enum`-per-item structure Ollama's JSON-schema decoding
supports) — that's a `report_prompt.py`/`REPORT_SCHEMA` change, i.e. touches a second frozen file,
and needs the same weight of sign-off as Findings 1/2. Filed here so it isn't lost, not queued for
action this session.

## Finding 5 — coupled two-file defect: control-byte over-capture + under-sanitization poisons rule generation and crashes YARA compilation, `static_analysis.py:82` + `yara_gen.py:35-39`

```python
# static_analysis.py:82
"url": re.compile(r"https?://[^\s\"']{4,}"),
```
```python
# yara_gen.py:35-39
def _yara_escape(value: str) -> str:
    value = value.replace("\n", " ").replace("\r", " ")
    return value.replace("\\", "\\\\").replace('"', '\\"')
```

**Observed, not hypothetical — found live tonight**, when `fix3_fp_harness.py`'s n=150 Fix #3
run crashed at sample 4 (`com.dmouayad.my_quran_233.apk`, a real F-Droid benign app) with an
uncaught `ValueError: embedded null character` from `yara.compile(source=...)`. Root-caused
by reproducing the crash directly and scanning the extracted `features` dict field by field.

**The chain:**
1. The app contains an embedded, null-terminated Adobe XMP metadata string in an image asset
   (`http://ns.adobe.com/xap/1.0/\x00` — `ns.adobe.com/xap/1.0/` is the standard XMP
   namespace URI baked into huge numbers of JPEG/PNG files by any Adobe-touched image
   pipeline).
2. `static_analysis.py:82`'s url regex, `[^\s"']{4,}`, excludes only whitespace and quote
   characters — **not control characters** — so the trailing NUL byte is captured as part of
   the matched string and lands in `features["suspicious_strings"]`.
3. `yara_gen.py`'s `_yara_escape()` (lines 35-39) strips `\n`/`\r` and escapes
   backslash/quote, but has **no NUL handling** — so the NUL flows unchanged into the
   generated `.yar` rule's string literal.
4. `yara.compile(source=rule_text)` rejects the resulting source with a plain `ValueError`
   (not `yara.Error`) — confirmed this is genuinely a different exception class, which is why
   `fix3_fp_harness.py`'s original `except yara.Error` didn't catch it and the whole batch
   died (harness-side fix applied and verified separately, see below — this finding is about
   the frozen-file root cause, not the harness bug it exposed).

**Two distinct consequences, both real:**
- **A crash** when the poisoned string reaches `yara.compile()` directly (any harness or
  future caller that doesn't specifically anticipate this).
- **Where a rule *does* still compile** (a NUL elsewhere in the string, or a different
  control byte YARA tolerates), a **poisoned indicator**: the generated rule would contain
  `$indicator_str_N = "...ns.adobe.com/xap/1.0/..."`, which really just means "this app
  contains an image processed by Adobe software at some point" — noise, present in benign
  and malicious apps alike, the same class of problem as a hallucinated LLM indicator
  (D4), except this one is injected by the static-analysis stage itself rather than the
  model.

**Blast radius, not yet measured but likely large:** XMP metadata is extremely common in
ordinary image assets bundled with ordinary apps — this is very unlikely to be a
one-freak-sample fluke. The restarted Fix #3 run's NUL-skip count (tracked as its own skip
reason, `yara_compile:embedded_null`) is the first real measurement of how common this is
in `fdroid_benign_apks/`.

**Demo-integrity note:** a live, uncaught `ValueError: embedded null character` crashing a
batch run (or worse, a live single-APK demo) in front of judges is a bad look, independent
of the noise/poisoning concern.

**Gate gap, checked tonight, not fixed:** `validation_gate.validate_indicator_traceability()`
was tested against a synthetic NUL-bearing indicator and **returned zero violations** — it
correctly confirms the value traces back to a real `suspicious_strings[].value` entry, but
has no well-formedness check (printable-only, no control characters) at all. The gate
validates *provenance*, not *sanity* — it would pass this indicator through as legitimate.
Noted for a future gate revision; not fixed tonight.

**Two options for the team, likely both needed (independent hardenings of the same
failure), deliberately not resolved by this session:**
- **(A) Tighten the regex** in `static_analysis.py:82` to exclude control characters (e.g.
  `[^\s"'\x00-\x1f]{4,}` or similar) — stops the poisoned value from ever entering
  `suspicious_strings` in the first place.
- **(B) Harden `_yara_escape()`** in `yara_gen.py` to strip or escape NUL (and other control
  bytes) defensively at rule-generation time — stops the crash even if some other unforeseen
  path produces a control-byte-bearing string.

**Proposed next step (for sign-off, not applied):** team picks (A), (B), or both (likely
both, since they guard different layers); a narrowly-scoped follow-up applies exactly that
fix to the named file(s) and nothing else. `static_analysis.py` and `yara_gen.py` were not
edited to investigate or produce this finding.

## Status

- **Finding 1** (unguarded `manifest.iter()`) — sign-off-gated, **not applied** this session.
- **Finding 2** (`None` component names) — sign-off-gated, **not applied** this session.
- **Finding 3** (temperature/seed pin) — **applied**. Verdict/confidence are now bit-for-bit
  deterministic; `cited_chunk_ids` is not (see Finding 4 for why) — team judged this an acceptable,
  substantively-closed result for measurement purposes, since no downstream measurement reads
  `cited_chunk_ids`.
- **Finding 4** (`cited_chunk_ids` schema-unconstrained) — parked research finding, **not applied**,
  touches `report_prompt.py`.
