# PS1 — Defects and Improvements

Scope: PS1 only. Ordered by severity. "Must fix" items are correctness or
demo-integrity problems. "Should improve" items make the system better but nothing
breaks without them.

Every item states the evidence it rests on. Items marked **[verify]** are things I
have not confirmed in the code — check before acting on them.

---

## MUST FIX

### D1 — The categorical verdict carries no signal
**Severity: critical.** 100% of 50 baseline samples returned `"suspicious"` — benign and
malicious alike. Confidence separates the classes correctly (~0.45–0.75 benign, ~0.75–0.85
malicious), so the reasoning is sound; only the label is useless.

**Why it must be fixed:** any downstream consumer (Bridge, Dashboard) keying off the
verdict string sees zero variation. It also makes the demo look broken if a judge asks to
see per-sample output.

**Likely causes, in order of suspicion:**
1. Asymmetric retrieval — see D2, which may be the root cause.
2. Hedging language in `SYSTEM_PROMPT` ("be cautious", "avoid definitive claims").
3. No decision thresholds in the prompt, so the model invents its own and lands in the middle.
4. Three-way enums invite the safe middle option under uncertainty.

**Fix options (team decision, not a silent patch):**
- Derive the verdict from the confidence float with explicit thresholds, and keep the
  model's enum as advisory only. Cheapest, most defensible.
- Add explicit decision criteria to the prompt ("call it benign when …, malicious when …").
- Collapse to a 2-way enum plus confidence.

**Do not** patch this mid-session without team sign-off — it changes the frozen schema's
semantics.

---

### D2 — Knowledge base has no benign-behaviour chunks
**Severity: critical (likely root cause of D1).** All 16 chunks describe *malicious*
behaviour. There is no chunk saying "SMS access is normal for a messaging app" or
"INTERNET is near-universal and not by itself suspicious."

Because similarity search always returns *k* results, a benign APK still retrieves *k*
malware-behaviour chunks. The model sees benign features juxtaposed with malware knowledge
and splits the difference — which is exactly the "suspicious" hedge.

**Fix:** add negative-evidence chunks — normal permission profiles for common app
categories (messaging, banking, media, utilities). This is cheap (writing text), needs no
code change, and plausibly fixes D1 at the source rather than papering over it downstream.

**This is the highest-leverage single change available in PS1.**

---

### D3 — Benign apps generate YARA rules
**Severity: critical.** Confirmed empirically: on a 2-sample smoke test of
`fix3_fp_harness.py`, one benign F-Droid app tripped the FP signal — verdict "suspicious",
rule generated.

A detection rule generated from a benign banking app is the worst possible failure for
this product. Shipping that to a SOC means false alerts on legitimate software.

**Fix:** this is the substance of Fix #3. Requires the real corpus (see D9) plus tuning of
(a) the gate that decides whether a rule is generated at all, and (b) the `condition:`
threshold. Target is 0 FP across the F-Droid corpus and all 16 real banking apps.

Depends on D1/D2 — if the verdict is always "suspicious", any gate keyed to it fires
always.

---

### D4 — No validation gate exists
**Severity: high.** This was a Week-2 roadmap deliverable and was never built. Nothing
between Mistral's output and rule generation checks that the report is sane.

**What a gate should check:**
- `verdict` is one of the legal enum values (JSON mode guarantees syntax, not semantics).
- `confidence` is in range and present.
- Cited MITRE IDs actually exist in `knowledge_base.py` — catches fabricated technique IDs.
- Indicators are non-empty and traceable to the extracted feature set — catches
  hallucinated indicators that would poison the YARA rule.

The MITRE-ID check is the important one: it is a direct, cheap grounding-faithfulness
test, and it is the same idea as the roadmap's optional "grounding-faithfulness gate"
stretch goal.

---

### D5 — YARA rules may not match raw APKs in general
**Severity: high.** Rules assume indicator strings are byte-present in *decompressed*
DEX/AXML. Most APK zip entries are DEFLATE-compressed, so YARA scanning a raw `.apk` reads
compressed bytes. Ad-hoc verification succeeded on 2 samples — likely because some entries
are `STORED` uncompressed — but that is "worked twice", not "works".

**Risk:** a rule that fails to match live in front of judges.

**Fix options:**
- Scan decompressed content: extract DEX + manifest, run YARA against those. Correct but
  changes the deployment story.
- Keep raw-APK scanning and validate breadth empirically across the full corpus, then state
  the measured hit rate honestly.

Either way, **volunteer this caveat before a judge finds it.**

---

### D6 — Reproducibility is unverified [verify]
**Severity: high.** Check the generation `temperature` in `rag_report.py`. If it is not
low/zero, the same APK can produce different verdicts across runs, which means the baseline
numbers are not reproducible — directly undermining Risk #5 in the roadmap ("re-run results
more than once before either goes in the progress report").

**Fix:** pin temperature low for a classification task. Then re-run a handful of samples
twice and confirm identical output.

---

### D7 — No retrieval distance threshold [verify]
**Severity: medium-high.** FAISS returns *k* results regardless of match quality. If
`rag_report.py` takes top-*k* blindly without inspecting distance scores, an APK whose
behaviour is unlike anything in the knowledge base still gets *k* confidently-formatted
chunks pasted into its prompt.

**Fix:** threshold on distance; if the nearest chunk exceeds it, either retrieve nothing
and let the prompt say so, or flag low retrieval confidence in the report.

---

### D8 — No reproducibility scaffolding
**Severity: medium-high.** No `requirements.txt`, no Dockerfile, no Makefile. The entire
pip + Ollama environment exists only as installed state on one machine. If the demo machine
changes or breaks before 27–28 August, setup is a manual rebuild under deadline.

**Fix:** `pip freeze` into a pinned `requirements.txt` at minimum; record Ollama model tags
(`mistral`, `nomic-embed-text`) and CUDA assumptions. An hour of work that removes a
single-point-of-failure risk.

---

### D9 — Fix #3 has no real corpus yet
**Severity: medium-high (blocking Fix #3).** `fix3_fp_harness.py` is built and works, but
the F-Droid pull (~500–1,000 apps) and the 16 real banking APKs are unsourced. Until they
exist, the FP number cannot be measured, let alone driven to zero.

---

### D10 — The n=50 confidence-separation re-run never finished
**Severity: medium.** `baseline_v2/` exists but is empty; the background job died with the
session. The open question — does confidence separation hold past n=10 malicious, or does
it bleed into the benign range? — is unanswered.

This matters because **confidence is the only signal that currently works** (see D1). If it
degrades at larger n, PS1 has no working discriminator at all.

**Fix:** re-run `batch_baseline.py` (already configured for `NUM_MALICIOUS=50`,
`OUT_DIR=baseline_v2`). Cheap. Use `nohup`/`tmux` so a session teardown does not kill it
silently again.

---

### D11 — Corrupted sample in the benign corpus
**Severity: low.** `fdroid_benign_apks/app.fedilab.nitterizeme_35.apk` is truncated at
exactly 1,048,576 bytes (cut-off download). Every harness already skip-logs it cleanly, so
nothing breaks — but delete and re-download so batch runs stop carrying dead weight.

---

## SHOULD IMPROVE

### I1 — Knowledge base is thin
16 chunks covering 14 MITRE IDs is defensible as curation, but coverage is the tradeoff:
behaviour outside those chunks retrieves the *nearest* chunk, not a *relevant* one. Expand
where the feature extractor produces fields no chunk grounds. The operating principle:
every meaningful feature field should have at least one chunk explaining its significance.

### I2 — No AutoYara fallback
Another unbuilt Week-2 deliverable. When the LLM produces no usable indicators, there is no
fallback path to a rule. Currently that sample just yields nothing.

### I3 — Condition threshold is likely fixed [verify]
If `yara_gen.py` always emits `2 of them` regardless of indicator count or confidence, rule
specificity is not adapting to evidence strength. Scaling the threshold with indicator count
or confidence would improve both FP rate and robustness.

### I4 — Confidence is uncalibrated
The confidence float separates classes but has never been checked for calibration — does
0.8 actually mean 80% likely malicious? Not required for the demo, but if you derive the
verdict from confidence (D1 fix), the thresholds should be set from measured distribution,
not intuition.

### I5 — No automated tests
No test suite anywhere. For six files declared frozen, a handful of smoke tests asserting
the 11-key schema and end-to-end run would make future changes safe and would answer
"how do you know you didn't break it?"

### I6 — Prompt is unversioned
Prompt wording materially changes output, but there is no record of which prompt version
produced which baseline. If you change `SYSTEM_PROMPT` to fix D1, the old baseline numbers
become incomparable. Add a prompt version string to the report `meta`.

---

## Suggested order of attack

1. **D2** (add benign chunks) — cheapest, likely fixes D1 at the source
2. **D1** (verdict decision, with the team) — unblocks D3 and the Bridge contract
3. **D6, D7** (verify temperature and distance thresholds) — minutes each, may be non-issues
4. **D4** (validation gate) — Week-2 deliverable, contains the grounding check
5. **D10** (re-run baseline_v2) — cheap, runs in background while you do the above
6. **D8** (requirements.txt) — an hour, removes single-machine risk
7. **D9 → D3** (source corpus, then drive FP to zero) — the bulk of Fix #3
8. **D5** (YARA compression) — measure breadth, decide with the team
9. Everything in "Should improve" as slack allows
