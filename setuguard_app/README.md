# SetuGuard — integrated app

One Flask backend (`backend/app.py`) plus a static dashboard (`frontend/`), wiring
together three components:

- **PS1** — Android banking-malware triage: Androguard static analysis → rule-based
  verdict → optional LLM narrative → YARA generation.
- **PS2** — mule-account scoring: XGBoost inference against a pre-trained artifact.
- **Bridge** — joins a PS1 APK's IOCs (certificate hash, and — not yet firing, see
  below — C2 host) to a PS2-scored account.

## Run it

```bash
cd backend
pip install -r requirements.txt
python app.py
```

Backend listens on `http://localhost:5000`. Then open `frontend/index.html` directly
in a browser (double-click it, or `python -m http.server` from the `frontend/`
folder). In the dashboard's **Settings** page, leave "Base URL" blank if you're
serving the frontend from the same origin as the backend, or set it to
`http://localhost:5000` if you're opening `index.html` as a plain file (`file://`) —
the frontend always calls `<base url> + /api/...`.

## What actually runs — read this before your demo

**PS1 verdict is rule-based, always — the LLM never touches it.**
`_rule_based_verdict()` computes `verdict`, `confidence`, `risk_score` and `severity`
from static evidence (permissions, APIs, strings) before Ollama is ever contacted.
`_try_llm_narrative()` then opens with `report = dict(rule_report)` and, if it
succeeds, assigns exactly two additional keys — `rationale` and `cited_chunk_ids`,
the narrative text and the knowledge-base citations. If Ollama is unreachable, those
two keys are simply omitted; every other field is identical either way. This is
verified behaviourally, not just by reading the code: with Ollama stopped, the same
APK returns the same verdict and the same confidence, captured in
`harness/browser_evidence/ollama_down/`. `verdict_source` in the response is a fixed
string, `"rule_based"` — it does not vary.

**"Confidence" is not a model probability.** It's `round(0.5 + score / 2, 2)`, an
affine transform of the same evidence-weighted score that produced the verdict. It
carries no information the score doesn't already carry. Read it as a second view of
the same number, not an independent signal.

**PS2 is inference-only.** `/api/analyze_dataset` loads a pre-trained XGBoost
artifact (`models/ps2_xgb_v1.json`) once at process start and scores whatever CSV you
upload against the bank's 18 finalized features. There is no training, no
cross-validation, and no SHAP explainer construction inside the request handler — the
explainer is also fitted once at import. The AUCPR/AUROC figures the response
surfaces are the offline 20-seed holdout study's numbers (`models/
ps2_repeated_splits_metrics.json`), not anything computed from your upload.

**Bridge matching is real, but only one of its two join keys fires.**
`/api/bridge` calls `bridge_matcher.extract_ioc_from_ps1()` and
`bridge_matcher.match_account_to_apk()` directly — nothing is reimplemented inline.
In the shipped configuration, only certificate-hash matching can produce a link: the
C2-host path is implemented but its one ground-truth entry has no host configured, so
it has never fired end-to-end. The account-to-APK linkage itself is constructed for
demonstration purposes — no dataset exists anywhere that links real Android malware
certificates to real Indian bank accounts, so the matching *mechanism* is real and the
*linkage* it's demonstrated against is labelled as constructed.

**PS1's static-only ranking inverts on legitimate banking apps.** Measured, not
assumed: PRIMARY AUC 0.1444 [0.0905, 0.2081] over 51 real legitimate banking apps
across 32 issuer clusters vs 360 confirmed malware — see `REPORT_FACTS.md`. The same
scorer separates malware from general-purpose benign apps at AUC 0.9366. PS1 is
scoped to untrusted/sideloaded APKs for this reason.

## Files
- `backend/app.py` — the Flask backend, ties everything together
- `backend/setuguard_ps1/*.py` — PS1 pipeline (six files frozen; see `CONTEXT.md` §5)
- `bridge/matcher.py` — the IOC join logic
- `frontend/*` — the dashboard UI
