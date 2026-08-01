# SetuGuard — integrated app

This folder wires together the four zips you uploaded into one runnable app:

- `SetuGuard-raghav-week2-ps1` → PS1 malware pipeline (`backend/setuguard_ps1/`)
- `SetuGuard-tanishka-ps2-mule-detection` → PS2 idea, generalized into a real
  endpoint that works on any CSV, not just the hackathon's AMLworld file
- `SetuGuard-bridge-teammate-b` → Bridge idea, wired to real PS1/PS2 output
- `SetuGuard_Frontend` → the dashboard UI, used as-is (`frontend/`)

## Run it

```bash
cd backend
pip install -r requirements.txt
python app.py
```

Backend listens on `http://localhost:5000`. Then just open `frontend/index.html`
directly in a browser (double-click it, or `python -m http.server` from the
`frontend/` folder). In the dashboard's **Settings** page, leave "Base URL"
blank if you're serving the frontend from the same origin as the backend, or
set it to `http://localhost:5000` if you're opening `index.html` as a plain
file (`file://`) — the frontend always calls `<base url> + /api/...`.

## What's real vs. adapted — read this before your demo

**PS1 (malware) — fully real.** `static_analysis.py` (Androguard feature
extraction) and `yara_gen.py` (rule generation) are Raghav's code, unmodified.
`rag_report.py` (the LLM triage stage) needs a local Ollama server running
`mistral` + `nomic-embed-text`. If the backend can't reach one, it
automatically falls back to a deterministic, rule-based verdict computed from
the *same* evidence (same permissions/APIs/strings), so the endpoint never
breaks — the response just says so in the report narrative. Install and start
Ollama (`ollama pull mistral && ollama pull nomic-embed-text`) if you want the
real LLM stage for your demo.

**PS2 (fraud/mule) — real pipeline, generalized.** Tanishka's scripts were
hardcoded to one dataset's column names (`F115`, `F321`, ...). Since the
frontend is a generic "upload any CSV" tool, `/api/analyze_dataset` here is a
from-scratch, general implementation of the same approach: auto-detects the
label column, audits for ID-like and label-leaking columns, trains XGBoost
with stratified CV (falls back to IsolationForest anomaly scoring if there's
no usable label), and explains predictions with SHAP. Point it at your real
AMLworld CSV and it'll work — it just doesn't assume the column names.

**Bridge — the one piece that's still simulated, on purpose.** All three of
your zips' `matcher.py` used explicitly fake, hand-written sample data (its
own comments say "Fake PS1 output" / "Fake PS2 output") — there's no real
device↔account linkage dataset anywhere in the repos to join on. So
`/api/bridge` here takes your **actual** most recent PS1 verdict and
**actual** most recent PS2 top alert and links them using the same
overlap-matching idea, but the specific shared IOC string is a deterministic
synthetic stand-in (clearly labeled `note` field in the response) rather than
a real shared field. If/when a real device/account linkage table exists, swap
that one function (`bridge_endpoint` in `backend/app.py`) to look it up for
real — everything upstream of it is already genuine computed output.

## Files changed from your originals
- `backend/app.py` — new; the only file that ties everything together
- `backend/setuguard_ps1/*.py` — copied unmodified from `raghav-week2-ps1`
- `frontend/*` — copied unmodified from `SetuGuard_Frontend`
