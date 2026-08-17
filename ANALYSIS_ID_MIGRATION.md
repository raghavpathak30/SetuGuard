# Migration spec: global `STATE` → addressable analysis IDs

**Status:** in progress (Batch A implemented, Batch B pending)
**Owner:** Raghav Pathak
**Target:** merged before 27 August (Grand Finale, IIT Hyderabad)
**Files touched:** `setuguard_app/backend/app.py`, one frontend call site, `FROZEN_FILE_FINDINGS.md`
**Files not touched:** all six frozen PS1 files, `models/ps2_xgb_v1.json`, any scorer

---

## 0. Assumptions — verified 2026-08-17, do not re-check

Section 0 originally listed assumptions to verify before starting, written without having
read `app.py`. All five have now been checked against the real code. Results below are
final; the checklist is kept only as a record of what was confirmed.

- **`STATE` location.** Confirmed. Not top-level `app.py` — the real path is
  `setuguard_app/backend/app.py:107`: `STATE = {"last_apk": None, "last_dataset": None}`.
  Every path elsewhere in this document has been corrected to that location.
- **Keys.** Confirmed: `last_apk`, `last_dataset` (matches assumption exactly).
- **`/api/bridge` reads from `STATE`, not the request body.** Confirmed. The handler
  (`setuguard_app/backend/app.py:740-743`) reads `STATE["last_apk"]` / `STATE["last_dataset"]`
  directly and never calls `request.json` or `request.get_json()` — there is currently zero
  input parsing on this endpoint to preserve.
- **Threaded Flask.** Confirmed true, but not for the reason assumed. `app.run(host=...,
  port=..., debug=False)` at line 805 sets no explicit `threaded=`. Checked directly against
  the installed Flask 3.1.1 source: `Flask.run()` does `options.setdefault("threaded", True)`.
  So this *is* threaded by default in this Flask version — the race condition described in
  §1 is real, not theoretical.
- **No other module imports `STATE`.** Confirmed. `grep -rn "STATE" --include=*.py .`
  repo-wide returns hits only inside `setuguard_app/backend/app.py` itself; every other match
  is the unrelated `READ_PHONE_STATE` Android permission string in `setuguard_ps1/*.py`. The
  migration is fully contained to this one file plus the frontend call site.

---

## 1. What this fixes and what it does not

**Fixes**

| Failure | Today | After |
|---|---|---|
| Bridge has no addressable inputs | Links whatever two artifacts were uploaded last, by anyone | Links two named artifacts, echoed back in the response |
| Concurrent requests corrupt each other | Two in-flight analyses overwrite one shared dict | Each analysis owns its own entry |
| Stage demo cross-contamination | A stray upload or refresh silently swaps the linked APK | Bridge names its inputs; a mismatch is visible, not silent |
| Bridge cannot be evaluated over a set | No way to iterate (APK, dataset) pairs | Pairs are addressable, so a batch harness becomes possible |

**Does not fix — still open after this lands**

- The bridge rests on a single synthetic linkage. This spec makes it *addressable*, not
  *evidenced*. Do not let the migration get described as strengthening the linkage itself.
- `shap_drivers` / `generated_rules` / `rule_validated` are hardcoded across all 9,082
  exported records.
- The bridge validation script imports functions `matcher.py` does not define, never calls
  the matcher, and reimplements matching inline. TP=10 / FP=0 / FN=0 / TN=90 remains
  evidence of nothing. (Note: the live `/api/bridge` handler itself does call
  `bridge_matcher.extract_ioc_from_ps1` / `match_account_to_apk` for real — this defect is in
  a separate validation script, not the serving path.)
- `matcher.py` still ships unused outside the one real call site above.
- The Play-signed allowlist is still unimplemented in the serving path.

---

## 2. Data structure

Replace the global with a bounded, lock-guarded store, in
`setuguard_app/backend/app.py`.

```python
import threading
import time
import uuid
from collections import OrderedDict

_ANALYSES_LOCK = threading.Lock()
_ANALYSES: "OrderedDict[str, dict]" = OrderedDict()
_ANALYSES_MAX = 64          # hard cap; oldest evicted first
_ANALYSES_TTL_SEC = 3600    # entries older than this are treated as absent
```

### Entry shape

Every entry, APK or dataset, has the same envelope. The payload under `result` is whatever
the existing analysis function already returns — do not reshape it in this migration.

```python
{
    "id":         "apk_9f2c1a4b",      # or "ds_7e0d33c1"
    "kind":       "apk",               # "apk" | "dataset"
    "created_at": 1755400000.123,      # time.time()
    "label":      "com.example.bank",  # package_name for APK, filename for dataset
    "result":     { ... }              # existing analysis payload, unchanged
}
```

### ID format

Prefixed, so a swapped argument is caught at the boundary instead of producing a plausible
wrong answer.

- APK: `apk_` + 8 hex chars — `f"apk_{uuid.uuid4().hex[:8]}"`
- Dataset: `ds_` + 8 hex chars — `f"ds_{uuid.uuid4().hex[:8]}"`

`/api/bridge` **must reject** an `apk_id` that does not start with `apk_` and a
`dataset_id` that does not start with `ds_`, with HTTP 400. This is the single most
valuable line in the migration: it converts the exact demo-day failure mode from a silent
wrong answer into an error message.

### Accessors

Three functions, all of them the only things that touch `_ANALYSES`:

```python
def store_analysis(kind: str, label: str, result: dict) -> str:
    """Insert an analysis, evict if over cap, return its id."""

def get_analysis(analysis_id: str, expect_kind: str) -> dict | None:
    """Fetch by id. Returns None if absent, expired, or kind mismatch."""

def latest_analysis(kind: str) -> dict | None:
    """Most recent non-expired entry of that kind. Backward-compat path only."""
```

All three take `_ANALYSES_LOCK` for the duration. The lock guards dict mutation only —
never hold it across an Androguard run or an Ollama call. Store the result *after* the
analysis completes.

---

## 3. Endpoint contracts

### `POST /api/analyze_apk`

Request: unchanged.

Response: existing body, plus two top-level fields.

```json
{
  "analysis_id": "apk_9f2c1a4b",
  "kind": "apk",
  "...": "all existing fields unchanged"
}
```

Adding fields is backward-compatible; the inherited frontend ignores what it doesn't read.

### `POST /api/analyze_dataset`

Same treatment. Response gains `"analysis_id": "ds_7e0d33c1"` and `"kind": "dataset"`.

### `POST /api/bridge`

Request body — both fields optional, for backward compatibility:

```json
{ "apk_id": "apk_9f2c1a4b", "dataset_id": "ds_7e0d33c1" }
```

Resolution order per field:

1. Present and valid → use it.
2. Present and malformed (wrong prefix) → **400**, do not fall back.
3. Present and well-formed but unknown/expired → **404**, do not fall back.
4. Absent → `latest_analysis(kind)`. If none exists → **409**.

Response gains a resolution block:

```json
{
  "inputs": {
    "apk":     { "id": "apk_9f2c1a4b", "label": "com.example.bank", "source": "explicit" },
    "dataset": { "id": "ds_7e0d33c1",  "label": "accounts_9082.csv", "source": "fallback" }
  },
  "...": "all existing bridge fields unchanged"
}
```

`source` is `"explicit"` or `"fallback"`. The dashboard renders both labels above the
linkage result. That one line of UI is what makes the bridge traceable for an analyst, and
it is what you point at on stage when a judge asks what is being joined to what.

### Error bodies

Uniform shape, so the frontend needs one handler:

```json
{ "error": "unknown_analysis", "detail": "apk_9f2c1a4b not found or expired", "field": "apk_id" }
```

Codes: `malformed_id` (400), `unknown_analysis` (404), `no_analysis_available` (409).

Note: previously, calling `/api/bridge` before ever running `/api/analyze_apk` or
`/api/analyze_dataset` returned a friendly 400 with a plain-text message. After this
migration that "never analyzed" case returns the structured 409 `no_analysis_available`
instead — a deliberate, documented change, not a regression. The behaviour that must stay
byte-identical is the *populated* case (something has already been analyzed, no explicit
ids given): that's the fallback path, and it's what batch-A's acceptance check verifies.

---

## 4. Frontend changes

Minimal and contained. Deferred to Batch B.

1. On a successful `/api/analyze_apk` response, store `analysis_id` in a module-level
   variable (`lastApkId`). Same for dataset (`lastDatasetId`).
2. `/api/bridge` sends both ids in the request body when they are non-null.
3. Render `inputs.apk.label` and `inputs.dataset.label` in the bridge result header.
4. Surface the three error codes as readable text rather than a blank panel.

If any of this fights the inherited frontend, ship steps 1–2 only. The backward-compat
fallback means the UI keeps working either way; steps 3–4 are the UX gain.

---

## 5. Migration steps — split into two batches

Batch A (Steps 2–5) is additive only: the store goes in, both analyze endpoints gain
`analysis_id`, `/api/bridge` learns to resolve inputs — but `STATE` and its writes stay in
`analyze_apk_endpoint` / `analyze_dataset_endpoint` untouched throughout. If the new
resolution logic in `/api/bridge` has a bug, reverting just that one function's diff
restores the old, fully-working behaviour, because `STATE` was never stopped being
populated. `/api/bridge` itself, however, is rewritten in Step 5 to resolve inputs via the
new store rather than reading `STATE` — that's the one piece of Batch A that isn't purely
additive, which is exactly why the acceptance check below exists.

Batch A stops after Step 5 for a manual acceptance check, run by a human against the live
server — not reported as "looks fine" by whatever implemented it. Only after that check
passes does Batch B (Steps 6–8) proceed, because Step 6 (deleting `STATE`) is the only
irreversible step in this migration: once `STATE` and its writes are gone, there is no
one-function revert left if a wrong assumption surfaces mid-demo.

**Step 1.** Branch and inventory.

```
cd ~/BOIhackathon
git checkout -b fix/analysis-id-store
grep -rn "STATE" --include=*.py .
```

Verify: you have a complete list of `STATE` reads and writes. Confirmed contained to
`setuguard_app/backend/app.py` (see §0).

**Step 2.** Add the store and the three accessors to `setuguard_app/backend/app.py`, above
the current `STATE` definition. Leave `STATE` in place, untouched, for now.

Verify: `python3 -c "import app"` (from `setuguard_app/backend/`) succeeds. Nothing behaves
differently yet.

**Step 3.** In `/api/analyze_apk`, call `store_analysis(...)` after the analysis completes
and add `analysis_id` / `kind` to the response. Keep the existing `STATE` write.

Verify: upload an APK through the UI. The dashboard still works. The response now carries
an `analysis_id` — check in the browser network tab or with a `curl` against the endpoint.

**Step 4.** Same for `/api/analyze_dataset`.

Verify: upload the CSV. Dashboard unchanged. Response carries `ds_...`.

**Step 5.** Rewrite `/api/bridge` to resolve inputs per §3 and emit the `inputs` block.
Fallback path preserves current behaviour exactly for the populated case (see the note at
the end of §3 for the one deliberate exception).

Verify — **human-run, not agent-reported:** run the bridge with an empty body against a
server that already has one APK and one dataset analyzed. Result must be byte-identical to
the pre-migration output, plus the new `inputs` block showing `"source": "fallback"` on
both. This is the check that proves the migration is behaviour-preserving. It is the gate
before Batch B.

--- BATCH A / BATCH B BOUNDARY ---

**Step 6.** Delete `STATE` and its remaining writes.

Verify: `grep -rn "STATE" --include=*.py .` returns nothing in application code.
Restart the server, run the full APK → dataset → bridge sequence, confirm unchanged output.

**Step 7.** Frontend steps 1–2, then 3–4 if they land cleanly.

Verify: bridge request body carries both ids; `inputs[*].source` reads `"explicit"`.

**Step 8.** Log in `FROZEN_FILE_FINDINGS.md` (§7), update `CONTEXT.md`, open the PR.

---

## 6. Test plan

Three tests. The second and third are the ones that matter.

**T1 — round trip.** Analyze APK, analyze dataset, bridge with explicit ids. Assert
`inputs.apk.id` and `inputs.dataset.id` match what was returned, and `source == "explicit"`
on both.

**T2 — argument swap is caught.** Call `/api/bridge` with `apk_id` set to a `ds_...` value.
Assert 400 `malformed_id`. Pre-migration this produced a confident wrong answer; that is
the whole point of the prefixes.

**T3 — concurrency.** Two APK analyses started within a second of each other, then bridge
each against the same dataset by explicit id. Assert each bridge result references the
correct package. Pre-migration one silently wins. If you can only afford one test, this is
it — run it once before the finale and note the result in `SESSION_LOG.md`, because it is
the answer to the most likely hostile question.

Concretely, with two APKs already on disk:

```
cd ~/BOIhackathon
curl -s -X POST -F "apk=@samples/apk_a.apk" http://127.0.0.1:5000/api/analyze_apk &
curl -s -X POST -F "apk=@samples/apk_b.apk" http://127.0.0.1:5000/api/analyze_apk &
wait
```

Substitute the real sample paths before running — do not run this line as-is. (Form field
name is `apk`, confirmed against `setuguard_app/backend/app.py:386`, not the placeholder
`file` originally guessed here.)

---

## 7. `FROZEN_FILE_FINDINGS.md` entry

Append verbatim once Batch B lands:

```
### Finding N — global STATE replaced with addressable analysis store (setuguard_app/backend/app.py)

Date: 2026-08-__
Files: setuguard_app/backend/app.py (non-frozen), frontend bridge call site (non-frozen)
Frozen files touched: none

Reason for change:
setuguard_app/backend/app.py held a single module-level dict STATE (app.py:107) containing
"the last APK analyzed" and "the last CSV analyzed", shared across every request the server
handled. Three consequences:

  1. /api/bridge did not join two named artifacts. It joined whichever two were most
     recently uploaded by anyone. The linkage was a function of request ordering, not of
     any key. This made the bridge unevaluable over a set of pairs.
  2. Concurrent requests mutated the same dict with no lock; one analysis silently
     overwrote another mid-flight. Confirmed exploitable: app.run() in this Flask version
     (3.1.1) defaults threaded=True, so concurrent requests are real, not theoretical.
  3. In a live demo, a stray upload or refresh would attach one APK's verdict to an
     unrelated account set and render it without any indication that it had done so.

Change:
STATE removed. Replaced with a bounded, lock-guarded OrderedDict keyed by generated
analysis ids (apk_<8hex> / ds_<8hex>), cap 64, TTL 3600s. /api/analyze_apk and
/api/analyze_dataset return their analysis_id. /api/bridge accepts optional apk_id and
dataset_id, rejects prefix mismatches with 400, and echoes the resolved inputs (id, label,
explicit-or-fallback) in its response. Omitting both ids reproduces the previous
most-recent behaviour for the populated case, so the inherited frontend is unaffected; the
never-analyzed edge case now returns a structured 409 instead of a plain-text 400 (see
ANALYSIS_ID_MIGRATION.md §3).

Not changed by this edit:
The bridge still rests on a single synthetic certificate-hash / C2-host linkage. This edit
makes the join addressable and traceable; it adds no evidence for the linkage itself.
Hardcoded shap_drivers / generated_rules / rule_validated in the exporter, the unused
matcher.py (outside its one real /api/bridge call site), and the non-functional bridge
validation script are all untouched and remain open.

Verification: T1/T2/T3 in ANALYSIS_ID_MIGRATION.md §6, run 2026-08-__, results in
SESSION_LOG.md.
```

---

## 8. Copilot prompt

Paste this into Copilot Chat with `setuguard_app/backend/app.py` open, after completing
Step 1.

> In `setuguard_app/backend/app.py`, replace the module-level `STATE` dict with a
> per-analysis store.
>
> Add a `threading.Lock`, a bounded `OrderedDict` capped at 64 entries with a 3600-second
> TTL, and three functions: `store_analysis(kind, label, result) -> str`,
> `get_analysis(analysis_id, expect_kind) -> dict | None`, and
> `latest_analysis(kind) -> dict | None`. All three acquire the lock; none of them hold it
> across I/O. IDs are `apk_` or `ds_` followed by 8 hex characters from `uuid.uuid4().hex`.
> Entry shape: `{"id", "kind", "created_at", "label", "result"}`.
>
> `/api/analyze_apk` and `/api/analyze_dataset` call `store_analysis` after their analysis
> completes and add `analysis_id` and `kind` to their existing JSON response. Do not change
> any other response field.
>
> `/api/bridge` accepts optional `apk_id` and `dataset_id` in the request body. Wrong prefix
> returns 400 `malformed_id`. Well-formed but unknown or expired returns 404
> `unknown_analysis`. Absent falls back to `latest_analysis` for that kind, and returns 409
> `no_analysis_available` if there is none. Never fall back after a 400 or 404. The response
> gains an `inputs` object with `apk` and `dataset` sub-objects, each carrying `id`, `label`,
> and `source` set to `"explicit"` or `"fallback"`. All existing bridge response fields stay
> as they are.
>
> Error bodies use the shape `{"error", "detail", "field"}`.
>
> Do not modify any file under `setuguard_ps1/`. Do not change the analysis logic itself.

---

## 9. Hostile judge questions this closes

- *"If I upload an APK right now while you're showing me the account analysis, what
  happens?"* → Nothing. The bridge names its inputs and the dashboard shows which two
  artifacts were linked.
- *"What identifies the APK and the account set you are joining?"* → An analysis id issued
  at ingest, echoed in the bridge response. The join key itself is certificate hash and C2
  host, exact-match.
- *"Show me the bridge running on a second pair."* → Now possible. Before this, it was not.

And the one it does **not** close, which you should still expect:

- *"How many real linkages do you have?"* → One, synthetic. Say it first, before they ask.

**Criteria moved:** Technical Feasibility (demo cannot cross-contaminate; concurrency
answer is real), Innovation (the bridge becomes a join with named operands), User
Experience (analyst can see what was linked to what). Scalability is *not* moved — the
honest answer there is still job IDs, a queue, and a result store, and this is a
single-process in-memory approximation of the first of those three.
