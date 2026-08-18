# Bridge demo runbook — verified matching and non-matching paths

**Status:** both paths run end to end against the live backend on 2026-08-18 and recorded
as JSON artifacts in this directory (`demo/match_*.json`, `demo/nomatch_*.json`).

The bridge only produces `matched: true` for one specific APK against the one entry in
`bridge/matcher.py`'s `SYNTHETIC_LINKAGE_GROUND_TRUTH` (account `9072`, cert-hash join key
only). Driving the live demo off an arbitrary APK shows an empty bridge panel — this
runbook exists so the matching path is never left to chance on stage.

---

## The two APKs

**Matching run:**
- Path: `cicmaldroid_banking/007556ca146f4b2e9ac6bd51dc66be5130538d514f5aa04d60c1a0b079585ef3.apk`
- SHA-256: `007556ca146f4b2e9ac6bd51dc66be5130538d514f5aa04d60c1a0b079585ef3`
- Package: `duyskab.txtxorxqlni.nflfnauti`
- cert_sha256: `d6e80c1de6423814bb8b8e4de46d9eb84d7eaa5cadfd5c8116918e4922e070d6` — matches
  `SYNTHETIC_LINKAGE_GROUND_TRUTH["9072"]["cert_hash"]` exactly

**Non-matching run:**
- Path: `banking_holdout_16/06c9ce6a7ba2c0c012bcc1079af86349b345e79ffe03e1156f8755987e2c13c3.apk`
- SHA-256: `06c9ce6a7ba2c0c012bcc1079af86349b345e79ffe03e1156f8755987e2c13c3`
- Package: `com.tmznjgf1.dudtjsq5`
- cert_sha256: `None` (unsigned/no cert extracted) — cannot match on cert_hash, and this
  sample's C2 host is not in the linkage table either

---

## Preconditions checklist

- [ ] Ollama running: `systemctl status ollama` shows `active (running)` — narrative
  enrichment is optional (the endpoint still returns a complete rule-based-only report if
  Ollama is down) but both recorded runs had it live (`narrative_source: "ollama_rag"`).
- [ ] Backend running: `cd setuguard_app/backend && python3 app.py`, confirm
  `curl http://127.0.0.1:5000/` returns `{"service":"SetuGuard backend","status":"ok"}`.
- [ ] Both APK files present at the paths above.
- [ ] `DataSet.csv` present at repo root.

---

## Matching run — exact command sequence

```
cd ~/BOIhackathon

curl -s -X POST -F "apk=@cicmaldroid_banking/007556ca146f4b2e9ac6bd51dc66be5130538d514f5aa04d60c1a0b079585ef3.apk" \
  http://127.0.0.1:5000/api/analyze_apk
```
Expected: `analysis_id` prefixed `apk_`, `verdict: "malicious"`, `severity: "CRITICAL"`,
`cert_sha256: "d6e80c1de6423814bb8b8e4de46d9eb84d7eaa5cadfd5c8116918e4922e070d6"`.
**Measured wall-clock: 162.2s** (`analysis_seconds` in the response; this APK is large —
do not expect the smaller holdout sample's time here, see the non-matching run below).

```
curl -s -X POST -F "dataset=@DataSet.csv" http://127.0.0.1:5000/api/analyze_dataset
```
Expected: `analysis_id` prefixed `ds_`, `tier_counts` present, no `error`.

```
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"apk_id":"<apk_id from step 1>","dataset_id":"<ds_id from step 2>"}' \
  http://127.0.0.1:5000/api/bridge
```
Expected: `matched: true`, `match_count: 1`, `account_hash: "9072"`, `tier: "T4"`,
`score: 0.982`, `shared_ioc: "cert_hash:d6e80c1de6423814bb8b8e4de46d9eb84d7eaa5cadfd5c8116918e4922e070d6"`,
`inputs.apk.source` / `inputs.dataset.source` both `"explicit"`.

Recorded output: `demo/match_01_apk.json`, `demo/match_02_dataset.json`,
`demo/match_03_bridge.json` — ids used were `apk_4b38730f` / `ds_19c7d9ce`; a fresh run will
mint new ids each time (they're regenerated per analysis), only the join fields
(`cert_sha256`, `account_hash: "9072"`) are guaranteed to repeat.

---

## Non-matching run — exact command sequence

```
cd ~/BOIhackathon

curl -s -X POST -F "apk=@banking_holdout_16/06c9ce6a7ba2c0c012bcc1079af86349b345e79ffe03e1156f8755987e2c13c3.apk" \
  http://127.0.0.1:5000/api/analyze_apk
```
Expected: `analysis_id` prefixed `apk_`, `cert_sha256: null`.
**Measured wall-clock: 119.7s.**

```
curl -s -X POST -F "dataset=@DataSet.csv" http://127.0.0.1:5000/api/analyze_dataset
```
Expected: same shape as the matching run's dataset step.

```
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"apk_id":"<apk_id from step 1>","dataset_id":"<ds_id from step 2>"}' \
  http://127.0.0.1:5000/api/bridge
```
Expected: `matched: false`, `match_count: 0`, `links: []`, `account_hash`/`tier`/`score`/
`shared_ioc` all `null`, `note` explaining zero matches is the expected result for most
pairs.

Recorded output: `demo/nomatch_01_apk.json`, `demo/nomatch_02_dataset.json`,
`demo/nomatch_03_bridge.json` — ids used were `apk_3b95643c` / `ds_dc021094`.

---

## Honest framing for the demo

The bridge matches on certificate hash and C2 host, exact-match only — nothing fuzzy, no
semantic similarity. The linkage table it matches against
(`bridge/matcher.py:SYNTHETIC_LINKAGE_GROUND_TRUTH`) is a small, explicitly synthetic
stand-in with exactly one entry, because no real device-to-account join key exists in any
of the source repos; it does not represent a validated real-world linkage rate. The
non-matching run above is included deliberately, not as a fallback — it demonstrates that
the bridge does not link unconditionally, and that a `matched: false` result with `links:
[]` is the correct, expected output for an arbitrary APK/dataset pair, not an error state.
