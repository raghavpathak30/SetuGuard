# Bridge demo runbook — verified cert-hash, C2-host, and non-matching paths

**Status:** all three paths run end to end against the live backend and recorded as JSON
artifacts in this directory (`demo/match_*.json` — 2026-08-18; `demo/c2match_*.json` and
`demo/nomatch_*.json` — 2026-08-21, Day 4).

The bridge fires on two independent join keys as of Day 4 (21 Aug):
`bridge/matcher.py`'s `SYNTHETIC_LINKAGE_GROUND_TRUTH` carries two entries, one per key —
account `9072` (cert-hash) and account `9062` (C2-host). Each entry is a single
hand-constructed linkage; **the account association is synthetic in both cases**, since no
real device-to-account join key exists in any source repo. Driving the live demo off an
arbitrary APK still shows an empty bridge panel — this runbook exists so neither matching
path is ever left to chance on stage.

---

## The three APKs

**Cert-hash matching run:**
- Path: `cicmaldroid_banking/007556ca146f4b2e9ac6bd51dc66be5130538d514f5aa04d60c1a0b079585ef3.apk`
- SHA-256: `007556ca146f4b2e9ac6bd51dc66be5130538d514f5aa04d60c1a0b079585ef3`
- Package: `duyskab.txtxorxqlni.nflfnauti`
- cert_sha256: `d6e80c1de6423814bb8b8e4de46d9eb84d7eaa5cadfd5c8116918e4922e070d6` — matches
  `SYNTHETIC_LINKAGE_GROUND_TRUTH["9072"]["cert_hash"]` exactly

**C2-host matching run (Day 4):**
- Path: `cicmaldroid_banking/30baab7000e14cd4a430c8a4a75ea3cae347a6360e0b75ae68c503b5e576cb52.apk`
- SHA-256: `30baab7000e14cd4a430c8a4a75ea3cae347a6360e0b75ae68c503b5e576cb52`
- Package: `com.kb` (real CICMalDroid banking-malware sample)
- 4 `suspicious_strings`, all `http://yessign.net:8688/...` (paths `send_sim_no.php` /
  `send_bank.php` / `upload.php` / bare) — normalizes to host `yessign.net`, which matches
  `SYNTHETIC_LINKAGE_GROUND_TRUTH["9062"]["c2_host"]` exactly. **On stage, write and say the
  host defanged: yessign[.]net.** It mimics the Korean accredited-certificate brand
  "yessign," extracted from a sample impersonating KB Kookmin Bank (package `com.kb`). WHOIS
  shows the domain actively registered (created 2015, renewed to 2028, updated 2025, live
  nameservers) with ownership redacted — **we make no claim about the domain's current
  ownership, registration, or activity; it is not confirmed as live C2.** The indicator
  itself is real, extracted from this sample by our own static analysis; only the link to
  account `9062` is constructed.

**Non-matching run:**
- Path: `banking_holdout_16/06c9ce6a7ba2c0c012bcc1079af86349b345e79ffe03e1156f8755987e2c13c3.apk`
- SHA-256: `06c9ce6a7ba2c0c012bcc1079af86349b345e79ffe03e1156f8755987e2c13c3`
- Package: `com.tmznjgf1.dudtjsq5`
- cert_sha256: `None` (unsigned/no cert extracted), no `suspicious_strings` matching either
  ground-truth entry — cannot match on either key

---

## Timing risk — one cause fixed (residency), a second (memory pressure) identified and NOT fixed. Read before running this live.

`analyze_apk` on the matching-cert APK (`007556ca...`) originally measured 46.47s,
61.47s, 162.2s, and 162.74s across direct timings taken 2026-08-19 — wide run-to-run
variance, all far above the ~9.86s single hand-written spot-check `SESSION_LOG.md:486`
records for this exact file (already flagged unverified, `CONTEXT.md` §7 U1). Rather
than genuine inference variance, this was **Ollama model residency**: `rag_report.py`'s
three Ollama calls (two `ollama.embed()`, one `ollama.chat()`) passed no `keep_alive`,
so Ollama's default ~5-minute idle unload applied, and any call arriving after 5+
minutes of quiet paid a full model reload. Confirmed with a same-APK three-run test —
cold 157.28s, immediately-after 71.81s, after-6-minute-idle 192.8s: slow/fast/slow,
the residency signature, not random variance.

**Mitigation applied and verified (`setuguard_ps1/FROZEN_FILE_FINDINGS.md` Finding 6):**
`keep_alive=-1` added to all three Ollama calls. Re-tested with a deliberate 6.5-minute
idle — longer than the window that produced the pre-fix 192.8s result — and the
post-idle call came back at **68.27s**, not slow. The idle-triggered reload penalty is
gone.

**What the only post-fix measurement says, and must be said on stage:** the only
measurement taken after the residency fix is Day 6 (`harness/DAY6_SCALING_RESULTS.json`,
22 Aug 2026): wall-clock **median 123.9s**, **IQR 107.1-145.7s**, **n=14 valid of 30**
requested/sampled, against the live `/api/analyze_apk` endpoint on
`harness/banking_legit_corpus/`, files <=50 MB (`MAX_APK_UPLOAD_MB`). That is the number
to plan around.

**Caveat that must not be dropped:** the three demo APKs (see "The three APKs" above)
are CICMalDroid samples — a different corpus from `harness/banking_legit_corpus/`, which
is what Day 6 measured. The demo APKs' post-residency-fix timing is **not measured**. Do
not estimate it and do not interpolate it from the banking-corpus median — if asked, say
"not measured."

**Stage guidance:** plan the patter around roughly **two minutes**, not one. The only
measured post-fix median (123.9s, on a different corpus) is already close to two
minutes, with an IQR reaching 145.7s; being early is survivable, being late in front of
judges is not.

### Second, separate cause: kernel memory pressure (identified 22 Aug, NOT fixed)

Ollama model residency and kernel memory pressure are **independent mechanisms**.
`keep_alive=-1` stops Ollama from unloading the model on idle; it does not stop the
kernel from paging the model's resident pages out under memory pressure — those are two
different subsystems.

Measured 22 Aug on the 15 GB machine (Day 6 harness run,
`harness/DAY6_SCALING_RESULTS.json`): preflight showed both llama-servers at
`VmSwap=0kB` and system swap at 8 KiB used. After 30 consecutive analyses, system swap
was 5.5 GiB used, the Mistral-7B process had `VmSwap` 4,793,536 kB, the embedding server
115,436 kB, and available memory was down to 3.3 GiB. Runs 1-14 were clean
(`voided=false`); runs 15-30 were all voided — a clean transition, not scattered noise.

Peak RSS under analysis, same run: Mistral-7B median 7,315,786 kB (max 9,355,416 kB);
Flask median 2,167,910 kB (max 4,271,904 kB); embedding server median 507,208 kB. Idle
Mistral RSS is about 5.1 GB, so the working set roughly doubles under load on a 15 GB
machine.

**Consequence for the stage machine, stated plainly:** this system cannot sustain thirty
consecutive analyses on 15 GB without paging. The demo itself is three calls, which is
within budget, but a judge asking for a fourth and fifth APK is a known hazard. This is
**not fixed** — it is managed operationally: fresh boot, `vm.swappiness=10`, no dev
tooling running, exactly one browser tab, warm-up done before judges arrive.

Two checks on the Day 6 result, stated plainly rather than glossed over:
- **Not a file-size artifact:** valid-run `size_mb` median 23.1 (range 8.7-40.9) vs.
  voided-run median 24.9 (range 5.9-50.2) — near-identical distributions. But the 14
  valid runs are simply the first 14 in execution order, not an independent random
  subsample.
- **Kernel OOM check was inconclusive, not clean:** `dmesg` was permission-denied
  (`errors=1`), so `oom_events_found=0` reflects a failed read, not a verified absence of
  OOM events (`clean=false`). Do not describe OOM as ruled out.

**Recommended demo sequence:** run one warm-up call (any APK) as the first item in the
Preconditions checklist below, well before judges are in the room — this both confirms
Ollama is reachable and puts the model into the now-persistent `keep_alive=-1` state so
it never unloads again for the rest of the session. Then the matching-cert APK can be
run live during the demo itself; plan for roughly two minutes, not one — the demo APKs'
timing is not measured post-fix, and the closest measured figure (Day 6, a different
corpus) has a median of 123.9s and an IQR reaching 145.7s. If asked why the wait is not
instant, say plainly: "the model is kept warm for the session — that's a one-line fix,
not a trick, and it removes the reload penalty — but the embedding and generation
compute itself still takes real time; the verdict and bridge match you're about to see
come from a real, unmodified pipeline run happening right now, not a pre-run."

## Preconditions checklist

- [ ] **Full reboot of the stage machine, not just a Flask restart.** Restarting
  `backend/app.py` alone does not clear kernel memory pressure — see "kernel memory
  pressure" above — and does not guarantee Ollama has no model resident. A clean boot is
  the only state this runbook's timing guidance was measured against.
- [ ] **Nothing else runs on the machine** for the rest of the session once it's booted:
  no dev tooling, no other browser tabs, no background builds — anything competing for
  the ~15 GB working set brings the memory-pressure onset closer, and Day 5 measured
  onset within roughly 4 sequential calls on this machine, far earlier than previously
  documented.
- [ ] **`ollama ps` shows zero resident models before the first call.** If anything is
  listed, the machine did not actually boot clean (or something else warmed a model) —
  do not proceed to the warm-up call until this is empty.
- [ ] **Expected pattern: a slower first call, then faster ones.** The warm-up call below
  pays the one-time cold-load cost; do not mistake a slow first call for a broken
  pipeline. If a later call in the same session is unexpectedly slow again, that's the
  separate, unfixed memory-pressure mechanism, not a residency regression.
- [ ] Ollama running: `systemctl status ollama` shows `active (running)` — narrative
  enrichment is optional (the endpoint still returns a complete rule-based-only report if
  Ollama is down) but both recorded runs had it live (`narrative_source: "ollama_rag"`).
- [ ] Backend running: from the repo root, `python3 setuguard_app/backend/app.py`
  (verified working). Do not `cd` into `setuguard_app/backend` first and run `python3
  app.py` -- that produces a `python3 app.py` cmdline that the Day 6 harness cannot
  detect (it looks for `backend/app.py` in the cmdline and refuses to proceed). Start it
  in a dedicated terminal that stays open and is not closed or killed for the rest of the
  session. Confirm `curl http://127.0.0.1:5000/` returns
  `{"service":"SetuGuard backend","status":"ok"}`.
- [ ] **The dashboard is `setuguard_app/frontend/index.html`, opened directly in the
  browser (`file://...`) — there is no second server to start.** `CORS(app)` on the
  Flask backend has no origin restriction, and `app.js` calls an absolute base URL, so
  opening the HTML file directly works with zero extra process on stage. `127.0.0.1:5000`
  in the address bar is the API only and returns the health JSON above, not the UI — if a
  judge asks for "the URL," the answer is the local `index.html` path, not a port.
- [ ] **Check `localStorage` key `sg_base_url` on the demo machine's browser profile before
  the freeze.** `app.js:3` reads its API base URL from `localStorage.getItem("sg_base_url")`,
  falling back to `http://127.0.0.1:5000` only if that key is unset. If it was ever set to
  something else during earlier testing on this machine, it persists silently across
  reloads — the dashboard loads fine and every call then fails against the wrong host.
  This is the worst kind of failure to debug live: no visible symptom until the first
  upload. Clear the key once (DevTools → Application → Local Storage, or
  `localStorage.removeItem("sg_base_url")` in the console) before judges arrive, and
  re-check after any browser-based testing between then and stage time.
- [ ] All three APK files present at the paths above.
- [ ] `DataSet.csv` present at repo root.
- [ ] For the Play-signed allowlist demo: `harness/banking_legit_corpus/7B1A1348794100FFBABCB6ADCE168E236D720BBD9C5AAED8914C838093EC83AC.apk` present.
- [ ] **Warm-up call**, run once, as early as practical before judges arrive:
  `curl -s -X POST -F "apk=@cicmaldroid_banking/007556ca146f4b2e9ac6bd51dc66be5130538d514f5aa04d60c1a0b079585ef3.apk" http://127.0.0.1:5000/api/analyze_apk -o /dev/null`.
  Pays the one-time cold-load cost (~1-3 minutes) so `keep_alive=-1` can hold the model
  warm for the rest of the session — see "Timing risk" above.

---

## Matching run — exact command sequence

```
cd ~/BOIhackathon

curl -s -X POST -F "apk=@cicmaldroid_banking/007556ca146f4b2e9ac6bd51dc66be5130538d514f5aa04d60c1a0b079585ef3.apk" \
  http://127.0.0.1:5000/api/analyze_apk
```
Expected: `analysis_id` prefixed `apk_`, `verdict: "malicious"`, `severity: "CRITICAL"`,
`cert_sha256: "d6e80c1de6423814bb8b8e4de46d9eb84d7eaa5cadfd5c8116918e4922e070d6"`.
**Timing: do not quote 162.2s — that figure is pre-Day-6, measured on a swapping
machine, and VOID.** The only quotable latency figure is the Day 6 distribution
(`harness/DAY6_SCALING_RESULTS.json`): median **123.9s**, IQR **107.1-145.7s** (n=14
valid of 30 attempted, live `/api/analyze_apk`, `harness/banking_legit_corpus/`, files
<=50 MB). **Per-call demo timings are not recorded in the response payload** —
`analysis_seconds` has been removed from `/api/analyze_apk`'s JSON — because single-call
samples on this machine, under varying memory pressure, ranged from 2.86s to 96.62s and
are not a latency measurement. Do not quote a specific per-run number on stage; plan
around the Day 6 distribution above.

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

## C2-host matching run (Day 4) — exact command sequence

```
cd ~/BOIhackathon

curl -s -X POST -F "apk=@cicmaldroid_banking/30baab7000e14cd4a430c8a4a75ea3cae347a6360e0b75ae68c503b5e576cb52.apk" \
  http://127.0.0.1:5000/api/analyze_apk
```
Expected: `analysis_id` prefixed `apk_`, `verdict: "suspicious"`, `severity: "HIGH"`,
`package: "com.kb"`, `c2_candidates` containing 4 `http://yessign.net:8688/...` strings.
**Timing: do not quote 46.45s — that figure is pre-Day-6, measured on a swapping
machine, and VOID.** The only quotable latency figure is the Day 6 distribution
(`harness/DAY6_SCALING_RESULTS.json`): median **123.9s**, IQR **107.1-145.7s** (n=14
valid of 30 attempted, live `/api/analyze_apk`, `harness/banking_legit_corpus/`, files
<=50 MB). **Per-call demo timings are not recorded in the response payload** —
`analysis_seconds` has been removed from `/api/analyze_apk`'s JSON, so
`demo/c2match_01_apk.json` no longer carries a timing field at all — because single-call
samples on this machine, under varying memory pressure, ranged from 2.86s to 96.62s and
are not a latency measurement. Do not quote a specific per-run number on stage; plan
around the Day 6 distribution above.

```
curl -s -X POST -F "dataset=@DataSet.csv" http://127.0.0.1:5000/api/analyze_dataset
```
Expected: same shape as the cert-hash run's dataset step; `top_alerts` contains account
`9062` (the top-ranked account by score — deterministic given the fixed model, confirmed
present across multiple runs).

```
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"apk_id":"<apk_id from step 1>","dataset_id":"<ds_id from step 2>"}' \
  http://127.0.0.1:5000/api/bridge
```
Expected: `matched: true`, `match_count: 1`, `account_hash: "9062"`, `tier: "T4"`,
`score: 0.988`, `matched_on: "c2_host"`, `shared_ioc: "c2_host:yessign.net"`,
`inputs.apk.source` / `inputs.dataset.source` both `"explicit"`.

Recorded output: `demo/c2match_01_apk.json`, `demo/c2match_02_dataset.json`,
`demo/c2match_03_bridge.json` — ids used were `apk_1c6e9395` / `ds_a2689ac9`; a fresh run
will mint new ids each time, only the join fields (`shared_ioc`, `account_hash: "9062"`)
are guaranteed to repeat.

**Say on stage, in this order:** "This APK's static analysis surfaced a network string —
written here defanged, yessign[.]net, so we're not putting a live-looking host on a slide
— on a non-standard port, in paths named `send_sim_no.php` and `send_bank.php`. It mimics
the Korean accredited-certificate brand 'yessign,' in a sample impersonating KB Kookmin
Bank. We checked WHOIS: the domain is actively registered, renewed through 2028, ownership
redacted — we make no claim about who holds it today or what it's used for now, and we
don't claim it's live C2. What we do know is that this exact string is embedded in this
exact malware sample, extracted by our own static analysis. The bridge joins that
indicator against an account carrying the same host. The account link is constructed for
this demo — no real dataset exists where an APK's C2 indicator and a mule account are
independently known to be connected — but the indicator itself is real, pulled from an
actual malware sample, not fabricated for the demo."

---

## Non-matching run — exact command sequence

```
cd ~/BOIhackathon

curl -s -X POST -F "apk=@banking_holdout_16/06c9ce6a7ba2c0c012bcc1079af86349b345e79ffe03e1156f8755987e2c13c3.apk" \
  http://127.0.0.1:5000/api/analyze_apk
```
Expected: `analysis_id` prefixed `apk_`, `cert_sha256: null`.
**Timing: do not quote 119.7s — that figure is pre-Day-6, measured on a swapping
machine, and VOID.** The only quotable latency figure is the Day 6 distribution
(`harness/DAY6_SCALING_RESULTS.json`): median **123.9s**, IQR **107.1-145.7s** (n=14
valid of 30 attempted, live `/api/analyze_apk`, `harness/banking_legit_corpus/`, files
<=50 MB). **Per-call demo timings are not recorded in the response payload** —
`analysis_seconds` has been removed from `/api/analyze_apk`'s JSON — because single-call
samples on this machine, under varying memory pressure, ranged from 2.86s to 96.62s and
are not a latency measurement. Do not quote a specific per-run number on stage; plan
around the Day 6 distribution above.

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

## Play-signed allowlist demo (Day 3, optional third moment — cheap, worth doing)

Built 19 Aug. Shows the conceded weakness (legitimate banking apps outrank malware under
the current scorer, PRIMARY AUC 0.1444) converted into a demonstrated control, not left as
a bare limitation. Small file, fast — measured 8.61s standalone, no residency-warmup
dependency.

```
curl -s -X POST -F "apk=@harness/banking_legit_corpus/7B1A1348794100FFBABCB6ADCE168E236D720BBD9C5AAED8914C838093EC83AC.apk" \
  http://127.0.0.1:5000/api/analyze_apk
```
Expected: `verdict: "suspicious"`, `severity: "CRITICAL"`, package `com.ubi.parivar` (a real
Union Bank UPI app), `play_signing: {"detected": true, ...}`. This is deliberately the
strongest version of the point: a genuine, legitimate bank app the scorer ranks CRITICAL,
now carrying an honest "Play Signing — Triage Prior, Not Part Of The Verdict" tag rather
than being presented as an unexplained false positive.

**Say on stage, in this order:** "This is a real Union Bank app, and our scorer ranks it
critical — that's the conceded weakness, permission breadth doesn't separate a banking app
from a banking trojan, we've measured that at AUC 0.1444 against a pre-registered corpus.
What we've built is a triage control, not a fix to the score: this certificate was re-signed
by Google Play App Signing, and that's now surfaced to the analyst as a lower-priority
signal — the verdict doesn't change, but the analyst's queue can." **If asked what it
misses:** "Two things, by design, and I'd rather name them than have a judge find them.
Self-signed or self-distributed banks aren't covered — that's 55% of our own corpus, more
than half. And a malicious app that shipped through Play would carry the identical
signature and get the identical tag — this sits alongside Play Protect, not instead of it."

Verified in a real browser (zero console/page errors); the render is a clearly-separated
section between "Verdict" and "Investigation Report," never inside the severity/risk-score
stat row.

---

## Honest framing for the demo

The bridge matches on certificate hash **or** C2 host, exact-match only — nothing fuzzy, no
semantic similarity. Both keys fire as of Day 4 (21 Aug): the linkage table it matches
against (`bridge/matcher.py:SYNTHETIC_LINKAGE_GROUND_TRUTH`) carries two entries, one per
key, because no real device-to-account join key exists in any of the source repos. **Two
distinct ground-truth linkages, each with a synthetic account association** — this does not
represent a validated real-world linkage rate, and should never be described as one. The
C2-host entry's indicator — written defanged, yessign[.]net — is a real hostname extracted
from an actual malware sample by our own static analysis; it mimics the Korean
accredited-certificate brand "yessign," in a sample impersonating KB Kookmin Bank (package
`com.kb`). It has not been independently confirmed as live C2 infrastructure, and that
distinction should be stated if the point comes up — a hostname parsed out of a URL string
is evidence the string exists in the APK, not evidence the host is active or malicious
infrastructure. WHOIS shows the domain is actively registered (created 2015, renewed to
2028, updated 2025, live nameservers); ownership is redacted. **No claim is made about the
domain's current ownership, registration, or activity.** Only which account it links to is
constructed.

**Hard rule: the demo machine must never issue a network request to this host, or to any
host extracted from an analyzed APK.** Extraction is static — parsing strings out of the
DEX/manifest — and nothing in the analysis or bridge code path resolves or fetches an
extracted indicator at runtime. Confirmed by reading every import in
`setuguard_ps1/static_analysis.py`, `bridge/matcher.py`, `setuguard_app/backend/app.py`,
and `setuguard_ps1/yara_gen.py`: no `socket`, `requests`, `urllib.request`, `http.client`,
or DNS-resolution call anywhere in any of them (`urllib.parse.urlparse` is used for string
parsing only, never to open a connection). The only network calls anywhere in the pipeline
are `rag_report.py`'s `ollama.embed()`/`ollama.chat()` to the local Ollama server, and those
pass only the indicator's `kind` (e.g. `"url"`, `"ip"`) as a token, never the host value
itself.

The matcher's join logic was verified by sabotage, not just by reading: breaking one
comparison branch (cert-hash, then separately C2-host) and confirming the expected metric
degraded — offline in `confusion_matrix_validation.py`, and live through `/api/bridge` with
a real backend and real uploads — then restoring the file and confirming a byte-identical,
zero-diff return. If the confusion matrix (`TP=10/FP=0/FN=0/TN=90`) comes up, lead with **2
distinct ground-truth linkages tested against 100 hand-built cases including 20 near-miss
confounders, matcher correct on all** — the bare "TP=10" overstates it, since those 10 are
10 correctly-linked accounts powered by only 2 distinct indicator values, and it is a
correctness test of the join logic, never a detection-rate or accuracy measurement.

The non-matching run above is included deliberately, not as a fallback — it demonstrates
that the bridge does not link unconditionally, and that a `matched: false` result with
`links: []` is the correct, expected output for an arbitrary APK/dataset pair, not an error
state.
