# Bridge IOC yield audit — read-only over the 668 cached extraction outputs

Date: 2026-08-12. Machine-readable companion: [`ioc_yield_audit.json`](ioc_yield_audit.json).

This is gate **G0b** in `PLAN.md`: does static analysis actually produce enough linkable network
indicators for the Bridge's Innovation claim to stand?

## Provenance

- **Input**: `harness/feature_cache/*.json` — 668 cached extraction outputs written by
  `harness/extract_features_pool.py` from `harness/sample_set_716.txt` (seed=42; 16
  `banking_holdout_16` + 400 `cicmaldroid_banking` + 300 `fdroid_benign_apks`, of which 668
  parsed and 48 were skipped).
- **Androguard was not re-invoked. No APK was opened. Nothing was re-extracted.** This audit
  reads JSON only.
- The audit script is ad hoc and **non-frozen** — it is not one of the six frozen PS1 files
  (`static_analysis.py`, `knowledge_base.py`, `report_prompt.py`, `rag_report.py`, `yara_gen.py`,
  `run_pipeline.py`) and not part of `batch_baseline.py`'s suite. Per the repo's four-file limit
  for the session that produced this document, the script itself was not committed; the exact
  counting logic is reproduced inline below so the numbers can be regenerated from the repo.

## Exactly which fields were counted, and why

Both counted fields are the ones `bridge/matcher.py` actually joins on — not a proxy for them.

| Counted as | Extraction-schema field | Why this field |
|---|---|---|
| **network host indicator** | `features.suspicious_strings[]` entries where `kind` is `"url"` or `"ip"` | `bridge/matcher.py:31-34` (`extract_ioc_from_ps1`) builds `c2_hosts` from exactly this filter — `[s["value"] for s in suspicious_strings if s.get("kind") in ("ip","url")]` |
| **usable certificate hash** | `features.certificate.sha256 is not None` | `bridge/matcher.py:82` reads `apk_ioc.get("cert_hash")` (populated from `cert.get("sha256")`) and None-guards both sides at lines 89-93 |

Reproduce:

```python
import json
from pathlib import Path
net = cert = both = neither = 0
for f in Path("harness/feature_cache").glob("*.json"):
    ft = json.loads(f.read_text())["features"]
    has_net = any(s.get("kind") in ("url", "ip") for s in ft.get("suspicious_strings") or [])
    has_cert = (ft.get("certificate") or {}).get("sha256") is not None
    net += has_net; cert += has_cert
    both += has_net and has_cert; neither += not has_net and not has_cert
print(net, cert, both, neither)   # -> 522 665 521 2
```

## Headline

**66.9% of malicious APKs (241/360) yield at least one network host indicator.** After removing
every host that also appears somewhere in the benign or banking-holdout corpora, **60.6%
(218/360)** still yield at least one. Both clear `PLAN.md`'s G1 gate of ≥30% by a wide margin.

## All extracted (n=668)

| Measure | Count | % of 668 |
|---|---|---|
| ≥1 network host indicator | 522 | 78.1% |
| ≥1 usable certificate hash | 665 | 99.6% |
| **Both** | 521 | 78.0% |
| **Zero network host indicators** | 146 | 21.9% |
| **Zero linkable indicators of either kind** | 2 | 0.3% |
| ≥1 `ip`-kind (bare dotted-quad) indicator | 106 | 15.9% |

Median network indicators per APK: 2. Max: 25 (the hard cap — see caveats).

## Malicious vs benign vs holdout

| | malicious (n=360) | benign (n=292) | banking_holdout (n=16) |
|---|---|---|---|
| ≥1 network host indicator | 241 (**66.9%**) | 269 (92.1%) | 12 (75.0%) |
| ≥1 usable cert hash | 358 (99.4%) | 292 (100%) | 15 (93.8%) |
| Both | 241 (66.9%) | 269 (92.1%) | 11 (68.8%) |
| **Zero network host indicators** | 119 (**33.1%**) | 23 (7.9%) | 4 (25.0%) |
| Zero linkable indicators of either kind | 2 (0.6%) | 0 | 0 |
| ≥1 `ip`-kind indicator | 38 (10.6%) | 66 (22.6%) | 2 (12.5%) |
| At the 25-string cap | 23 | 60 | 1 |
| Median indicators/APK | 1 | 5 | 1 |

Note the direction: **benign apps yield more network indicators than malware does** (92.1% vs
66.9%), because ordinary apps embed analytics, CDN and update endpoints in the clear while packed
or obfuscated malware often resolves its C2 at runtime. This is consistent with the measured
`suspicious_strings` term being *backwards* as a maliciousness signal (separation −20.7,
`SESSION_LOG.md` 2026-08-10), which is why scorer-v2 narrowed it to bare-IP hosts and
non-standard ports. Yield and discriminative power are different properties; this file measures
yield only.

## Distribution of network host indicators per APK (all 668)

| indicators | 0 | 1 | 2 | 3 | 4 | 5 | 6-10 | 11-24 | 25 (capped) |
|---|---|---|---|---|---|---|---|---|---|
| APKs | 146 | 156 | 76 | 52 | 28 | 18 | 48 | 63 | 81 |

Distinct-host counts after parsing (rather than raw string counts): 146 APKs with 0 hosts, 228
with exactly 1, and a long tail to 25.

## De-noised malicious view

Raw "≥1 URL string" overstates joinability, because the top hosts in the malicious corpus include
plain framework and namespace URLs:

| in malicious | host | | in benign | host |
|---|---|---|---|---|
| 23 | `schemas.android.com` | | 232 | `schemas.android.com` |
| 15 | `xmlpull.org` | | 85 | `ns.adobe.com` |
| 13 | `10.0.0.172` | | 70 | `github.com` |
| 12 | `market.android.com` | | 43 | `127.0.0.1` |
| 12 | `110.34.233.250` | | 39 | `www.w3.org` |
| 11 | `www.google.com` | | 30 | `play.google.com` |
| 10 | `192.151.226.138` | | 22 | `localhost` |
| 10 | `sennapious.com` | | 20 | `apache.org` |

Subtracting every host seen anywhere in benign or banking_holdout:

- **218/360 malicious APKs (60.6%)** still carry ≥1 host not seen in the legitimate corpora.
- **411 of 469** distinct hosts observed across the malicious corpus are unique to it.

That 60.6% is the number to quote when the claim is "the Bridge has something specific to join
on," and 66.9% when the claim is "static extraction produces a network indicator at all."

## Caveats this number must always be quoted with

1. **Right-censoring at 25.** `setuguard_ps1/static_analysis.py:86` sets
   `MAX_SUSPICIOUS_STRINGS = 25`, and `_extract_suspicious_strings()` iterates `STRING_PATTERNS`
   in `url`, `ip`, `shell` order. An APK with ≥25 distinct URL matches therefore records **zero**
   `ip`-kind and zero `shell`-kind strings — the IP extractor never runs. 84/668 (12.6%) of cached
   outputs sit at that cap, including 23/360 malicious. Every per-APK count here is censored, and
   the `ip`-kind rate is a **lower bound**, not a measurement.
2. **These are strings, not traffic.** A "network host indicator" is a literal found in the DEX
   string pool. It is not evidence of a C2 channel and not evidence the host was ever contacted.
   This audit measures joinability, not malice. Runtime-observed hostnames (`PLAN.md` G6) are the
   experiment that would change that.
3. **The matcher cannot use most of these today.** `bridge/matcher.py:94-98` matches `c2_host` by
   `linked_c2 in apk_c2_hosts` — exact equality against the **raw** `suspicious_strings` value,
   which for `kind == "url"` is the full URL including scheme and path. The matcher never calls
   `urlparse`. So a ground-truth `c2_host` recorded as a bare hostname can never match a url-kind
   indicator; only `kind == "ip"` values (bare dotted quads, present in 10.6% of malicious APKs)
   or a ground-truth entry holding a byte-identical full URL can join. The de-noised 60.6% is the
   *ceiling* if the matcher were host-aware; it is not what the shipped matcher achieves.
4. **Sample-selection bias.** The 360 malicious outputs exclude 39 APKs whose obfuscated bytecode
   Androguard's disassembler rejected. Heavily obfuscated samples are precisely the ones most
   likely to hide their C2, so the true malicious yield over the full 400-sample draw is probably
   *below* 66.9%. Treating 39/400 as all-zero-yield gives a conservative floor of 60.3%
   (241/400).
5. **`banking_holdout` n=16** is reported for completeness only; no rate claim off 16 samples is
   adequately powered.
