# Banking corpus inclusion rule — pre-registered 2026-08-13

Written and committed **before any AndroZoo row is scored**, on purpose. `banking_holdout_16/`
failed because nobody wrote down what it was supposed to contain until five weeks after it was
used (`harness/BANKING_HOLDOUT_16_PROVENANCE.md`). This file, and the commit that adds it, is the
answer to a judge who asks whether the rule was written to fit the result: the git log shows this
file predates every row this corpus will ever contain.

## Deviation from the task brief, stated up front

This rule was supposed to match against **"Raghav's hand-assembled list."** No such list exists
anywhere in the repository — checked `package_ids.txt`, `clean_package_ids.txt`,
`all_packages.txt` (all three are F-Droid artifacts, unrelated) and grepped for known banking
package fragments across every `.txt`/`.md` file. Nothing.

**What exists instead:** `harness/banking_packages.csv`, 34 package names across four tiers,
assembled this session via web search against Google Play listings, not hand-assembled by
Raghav and not verified by him. Every row is tagged `confirmed_2026-08-13` (a specific Play
Store URL was returned by a search this session) or `unconfirmed_recall` (one entry — Google Pay
India's package name, which I could not reconfirm and which is flagged for that reason). This is
a real, load-bearing deviation, not a formality: **the inclusion rule matches names I chose, not
names Raghav chose**, and it should be reviewed before the corpus is treated as authoritative.

## Source

**AndroZoo `latest.csv.gz`.** Its own file identity must be recorded at filter time and is not
yet known — the download was still in progress when this rule was written. The filter script
(`harness/filter_banking_candidates.py`) records the SHA-256 of the exact `latest.csv.gz` it ran
against, plus the date it ran, in its output. That record is what makes "which snapshot of
AndroZoo's list produced this corpus" answerable later, the same way
`harness/BANKING_ARCHIVE_MANIFEST.tsv` now answers "which archive produced
`cicmaldroid_banking/`."

## Matching rule

- **`pkg_name` matched exactly** against `harness/banking_packages.csv`, column 1. **Never by
  substring, never by prefix.** AndroZoo carries repackaged fake banking apps under
  near-identical package names; substring matching would admit exactly the kind of sample this
  corpus exists to exclude.
- **`markets` must contain `play.google.com`.** Anything sideloaded-only is excluded regardless
  of package name match.
- **`vt_detection` literally `0`**, and **`vt_scan_date` non-empty**. An empty detection field
  means the file was never scanned by VirusTotal, not that it is clean. Admitting an unscanned
  row on the assumption it's probably fine is the same category of error as trusting a directory
  name — treat "never scanned" as "unverified," not as "verified clean."
- **The malformed row.** AndroZoo's `latest.csv` has at least one row whose `pkg_name` field
  contains an unescaped comma, which breaks naive CSV splitting. Excluded explicitly:
  `grep -v ',snaggamea'`. `filter_banking_candidates.py` reads the header and indexes columns by
  name rather than position — AndroZoo's column order has changed historically, and positional
  indexing is how this kind of thing breaks silently instead of loudly.

## Version selection — two arms

CICMalDroid 2020 samples were collected **December 2017 – December 2018**. A current-build
banking corpus sits roughly eight years newer than the malware, and any AUC computed against it
could be a target-SDK, permission-model, or packing-era artifact rather than a statement about
class convergence — the same shape of error this whole exercise exists to correct.

- **Era-matched (PRIMARY).** For each matched package, the row with the **highest `vercode`**
  among rows with **`vt_scan_date` ≤ 2019-12-31**. Isolates the hypothesis from the vintage gap.
  Also the smaller files on average (older APKs), so this arm is the bandwidth-cheap one —
  convenient, not coincidental, given tonight's transfer constraint.
- **Current (SECONDARY, opportunistic).** For each matched package, the row with the highest
  `vercode` overall, no date bound. Product-relevant; built only if transfer budget allows after
  the primary arm.

**`dex_date` is not used for era selection.** The vast majority of Play Store apps carry a 1980
`dex_date` (a build-tooling artifact, not a real date), which is unusable as an ordering signal —
confirmed as a known AndroZoo quirk, not assumed. `vercode` orders versions; `vt_scan_date`
brackets the era.

If a package has **no row** with `vt_scan_date ≤ 2019-12-31`, it has no era-matched candidate and
contributes to the current arm only. Reported per-tier in `filter_banking_candidates.py`'s output
(B1).

## Tier labels

From `harness/banking_packages.csv`, column 2 — the same four-tier scheme committed in
`harness/identify_holdout_16.py:TIER_RULES` on 2026-08-12, extended with Tier D:

| Tier | Definition |
|---|---|
| **A** | Scheduled commercial bank first-party app (India) |
| **B** | UPI / PSP app |
| **C** | NBFC, wallet, or fintech |
| **D** | International bank, India-facing app |

## Target and its actual ceiling

**Target: n ≥ 100 overall, floor n ≥ 40 in Tier A.** Stated in the task as bandwidth-contingent.
It is now **also package-list-contingent**, independently of bandwidth, and this is the more
binding constraint:

`harness/banking_packages.csv` contains **21 Tier A** package names. **Even at a 100% AndroZoo
hit rate for every one of them, on both arms, Tier A cannot exceed 21 samples with the current
list.** The n ≥ 40 floor is therefore already known to be unreachable before a single byte of
`latest.csv.gz` has been filtered, unless the list grows. Total across all four tiers: 34 package
names, so n ≥ 100 overall is unreachable on package-list grounds alone as well, before AndroZoo
hit rate or bandwidth are even considered.

This is recorded here, before scoring, for the same reason the whole file exists: so it is
legible as a pre-existing constraint rather than something noticed only if the result looks
convenient. **Growing `harness/banking_packages.csv` is the highest-leverage remaining action on
this corpus build** — higher leverage than more bandwidth, since bandwidth only helps once the
package ceiling is raised.

## What "verified" means for this corpus, stated in advance

A verification pass (`harness/verify_banking_corpus.py`, run in B3) rejects any downloaded APK
that is debug-signed, carries the AOSP public test key, or has no certificate at all.
**Every one of the sixteen files in `banking_holdout_16/` would have failed this exact check** —
see `harness/BANKING_HOLDOUT_16_PROVENANCE.md`. Ordinary self-signing is not itself grounds for
rejection; it is close to universal on Android and carries no information on its own.

## Also excluded, permanently, from this corpus by construction

`pkg_name` collision against `harness/BANKING_ARCHIVE_MANIFEST.tsv`, `cicmaldroid_banking/`, or
the 716-APK sample set is checked in B3 and is a **loud** rejection, not a silent one — a
collision would mean the same corpus-identity error has recurred.

---

## 2026-08-15 update — list grown 35 → 83, tiers re-derived, `latest.csv.gz` downloaded

**Correction to two counts above, found while preparing this update:** "Target and its actual
ceiling" states the prior list as 34 packages / 21 Tier A. The file that actually existed at that
point (`harness/banking_packages_v1_superseded.csv`, superseded by this update) has **35** rows,
**22** of them Tier A — both off by one in the original text. Left uncorrected in place above, per
this project's convention of appending corrections rather than rewriting; recorded accurately
here.

### List: 35 → 83 packages

Assembled from three manually-collected Play Store lists plus two `adb shell pm list packages -3`
device dumps. Full merge and tiering rationale — including judgement calls (foreign banks'
India-facing apps as Tier A, small finance banks as Tier A, `org.npci.erupee*` moved to Tier B),
same-issuer/same-vendor clustering caveats that bear on effective n, and rows still flagged
`VERIFY` pending confirmation — is in `harness/BANKING_PACKAGE_TIERING_DECISIONS.md`. Not
duplicated here.

| Tier | n | Definition |
|---|---|---|
| A | 62 | Indian scheduled commercial bank (incl. SFB) first-party app |
| B | 8 | UPI/PSP app not issued by a bank |
| C | 5 | NBFC, wallet, fintech, non-banking |
| D | 8 | Foreign bank, non-India market |

**Tier A ceiling raised from 22 to 62.** The binding constraint identified above ("Target and its
actual ceiling") is substantially relaxed — the n≥40 Tier A floor is reachable on package-list
grounds for the first time, though AndroZoo hit rate and per-issuer/per-vendor clustering
(`BANKING_PACKAGE_TIERING_DECISIONS.md`'s effective-n caveat) still bound the *independent* sample
count below the nominal 62.

### Tiers reassigned: positional → categorical

The three source lists used A/B/C to mean *first, second, third app per developer* — every
developer had exactly one of each. This rule's tiers are categories, not list position. All 35
carried-forward labels plus every new row were assigned against this rule's Tier definitions
(above), before any scoring — a re-interpretation of collected data, not a change to the rule
itself.

### 4 packages excluded, not deleted

| Package | Reason |
|---|---|
| `com.ipru.iciciprulife.customer.release` | Life insurance, not banking |
| `com.maxlifeinsurance.www.twa` | Life insurance, not banking |
| `com.axismf.investorapp` | Asset management, not banking |
| `com.compass.reward` | Rewards app, not banking |

Two insurance, one asset-management, one rewards app — not one uniform category. Insurance and AMC
apps in particular have a materially different permission surface from banking apps; including any
of the four would bias the comparison in the direction that flatters the scorer, which is the
direction least affordable here.

### Schema change: `app_name_hint` → `issuer`

`harness/banking_packages.csv`'s third column is renamed `issuer` (was `app_name_hint`) — the
merged list records who issues the app, not a recalled display name. `harness/
filter_banking_candidates.py:116` updated to match: `hint_of` is now keyed from `row["issuer"]`.
Confirmed the new CSV actually carries an `issuer` column (not a rename to a key that doesn't
exist) and that `filter_banking_candidates.py` parses the new file without a `KeyError`.

### `latest.csv.gz` provenance

| Field | Value |
|---|---|
| SHA-256 | `770ce0cc92b6d9b5bcd6f657466fc8a2c43f101326c1fdaba7393294d3a8c4a6` |
| Size | 3,510,531,575 bytes (3.27 GiB) |
| Downloaded | 2026-08-14 19:22 UTC = 2026-08-15 00:35 IST (file mtime; both calendar dates are the same download, either side of the UTC/IST midnight boundary) |
| Integrity | `gzip -t` passes |

Recorded here per this file's own "Source" section above, which flagged the identity of this
download as unknown at write-time. Independently corroborated: `harness/filter_banking_candidates.py`
recorded the same SHA-256 itself, in its own `source_csv_identity` block inside
`harness/banking_candidates.json`, at `recorded_at_utc: 2026-08-14T19:22:14` — two independent
computations of the same hash, not one hash trusted twice.

### B1 filter has already run — first real numbers off this corpus

`harness/banking_candidates.json` (`filter_banking_candidates.py --packages
harness/banking_packages.csv --out harness/banking_candidates.json`) is on disk. Per-tier
found-in-`latest.csv`/passed-filter counts:

| Tier | Requested | Found in `latest.csv` | Passed filters | Era-matched picks | Current picks |
|---|---|---|---|---|---|
| A | 62 | 52 | 52 | 20 | 52 |
| B | 8 | 4 | 4 | 1 | 4 |
| C | 5 | 3 | 3 | 1 | 3 |
| D | 8 | 8 | 8 | 5 | 8 |

**16 of 83 requested packages have zero rows in `latest.csv.gz` at all** — not filtered out, never
present — including `com.boi.erupee.prod`, `com.bankofbaroda.bobworlddmb`, `com.bcg.psbbank`,
`com.bom.lifestylebanking`, `com.infrasoft.cbiMiniMerchant`, and 11 others (full list in
`banking_candidates.json`'s `zero_hit_packages`). **27 era-matched picks, 67 current-arm picks**
total across all tiers — both below the requested-83 ceiling and below the passed-filter counts
above, because a package can pass filters on the current arm without having any row dated
`vt_scan_date ≤ 2019-12-31` for the era-matched arm.

Tier A's effective era-matched count (20) is well short of the `n ≥ 40` floor on its own; whether
the current arm (52) plus era arm together clear the corpus's actual target gate is a question for
the next stage (B2/B3 verification and download), not answered by this filtering step alone. No
APK has been downloaded or verified yet — `harness/verify_banking_corpus.py` and
`harness/download_banking_corpus.py` are the next steps, against this candidate file.
