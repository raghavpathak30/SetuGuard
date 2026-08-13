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
