# Banking package list — merge and tiering decisions

Assembled 2026-08-13/14 from three manually-collected Play Store lists plus two
`adb shell pm list packages -3` device dumps. **83 unique packages.**

| Tier | n | Definition |
|---|---|---|
| A | 62 | Indian scheduled commercial bank (incl. SFB) first-party app |
| B | 8 | UPI/PSP app not issued by a bank |
| C | 5 | NBFC, wallet, fintech, non-banking |
| D | 8 | Foreign bank, non-India market |

## Re-tiering: source labels were positional, not categorical

The three source files used A/B/C to mean *first, second, third app per
developer* — every developer had exactly one of each. The inclusion rule
defines the tiers as categories. All labels were reassigned against the rule's
definitions. This is a re-interpretation of the same collected data, not a
change to the rule, and it happened before any scoring.

## Exclusions — recorded, not deleted

| Package | Reason |
|---|---|
| `com.ipru.iciciprulife.customer.release` | Life insurance, not banking |
| `com.maxlifeinsurance.www.twa` | Life insurance, not banking |
| `com.axismf.investorapp` | Asset management, not banking |
| `com.compass.reward` | Rewards app, not banking |

Insurance and AMC apps have a materially different permission surface from
banking apps. Including them would bias the comparison in the direction that
flatters the scorer, which is the direction least affordable here.

## Judgement calls made explicit

**Foreign banks' India apps are Tier A.** HSBC India, DBS India, Deutsche
India, Standard Chartered India are RBI-regulated Indian banking operations.
Tier D is reserved for non-India markets (`ae.hsbc.hsbcuae`,
`com.dbs.sg.dbsmbanking`, `com.YONOUKMobileApp` = SBI UK, etc.).

**Small finance banks are Tier A.** AU, Ujjivan, Equitas, Jana, Suryoday,
Utkarsh, ESAF, Unity, Shivalik, Capital are scheduled commercial banks under
RBI classification.

**`org.npci.erupee*` moved to Tier B.** Publisher is NPCI, not the bank. See
the clustering note below for the second reason.

**Bank-issued UPI and CBDC apps under a bank's own package prefix stay Tier A**
(`com.sbi.upi`, `com.bankofbaroda.upi`, `com.pnb.cbdc`, `com.uco.cbdc`,
`com.boi.erupee.prod`).

## Two threats to effective n — flag these in the results

**1. Shared-codebase clustering.** 11 Tier A packages are vendor white-labels:
Infrasoft (4), Lcode (3), Euronet, iExceed, MGS, Montran, Snapwork. Several
Indian banks buy from the same vendor, so those APKs may be near-identical
builds with different branding. The six `org.npci.erupee*` CBDC apps are
almost certainly one codebase — a large part of why they sit in Tier B.

**2. Same-issuer clustering.** Nine issuers contribute 3 Tier A packages each
(SBI, PNB, BoB, BOI, Kotak, IndusInd, Yes, UCO, Central Bank). Sibling apps
from one bank share a codebase and a signing certificate.

Both mean **effective n is below the nominal 62.** After extraction, cluster
the feature vectors and report how many distinct groups exist. If Tier A
collapses to ~35 independent samples, say 35 and widen the CI accordingly.
Bootstrap should resample by issuer, not by app, or the CI will be too narrow.

## Rows needing confirmation before download

| Package | Question |
|---|---|
| `com.infra.aryavartupi` | Aryavart is a regional rural bank — RRB, not a commercial bank. Reclassify or drop. |
| `com.lcode.clabmbanking` | Issuer assumed Capital SFB from the `clab` fragment. Unconfirmed. |
| `com.yespaylite` | Publisher not confirmed as Yes Bank. |
| `com.euronet.merchantapp` | Generic name; may be Euronet's own product, not bank-branded. |
| `org.npci.erupeeI` | Which bank the `I` denotes is unknown. |

These carry `VERIFY` in the note column. They do not block the filter — if a
package doesn't resolve in AndroZoo it drops out anyway. But any that survives
to the download stage should be confirmed against its Play Store listing
before it enters Tier A.

## Repairs applied

- `com.infrasoft.cbiMiniMerchant . C` — period instead of comma in source, repaired.
- `com.infrasoft.uboi` appeared twice (A and B), resolved to A.
- `com.idfcfirstbank.optimus` appeared twice, deduplicated.
- Whitespace stripped throughout.

## Device-verified rows

Four packages came from `adb`, not a web page, so their strings cannot contain
a transcription error: `com.snapwork.hdfc`, `com.hdfcbank.android.now`,
`com.sbi.lotusintouch`, `net.one97.paytm`,
`com.google.android.apps.nbu.paisa.user`. The last resolves the
`unconfirmed_recall` flag previously carried in the inclusion rule for Google
Pay.

HDFC appeared in neither manual list — it entered the corpus only via the
device dump.
