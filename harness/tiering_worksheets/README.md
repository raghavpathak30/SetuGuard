# Tiering worksheets

Raw manual working record behind `harness/BANKING_PACKAGE_TIERING_DECISIONS.md`.
Format: `package_name , TIER` grouped by bank identity. Tiers A/B/C correspond
to the tier labels in `harness/download_run.log`.

These are the manual bank-identity labels behind the issuer clustering. The
labels were assigned from research on bank identity, not derived from scores.
The load-bearing evidence for ordering is the commit history of
`harness/BANKING_PACKAGE_TIERING_DECISIONS.md` relative to the scoring runs,
not the mtimes of these files — mtimes are not evidence and are not offered
as any.

Renamed on commit; original filenames were the first line of each file
(`appi.txt`, `com.csam.icici.bank.imobile,A.txt`, `in.hsbc.hsbcindia, A.txt`).
Contents unmodified.

NOT FROZEN.

## Ordering chain (verifiable in git log)

| Step | Commit | Date |
|---|---|---|
| Bank-identity labels committed | `fd2f620` | 2026-08-15 01:18 |
| AUC claims pre-registered, before scoring | `be6a15c` | 2026-08-15 21:04 |
| PRIMARY banking-corpus AUC measured | `2b558a9` | 2026-08-15 22:51 |

Labels, then claim, then number. Verify with:
`git log --format='%h %ad %s' --date=iso -- harness/BANKING_PACKAGE_TIERING_DECISIONS.md harness/PREREGISTERED_BANKING_AUC_CLAIMS.md harness/BANKING_AUC_RESULTS.json`

Git commit dates are settable, so this ordering is corroboration, not proof.
The substantive argument is the clustering design itself: issuer clusters are
defined by bank identity, a variable that makes no reference to any score. A
score-derived clustering would have to be expressible in terms of the scores;
this one is not.
