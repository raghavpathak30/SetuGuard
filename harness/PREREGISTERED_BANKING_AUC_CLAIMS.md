# Pre-registered claims — PS1 score vs legitimate banking applications

Written and committed **before** any score was computed on
`harness/banking_legit_corpus/`. The commit timestamp of this file preceding the
scoring run is the point of the file.

## Design, fixed in advance

- **Primary analysis:** current-generation Tier A arm, one APK per package (most
  recent build). Era-matched builds excluded from the primary.
- **Secondary analysis:** era-matched arm, reported separately. The two arms are
  never pooled into a single figure.
- **Positive class:** the 360 scored CICMalDroid banking-malware samples.
- **Statistic:** AUC of the evidence-weighted score (never "confidence").
- **Interval:** 95% CI by bootstrap resampling **over issuer clusters**, not over
  APK files. Both the file count and the issuer-cluster count are reported wherever
  the AUC is reported.
- **Tier B/C/D:** reported separately, excluded from the headline figure.

## Outcome 1 — CI entirely above 0.5

"PS1's evidence-weighted score separates CICMalDroid banking malware from
legitimate Indian banking applications, AUC = A [CI], over n packages from k
issuers. This figure is confounded by platform evolution: the malware corpus was
collected 2017-2018, the legitimate corpus is current-generation, and Play Store
policy has since restricted SMS and call-log access for non-default handlers. The
era-matched arm is reported alongside as the confound check; the confound is not
resolved by this measurement."

## Outcome 2 — CI spans 0.5

"At this sample size the interval includes chance, and we do not claim separation.
This is the class-convergence hypothesis surviving its first test: legitimate
banking applications and banking trojans request overlapping permission and API
surfaces by construction, and PS1's static feature set does not distinguish them.
PS1's stated contribution is evidence extraction, MITRE-mapped IOC reporting and
YARA generation - not banking-app-versus-malware classification."

## Outcome 3 — CI entirely below 0.5

"AUC = A [CI], below chance: legitimate banking applications score higher than
banking malware on PS1's evidence-weighted score. This is a measured negative
result; the scorer's term weights are not valid for this discrimination."
Followed by the product framing of Outcome 2, verbatim.

## Outcome 4 — the two arms disagree

Both are reported. Any statement about the class-convergence hypothesis leads with
the era-matched arm. Any statement about operational false-positive load leads with
the current arm. Neither number is used for both claims.

## Operational recommendation — identical under all four outcomes

PS1 is scoped to untrusted and sideloaded APKs, with an allowlist of Play-signed
banking packages applied upstream. A fraud analyst does not need a detector that
reasons about whether a bank's own published application is malware; they need one
that reasons about the APK a customer was tricked into sideloading. This scoping is
a deliberate product boundary, not a response to the measurement.

## Prohibited regardless of outcome

- Reporting an AUC over file count rather than issuer clusters.
- Pooling the current and era-matched arms.
- Any post-hoc threshold, term-weight or corpus-composition change followed by
  re-reporting this AUC as if pre-registered.
- Reviving the triage-percentile reframe.
- Any claim that the class-convergence hypothesis was "confirmed" - it can survive
  a test or fail one; the corpus is too small to confirm it.

## 2026-08-19 — issuer-cluster integrity check, appended post-hoc, original text above unchanged

This section verifies a concern raised after the AUC was published, not a change to the
design above. Appended per this file's own amend-don't-delete discipline.

**The concern:** "resample by issuer clusters" (design section above) does not itself
specify what identifies an issuer. If clustering had used the APK's raw X.509
certificate-issuer field, Google Play App Signing re-signing would collapse many
structurally independent banks into a single "Google Inc." cluster, since Play
re-signs the APK with Google's own key at distribution time. That would understate
how much independent structure the published interval rests on. Checked directly:
**27 of the ~73 Tier A files carry raw cert issuer "Google Inc."**
(`harness/BANKING_CORPUS_VERIFICATION.md`), so this was a real risk, not a hypothetical
one.

**What was actually clustered on:** `harness/score_banking_corpus.py` (the file that
produced `harness/BANKING_AUC_RESULTS.json`) never reads the raw certificate-issuer
field. Its `issuer` comes from `harness/BANKING_CORPUS_MANIFEST.tsv`, which joins from
`harness/banking_packages.csv` — a manually-researched bank-identity label assigned per
package (`source` column: 78/83 rows `manual`), built 13-14 Aug per
`harness/BANKING_PACKAGE_TIERING_DECISIONS.md`, which independently flags "same-issuer
clustering" as a named risk to effective n **before any scoring ran**, and is the reason
issuer-cluster resampling exists in the design section above at all.

**Verified by reconstruction** (the assignment itself is not stored in
`BANKING_AUC_RESULTS.json` — only the cluster count is; the assignment was
reconstructed here from `BANKING_CORPUS_MANIFEST.tsv` + `score_banking_corpus.py`'s own
`load_manifest()`/`load_banking_scored()` functions, imported and run read-only, not
reimplemented, so this is not an independent re-derivation that could silently diverge):
PRIMARY (current arm) reconstructs to exactly 51 files / 32 issuer clusters, largest
cluster 3 packages (State Bank of India, Kotak Mahindra Bank, IndusInd Bank), zero
clusters labelled Google. SECONDARY (era-matched arm) reconstructs to exactly 20 files /
16 issuer clusters, largest cluster 2 packages, zero clusters labelled Google. Both
match the published counts in `BANKING_AUC_RESULTS.json` exactly. The one package
genuinely labelled "Google" anywhere in the full 83-package list
(`com.google.android.apps.nbu.paisa.user`, Google Pay — a real Google product, correctly
attributed) is Tier B and outside both scored populations.

**Decision rule fixed in advance of this check:** largest Google-signed cluster ≤3
packages → record in limitations, no recomputation; ≥4 → recompute both CIs with
Google-signed apps clustered by package instead of issuer and report both. **Largest
Google-signed cluster found: 0 packages.** First branch applies, more strongly than its
own threshold. **No recomputation performed. 0.1444 [0.0905, 0.2081] and 0.3190
[0.2202, 0.4290] stand as published, unchanged.**

**What remains a live limitation, not resolved by this check:** the manual issuer labels
in `banking_packages.csv` are researched, not certificate-derived, so their accuracy
depends on that research being correct — this check verified internal consistency (the
labels used match what was published, and correctly separate Play-signed apps by true
publisher) but did not re-verify each of the 83 manual attributions against an
independent source. `BANKING_PACKAGE_TIERING_DECISIONS.md`'s own "Rows needing
confirmation" table flags five packages as unconfirmed (`VERIFY` in its note column).
**Checked by name against the cluster tables above — two of the five are in the scored
sets, not zero as first assumed here and corrected before this file was committed:**
`com.infra.aryavartupi` (PRIMARY only, singleton "Aryavart Bank" cluster — the open
question is whether it is a scheduled commercial bank or a regional rural bank at all,
i.e. whether it belongs in Tier A, not which bank owns it) and `com.lcode.clabmbanking`
(both PRIMARY and SECONDARY, singleton "Capital Small Finance Bank" cluster in each arm —
the open question here is bank identity itself: "issuer assumed Capital SFB from the
`clab` fragment, unconfirmed"). Both are already singleton clusters (n=1 package), so
neither can be silently merging two distinct banks under one label — an identity error
here would misattribute one data point, not collapse independent structure the way the
Google-signing concern above could have. The other three (`com.yespaylite`,
`com.euronet.merchantapp`, `org.npci.erupeeI`) are confirmed absent from both scored
sets. Resolving `com.lcode.clabmbanking`'s issuer is the more material of the two open
items, since it affects both arms; unscheduled, flagged here rather than silently
carried forward.
