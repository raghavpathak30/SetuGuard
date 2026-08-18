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
