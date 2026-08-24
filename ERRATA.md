# SetuGuard — Errata to the Submitted Progress Report

**Written 24 August 2026, ahead of the Grand Finale, 27–28 August, IIT Hyderabad.**

This document records every point at which the submitted report and the system as it
stands on 24 August do not say the same thing. It is written to be read alongside the
report, not to replace it. Two file variants of the report exist; their load-bearing
claims were diffed and found identical, so this errata applies to either.

Entries are of two kinds. **Corrections** are places where the report states something
that further measurement has narrowed or qualified. **Progress since submission** are
places where the report discloses a defect that has since been closed — recorded here
so that the report's disclosure is not mistaken for a stale one.

---

## Corrections

### C1 — The throughput figure includes two failed extractions, and the slowest-file figure is not the slowest file

**The report states:** throughput at parallelism one of 60 applications in 2,374
seconds, or 39.6 seconds per application, with the slowest single extraction at 77.9
seconds for a 251 MB protected application; single-machine figures over n=73, no
percentile quoted.

Three corrections follow. All are drawn from the same source records the report used,
and none changes the memory figures in the same section, which are correct as printed.

**C1.1 — The divisor counts attempts, not completions, and two attempts did not
complete.** Of the 60 applications in that run, 58 completed and 2 reached the
600-second extraction budget without finishing. The two unfinished attempts contribute
1,200.2 seconds — 50.7 percent of the wall clock — to a total the report divides by all
60. The 58 completions took 1,166.2 seconds between them, a mean of 20.1 seconds per
completed application at parallelism one.

The corrected statement is therefore: **58 of 60 applications completed, averaging 20.1
seconds each at parallelism one; 2 applications reached a 600-second budget and did not
complete.** Throughput and failure are reported separately, because a mean that absorbs
its own failures describes neither.

**C1.2 — 77.9 seconds is not the slowest extraction.** It is the slowest file in a
three-file probe batch. In the 60-file run, the slowest completed extraction was 93.9
seconds, for a 251 MB application; two further applications did not complete at all.
The report presents 77.9 seconds inside a paragraph scoped to n=73, which implies a
worst case across the whole measured set. It is not that.

**C1.3 — All of these figures measure static extraction, not the served endpoint.**
Latency of the full `/api/analyze_apk` path, measured 23 August: median 123.9 seconds,
IQR 107.1–145.7 seconds, n=14 valid of 30 attempted, against the legitimate banking
corpus, restricted to files of 50 MB or less. Runs in which the narrative model held
non-zero swap were excluded under a criterion stated before the runs; 16 of 30 met it.

The difference between the extraction figures and the endpoint figure is the retrieval
and narrative-generation stages, which extraction does not include. This is a scope
difference, not two measurements of the same thing disagreeing.

**Why the scope difference matters operationally:** the narrative model is not the
verdict source. Verdict, score and severity are produced by the rule scorer against
extracted static features, and are unchanged with the model unavailable. The stage that
accounts for the gap between the extraction figures and the endpoint figure is
therefore precisely the stage that can be queued, batched or dropped at volume without
altering a single verdict.

**No figure in this section should be quoted without its scope, its n, and whether it
counts attempts or completions.**

**Not corrected — the memory figures in the same section are accurate.** The largest
clean isolated peak of 9.68 GiB, the largest observed peak on a similarly sized
application, the coincident swap-out of roughly 1.46 GB, and the sizing rule of
approximately 10 GB measured and 16 GB provisioned per concurrent application all
reconcile against the per-file records. The two peak figures are converted from mebibytes
under different conventions, so the larger one reads about two percent high; the sizing
rule it supports is unaffected.

### C2 — The account-scoring latency figure has no producing harness

**The report states:** the serving path is inference-only against a committed model
artifact and returns in roughly 0.66 seconds.

**Correction:** no script in the repository produces that figure. It originates in a
hand-recorded set of three observations, alongside two other per-application timings
that do not agree with each other or with any measured figure. It is not reproducible
from a clone of this repository and should not be treated as a characterised latency.

The claim it supports — that account scoring is not the bottleneck — does not rest on
it. Scoring is inference-only over eighteen features against a committed model
artifact, and is cheaper than static extraction by a wide margin on any measurement in
this project. The claim stands; the number should not be quoted.

### C3 — The excluded benign corpus remains excluded

The report states in its limitations that an earlier benign measurement produced a far
more favourable AUC against a general free-software corpus, that the corpus was
available during scorer term selection, and that the figure is therefore contaminated
by selection and appears nowhere in the report.

**This errata restates that exclusion and extends it to spoken claims.** Neither the
favourable AUC nor the flag rate computed against that same corpus is quoted in any
presentation, answer or supporting material. Both derive from the contaminated corpus
and both fall under the same exclusion.

Consequently the static component has no false-positive rate, and does not claim one.
It carries no threshold. The only threshold figure that exists is the one the report
already gives: at a score of 0.30, 50 of 51 legitimate banking packages flag. That is
the negative result, and it is the reason the static component's claim is narrowed to
evidence extraction and reporting.

### C4 — Two different risk-tier ladders exist, and they disagree

The account model's risk tiers are assigned by fixed probability cutoffs. **Two
different sets of cutoffs are implemented in this repository, and they do not agree.**

The served path, in the analysis backend, assigns T2 at 0.25 and above, T3 at 0.50 and
above, and T4 at 0.75 and above. The offline baseline script assigns T2 above 0.25, T3
above 0.55, and T4 above 0.80, and carries an action in each label: no action, monitor,
enhanced review, and temporary debit freeze.

Two bands therefore disagree. An account scoring between 0.50 and 0.55 is T3 on the
served path and T2 offline. An account scoring between 0.75 and 0.80 is T4 on the served
path and T3 offline — a temporary debit freeze against an enhanced review, for the same
account under the same model.

**The served ladder is authoritative for every tier figure stated anywhere.** The tier
counts reported for the 9,082-account dataset — 8,490 in T1, 380 in T2, 110 in T3 and
102 in T4 — are produced by the served ladder. The offline script's tiers appear in
offline export artifacts and are excluded from every claim. The ladders are not
reconciled in code, because doing so this close to the demonstration would change the
served tier counts and invalidate figures already recorded.

**Neither ladder is calibrated.** Both are hardcoded probability cutoffs. Neither is
derived from a percentile of the score distribution, from an analyst triage capacity,
or from a cost model. Three consequences follow, and all three constrain what may be
said:

- The tier counts describe what one fixed ladder selects on this particular dataset.
  They are an observation about this dataset, never a designed queue capacity, and they
  will not hold their size on a different portfolio.
- **Tier counts must never be paired with the recall figures.** Recall at the top one
  percent and top five percent is computed by ranking and cutting at a percentile;
  tiers are assigned by a fixed probability threshold. These are different selection
  rules over the same scores, and a queue size drawn from one cannot be quoted against
  a recall drawn from the other.
- In a production deployment the boundaries would be set from the bank's own triage
  capacity and its cost of a missed mule against its cost of a frozen legitimate
  account. That calibration has not been done here and is not claimed.

**A related asymmetry, verified in the serving path.** Bridge link records carry both an
account tier and a recommended action, but the recommended action is derived from the
severity of the linked application alone. The account's tier does not enter it, so two
accounts in different tiers linked to the same application receive the same instruction.
The tier is carried alongside so that an analyst can prioritise among several links, and
a production version would key the action on the pair rather than on one side of it.
The tier shown in a bridge link is produced by the served ladder, so no single response
mixes the two ladders described above.

---

## Progress since submission

The report discloses the following as known and deliberately unfixed, scheduled ahead
of the final demonstration. Each has since been addressed. They are listed here so the
report's disclosure is read as accurate at the time of writing rather than as an
outstanding defect.

**Fail-closed handling on the analysis path.** A parse failure previously returned an
HTTP 500 carrying the exception string. It now returns a structured refusal naming the
reason and the analyst action.

**Upload cap.** Uploads were previously uncapped. A size limit is now enforced on the
analysis path.

**Repository documentation and front-end capability claims.** The repository
documentation described an earlier architecture in which the language model produced
the verdict, and the front end advertised capabilities that did not exist. Both have
been corrected to describe the shipped system.

**Publisher allowlist.** The report states in three places that the allowlist scoping
the static component is specified in the pre-registration but not implemented, and
lists implementing it as the first item of remaining work. Publisher tagging is now
present at the display layer, identifying which analysed packages carry a recognised
publisher certificate. **This is tagging, not an enforced upstream exclusion, and no
metric has been re-run with allowlisted packages removed.** Coverage is 23 of the 51
scored primary-arm packages, or 45 percent; the remainder of the legitimate corpus is
self-signed. The control the report describes as future work remains future work.

---

## Standing constraints on how results are stated

These are not corrections to the report. They are the rules under which its results are
described in person, recorded here so that written and spoken claims cannot diverge.

- The static separation result is a negative result and is reported as the principal
  measured finding, in the terms the pre-registration committed in advance.
- The explanation that the two classes are convergent by construction is an untested
  hypothesis offered to account for the result. It is not itself a result.
- The bridge confusion matrix is a correctness test of join logic over constructed
  data. It is never described as a detection rate. The figures stated are two distinct
  ground-truth linkages, one hundred test cases and twenty near-miss confounders.
- The account-model leakage work is an audit and a quantification of columns the bank's
  own finalized feature list already excludes. It is never described as discovery.
- The graph-feature experiment assigned features using the target label and is excluded
  from every claim.
- File count is not package count and neither is issuer-cluster count. The corpus spans
  95 files, 68 packages and 47 issuer clusters; the primary arm attempted 53 packages,
  scored 51, and spans 32 clusters.
- Any observed candidate command-and-control host is displayed defanged, and is
  described as an extracted indicator rather than as confirmed live infrastructure.

---

## Known defect disclosed and not fixed

The generated narrative sometimes names MITRE technique identifiers that the extractor
did not produce for that sample. The technique table in each analysis is the
authoritative evidence: it is produced deterministically from extracted features, and
each row names the specific class and method that triggered it. The narrative is
model-generated commentary and is subordinate to that table. **Technique identifiers
appearing in narrative prose are not extraction results and must not be read as
evidence.**

This is disclosed rather than fixed because a change to the generation path this close
to the demonstration carries more risk than the defect does, given that the narrative
reaches no verdict field.

Relatedly, the analysis response carries no knowledge-base chunk identifiers. Any
description of evidence as traceable to a retrieved chunk is withdrawn. What is
traceable is the extracted suspicious-API list, with call counts and categories, and
the detection field of each technique row, which names the API the finding rests on.
