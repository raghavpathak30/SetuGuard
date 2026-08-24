# SetuGuard — Business Potential

**Written 24 August 2026.** Every figure below carries its source. Where a number is an
observation about our own dataset rather than a designed capacity, it says so. Nothing
here is a validated pricing model, and no cost saving is claimed that has not been
measured.

---

## 1. The problem, sized against the right series

The obvious series to cite is the RBI's bank-fraud data, and it is the wrong one.

The RBI Annual Report 2025-26 records 10,114 fraud cases involving ₹48,021 crore for
2025-26. Three properties make that series a poor fit for what SetuGuard addresses.
It covers only frauds of ₹1 lakh and above. It counts fraud *against the bank*, whereas
in device-driven mule fraud the victim is the customer and the bank is the conduit. And
its 2025-26 total is dominated by reclassified legacy loan cases reported afresh
following a March 2023 Supreme Court judgement, which says nothing about device-side
fraud today. In that series the card, internet and digital-payments category fell to 293
cases worth ₹29 crore in 2025-26, from 13,332 cases in 2024-25.

**The citizen-side series is the correct denominator**, and it is collected by the
Indian Cyber Crime Coordination Centre under the Ministry of Home Affairs. In 2025 the
National Cyber Crime Reporting Portal recorded 21,77,524 complaints with roughly
₹19,812 crore lost, against 19,18,852 complaints and ₹22,849 crore in 2024.

Read those two years together carefully, because the shape matters more than either
number. **Complaint volume rose by roughly 13 percent while total value fell by roughly
13 percent.** Fraud is not getting larger; it is getting more numerous and smaller per
case. That is precisely the profile under which manual triage stops working: the cost of
assembling context for an alert is roughly constant per alert, so as cases multiply and
individual values shrink, the analyst-hours per rupee recovered rise. Automation of the
assembly step is worth more each year that this shape holds, and it is worth nothing to
argue that losses are exploding when the published data says otherwise.

---

## 2. The buyer, and the workflow already in place

The buyer is not hypothetical and does not need to be assembled.

The Citizen Financial Cyber Fraud Reporting and Management System, operated by I4C since
2021, exists to report financial fraud immediately and stop funds being siphoned off. As
of December 2025 it had saved more than ₹7,130 crore across more than 23.02 lakh
complaints. Separately, a Cyber Fraud Mitigation Centre has been established at I4C
where representatives of major banks, financial intermediaries, payment aggregators,
telecom service providers and state law-enforcement agencies work together for immediate
action.

**That is the workflow SetuGuard's account-side model plugs into, and it already has a
convening body, participating banks and a funding line.** The procurement question is not
whether an institution would run mule-account triage; institutions are running it now,
at national scale, with humans doing the assembly.

The device-side half is recognised too. I4C's public awareness campaign names its target
modus operandi explicitly, and the list includes malware and fake loan apps — the exact
vector SetuGuard's static analysis component addresses.

**Who signs:** a public-sector bank's fraud risk management or cyber security function,
procuring for its own analyst team, with the CFMC as the multi-institution deployment
path rather than the first sale.

---

## 3. What it replaces

Not detection. **Assembly.**

When an analyst receives a mule-account alert today, the detection has already happened —
a rule fired, or a complaint arrived through the portal. What consumes the analyst's time
is everything after: pulling the indicators, establishing whether a device-side artefact
is involved, mapping observed behaviour to a technique, checking whether the account has
any link to a known malicious application, and assembling all of it into something a
supervisor can act on.

SetuGuard performs that assembly and hands the analyst a decision with its evidence
attached: the technique table produced deterministically from extracted features, the
specific APIs each finding rests on, the account's score and tier, and the join key on
which the two halves were linked.

**We have not measured analyst-minutes saved, and we do not claim a figure.** Doing so
would require a time-and-motion study inside a bank's fraud operations, which is not
available to us. What we can state is what the system produces and how long it takes to
produce it, which is in Section 5.

---

## 4. Run economics

**One machine, fully offline, no per-call cost.**

The entire pipeline runs on a single workstation: 20 cores, 15 GB RAM, one GPU. The
language model runs locally through Ollama. There is no external API, no per-inference
charge, no usage tier and no vendor dependency in the serving path.

For a bank this is a procurement argument before it is a cost argument. **No customer
account data and no submitted application leaves the institution's own hardware.** A
fraud tool that ships account records to a third-party endpoint has a data-residency and
regulatory conversation to win before it has a technical one. SetuGuard does not have
that conversation, because it never makes the call.

The account-scoring path is inference-only against a committed model artifact over
eighteen bank-approved features. Adding accounts costs compute proportional to the number
of rows and nothing else — no retraining, no per-account licence, no external lookup.

The honest limits: capital cost of the workstation, and the fact that the static-analysis
component is memory-bound rather than CPU-bound, so throughput scales with concurrent
memory budget rather than core count. Sizing is roughly 10 GB measured and 16 GB
provisioned per concurrent application under analysis.

---

## 5. What is actually measured

Stated with the negative class and the denominator in every case, because a business
case built on an unstated denominator does not survive contact with a technical
reviewer.

**The account model, on the bank-supplied dataset of 9,082 accounts at a 0.89 percent
base rate**, over 20-seed repeated stratified holdout: AUCPR median 0.271 with an
interquartile range of 0.221 to 0.362, AUROC median 0.872. Recall at the top one percent
of ranked accounts is 25.0 percent, which is 4 of 16 positives; at the top five percent
it is 53.1 percent, or 8 of 16. Against a random baseline of roughly 0.0089, that is
approximately a thirty-fold lift.

Sixteen positives is a small number and the percentages rest on it. We state the
fractions alongside the percentages for that reason.

**The static-analysis component ships as evidence extraction, not detection, and has no
false-positive rate because it carries no threshold.** Our own pre-registered measurement
found that a permission-and-API scorer ranks production banking applications above
confirmed banking trojans — AUC 0.1444 with a confidence interval of 0.0905 to 0.2081,
against a corpus of real production banking applications, pre-registered before any
score was computed. The commercial consequence is stated plainly: the device-side
component's value is the MITRE-mapped indicator extraction, the generated detection rule
and the join key it supplies to the account side. It is not a device-side verdict engine
and is not sold as one.

**Throughput.** Static extraction at parallelism one completed 58 of 60 applications
averaging 20.1 seconds each; two applications reached a 600-second budget without
completing. The full served analysis endpoint, which additionally runs retrieval and
narrative generation, has a median of 123.9 seconds over 14 valid runs of 30 attempted,
on files of 50 MB or less.

The operationally important property: **the language model is not the verdict source.**
Verdict, score and severity come from a rule scorer over extracted static features and
are unchanged when the model is unavailable. At volume, the narrative stage can be
queued, batched or dropped and no verdict changes. The expensive component is the
optional one.

---

## 6. What we do not claim

**No queue-capacity claim.** The risk tiers are assigned by fixed probability cutoffs.
They are not derived from a percentile of the score distribution, from an analyst triage
capacity, or from a cost model. On our dataset the served ladder places 102 of 9,082
accounts in the top tier, but that is an observation about this dataset and will not hold
its size on a different portfolio. Tier counts are never quoted against the recall
figures, which are computed by percentile and are a different selection rule.

**No cost-saving figure**, because analyst-minutes have not been measured.

**No pricing model**, because it has not been validated against a buyer.

**No claim of validation on real linked fraud.** No public dataset links Android malware
certificates to Indian bank account records; that data exists inside banks. What is built
is the join mechanism and the key space — publisher certificate SHA-256 and normalised
command-and-control host, both extracted by the static analyser. The linkage demonstrated
is constructed and labelled as constructed. The bank supplies the other side of the join,
which it already holds.

---

## 7. Anticipated questions

**"What does this cost a bank to run, and what does it replace?"**
One machine with a GPU, fully offline, no per-call cost, no data leaving the institution.
What it replaces is the analyst time spent assembling context for an alert — pulling
indicators, mapping them to techniques, checking for a device-side link. The assembly is
the cost, not the detection. We have not measured the minutes saved and do not quote a
figure.

**"Digital payment fraud is falling in the RBI data. Why does this matter?"**
It is falling in the RBI's bank-fraud series, which counts frauds of ₹1 lakh and above
committed against banks. Mule-account fraud is high-volume and low-value and the victim
is the customer, so most of it never enters that series. In the citizen-side data the
complaint count rose to 21,77,524 in 2025 while total value fell — more cases, each
smaller. That is the shape that breaks manual triage.

**"Who is your first customer?"**
A public-sector bank's fraud risk function. The multi-institution path already exists as
the Cyber Fraud Mitigation Centre at I4C, where banks, payment aggregators and telecom
operators are already convened for exactly this work.

**"You have 16 fraud positives. Is that a product?"**
No, it is a prototype evaluated on the data the problem statement supplied. The
architecture is inference-only against a committed artifact over the bank's own approved
feature list, so scaling to a real portfolio is a batch job rather than a redesign. What
a production deployment needs from the bank is volume and a calibrated operating point,
neither of which we can manufacture.

---

## Sources

- Reserve Bank of India, Annual Report 2025-26 (fraud case counts and amounts, category
  breakdown, ₹1 lakh reporting floor, Supreme Court reclassification note).
- Ministry of Home Affairs, Lok Sabha Unstarred Question No. 432, 2 December 2025
  (CFCFRMS: ₹7,130 crore saved across 23.02 lakh complaints; awareness campaign modus
  operandi list).
- Ministry of Home Affairs, Lok Sabha Unstarred Question No. 344, 22 July 2025 (Cyber
  Fraud Mitigation Centre composition).
- Indian Cyber Crime Coordination Centre / National Cyber Crime Reporting Portal, 2024
  and 2025 complaint volumes and reported losses, as compiled in press reporting of I4C
  data.
- All SetuGuard figures: this repository's evidence files, with negative class and
  denominator stated at each point of use.
