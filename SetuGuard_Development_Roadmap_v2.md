# SetuGuard — Revised Development Roadmap (v2)
### Incorporating the four research-backed fixes, Claude Code assumed for implementation

---

## What changed from v1

- Baseline core builds compress significantly with Claude Code doing implementation — the bottleneck shifts from "how fast can we type" to "how fast can we get real data" and "does everyone understand what they shipped."
- The four fixes (graph features, synthetic bridge validation, expanded YARA corpus, adversarial obfuscation testing) are no longer squeezed into Phase 2 — they're pulled into Phase 1, with two explicit early "risk spikes" to surface data-acquisition and tooling problems before committing full days to them.
- Ownership is reassigned so each person owns one fix end-to-end (build + understand + defend in Q&A), not just "whoever's faster at Python."

## Revised ownership

| Part | Owner | Baseline | + Fix |
|---|---|---|---|
| 1 — PS1 engine | You | Androguard, RAG report, YARA gen | **Fix #3** (F-Droid + 16 real banking-app holdout) + **Fix #4** (Obfuscapk adversarial survival matrix) |
| 2 — PS2 model | Teammate | Data audit, XGBoost/SHAP/tiers | **Fix #2** (Louvain/betweenness/PageRank on AMLworld) |
| 3 — Bridge | Teammate | IOC enrichment, DiCE, mock regulatory feed | **Fix #1** (synthetic ground-truth linkage validation — depends on Fix #2's graph) |
| 4 — Dashboard/Audit | Teammate | UI, AuditTrailRecord, compliance | **Optional:** grounding-faithfulness gate on the Mistral report, only if slack exists |

You own the two PS1 fixes because they extend the engine you already own and don't require anyone else's output first. Fix #1 explicitly depends on Fix #2 — that dependency is why the timeline below sequences them.

---

## Phase 1 (1–31 Jul) — Revised week-by-week

### Week 1 (1–7 Jul) — Baseline core, accelerated, plus two risk spikes

With Claude Code handling implementation, aim for **working baseline pipelines by end of week 1**, not just skeletons.

**You (PS1):**
- Full Androguard → feature vector → RAG report → YARA gen pipeline, end to end, even if rough
- **Risk spike (Day 5–6):** install Obfuscapk, run it against one trojan sample, confirm it actually completes without erroring on your APK set. This is a "does this tool even work on our data" check — do it now, not when it's on the critical path in Week 3.

**Teammate (PS2):**
- Baseline XGBoost/SHAP pipeline running on ULB data with real numbers
- **Risk spike (Day 5–6):** pull AMLworld HI-Small from Kaggle, load a subsample into NetworkX, confirm Louvain/betweenness run without choking. This surfaces "is this dataset actually usable on our machines" before you're relying on it for Fix #1 and #2 both.

**Teammate (Bridge):**
- Mock enrichment logic against stub PS1/PS2 outputs (can't do more until schemas + AMLworld spike land)

**Teammate (Dashboard):**
- UI shell against the AuditTrailRecord schema

**End of week checkpoint:** schemas frozen (as in v1), *plus* both risk spikes reported back to the team. If either spike failed (Obfuscapk won't run, AMLworld won't load), you now have 3 weeks of runway to find a fallback instead of discovering it in Week 3.

---

### Week 2 (8–14 Jul) — Finish baseline integration + start the two lower-risk fixes

**You (PS1):**
- Finish PS1 end-to-end: validation gate, AutoYara fallback, full stress testing
- **Start Fix #3:** script the F-Droid pull (~500–1,000 apps) and source the 16 real target banking APKs. Get the batch YARA test harness running, even against the baseline corpus.

**Teammate (PS2):**
- Finish baseline: DiCE counterfactuals, full ULB benchmark confirmed reproducible
- **Start Fix #2:** compute the four graph features (community, betweenness, PageRank, fan-in/out ratio) on the AMLworld subgraph, confirm mule-labeled nodes actually surface as expected before wiring into XGBoost

**Teammate (Bridge):**
- First real end-to-end wiring: PS1 IOC schema → PS2 enrichment, using real (not stub) outputs from both

**Teammate (Dashboard):**
- Wire dashboard to real PS1+PS2+Bridge outputs

**End of week checkpoint:** first full dry-run demo of the *baseline* system (this is roughly what v1 had you doing in Week 3 — you're now a week ahead).

---

### Week 3 (15–21 Jul) — The two higher-effort fixes + dry run #2

**You (PS1):**
- **Fix #4:** run the Obfuscapk survival matrix — five escalating profiles against your trojan set, re-run YARA rules against each variant, tabulate which IOC types survive
- Finish Fix #3: get the FP-rate numbers finalized (target: 0 FP across F-Droid corpus and all 16 real banking apps)

**Teammate (PS2):**
- Finish Fix #2: feed the four graph features into XGBoost as new columns, confirm it doesn't degrade the existing AUCPR, document the "mule nodes rank in top-percentile betweenness" finding

**Teammate (Bridge):**
- **Fix #1** (now that Fix #2's graph exists): build the ~50–100 account synthetic linkage set with ground-truth APK associations plus near-miss confounders, run the deterministic matcher, generate the confusion matrix

**Teammate (Dashboard):**
- Wire the new fix outputs into the demo: graph viz with highlighted mule pivot nodes, obfuscation survival heatmap, confusion matrix panel

**Full dry-run #2:** walk through baseline + all four fixes live, even if rough on the edges. This is your real integration test — you're doing it a week earlier than v1's plan, which buys you a full extra week of polish instead of scrambling.

---

### Week 4 (22–31 Jul) — Hardening, polish, optional stretch

- Bug fixing from dry-run #2, prioritized by demo-visibility
- **If your team has slack:** Part 4 owner builds the grounding-faithfulness gate (cross-checking Mistral report claims against extracted IOCs/FAISS retrievals) — cheap, reuses existing stack, directly answers the RBI FREE-AI "Ethics" claim
- Finalize the MITRE ATT&CK-Mobile coverage table against real triggered samples
- Rehearse the full walkthrough: baseline kill-chain demo → graph mule detection → bridge confusion matrix → obfuscation survival table
- Draft the honest scope note for the progress report: what's measured on synthetic ground truth vs. real data, stated plainly (this is your team's established strength — keep doing it)

---

## Phase 2 (1–17 Aug) — Lighter, now genuinely about depth not scramble

Because Phase 1 now ships all four fixes instead of deferring them, Phase 2 becomes what it should be: deepening what's real, not building new features under deadline pressure.

- **Week 1 (1–7 Aug):** Scale up whichever fix has the most room to grow — likely expanding the F-Droid corpus further, or adding AndroZoo apps if the API key came through, or expanding the AMLworld subsample if compute allows
- **Week 2 (8–17 Aug):** Progress report writeup — this now has real evidence to cite (confusion matrix numbers, betweenness percentiles, FP counts, survival matrix) instead of "planned/simulated" caveats throughout. Second full dry-run before submission.

## Phase 3 (18–28 Aug) — Unchanged from v1

Rehearsal, hardening, judge Q&A prep (each person defends their owned fix), finale 27–28 Aug.

---

## Risk register (updated)

1. **AMLworld and Obfuscapk are now front-loaded as Week 1 spikes** — this was the single biggest risk in v1's estimate and is now addressed by design, not left to hope.
2. **Mistral 7B local latency** — still test this Day 1, unchanged from v1.
3. **Schema drift** — still lock Week 1, unchanged from v1.
4. **Comprehension bottleneck (new risk from Claude Code acceleration):** faster typing means it's possible to ship code nobody fully understands. Each fix owner should be able to explain their fix's methodology cold, without notes, by end of Week 3 — build this into the Week 4 rehearsal explicitly.
5. **Reproducibility** — re-run the ULB AUCPR number and the graph-feature results more than once before either goes in the progress report.
