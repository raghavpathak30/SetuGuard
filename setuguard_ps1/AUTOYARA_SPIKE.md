# AutoYara Feasibility Spike (I2) — GO/NO-GO, not an integration

Same discipline as the Week-1 Obfuscapk risk spike: feasibility only. **Nothing was
installed system-wide, no dependency was added, no integration code was written, and
`yara_gen.py` was not modified.** All claims below are from sources actually fetched this
session (linked at the bottom), not from memory.

## What AutoYara actually is

- **Repository:** [`FutureComputing4AI/AutoYara`](https://github.com/FutureComputing4AI/AutoYara)
  (an academic project, formerly hosted under `NeuromorphicComputationResearchProgram`).
  This is the tool the defects doc's I2 item ("AutoYara fallback") refers to — the
  biclustering-based rule generator from the paper
  [Automatic Yara Rule Generation Using Biclustering](https://arxiv.org/abs/2009.03779)
  (Raff et al., 2020 ACM AISec workshop).
- **Language/runtime:** Java, requires **JDK 11+**. Build system is Maven
  (`pom.xml` present in the repo). **Not a Python package** — no PyPI listing exists
  (confirmed: `pip index versions autoyara` → no matching distribution; `pypi.org/pypi/autoyara/json`
  → HTTP 404).
- **Packaging:** a single GitHub Release ("Version 1.0", dated to at least
  September 2017 based on the release notes) provides a pre-built `AutoYara.jar` plus two
  accompanying **bloom-filter files** (built from the Ember-2017 malware corpus) that the
  jar needs alongside it to run. No Docker/container image exists under this project (no
  official image found on Docker Hub — `hub.docker.com/v2/repositories/library/autoyara/`
  → HTTP 404; this checks the official-images namespace, not every possible third-party
  image, so absence there is a signal, not exhaustive proof of absence).
- **License:** Apache 2.0.
- **Maintenance status:** appears **abandoned/research-stage**, not production software.
  One release, no visible ongoing updates, and the release notes themselves describe it as
  "research software" with no warranty or support commitment.
- **Usage shape (from the README):** `java -jar AutoYara.jar -i <path-to-malware-family-dir>
  [--out rule.yara]` — it's designed to be pointed at a directory of *already-labeled,
  same-family* malware samples and biclusters n-grams (n≥8) across them into rule
  candidates, not to process one APK's already-extracted `features` dict.

## What's actually confirmed usable in this environment

- **Java is already installed on this machine**: `java -version` → OpenJDK 25.0.2 — well
  above the JDK 11+ requirement. If the JAR were fetched, it would very likely run without
  any new system-wide install.
- Not fetched or run this session (per the spike-only scope) — this is "would probably
  work," not "confirmed working."

## Adoption cost and design-fit assessment

- **It is not a drop-in fallback for the current pipeline's `<2 indicators → None` case.**
  `yara_gen.py`'s indicator-count gate operates on **one already-analyzed APK's**
  `features` dict (permissions/APIs/strings extracted by `static_analysis.py`). AutoYara's
  actual design input is **a directory of multiple raw APK files from the same malware
  family**, biclustered against each other — a fundamentally different unit of work. There
  is no single-sample mode in the tool as documented.
- Integrating it for real would mean: (a) shelling out to a separate JVM process (a new
  runtime dependency alongside Python/Ollama/YARA — this repo has none today), (b)
  maintaining a labeled-by-family corpus for it to bicluster against (the project doesn't
  have per-APK family labels anywhere in the current pipeline or corpora), and (c)
  reconciling its raw n-gram-based YARA output style with this project's `SetuGuard_<pkg>`
  rule-naming/`meta`-block convention (`yara_gen.py`'s format, Section 4 of `CONTEXT.md`) —
  a nontrivial adapter layer, not a config change.
- **License and packaging are not blockers** (Apache 2.0, Java already present) — the
  blocker is architectural fit, not availability.

## The unresolved ambiguity — flagged, not resolved

The defects doc's I2 ("No AutoYara fallback... when the LLM produces no usable indicators,
there is no fallback path to a rule") is ambiguous about which of two very different things
it's asking for, and this session is not resolving that ambiguity:

1. **Adopt the actual AutoYara tool** — which, per the above, would require reframing the
   whole `<2 indicators` case around family-labeled multi-sample biclustering, a
   significantly bigger design change than the current single-APK pipeline shape.
2. **Build a homegrown fallback** for the `<2 indicators → None` case using this project's
   own existing data (e.g., a simpler n-gram/string-overlap heuristic scoped to what
   `static_analysis.py` already extracts) — much cheaper, fits the existing architecture,
   but isn't "AutoYara" in any literal sense, just inspired by the same biclustering-adjacent
   idea.

**This session flags the ambiguity and does not pick a side.** Whichever the team means,
it's a design decision with real cost attached, not a quick Week-2 addition.

## GO/NO-GO

**NO-GO for adopting the actual AutoYara tool as a fallback in the current architecture.**
Not because it's unobtainable (it is obtainable — Apache 2.0, Java already installed, one
`git clone`/release download away) but because its input shape (multi-sample, family-
labeled, cross-APK biclustering) doesn't fit this pipeline's single-APK
`features → report → rule` shape without a substantial redesign, and the project itself
looks unmaintained since its one 2017-era release.

**Open/undecided:** whether a homegrown, single-APK-scoped fallback (option 2 above) is
worth building for the `<2 indicators` case — that's a real, much cheaper option this spike
did not evaluate in depth, and is a separate team decision.

## Sources fetched this session

- [github.com/FutureComputing4AI/AutoYara](https://github.com/FutureComputing4AI/AutoYara)
- [github.com/FutureComputing4AI/AutoYara/releases](https://github.com/FutureComputing4AI/AutoYara/releases)
- [arxiv.org/abs/2009.03779](https://arxiv.org/abs/2009.03779) — "Automatic Yara Rule Generation Using Biclustering"
- PyPI: `pypi.org/pypi/autoyara/json` → 404 (checked via direct HTTP request)
- Docker Hub official images: `hub.docker.com/v2/repositories/library/autoyara/` → 404
- Local: `java -version` (OpenJDK 25.0.2, already installed on this machine)
