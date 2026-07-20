"""SetuGuard PS1 — glue entrypoint. Runs static -> rag -> yara in sequence.

CLI: python run_pipeline.py <apk>

Writes out/<pkg>.features.json, out/<pkg>.report.json, out/<pkg>.report.md,
and out/<pkg>.yar (if a rule was generated) and prints a one-line summary
with per-stage timing.
"""
import json
import sys
import time
from pathlib import Path

from static_analysis import analyze_apk
from rag_report import generate_report
from yara_gen import generate_yara

# ============================== SETTINGS ==============================

OUT_DIR = Path(__file__).parent / "out"

# ========================================================================


def _render_markdown(features: dict, report: dict) -> str:
    lines = [f"# SetuGuard PS1 Report — {features['package_name']}"]
    lines.append("")
    lines.append(f"- **App name:** {features['app_name']}")
    lines.append(f"- **SHA256:** {report['sha256']}")
    lines.append(f"- **Verdict:** {report['verdict']}")
    lines.append(f"- **Confidence:** {report['confidence']}")
    lines.append("")
    lines.append("## Rationale")
    lines.append(report["rationale"])
    lines.append("")
    lines.append("## Cited knowledge-base chunks")
    for cid in report.get("cited_chunk_ids", []):
        lines.append(f"- {cid}")
    lines.append("")
    lines.append("## Retrieved knowledge-base chunks")
    for cid in report.get("retrieved_chunk_ids", []):
        lines.append(f"- {cid}")
    lines.append("")
    lines.append("## Key static indicators")
    lines.append(f"- Dangerous permissions: {', '.join(features['dangerous_permissions']) or 'none'}")
    for api in features["suspicious_apis"]:
        lines.append(
            f"- Suspicious API [{api['category']} / {api['mitre']}]: "
            f"{api['class']} -> {api['method']} (call_count={api['call_count']})"
        )
    for s in features["suspicious_strings"]:
        lines.append(f"- Suspicious string [{s['kind']}]: {s['value']}")
    for comp in features["exported_components"]:
        lines.append(f"- Exported {comp['type']}: {comp['name']}")
    cert = features["certificate"]
    lines.append(
        f"- Certificate: subject={cert['subject']} self_signed={cert['self_signed']} "
        f"is_debug={cert['is_debug']}"
    )
    return "\n".join(lines)


def main():
    if len(sys.argv) != 2:
        print("usage: python run_pipeline.py <apk>", file=sys.stderr)
        sys.exit(1)
    apk_path = sys.argv[1]

    OUT_DIR.mkdir(exist_ok=True)

    t0 = time.perf_counter()
    features = analyze_apk(apk_path)
    t_static = time.perf_counter() - t0

    t0 = time.perf_counter()
    report = generate_report(features)
    t_rag = time.perf_counter() - t0

    t0 = time.perf_counter()
    rule = generate_yara(features, report)
    t_yara = time.perf_counter() - t0

    pkg = features["package_name"]
    (OUT_DIR / f"{pkg}.features.json").write_text(json.dumps(features, indent=2))
    (OUT_DIR / f"{pkg}.report.json").write_text(json.dumps(report, indent=2))
    (OUT_DIR / f"{pkg}.report.md").write_text(_render_markdown(features, report))

    rule_written = rule is not None
    if rule_written:
        (OUT_DIR / f"{pkg}.yar").write_text(rule)
    else:
        print("no YARA rule generated", file=sys.stderr)

    print(
        f"[{pkg}] verdict={report['verdict']} confidence={report['confidence']:.2f} "
        f"rule_written={rule_written} | "
        f"static={t_static:.2f}s rag={t_rag:.2f}s yara={t_yara:.2f}s"
    )


if __name__ == "__main__":
    main()
