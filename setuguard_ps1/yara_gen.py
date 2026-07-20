"""SetuGuard PS1 — Stage 3: YARA rule generation from static evidence.

CLI: python yara_gen.py <feat.json> <report.json> [-o rule.yar]

CAVEAT (flagged, not silently stubbed): YARA matches raw bytes. Most APK zip
entries (classes.dex, AndroidManifest.xml) are DEFLATE-compressed inside the
.apk container, so a plaintext string here will not literally byte-match
against a raw, untouched .apk file unless the scanning engine is zip-aware
(e.g. unpacks classes.dex/AXML first, as VirusTotal-style multi-file scanners
do). These rules are written assuming the indicator strings are byte-present
in *decompressed* DEX/AXML content, per the spec's stated assumption — not
guaranteed against a raw compressed .apk on disk.
"""
import argparse
import json
import math
import re
import sys
from pathlib import Path

# ============================== SETTINGS ==============================

GENERATED_BY = "SetuGuard-PS1"

# ========================================================================


def _sanitize_identifier(name: str) -> str:
    ident = re.sub(r"[^A-Za-z0-9_]", "_", name or "")
    if not ident or ident[0].isdigit():
        ident = "_" + ident
    return ident


def _yara_escape(value: str) -> str:
    # Strip embedded newlines (YARA string literals must be single-line) and
    # escape backslash/quote so the literal is valid inside a "..." string.
    value = value.replace("\n", " ").replace("\r", " ")
    return value.replace("\\", "\\\\").replace('"', '\\"')


def generate_yara(features: dict, report: dict) -> str | None:
    # Spec's function signature is written as generate_yara(features, verdict),
    # but the required meta also includes confidence, which only lives in
    # report.json — so this takes the whole report dict (verdict+confidence
    # together) rather than just the verdict string. The CLI loads both files
    # anyway.
    verdict = report["verdict"]
    confidence = report["confidence"]

    # "Benign apps don't yield malware rules" is a hard invariant, not just an
    # incidental side effect of low indicator counts: a genuinely benign app
    # can still rack up >=2 indicators (e.g. READ_PHONE_STATE to pause audio
    # on a call + a GitHub URL + RECEIVE_BOOT_COMPLETED), so the verdict must
    # gate rule emission directly rather than relying on the count threshold
    # alone.
    if verdict == "benign":
        return None

    indicators = []  # list of (var_name, yara_string_value, modifiers)

    # Dangerous permission strings — plaintext in the AXML string pool.
    for i, perm in enumerate(features.get("dangerous_permissions", [])):
        indicators.append((f"indicator_perm_{i}", _yara_escape(perm), "ascii wide"))

    # Suspicious API class descriptors (DEX string pool) — class only, NOT the
    # "Lcls;->method" arrow form, and deduped since multiple methods can share
    # a class.
    seen_classes = set()
    api_i = 0
    for api in features.get("suspicious_apis", []):
        cls = api["class"]
        if cls in seen_classes or cls == "<manifest>":
            continue
        seen_classes.add(cls)
        indicators.append((f"indicator_api_{api_i}", _yara_escape(cls), "ascii"))
        api_i += 1

    # Suspicious strings (url/ip/shell), already capped at 25 upstream.
    for i, s in enumerate(features.get("suspicious_strings", [])):
        indicators.append((f"indicator_str_{i}", _yara_escape(s["value"]), "ascii wide"))

    if len(indicators) < 2:
        return None

    n_required = max(2, math.ceil(0.6 * len(indicators)))

    rule_name = f"SetuGuard_{_sanitize_identifier(features['package_name'])}"

    lines = [f"rule {rule_name}", "{", "    meta:"]
    lines.append(f'        package = "{features["package_name"]}"')
    lines.append(f'        sha256 = "{features["sha256"]}"')
    lines.append(f'        verdict = "{verdict}"')
    lines.append(f'        confidence = "{confidence}"')
    lines.append(f'        generated_by = "{GENERATED_BY}"')
    lines.append("    strings:")
    for var_name, value, modifiers in indicators:
        lines.append(f'        ${var_name} = "{value}" {modifiers}')
    lines.append("    condition:")
    lines.append(f"        uint32(0) == 0x04034b50 and {n_required} of ($indicator*)")
    lines.append("}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="SetuGuard PS1 YARA rule generation")
    parser.add_argument("feat_json", help="Path to feature JSON produced by static_analysis.py")
    parser.add_argument("report_json", help="Path to report JSON produced by rag_report.py")
    parser.add_argument("-o", "--output", help="Write the .yar rule here instead of stdout")
    args = parser.parse_args()

    features = json.loads(Path(args.feat_json).read_text())
    report = json.loads(Path(args.report_json).read_text())

    rule = generate_yara(features, report)

    if rule is None:
        print("no YARA rule generated (fewer than 2 indicators)", file=sys.stderr)
        return

    if args.output:
        Path(args.output).write_text(rule)
        print(f"Wrote {args.output}", file=sys.stderr)
    else:
        print(rule)


if __name__ == "__main__":
    main()
