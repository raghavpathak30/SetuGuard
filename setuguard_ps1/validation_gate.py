"""SetuGuard PS1 — Week-2 validation gate (D4).

NOT one of the six frozen pipeline files (static_analysis.py, knowledge_base.py,
report_prompt.py, rag_report.py, yara_gen.py, run_pipeline.py). Imports
knowledge_base.CHUNKS read-only for ground-truth chunk/MITRE IDs and does not
modify any of the six.

This module VALIDATES ONLY. It never corrects, coerces, or overrides a verdict,
confidence, rationale, or generated rule — it only reports a list of violation
strings. Deciding what to do about a violation (retry generation, reject the
sample, alert a human) is a caller/team decision, not this module's job.

All schema facts below (the 11-key features contract, the suspicious_apis
category/mitre vocab, the exported_components type enum, the suspicious_strings
kind enum, the REPORT_SCHEMA verdict enum) are read directly from
static_analysis.py and report_prompt.py source at the time this file was
written (Week 2), not copied from CONTEXT.md prose. If the source changes,
re-derive — do not hand-edit these constants from memory.

CLI: python3 validation_gate.py <features.json> [report.json] [rule.yar]
Exits non-zero if any violation is found in whichever of the three checks ran
(features schema always; report grounding if report.json given; indicator
traceability if rule.yar given).
"""
import argparse
import json
import re
import sys
from pathlib import Path

from knowledge_base import CHUNKS

# ============================== SETTINGS ==============================

# Derived from static_analysis.py's `return {...}` in analyze_apk() — the 11
# frozen top-level keys and their types.
FEATURES_TOP_LEVEL_SCHEMA = {
    "apk_path": str,
    "sha256": str,
    "package_name": str,
    "app_name": str,
    "target_sdk": str,
    "permissions": list,
    "dangerous_permissions": list,
    "exported_components": list,
    "suspicious_apis": list,
    "suspicious_strings": list,
    "certificate": dict,
}

# Derived from static_analysis.py's SUSPICIOUS_API_CATALOG keys plus the
# synthetic "accessibility_service" category added in analyze_apk().
SUSPICIOUS_API_CATEGORIES = {
    "dynamic_code_loading", "reflection", "sms_control", "device_admin",
    "installed_app_discovery", "device_fingerprinting", "runtime_exec",
    "crypto_usage", "accessibility_service",
}
# Derived from the mitre id in each SUSPICIOUS_API_CATALOG tuple plus
# ACCESSIBILITY_MITRE.
SUSPICIOUS_API_MITRE_IDS = {
    "T1407", "T1406", "T1582", "T1626", "T1418", "T1426", "T1623", "T1521",
    "T1417.001",
}
SUSPICIOUS_API_SCHEMA = {"category": str, "class": str, "method": str, "call_count": int, "mitre": str}

# Derived from STRING_PATTERNS keys in static_analysis.py.
SUSPICIOUS_STRING_KINDS = {"url", "ip", "shell"}
SUSPICIOUS_STRING_SCHEMA = {"kind": str, "value": str}

# Derived from the comp_type tuple iterated in _extract_exported_components.
EXPORTED_COMPONENT_TYPES = {"activity", "service", "receiver", "provider"}
EXPORTED_COMPONENT_SCHEMA = {"type": str, "name": str, "intent_actions": list}

CERTIFICATE_SCHEMA = {
    "subject": (str, type(None)),
    "issuer": (str, type(None)),
    "sha256": (str, type(None)),
    "self_signed": bool,
    "is_debug": bool,
}

# Derived from REPORT_SCHEMA in report_prompt.py.
REPORT_VERDICT_ENUM = {"benign", "suspicious", "malicious"}

# Ground truth for the D4 grounding check — every id a chunk can be cited under.
# Confirmed (Phase 0.6): every chunk's "mitre" field equals its "id" field, so
# the legal chunk-id set and legal MITRE-id set are the same 16 strings.
LEGAL_CHUNK_IDS = {c["id"] for c in CHUNKS}
LEGAL_MITRE_IDS = {c["mitre"] for c in CHUNKS}

# ========================================================================


def _check_type(val, expected_type, path, violations):
    if isinstance(expected_type, tuple):
        if not isinstance(val, expected_type) or isinstance(val, bool) and bool not in expected_type:
            violations.append(f"{path}: {val!r} is not one of types {[t.__name__ for t in expected_type]}")
        return
    if expected_type is bool:
        if not isinstance(val, bool):
            violations.append(f"{path}: {val!r} is not bool (type={type(val).__name__})")
        return
    if expected_type is int:
        if not isinstance(val, int) or isinstance(val, bool):
            violations.append(f"{path}: {val!r} is not int (type={type(val).__name__})")
        return
    if not isinstance(val, expected_type):
        violations.append(f"{path}: {val!r} is not {expected_type.__name__} (type={type(val).__name__})")


def validate_features_schema(features: dict) -> list[str]:
    """The 11-key frozen features contract: presence, types, sub-key schemas, enums."""
    violations = []

    if not isinstance(features, dict):
        return [f"features is not a dict (type={type(features).__name__})"]

    keys = set(features.keys())
    expected_keys = set(FEATURES_TOP_LEVEL_SCHEMA.keys())
    if keys != expected_keys:
        missing = expected_keys - keys
        extra = keys - expected_keys
        if missing:
            violations.append(f"features: missing top-level keys {sorted(missing)}")
        if extra:
            violations.append(f"features: unexpected top-level keys {sorted(extra)}")

    for key, expected_type in FEATURES_TOP_LEVEL_SCHEMA.items():
        if key in features:
            _check_type(features[key], expected_type, f"features.{key}", violations)

    for i, api in enumerate(features.get("suspicious_apis", []) or []):
        if not isinstance(api, dict):
            violations.append(f"features.suspicious_apis[{i}] is not a dict")
            continue
        sub_keys = set(api.keys())
        expected_sub = set(SUSPICIOUS_API_SCHEMA.keys())
        if sub_keys != expected_sub:
            violations.append(
                f"features.suspicious_apis[{i}]: key mismatch — got {sorted(sub_keys)}, expected {sorted(expected_sub)}"
            )
        for key, expected_type in SUSPICIOUS_API_SCHEMA.items():
            if key in api:
                _check_type(api[key], expected_type, f"features.suspicious_apis[{i}].{key}", violations)
        if api.get("category") is not None and api["category"] not in SUSPICIOUS_API_CATEGORIES:
            violations.append(
                f"features.suspicious_apis[{i}].category = {api['category']!r} not in known catalog "
                f"{sorted(SUSPICIOUS_API_CATEGORIES)}"
            )
        if api.get("mitre") is not None and api["mitre"] not in SUSPICIOUS_API_MITRE_IDS:
            violations.append(
                f"features.suspicious_apis[{i}].mitre = {api['mitre']!r} not in known catalog "
                f"{sorted(SUSPICIOUS_API_MITRE_IDS)}"
            )

    for i, s in enumerate(features.get("suspicious_strings", []) or []):
        if not isinstance(s, dict):
            violations.append(f"features.suspicious_strings[{i}] is not a dict")
            continue
        sub_keys = set(s.keys())
        expected_sub = set(SUSPICIOUS_STRING_SCHEMA.keys())
        if sub_keys != expected_sub:
            violations.append(
                f"features.suspicious_strings[{i}]: key mismatch — got {sorted(sub_keys)}, expected {sorted(expected_sub)}"
            )
        for key, expected_type in SUSPICIOUS_STRING_SCHEMA.items():
            if key in s:
                _check_type(s[key], expected_type, f"features.suspicious_strings[{i}].{key}", violations)
        if s.get("kind") is not None and s["kind"] not in SUSPICIOUS_STRING_KINDS:
            violations.append(
                f"features.suspicious_strings[{i}].kind = {s['kind']!r} not in {sorted(SUSPICIOUS_STRING_KINDS)}"
            )

    if len(features.get("suspicious_strings", []) or []) > 25:
        violations.append(
            f"features.suspicious_strings has {len(features['suspicious_strings'])} entries, "
            f"exceeds the frozen MAX_SUSPICIOUS_STRINGS=25 cap"
        )

    for i, comp in enumerate(features.get("exported_components", []) or []):
        if not isinstance(comp, dict):
            violations.append(f"features.exported_components[{i}] is not a dict")
            continue
        sub_keys = set(comp.keys())
        expected_sub = set(EXPORTED_COMPONENT_SCHEMA.keys())
        if sub_keys != expected_sub:
            violations.append(
                f"features.exported_components[{i}]: key mismatch — got {sorted(sub_keys)}, expected {sorted(expected_sub)}"
            )
        for key, expected_type in EXPORTED_COMPONENT_SCHEMA.items():
            if key in comp:
                _check_type(comp[key], expected_type, f"features.exported_components[{i}].{key}", violations)
        if comp.get("type") is not None and comp["type"] not in EXPORTED_COMPONENT_TYPES:
            violations.append(
                f"features.exported_components[{i}].type = {comp['type']!r} not in {sorted(EXPORTED_COMPONENT_TYPES)}"
            )

    cert = features.get("certificate")
    if isinstance(cert, dict):
        sub_keys = set(cert.keys())
        expected_sub = set(CERTIFICATE_SCHEMA.keys())
        if sub_keys != expected_sub:
            violations.append(
                f"features.certificate: key mismatch — got {sorted(sub_keys)}, expected {sorted(expected_sub)}"
            )
        for key, expected_type in CERTIFICATE_SCHEMA.items():
            if key in cert:
                _check_type(cert[key], expected_type, f"features.certificate.{key}", violations)
        # Guarded unsigned-APK invariant from _extract_certificate(): if there's
        # no certificate at all, subject/issuer/sha256 are all None together and
        # self_signed/is_debug are both False — never a partial None.
        cert_none_fields = [k for k in ("subject", "issuer", "sha256") if cert.get(k) is None]
        if cert_none_fields and len(cert_none_fields) != 3:
            violations.append(
                f"features.certificate: inconsistent unsigned-cert state — only "
                f"{cert_none_fields} are None, expected all of subject/issuer/sha256 together or none"
            )
        if len(cert_none_fields) == 3 and (cert.get("self_signed") is not False or cert.get("is_debug") is not False):
            violations.append(
                "features.certificate: unsigned (subject/issuer/sha256 all None) but "
                f"self_signed={cert.get('self_signed')!r} / is_debug={cert.get('is_debug')!r}, expected both False"
            )

    try:
        json.dumps(features)
    except TypeError as e:
        violations.append(f"features dict failed json.dumps round-trip: {e}")

    return violations


def validate_report_grounding(features: dict, report: dict) -> list[str]:
    """Sanity + D4 grounding-faithfulness check on a rag_report.py report dict."""
    violations = []

    if not isinstance(report, dict):
        return [f"report is not a dict (type={type(report).__name__})"]

    verdict = report.get("verdict")
    if verdict is None:
        violations.append("report.verdict is missing")
    elif verdict not in REPORT_VERDICT_ENUM:
        violations.append(f"report.verdict = {verdict!r} not in legal enum {sorted(REPORT_VERDICT_ENUM)}")

    confidence = report.get("confidence")
    if confidence is None:
        violations.append("report.confidence is missing")
    elif not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
        violations.append(f"report.confidence = {confidence!r} is not a number")
    elif not (0 <= confidence <= 1):
        violations.append(f"report.confidence = {confidence!r} is outside [0, 1]")

    rationale = report.get("rationale")
    if not isinstance(rationale, str) or not rationale.strip():
        violations.append(f"report.rationale = {rationale!r} is not a non-empty string")

    cited = report.get("cited_chunk_ids")
    if not isinstance(cited, list) or not all(isinstance(c, str) for c in cited):
        violations.append(f"report.cited_chunk_ids = {cited!r} is not a list[str]")
    else:
        for cid in cited:
            if cid not in LEGAL_CHUNK_IDS:
                violations.append(
                    f"report.cited_chunk_ids: {cid!r} does not exist in knowledge_base.CHUNKS "
                    f"(fabricated chunk id — grounding-faithfulness violation)"
                )

    # retrieved_chunk_ids is programmatically added by generate_report(), not
    # model-authored, but a fabricated id there would indicate a bug in
    # rag_report.py's own retrieval, which is still worth catching.
    retrieved = report.get("retrieved_chunk_ids")
    if retrieved is not None:
        if not isinstance(retrieved, list) or not all(isinstance(c, str) for c in retrieved):
            violations.append(f"report.retrieved_chunk_ids = {retrieved!r} is not a list[str]")
        else:
            for cid in retrieved:
                if cid not in LEGAL_CHUNK_IDS:
                    violations.append(
                        f"report.retrieved_chunk_ids: {cid!r} does not exist in knowledge_base.CHUNKS"
                    )

    return violations


_YARA_STRING_LINE = re.compile(r'^\s*\$(?P<name>\w+)\s*=\s*"(?P<value>(?:[^"\\]|\\.)*)"')


def _yara_unescape(value: str) -> str:
    """Reverse yara_gen.py's _yara_escape() (backslash then quote escaping)."""
    out = []
    i = 0
    while i < len(value):
        if value[i] == "\\" and i + 1 < len(value) and value[i + 1] in ("\\", '"'):
            out.append(value[i + 1])
            i += 2
        else:
            out.append(value[i])
            i += 1
    return "".join(out)


def validate_indicator_traceability(features: dict, rule_text: str) -> list[str]:
    """Every $indicator_* string literal in rule_text must trace back to a real
    features field: dangerous_permissions, a suspicious_apis[].class, or a
    suspicious_strings[].value. An indicator with no source would mean a
    hallucinated indicator poisoning the generated YARA rule."""
    violations = []

    if not isinstance(rule_text, str) or not rule_text.strip():
        return ["rule_text is empty or not a string — nothing to validate"]

    source_values = set(features.get("dangerous_permissions", []) or [])
    source_values |= {api.get("class") for api in (features.get("suspicious_apis", []) or []) if isinstance(api, dict)}
    source_values |= {s.get("value") for s in (features.get("suspicious_strings", []) or []) if isinstance(s, dict)}
    source_values.discard(None)

    found_any_indicator = False
    for line in rule_text.splitlines():
        m = _YARA_STRING_LINE.match(line)
        if not m or not m.group("name").startswith("indicator_"):
            continue
        found_any_indicator = True
        name = m.group("name")
        # YARA string literals are single-line by construction (yara_gen.py
        # strips embedded newlines/CRs to a space before escaping), so this
        # unescape is lossless for anything yara_gen.py itself produced.
        value = _yara_unescape(m.group("value"))
        if value not in source_values:
            violations.append(
                f"rule ${name} = {value!r} does not trace to any dangerous_permission, "
                f"suspicious_apis[].class, or suspicious_strings[].value in features "
                f"(hallucinated/untraceable indicator)"
            )

    if not found_any_indicator:
        violations.append("rule_text has no $indicator_* string definitions to validate")

    return violations


def main():
    parser = argparse.ArgumentParser(description="SetuGuard PS1 validation gate (D4)")
    parser.add_argument("features_json", help="Path to features.json produced by static_analysis.py")
    parser.add_argument("report_json", nargs="?", help="Optional path to report.json produced by rag_report.py")
    parser.add_argument("rule_yar", nargs="?", help="Optional path to rule.yar produced by yara_gen.py")
    args = parser.parse_args()

    features = json.loads(Path(args.features_json).read_text())

    all_violations = []
    all_violations.extend(f"[features_schema] {v}" for v in validate_features_schema(features))

    if args.report_json:
        report = json.loads(Path(args.report_json).read_text())
        all_violations.extend(f"[report_grounding] {v}" for v in validate_report_grounding(features, report))

    if args.rule_yar:
        rule_text = Path(args.rule_yar).read_text()
        all_violations.extend(f"[indicator_traceability] {v}" for v in validate_indicator_traceability(features, rule_text))

    if all_violations:
        print(f"{len(all_violations)} violation(s):", file=sys.stderr)
        for v in all_violations:
            print(f"  - {v}", file=sys.stderr)
        sys.exit(1)
    else:
        print("PASS: no violations found", file=sys.stderr)
        sys.exit(0)


if __name__ == "__main__":
    main()
