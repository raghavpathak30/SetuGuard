"""SetuGuard PS1 — model contract for the RAG report stage.

Holds only the prompt/schema contract with the LLM. No pipeline logic lives
here (no ollama calls, no retrieval) — that's rag_report.py's job.
"""

# ============================== SETTINGS ==============================

SYSTEM_PROMPT = (
    "You are a mobile malware triage analyst reviewing static-analysis evidence "
    "for a single Android APK. Reason ONLY from the evidence and the retrieved "
    "MITRE ATT&CK for Mobile / OWASP MASTG context given to you in the user "
    "message. Do not assume anything about the app's behavior that isn't stated "
    "in the evidence or retrieved context, and do not invent APIs, permissions, "
    "or strings that weren't reported. If the evidence is weak, ambiguous, or "
    "largely dual-use, say so explicitly and lower your confidence accordingly "
    "instead of defaulting to a severe verdict. Respond only in the requested "
    "JSON format."
)

REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {
            "type": "string",
            "enum": ["benign", "suspicious", "malicious"],
        },
        "confidence": {
            "type": "number",
            "minimum": 0,
            "maximum": 1,
        },
        "rationale": {
            "type": "string",
        },
        "cited_chunk_ids": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
    "required": ["verdict", "confidence", "rationale", "cited_chunk_ids"],
}

# ========================================================================


def build_user_prompt(features: dict, retrieved_chunks: list) -> str:
    lines = []
    lines.append(f"# APK under review: {features['package_name']} ({features['app_name']})")
    lines.append(f"sha256: {features['sha256']}")
    lines.append(f"target_sdk: {features['target_sdk']}")
    lines.append("")

    lines.append("## Dangerous permissions")
    if features["dangerous_permissions"]:
        for perm in features["dangerous_permissions"]:
            lines.append(f"- {perm}")
    else:
        lines.append("- none")
    lines.append("")

    lines.append("## Exported components (attack surface)")
    if features["exported_components"]:
        for comp in features["exported_components"]:
            actions = ", ".join(comp["intent_actions"]) or "no declared actions"
            lines.append(f"- [{comp['type']}] {comp['name']} — intent actions: {actions}")
    else:
        lines.append("- none exported")
    lines.append("")

    lines.append("## Suspicious API usage (confirmed called, cross-referenced)")
    if features["suspicious_apis"]:
        for api in features["suspicious_apis"]:
            lines.append(
                f"- [{api['category']} / {api['mitre']}] {api['class']} -> {api['method']} "
                f"(call_count={api['call_count']})"
            )
    else:
        lines.append("- none detected")
    lines.append("")

    lines.append("## Suspicious strings (capped)")
    if features["suspicious_strings"]:
        for s in features["suspicious_strings"]:
            lines.append(f"- [{s['kind']}] {s['value']}")
    else:
        lines.append("- none detected")
    lines.append("")

    cert = features["certificate"]
    lines.append("## Signing certificate")
    lines.append(f"- subject: {cert['subject']}")
    lines.append(f"- issuer: {cert['issuer']}")
    lines.append(f"- self_signed: {cert['self_signed']}")
    lines.append(f"- is_debug: {cert['is_debug']}")
    lines.append("")

    lines.append("## Retrieved MITRE ATT&CK / OWASP MASTG context")
    if retrieved_chunks:
        for chunk in retrieved_chunks:
            lines.append(f"- ({chunk['id']} / {chunk['mitre']}) {chunk['title']}: {chunk['text']}")
    else:
        lines.append("- no context retrieved")
    lines.append("")

    lines.append(
        "Based only on the evidence and context above, produce a verdict "
        "(benign/suspicious/malicious), a confidence between 0 and 1, a short "
        "rationale grounded in the specific evidence listed, and the list of "
        "retrieved context chunk ids you actually relied on."
    )

    return "\n".join(lines)
