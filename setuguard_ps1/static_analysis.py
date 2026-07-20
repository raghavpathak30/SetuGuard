"""SetuGuard PS1 — Stage 1: static feature extraction.

CLI: python static_analysis.py <apk> [-o feat.json]
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from loguru import logger
# androguard 4.1.4 logs XREF resolution at DEBUG via loguru, not stdlib logging.
# The stdlib "logging.getLogger('androguard').setLevel(WARNING)" trick is a no-op on 4.x.
logger.disable("androguard")

from androguard.misc import AnalyzeAPK

# ============================== SETTINGS ==============================

MANIFEST_NS = "{http://schemas.android.com/apk/res/android}"

DANGEROUS_PERMISSIONS = {
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.WRITE_SETTINGS",
}

# category -> [(class_regex, method_regex, mitre_id), ...]
# Matched against androguard's dx.find_methods(classname=..., methodname=...).
# A match only counts if list(m.get_xref_from()) is non-empty (actually called).
SUSPICIOUS_API_CATALOG = {
    # Constructor call = the app instantiates a classloader; that's the signal,
    # not every inherited method (toString/equals/etc.) on the class.
    "dynamic_code_loading": [
        (r"Ldalvik/system/(?:DexClassLoader|PathClassLoader|BaseDexClassLoader);", r"<init>", "T1407"),
    ],
    # WEAK signal by design — reflection is heavily used by benign frameworks too.
    "reflection": [
        (r"Ljava/lang/reflect/Method;", r"invoke", "T1406"),
        (r"Ljava/lang/Class;", r"forName", "T1406"),
    ],
    "sms_control": [
        (r"Landroid/telephony/SmsManager;", r"sendTextMessage|sendMultipartTextMessage", "T1582"),
    ],
    "device_admin": [
        (r"Landroid/app/admin/DevicePolicyManager;", r"lockNow|wipeData", "T1626"),
    ],
    "installed_app_discovery": [
        (r"Landroid/content/pm/PackageManager;", r"getInstalledPackages|getInstalledApplications", "T1418"),
    ],
    "device_fingerprinting": [
        (r"Landroid/telephony/TelephonyManager;", r"getDeviceId|getImei|getSubscriberId", "T1426"),
    ],
    "runtime_exec": [
        (r"Ljava/lang/Runtime;", r"exec", "T1623"),
    ],
    # Dual-use — report for context, don't auto-flag as malicious downstream.
    "crypto_usage": [
        (r"Ljavax/crypto/Cipher;", r"doFinal", "T1521"),
        (r"Ljavax/crypto/spec/SecretKeySpec;", r"<init>", "T1521"),
    ],
}

# Accessibility abuse is deliberately NOT dx-matched: AccessibilityEvent methods
# fire on benign apps too (verified: benign hello-world fired 23 accessibility
# hits, 41 reflection hits). Detected from the manifest instead.
ACCESSIBILITY_PERMISSION = "android.permission.BIND_ACCESSIBILITY_SERVICE"
ACCESSIBILITY_SERVICE_ACTION = "android.accessibilityservice.AccessibilityService"
ACCESSIBILITY_MITRE = "T1417.001"

STRING_PATTERNS = {
    "url": re.compile(r"https?://[^\s\"']{4,}"),
    "ip": re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"),
    "shell": re.compile(r"/system/(?:x)?bin/|\bsu\b|chmod\s+777|mount\s+-o"),
}
MAX_SUSPICIOUS_STRINGS = 25

# ========================================================================


def _resolve_component_name(name, package_name):
    """Android allows manifest component names like '.MainActivity' as shorthand
    for '<package>.MainActivity'. Expand it so the report is unambiguous."""
    if name and name.startswith("."):
        return package_name + name
    return name


def _extract_exported_components(manifest, package_name):
    """Returns (exported_components[], accessibility_service_names[])."""
    exported_components = []
    accessibility_service_names = []

    for comp_type in ("activity", "service", "receiver", "provider"):
        for node in manifest.iter(comp_type):
            name = _resolve_component_name(node.get(MANIFEST_NS + "name"), package_name)
            exported_attr = node.get(MANIFEST_NS + "exported")
            intent_filters = node.findall("intent-filter")

            actions = []
            for itf in intent_filters:
                for action in itf.findall("action"):
                    action_name = action.get(MANIFEST_NS + "name")
                    if action_name:
                        actions.append(action_name)

            if exported_attr == "true":
                exported = True
            elif exported_attr == "false":
                exported = False
            elif comp_type == "provider":
                # Spec simplification: absent attribute -> provider treated as not exported.
                exported = False
            else:
                # activity/service/receiver: absent attribute defaults to exported
                # iff the component declares at least one intent-filter.
                exported = len(intent_filters) > 0

            if exported:
                exported_components.append({
                    "type": comp_type,
                    "name": name,
                    "intent_actions": actions,
                })

            if comp_type == "service" and ACCESSIBILITY_SERVICE_ACTION in actions:
                accessibility_service_names.append(name)

    return exported_components, accessibility_service_names


def _extract_suspicious_apis(dx):
    suspicious_apis = []
    for category, specs in SUSPICIOUS_API_CATALOG.items():
        for class_regex, method_regex, mitre in specs:
            for m in dx.find_methods(classname=class_regex, methodname=method_regex):
                if not list(m.get_xref_from()):
                    continue
                suspicious_apis.append({
                    "category": category,
                    "class": m.class_name,
                    "method": m.name,
                    "call_count": len(list(m.get_xref_from())),
                    "mitre": mitre,
                })
    return suspicious_apis


def _extract_suspicious_strings(dx):
    suspicious_strings = []
    seen_values = set()
    for kind, pattern in STRING_PATTERNS.items():
        if len(suspicious_strings) >= MAX_SUSPICIOUS_STRINGS:
            break
        for s in dx.find_strings(pattern.pattern):
            value = s.get_value()
            if value in seen_values:
                continue
            seen_values.add(value)
            suspicious_strings.append({"kind": kind, "value": value})
            if len(suspicious_strings) >= MAX_SUSPICIOUS_STRINGS:
                break
    return suspicious_strings


def _extract_certificate(a):
    certs = a.get_certificates()
    # Multi-signer APKs exist but are rare; take the first signer as representative.
    # No certificate at all (unsigned) is an edge case seen in some malformed/test
    # samples, so this is guarded rather than assumed to always exist.
    if not certs:
        return {
            "subject": None,
            "issuer": None,
            "sha256": None,
            "self_signed": False,
            "is_debug": False,
        }
    cert = certs[0]
    subject = cert.subject.human_friendly
    issuer = cert.issuer.human_friendly
    return {
        "subject": subject,
        "issuer": issuer,
        "sha256": cert.sha256.hex(),
        "self_signed": subject == issuer,
        # Heuristic: stock Android debug certs use the well-known "Android Debug" CN.
        "is_debug": "Android Debug" in subject,
    }


def analyze_apk(apk_path: str) -> dict:
    a, d, dx = AnalyzeAPK(apk_path)

    package_name = a.get_package()
    permissions = a.get_permissions()
    manifest = a.get_android_manifest_xml()

    exported_components, accessibility_service_names = _extract_exported_components(manifest, package_name)

    suspicious_apis = _extract_suspicious_apis(dx)

    # Synthetic accessibility-abuse entry, flows downstream like any other suspicious_apis row.
    if ACCESSIBILITY_PERMISSION in permissions or accessibility_service_names:
        targets = accessibility_service_names or [package_name]
        for name in targets:
            suspicious_apis.append({
                "category": "accessibility_service",
                "class": name,
                "method": "<manifest>",
                "call_count": 0,
                "mitre": ACCESSIBILITY_MITRE,
            })

    suspicious_strings = _extract_suspicious_strings(dx)
    certificate = _extract_certificate(a)

    sha256 = hashlib.sha256(Path(apk_path).read_bytes()).hexdigest()

    return {
        "apk_path": str(apk_path),
        "sha256": sha256,
        "package_name": package_name,
        "app_name": a.get_app_name(),
        "target_sdk": str(a.get_target_sdk_version()),
        "permissions": permissions,
        "dangerous_permissions": sorted(set(permissions) & DANGEROUS_PERMISSIONS),
        "exported_components": exported_components,
        "suspicious_apis": suspicious_apis,
        "suspicious_strings": suspicious_strings,
        "certificate": certificate,
    }


def main():
    parser = argparse.ArgumentParser(description="SetuGuard PS1 static feature extraction")
    parser.add_argument("apk", help="Path to the APK file")
    parser.add_argument("-o", "--output", help="Write feature JSON here instead of stdout")
    args = parser.parse_args()

    features = analyze_apk(args.apk)
    output = json.dumps(features, indent=2)

    if args.output:
        Path(args.output).write_text(output)
        print(f"Wrote {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
