"""
SetuGuard Bridge — matcher.py
=================================================================
The core Bridge matching logic: connects PS1's extracted APK IOCs
to PS2's scored accounts, via synthetic ground-truth linkage
(no real device/KYC join key exists in the competition dataset —
see PDF Page 8 for why this is the honest, correctly-scoped approach).

Revised per code review (Raghav, 2026-08): explicit None-guards on
BOTH sides of every comparison, so an unsigned APK or an account
with no linkage data can never accidentally "match" on emptiness.
"""

import json


# ---------------------------------------------------------------------------
# STEP 1: Parse real PS1 output (from analyze_apk()) into a flat IOC dict
# ---------------------------------------------------------------------------

def extract_ioc_from_ps1(apk_analysis: dict) -> dict:
    """
    Takes PS1's raw analyze_apk() output (nested dict/list schema) and
    extracts a clean, flat set of fields the matcher actually needs.
    """
    cert = apk_analysis.get("certificate", {}) or {}

    # C2 hosts aren't a flat field — they're buried inside suspicious_strings
    # as {"kind": "ip"/"url"/"shell", "value": "..."}. Pull out IP/URL candidates.
    suspicious_strings = apk_analysis.get("suspicious_strings", [])
    candidate_c2_hosts = [
        s["value"] for s in suspicious_strings
        if s.get("kind") in ("ip", "url")
    ]

    # MITRE-mapped behaviors — static/rule-based tagging from suspicious_apis,
    # NOT from the RAG/LLM report stage (confirmed with Raghav) — safe to use.
    mitre_behaviors = [
        api.get("mitre") for api in apk_analysis.get("suspicious_apis", [])
        if api.get("mitre")
    ]

    return {
        "apk_sha256": apk_analysis.get("sha256"),
        "cert_hash": cert.get("sha256"),
        "cert_issuer": cert.get("issuer"),
        "c2_hosts": candidate_c2_hosts,
        "target_package": apk_analysis.get("package_name"),
        "mitre_behaviors": mitre_behaviors,
        # family/severity: not produced by static_analysis.py. The RAG report
        # stage produces "verdict"/"confidence" instead, and per Raghav's
        # flag, verdict is currently unreliable (100% "suspicious" so far) —
        # deliberately NOT consumed here.
        "family": apk_analysis.get("family"),
        "severity": apk_analysis.get("severity"),
    }


# ---------------------------------------------------------------------------
# STEP 2: The synthetic linkage layer — since no real PS2 account carries
# any device/cert field, this dict stands in for what a real KYC/device
# join would eventually provide (PDF Page 8's honestly-scoped limitation).
# ---------------------------------------------------------------------------

SYNTHETIC_LINKAGE_GROUND_TRUTH = {
    "9072": {
        "cert_hash": "d6e80c1de6423814bb8b8e4de46d9eb84d7eaa5cadfd5c8116918e4922e070d6",
        "c2_host": None,
    },
}


# ---------------------------------------------------------------------------
# STEP 3: The matcher — exact-match only, explicit guards on BOTH sides
# ---------------------------------------------------------------------------

def match_account_to_apk(account_id: str, apk_ioc: dict, ground_truth=SYNTHETIC_LINKAGE_GROUND_TRUTH):
    linked = ground_truth.get(account_id, {})

    linked_cert = linked.get("cert_hash")
    linked_c2 = linked.get("c2_host")
    apk_cert = apk_ioc.get("cert_hash")
    apk_c2_hosts = apk_ioc.get("c2_hosts") or []  # defensive: None or missing -> []

    # Guard BOTH sides explicitly. An unsigned APK (apk_cert is None) or an
    # account with no linkage (linked_cert is None) must never accidentally
    # "match" just because both happen to be empty — None == None is True
    # in Python, so this guard is what prevents that false match.
    cert_match = (
        linked_cert is not None
        and apk_cert is not None
        and linked_cert == apk_cert
    )
    c2_match = (
        linked_c2 is not None
        and len(apk_c2_hosts) > 0
        and linked_c2 in apk_c2_hosts
    )

    if cert_match or c2_match:
        return {
            "account_id": account_id,
            "linked_apk": apk_ioc.get("apk_sha256"),
            "family": apk_ioc.get("family"),
            "severity": apk_ioc.get("severity"),
            "matched_on": "cert_hash" if cert_match else "c2_host",
        }
    return None


# ---------------------------------------------------------------------------
# STEP 4: Load real PS2 accounts from Tanishka's actual export
# ---------------------------------------------------------------------------

def load_ps2_accounts(bridge_payload_path: str):
    with open(bridge_payload_path) as f:
        payload = json.load(f)
    return payload["records"]


# ---------------------------------------------------------------------------
# MAIN — quick smoke test against real PS1 + real PS2 data at real scale
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    real_ps1_output = {
        "sha256": "007556ca146f4b2e9ac6bd51dc66be5130538d514f5aa04d60c1a0b079585ef3",
        "package_name": "duyskab.txtxorxqlni.nflfnauti",
        "certificate": {
            "sha256": "d6e80c1de6423814bb8b8e4de46d9eb84d7eaa5cadfd5c8116918e4922e070d6",
            "issuer": "Common Name: Tgqyu Fcpxaawf, Organizational Unit: Xkbzkqbkg, Organization: Nnckkvcub, Locality: Dgfob, State/Province: Lopyut, Country: US",
            "subject": None,
            "self_signed": True,
            "is_debug": False,
        },
        "suspicious_strings": [],  # real: this sample had none detected
        "suspicious_apis": [
            {"category": "reflection", "class": "Ljava/lang/reflect/Method;", "method": "invoke", "call_count": 15, "mitre": "T1406"},
            {"category": "sms_control", "class": "Landroid/telephony/SmsManager;", "method": "sendMultipartTextMessage", "call_count": 1, "mitre": "T1582"},
            {"category": "device_fingerprinting", "class": "Landroid/telephony/TelephonyManager;", "method": "getDeviceId", "call_count": 1, "mitre": "T1426"},
        ],
    }

    apk_ioc = extract_ioc_from_ps1(real_ps1_output)
    print("Extracted (REAL) PS1 IOC:", apk_ioc)

    accounts = load_ps2_accounts("test_fixtures_ps2_sample.json")
    print(f"Testing matcher against {len(accounts)} real accounts...")

    linked_count = 0
    for acc in accounts:
        result = match_account_to_apk(acc["account_id_raw"], apk_ioc)
        if result:
            print("LINKED:", result)
            linked_count += 1

    print(f"\nTotal accounts linked: {linked_count} (expected: 1)")

    # Edge-case smoke test: unsigned APK vs. an account with nothing set —
    # must never accidentally match on emptiness.
    unsigned_apk_analysis = {
        "sha256": "deadbeef00000000000000000000000000000000000000000000000000000",
        "package_name": "com.example.unsigned_test",
        "certificate": {"sha256": None, "issuer": None, "subject": None, "self_signed": False, "is_debug": False},
        "suspicious_strings": [],
        "suspicious_apis": [],
    }
    unsigned_apk_ioc = extract_ioc_from_ps1(unsigned_apk_analysis)
    edge_result = match_account_to_apk(
        "UNSIGNED_TEST_ACCOUNT", unsigned_apk_ioc,
        ground_truth={"UNSIGNED_TEST_ACCOUNT": {"cert_hash": None, "c2_host": None}}
    )
    print("Unsigned APK vs empty account — should be None:", edge_result)