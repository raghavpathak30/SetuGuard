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

Day 4 (2026-08-21): C2-host matching previously compared raw values —
a "url"-kind indicator carries scheme+host+path, so a hostname-valued
ground-truth entry could never equal it (only a bare "ip"-kind value,
already host-only, ever matched). Both sides now go through
_normalize_host() before comparison, the same one-function-both-sides
discipline as norm_sha() elsewhere in this repo, so this can't drift
into a one-sided-normalization bug.
"""

import json
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Host normalization — applied identically to the candidate C2 host
# extracted from PS1's suspicious_strings AND to the ground-truth c2_host
# value, so the two sides can never silently drift apart (the norm_sha bug
# class: normalizing only one side of a comparison).
# ---------------------------------------------------------------------------

def _normalize_host(value: str, kind: str | None = None) -> str | None:
    """Reduce a candidate or ground-truth C2 value to a bare, comparable host.

    kind == "ip": value is already a bare dotted quad (static_analysis.py's
    IP regex has no port group) — skip URL parsing entirely, since
    urlparse("185.44.22.10").hostname returns None for a schemeless bare IP
    with no "//" prefix, and this path must never regress into a non-match.

    Otherwise (kind == "url", or unspecified for a ground-truth value that
    may itself be a bare hostname): urlparse a "//"-prefixed form so a
    schemeless string still parses into netloc/hostname instead of falling
    through as a path. Falls back to the raw value if urlparse still can't
    produce a hostname (malformed input), rather than dropping the value.
    """
    if not value:
        return None
    raw = value.strip()
    host = None
    if kind != "ip":
        candidate = raw if "//" in raw else f"//{raw}"
        try:
            host = urlparse(candidate).hostname
        except ValueError:
            host = None
    if host is None:
        host = raw
    host = host.strip().rstrip(".").lower()
    if ":" in host and not host.startswith("["):
        host = host.split(":", 1)[0]
    return host


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
    # as {"kind": "ip"/"url"/"shell", "value": "..."}. Pull out IP/URL
    # candidates and normalize each to a bare host (see _normalize_host) so
    # a "url"-kind entry's scheme+path doesn't block a hostname-valued match.
    suspicious_strings = apk_analysis.get("suspicious_strings", [])
    candidate_c2_hosts = [
        h for h in (
            _normalize_host(s["value"], s.get("kind"))
            for s in suspicious_strings
            if s.get("kind") in ("ip", "url")
        )
        if h
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
    # Day 4 (2026-08-21): second entry, one per join key, to demonstrate the
    # C2-host path now that _normalize_host() lets a "url"-kind indicator's
    # extracted hostname match a bare ground-truth hostname. Replaced the
    # original RFC 2606 ".test" placeholder (same day, later session) with a
    # real host: "yessign.net" is extracted by our own static analysis from
    # com.kb (cicmaldroid_banking/30baab7000e14cd4a430c8a4a75ea3cae347a6360e
    # 0b75ae68c503b5e576cb52.apk, a real CICMalDroid banking-malware sample)
    # — 4 suspicious_strings, all "http://yessign.net:8688/..." — so the
    # indicator itself is real, not fabricated. Only the account association
    # (which PS2 account this host links to) remains hand-constructed; no
    # real device<->account join key exists in any source repo, and none is
    # implied here.
    "9062": {
        "cert_hash": None,
        "c2_host": "yessign.net",
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
    # apk_c2_hosts is already normalized (extract_ioc_from_ps1); normalize
    # linked_c2 here so both sides go through _normalize_host() and can't
    # drift apart (one-sided normalization is exactly the norm_sha bug class).
    linked_c2_normalized = _normalize_host(linked_c2) if linked_c2 is not None else None
    c2_match = (
        linked_c2_normalized is not None
        and len(apk_c2_hosts) > 0
        and linked_c2_normalized in apk_c2_hosts
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