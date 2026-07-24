import pandas as pd

# Fake PS1 output (stand-in until your teammate's real pipeline exists)
fake_apk_iocs = {
    "apk_sha256": "9b2c...77",
    "cert_hash": "abc123...",
    "cert_issuer": "TrustedCA-Ltd",
    "c2_host": "185.44.22.10",
    "device_fingerprint": "Android11_Pixel4_Generic",
    "target_package": "com.boi.boiapp",
    "family": "SharkBot-variant",
    "severity": "CRITICAL"
}

# Fake PS2 output (stand-in until your teammate's real pipeline exists)
fake_accounts = pd.DataFrame([
    {"account_id": "a3f9...e21", "tier": "T3", "score": 0.71,
     "linked_cert_hash": "abc123...", "linked_c2_host": "185.44.22.10"},
    {"account_id": "b7d2...11", "tier": "T2", "score": 0.40,
     "linked_cert_hash": None, "linked_c2_host": None},
])

# Near-miss confounder: same /24 subnet as the real C2 host, but not identical
confounder_account = pd.DataFrame([
    {"account_id": "c9f1...44", "tier": "T2", "score": 0.35,
     "linked_cert_hash": None, "linked_c2_host": "185.44.22.187"},  # same subnet, different last octet
])

# Confounder 2: same cert *issuer*, but a different cert *hash*
cert_issuer_confounder = pd.DataFrame([
    {"account_id": "d4e8...92", "tier": "T2", "score": 0.30,
     "linked_cert_hash": "xyz999...",       # different hash — this is a DIFFERENT cert
     "linked_cert_issuer": "TrustedCA-Ltd", # same issuer as the real IOC
     "linked_c2_host": None, "linked_device_fingerprint": None},
])

# Confounder 3: shared generic device fingerprint, nothing else matches
device_confounder = pd.DataFrame([
    {"account_id": "e5f2...33", "tier": "T2", "score": 0.28,
     "linked_cert_hash": None, "linked_cert_issuer": None,
     "linked_c2_host": None,
     "linked_device_fingerprint": "Android11_Pixel4_Generic"},  # common device, proves nothing alone
])

fake_accounts = pd.concat([fake_accounts, confounder_account, cert_issuer_confounder, device_confounder], ignore_index=True)

fake_accounts = pd.concat([fake_accounts, confounder_account], ignore_index=True)

# DESIGN NOTE (Fix #1 methodology):
# device_fingerprint is intentionally NOT checked here as a standalone match field.
# It's too generic on its own (many unrelated devices share OS/model strings) —
# it should only ever count as CORROBORATING evidence alongside a cert_hash or
# c2_host match, never as a trigger by itself. If added later, guard it with
# an AND condition, not a bare OR.

def match_account_to_apk(account_row, apk_iocs):
    if account_row["linked_cert_hash"] == apk_iocs["cert_hash"] or \
       account_row["linked_c2_host"] == apk_iocs["c2_host"]:
        return {
            "account": account_row["account_id"],
            "tier": account_row["tier"],
            "linked_apk": apk_iocs["apk_sha256"],
            "family": apk_iocs["family"],
            "severity": apk_iocs["severity"],
        }
    return None

# Run the matcher across every fake account
for _, row in fake_accounts.iterrows():
    result = match_account_to_apk(row, fake_apk_iocs)
    if result:
        print("LINKED:", result)
    else:
        print("No link for account:", row["account_id"])