"""
SetuGuard Bridge — Fix #1: Confusion Matrix Validation of the IOC Matcher
============================================================================
v2 — revised per Raghav's code review (2026-08):
  - Now calls the REAL match_account_to_apk() from matcher.py directly,
    instead of reimplementing the match logic inline. The confusion matrix
    now proves the actual shipped matcher works, not a duplicated copy.
  - Ground truth for true positives is now a hardcoded literal, not read
    from the same apk_ioc dict being compared against — avoids a trivially-
    true-by-construction test.
  - Added true positives that match via C2 host (previously only cert_hash
    was ever exercised as a genuine positive match).
  - Added two new negative-set edge cases: an unsigned APK (no certificate
    at all) and an account with every linkage field set to None.

Usage:
    python confusion_matrix_validation.py
"""

import json
import random
from sklearn.metrics import confusion_matrix

from matcher import extract_ioc_from_ps1, match_account_to_apk, load_ps2_accounts

SCRIPT_VERSION = "v2 (post code-review: real matcher call, independent ground truth, C2 TPs, edge cases)"

RANDOM_SEED = 42
N_TRUE_POSITIVE_CERT = 6
N_TRUE_POSITIVE_C2 = 4
N_CONFOUNDER_SUBNET = 10
N_CONFOUNDER_WRONG_HASH = 10
N_TRUE_NEGATIVE = 68
N_EDGE_CASE_UNSIGNED_APK = 1
N_EDGE_CASE_ALL_NONE = 1
# total = 6 + 4 + 10 + 10 + 68 + 1 + 1 = 100

# ---------------------------------------------------------------------------
# STEP 1: Reference APK — the real analyzed sample Raghav sent.
# Ground-truth "known good" values are HARDCODED here as independent
# literals (not read from apk_ioc at match time), per Raghav's point that
# comparing a value against itself trivializes the test.
# ---------------------------------------------------------------------------

REFERENCE_APK_ANALYSIS = {
    "sha256": "007556ca146f4b2e9ac6bd51dc66be5130538d514f5aa04d60c1a0b079585ef3",
    "package_name": "duyskab.txtxorxqlni.nflfnauti",
    "certificate": {
        "sha256": "d6e80c1de6423814bb8b8e4de46d9eb84d7eaa5cadfd5c8116918e4922e070d6",
        "issuer": "Common Name: Tgqyu Fcpxaawf, Organizational Unit: Xkbzkqbkg, Organization: Nnckkvcub, Locality: Dgfob, State/Province: Lopyut, Country: US",
        "subject": None,
        "self_signed": True,
        "is_debug": False,
    },
    "suspicious_strings": [{"kind": "ip", "value": "185.44.22.10"}],
    "suspicious_apis": [
        {"category": "reflection", "class": "Ljava/lang/reflect/Method;", "method": "invoke", "call_count": 15, "mitre": "T1406"},
        {"category": "sms_control", "class": "Landroid/telephony/SmsManager;", "method": "sendMultipartTextMessage", "call_count": 1, "mitre": "T1582"},
        {"category": "device_fingerprinting", "class": "Landroid/telephony/TelephonyManager;", "method": "getDeviceId", "call_count": 1, "mitre": "T1426"},
    ],
}

# Independent literals — typed by hand, matching what we know the real APK
# analysis produces, but NOT read from REFERENCE_APK_ANALYSIS/apk_ioc at
# ground-truth-construction time. This is what makes the test non-trivial.
KNOWN_GOOD_CERT_HASH = "d6e80c1de6423814bb8b8e4de46d9eb84d7eaa5cadfd5c8116918e4922e070d6"
KNOWN_GOOD_C2_HOST = "185.44.22.10"

# An "unsigned APK" analysis — certificate block present but with no sha256
# at all (e.g. androguard couldn't extract a cert, or the APK is genuinely
# unsigned). Tests that match_account_to_apk's guard against apk_cert=None
# actually holds.
UNSIGNED_APK_ANALYSIS = {
    "sha256": "deadbeef00000000000000000000000000000000000000000000000000000",
    "package_name": "com.example.unsigned_test",
    "certificate": {"sha256": None, "issuer": None, "subject": None, "self_signed": False, "is_debug": False},
    "suspicious_strings": [],
    "suspicious_apis": [],
}

unsigned_apk_ioc = extract_ioc_from_ps1(UNSIGNED_APK_ANALYSIS)
result = match_account_to_apk(
    "UNSIGNED_TEST_ACCOUNT", unsigned_apk_ioc,
    ground_truth={"UNSIGNED_TEST_ACCOUNT": {"cert_hash": None, "c2_host": None}}
)
print("Unsigned APK vs empty account — should be None:", result)

# ---------------------------------------------------------------------------
# STEP 2: Build the synthetic ground-truth set on real PS2 account IDs
# ---------------------------------------------------------------------------

def build_synthetic_ground_truth(real_accounts: list) -> dict:
    random.seed(RANDOM_SEED)
    account_ids = [acc["account_id_raw"] for acc in real_accounts]
    random.shuffle(account_ids)

    ground_truth = {}
    idx = 0

    # --- TRUE POSITIVES via cert_hash ---
    for _ in range(N_TRUE_POSITIVE_CERT):
        acc_id = account_ids[idx]; idx += 1
        ground_truth[acc_id] = {
            "linked_cert_hash": KNOWN_GOOD_CERT_HASH,
            "linked_c2_host": None,
            "true_label": "TP_CERT",
        }

    # --- TRUE POSITIVES via C2 host (previously untested path) ---
    for _ in range(N_TRUE_POSITIVE_C2):
        acc_id = account_ids[idx]; idx += 1
        ground_truth[acc_id] = {
            "linked_cert_hash": None,
            "linked_c2_host": KNOWN_GOOD_C2_HOST,
            "true_label": "TP_C2",
        }

    # --- CONFOUNDER: same /24 subnet, different IP ---
    subnet_prefix = ".".join(KNOWN_GOOD_C2_HOST.split(".")[:3])
    for _ in range(N_CONFOUNDER_SUBNET):
        acc_id = account_ids[idx]; idx += 1
        near_miss_ip = f"{subnet_prefix}.{random.randint(100, 250)}"
        ground_truth[acc_id] = {
            "linked_cert_hash": None,
            "linked_c2_host": near_miss_ip,
            "true_label": "CONFOUNDER_SUBNET",
        }

    # --- CONFOUNDER: same cert issuer, different hash ---
    for i in range(N_CONFOUNDER_WRONG_HASH):
        acc_id = account_ids[idx]; idx += 1
        ground_truth[acc_id] = {
            "linked_cert_hash": f"decoyhash{i:04d}" + "0" * 48,
            "linked_c2_host": None,
            "true_label": "CONFOUNDER_WRONG_HASH",
        }

    # --- EDGE CASE: all-None account (zero linkage fields set at all) ---
    for _ in range(N_EDGE_CASE_ALL_NONE):
        acc_id = account_ids[idx]; idx += 1
        ground_truth[acc_id] = {
            "linked_cert_hash": None,
            "linked_c2_host": None,
            "true_label": "EDGE_ALL_NONE",
        }

    # --- TRUE NEGATIVES ---
    for _ in range(N_TRUE_NEGATIVE):
        acc_id = account_ids[idx]; idx += 1
        ground_truth[acc_id] = {
            "linked_cert_hash": None,
            "linked_c2_host": None,
            "true_label": "TN",
        }

    return ground_truth


# ---------------------------------------------------------------------------
# STEP 3: Run the REAL matcher (imported, not reimplemented) across every
# account, including one unsigned-APK-vs-account pairing as an extra edge case.
# ---------------------------------------------------------------------------

def run_matcher(ground_truth: dict, apk_ioc: dict, unsigned_apk_ioc: dict) -> list:
    results = []

    for acc_id, gt in ground_truth.items():
        local_ground_truth = {
            acc_id: {"cert_hash": gt["linked_cert_hash"], "c2_host": gt["linked_c2_host"]}
        }
        result = match_account_to_apk(acc_id, apk_ioc, ground_truth=local_ground_truth)
        should_link = gt["true_label"] in ("TP_CERT", "TP_C2")

        results.append({
            "account_id": acc_id,
            "true_label": gt["true_label"],
            "ground_truth_should_link": should_link,
            "matcher_predicted_link": result is not None,
            "matched_on": result["matched_on"] if result else None,
        })

    # Extra edge case: pair the EDGE_ALL_NONE-style account against the
    # UNSIGNED APK specifically (both sides have no usable cert) —
    # this must never match, and specifically exercises apk_cert=None.
    unsigned_test_account_id = "UNSIGNED_APK_EDGE_TEST"
    local_ground_truth = {unsigned_test_account_id: {"cert_hash": None, "c2_host": None}}
    result = match_account_to_apk(unsigned_test_account_id, unsigned_apk_ioc, ground_truth=local_ground_truth)
    results.append({
        "account_id": unsigned_test_account_id,
        "true_label": "EDGE_UNSIGNED_APK",
        "ground_truth_should_link": False,
        "matcher_predicted_link": result is not None,
        "matched_on": result["matched_on"] if result else None,
    })

    return results


# ---------------------------------------------------------------------------
# STEP 4: Score with a confusion matrix
# ---------------------------------------------------------------------------

def score_results(results: list):
    y_true = [1 if r["ground_truth_should_link"] else 0 for r in results]
    y_pred = [1 if r["matcher_predicted_link"] else 0 for r in results]

    cm = confusion_matrix(y_true, y_pred, labels=[1, 0])
    tp, fn = cm[0]
    fp, tn = cm[1]

    print("\n" + "=" * 60)
    print(f"CONFUSION MATRIX — Bridge IOC Matcher (Fix #1, {SCRIPT_VERSION})")
    print("=" * 60)
    print(f"{'':20}{'Predicted LINK':>18}{'Predicted ABSTAIN':>20}")
    print(f"{'Actual: should link':20}{tp:>18}{fn:>20}")
    print(f"{'Actual: should NOT':20}{fp:>18}{tn:>20}")
    print("=" * 60)
    print(f"TP: {tp}  FN: {fn}  FP: {fp} (critical cell)  TN: {tn}")

    for label in ("TP_CERT", "TP_C2", "CONFOUNDER_SUBNET", "CONFOUNDER_WRONG_HASH", "EDGE_ALL_NONE", "EDGE_UNSIGNED_APK"):
        subset = [r for r in results if r["true_label"] == label]
        if not subset:
            continue
        wrongly_linked = sum(1 for r in subset if r["matcher_predicted_link"] and label not in ("TP_CERT", "TP_C2"))
        correctly_linked = sum(1 for r in subset if r["matcher_predicted_link"] and label in ("TP_CERT", "TP_C2"))
        print(f"  {label:24} n={len(subset):3}  "
              f"{'correct link: ' + str(correctly_linked) if label in ('TP_CERT','TP_C2') else 'wrongly linked: ' + str(wrongly_linked)}")

    return {"tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn)}


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"Script version: {SCRIPT_VERSION}")

    print("Loading real PS2 accounts...")
    real_accounts = load_ps2_accounts("test_fixtures_ps2_sample.json")
    print(f"Loaded {len(real_accounts)} real accounts.")

    print("\nExtracting IOC from reference APK...")
    apk_ioc = extract_ioc_from_ps1(REFERENCE_APK_ANALYSIS)
    UNSIGNED_APK_ANALYSIS = {
    "sha256": "deadbeef00000000000000000000000000000000000000000000000000000",
    "package_name": "com.example.unsigned_test",
    "certificate": {"sha256": None, "issuer": None, "subject": None, "self_signed": False, "is_debug": False},
    "suspicious_strings": [],
    "suspicious_apis": [],
    }
    unsigned_apk_ioc = extract_ioc_from_ps1(UNSIGNED_APK_ANALYSIS)
    print("Reference APK IOC:", apk_ioc)

    print("\nBuilding synthetic ground truth...")
    ground_truth = build_synthetic_ground_truth(real_accounts)

    print(f"\nRunning matcher (real match_account_to_apk) across {len(ground_truth)} accounts...")
    results = run_matcher(ground_truth, apk_ioc, unsigned_apk_ioc)

    scores = score_results(results)

    output = {
        "script_version": SCRIPT_VERSION,
        "scores": scores,
        "results": results,
    }
    output_path = "fix1_confusion_matrix_results.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nSaved full results to {output_path}")