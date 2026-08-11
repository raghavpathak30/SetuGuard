"""
Negative test for train_ps2_model.py's leakage guard. NON-FROZEN.

This is the artifact backing the claim "we verified why the bank's
finalized list excludes those features" -- without it that claim is
unsupported.

What this deliberately does NOT test: calling load_dataset() end to end
against a CSV that happens to contain a leaky column. usecols already makes
that structurally impossible -- pandas' usecols filters at read time, so
load_dataset()'s own df.columns can never include a column that isn't in
BANK_FINALIZED_FEATURES + [TARGET_COLUMN], regardless of what the source
CSV contains. Testing that path would only prove usecols works, not that
the guard (assert_no_excluded_features, factored out of load_dataset() for
exactly this reason) actually catches a leaky column when handed one.

So each case below builds a real, in-memory pandas Index/DataFrame that
deliberately DOES contain an excluded column (bypassing usecols entirely --
the guard is called directly, the same function load_dataset() calls
internally, not a reimplementation) and confirms assert_no_excluded_features
raises RuntimeError naming that column, rather than silently dropping it.

Cases:
  1. F3912 (FRAUD_SUSPECTED) -- a post-resolution analyst disposition;
     EXCLUDED_LEAKY_FEATURES.
  2. F3906 (STATUS_CHANGE_AFTER_WD) -- one of the 12 F3900-F3911 "Alert
     description flag" features encoding legacy rule-engine decisions;
     EXCLUDED_ALERT_DERIVED.
  3. F2230 (MNTH) -- separates classes temporally by construction;
     EXCLUDED_ALERT_DERIVED.
  4. Control: BANK_FINALIZED_FEATURES alone (no excluded column) must NOT
     raise -- confirms case 1-3 failures are actually about the excluded
     column, not the guard being trigger-happy.

Usage:
    python3 harness/test_leakage_assert.py
Exits 0 if all cases pass, 1 otherwise. Prints a PASS/FAIL line per case.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from train_ps2_model import (  # noqa: E402
    BANK_FINALIZED_FEATURES,
    EXCLUDED_ALERT_DERIVED,
    EXCLUDED_LEAKY_FEATURES,
    assert_no_excluded_features,
)

CASES = [
    ("F3912 (FRAUD_SUSPECTED, EXCLUDED_LEAKY_FEATURES)", "F3912", True),
    ("F3906 (STATUS_CHANGE_AFTER_WD, EXCLUDED_ALERT_DERIVED)", "F3906", True),
    ("F2230 (MNTH, EXCLUDED_ALERT_DERIVED)", "F2230", True),
    ("control: BANK_FINALIZED_FEATURES only, no excluded column", None, False),
]


def main():
    assert "F3912" in EXCLUDED_LEAKY_FEATURES, "test assumption broken: F3912 not in EXCLUDED_LEAKY_FEATURES"
    assert "F3906" in EXCLUDED_ALERT_DERIVED, "test assumption broken: F3906 not in EXCLUDED_ALERT_DERIVED"
    assert "F2230" in EXCLUDED_ALERT_DERIVED, "test assumption broken: F2230 not in EXCLUDED_ALERT_DERIVED"

    all_passed = True
    for label, extra_col, should_raise in CASES:
        columns = list(BANK_FINALIZED_FEATURES) + ([extra_col] if extra_col else [])
        raised = None
        try:
            assert_no_excluded_features(columns)
        except RuntimeError as e:
            raised = e

        if should_raise:
            ok = raised is not None and extra_col in str(raised)
            detail = f"raised: {raised}" if raised else "did NOT raise (BUG: column would be silently dropped)"
        else:
            ok = raised is None
            detail = "did not raise" if raised is None else f"raised unexpectedly: {raised}"

        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {label} -- {detail}")
        all_passed = all_passed and ok

    if all_passed:
        print("\nALL CASES PASSED -- the guard raises loudly on every excluded feature tested, "
              "and does not raise on a clean BANK_FINALIZED_FEATURES-only column list.")
        sys.exit(0)
    else:
        print("\nFAILURE -- see above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
