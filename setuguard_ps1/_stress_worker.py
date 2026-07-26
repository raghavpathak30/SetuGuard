"""SetuGuard PS1 — subprocess worker for stress_harness.py.

NOT one of the six frozen pipeline files. Invoked by stress_harness.py in a
fresh subprocess per test case so a crash/hang in analyze_apk() is isolated
from the harness itself. Imports and calls static_analysis.analyze_apk() (and,
only with --with-rag, rag_report.generate_report() + yara_gen.generate_yara())
read-only — never edits any of the six.

Always exits 0 and prints exactly one JSON line to stdout describing the
outcome ("success" | "clean_raise" | "dirty"). A genuinely dirty failure
(segfault, OOM kill, uncaught fatal error below Python's own try/except, or a
hang) shows up to the parent as a nonzero exit code or no parseable output at
all — the parent (stress_harness.py) is what classifies those as "dirty",
since a crashed/hung process can't self-report.
"""
import argparse
import json


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    parser.add_argument("--with-rag", action="store_true")
    args = parser.parse_args()

    try:
        from static_analysis import analyze_apk
    except Exception as e:
        print(json.dumps({
            "outcome": "dirty",
            "reason": "import_failure",
            "exception_type": type(e).__name__,
            "exception_message": str(e)[:500],
        }))
        return

    try:
        features = analyze_apk(args.path)
    except Exception as e:
        print(json.dumps({
            "outcome": "clean_raise",
            "stage": "analyze_apk",
            "exception_type": type(e).__name__,
            "exception_message": str(e)[:500],
        }))
        return

    if not isinstance(features, dict) or "package_name" not in features:
        print(json.dumps({
            "outcome": "dirty",
            "reason": "silent_wrong_output",
            "detail": f"analyze_apk returned {type(features).__name__}, not a valid features dict",
        }))
        return

    result = {
        "outcome": "success",
        "stage": "analyze_apk",
        "package_name": features.get("package_name"),
        "num_top_level_keys": len(features.keys()),
        "num_dangerous_permissions": len(features.get("dangerous_permissions", [])),
        "num_suspicious_apis": len(features.get("suspicious_apis", [])),
    }

    if args.with_rag:
        try:
            from rag_report import generate_report
            from yara_gen import generate_yara
            report = generate_report(features)
            rule = generate_yara(features, report)
            result["rag_outcome"] = "success"
            result["verdict"] = report.get("verdict")
            result["confidence"] = report.get("confidence")
            result["rule_written"] = rule is not None
        except Exception as e:
            result["rag_outcome"] = "clean_raise"
            result["rag_exception_type"] = type(e).__name__
            result["rag_exception_message"] = str(e)[:500]

    print(json.dumps(result))


if __name__ == "__main__":
    main()
