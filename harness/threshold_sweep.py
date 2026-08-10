"""SetuGuard — D1 threshold sweep, measurement only.

NOT one of the six frozen PS1 files, not part of batch_baseline.py's suite.
Ad hoc, non-frozen script written 2026-08-10 to sweep candidate
malicious/suspicious cutoffs against the capped rule-based scorer and report
benign FP rate / malicious recall per candidate pair. Does NOT change any
threshold in setuguard_app/backend/app.py — this is measurement only, per
instruction ("I'll pick the operating point").

Mirrors _rule_based_verdict()'s scoring formula in
setuguard_app/backend/app.py EXACTLY (as of commit fcd2fd4 — capped
suspicious_apis, one score per distinct category) so raw scores can be
recomputed locally (via static_analysis.analyze_apk(), no HTTP/Ollama
needed) without reverse-engineering them from rounded confidence values.
If app.py's scorer changes, this copy must be re-synced by hand.

Usage:
    python3 threshold_sweep.py [--sample-list ../harness/sample_set_86.txt]
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "setuguard_ps1"))
import static_analysis  # noqa: E402


def _score(features: dict) -> float:
    """Exact mirror of _rule_based_verdict()'s score computation in app.py."""
    score = 0.0

    dp = features["dangerous_permissions"]
    if dp:
        score += min(len(dp) * 0.06, 0.30)

    sapis = features["suspicious_apis"]
    weight_by_cat = {
        "dynamic_code_loading": 0.20, "sms_control": 0.20, "device_admin": 0.15,
        "accessibility_service": 0.20, "installed_app_discovery": 0.10,
        "reflection": 0.05,
    }
    seen_cats = {api["category"] for api in sapis}
    for cat in seen_cats:
        score += weight_by_cat.get(cat, 0.08)

    strs = features["suspicious_strings"]
    ip_url = [s for s in strs if s["kind"] in ("url", "ip")]
    if ip_url:
        score += min(len(ip_url) * 0.05, 0.20)

    cert = features["certificate"]
    if cert.get("self_signed"):
        score += 0.05
    if cert.get("is_debug"):
        score += 0.05

    return max(0.0, min(score, 1.0))


def _read_sample_list(path: Path):
    samples = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        path_str, label = line.rsplit(",", 1)
        samples.append((Path(path_str), label))
    return samples


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--sample-list", type=Path,
                    default=Path(__file__).parent / "sample_set_86.txt")
    args = p.parse_args()

    samples = _read_sample_list(args.sample_list)
    scored = []
    for idx, (apk_path, true_label) in enumerate(samples, start=1):
        try:
            features = static_analysis.analyze_apk(str(apk_path))
        except Exception as e:
            print(f"  [{idx}/{len(samples)}] {apk_path.name} SKIPPED: {e}", file=sys.stderr)
            continue
        s = _score(features)
        scored.append((apk_path.name, true_label, s))
        print(f"  [{idx}/{len(samples)}] {apk_path.name} ({true_label}) score={s:.3f}", file=sys.stderr)

    benign_scores = [s for _, lbl, s in scored if lbl == "benign"]
    malicious_scores = [s for _, lbl, s in scored if lbl == "malicious"]
    print(f"\nScored {len(scored)}/{len(samples)} "
          f"({len(benign_scores)} benign, {len(malicious_scores)} malicious)", file=sys.stderr)

    susp_cuts = [0.20, 0.25, 0.30, 0.35, 0.40]
    mal_cuts = [0.55, 0.60, 0.65, 0.70, 0.75]

    print()
    print(f"{'susp_cut':>9} {'mal_cut':>8} | {'benign_FP':>10} {'benign_FP%':>11} | "
          f"{'mal_flagged':>12} {'flag_recall%':>13} | {'mal_strict':>11} {'strict_recall%':>15}")
    print("-" * 100)
    for sc in susp_cuts:
        for mc in mal_cuts:
            if mc <= sc:
                continue
            benign_fp = sum(1 for s in benign_scores if s >= sc)
            mal_flagged = sum(1 for s in malicious_scores if s >= sc)
            mal_strict = sum(1 for s in malicious_scores if s >= mc)
            benign_fp_pct = 100 * benign_fp / len(benign_scores) if benign_scores else 0
            flag_recall_pct = 100 * mal_flagged / len(malicious_scores) if malicious_scores else 0
            strict_recall_pct = 100 * mal_strict / len(malicious_scores) if malicious_scores else 0
            print(f"{sc:>9.2f} {mc:>8.2f} | {benign_fp:>4}/{len(benign_scores):<5} {benign_fp_pct:>10.1f}% | "
                  f"{mal_flagged:>5}/{len(malicious_scores):<6} {flag_recall_pct:>12.1f}% | "
                  f"{mal_strict:>4}/{len(malicious_scores):<6} {strict_recall_pct:>14.1f}%")


if __name__ == "__main__":
    main()
