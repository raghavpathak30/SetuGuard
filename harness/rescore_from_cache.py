"""SetuGuard — rescore cached features with old/new scorer, compute AUCs.

NOT one of the six frozen PS1 files, not part of batch_baseline.py's suite.
Read-only consumer of harness/feature_cache/*.json (built by
extract_features_pool.py). Never re-invokes Androguard.

Both scorer formulas below are frozen, pinned copies (not imports), same
precedent as threshold_sweep.py:
  - _score_old mirrors setuguard_app/backend/app.py's _rule_based_verdict()
    as of commit 46ce2ea (pre scorer-v2 pruning): includes reflection,
    self_signed, and the unnarrowed any-url/ip term.
  - _score_new mirrors the same function as of the scorer-v2 pruning commit
    (this session, 2026-08-12): reflection and self_signed removed, url/ip
    term narrowed to bare-IP-host / non-standard-port only.
If app.py's scorer changes again, these copies must be re-synced by hand.

AUC is computed via the Mann-Whitney U / rank-sum identity (exact, matches
sklearn.metrics.roc_auc_score for the binary case) -- no scipy/sklearn
dependency added.

Usage:
    python3 rescore_from_cache.py --cache-dir feature_cache --out-csv results_716.csv
"""
import argparse
import csv
import json
from pathlib import Path
from urllib.parse import urlparse
import ipaddress


# ---------------------------------------------------------------------------
# OLD scorer (pre scorer-v2, commit 46ce2ea) -- frozen copy for comparison
# ---------------------------------------------------------------------------
def _score_old(features: dict) -> float:
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


# ---------------------------------------------------------------------------
# NEW scorer (scorer-v2, this session) -- frozen copy, must match app.py
# ---------------------------------------------------------------------------
def _url_host_is_bare_ip(url: str) -> bool:
    try:
        host = urlparse(url).hostname
    except ValueError:
        return False
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _url_has_nonstandard_port(url: str) -> bool:
    try:
        port = urlparse(url).port
    except ValueError:
        return False
    return port is not None and port not in (80, 443)


def _score_new(features: dict) -> float:
    score = 0.0
    dp = features["dangerous_permissions"]
    if dp:
        score += min(len(dp) * 0.06, 0.30)

    sapis = features["suspicious_apis"]
    weight_by_cat = {
        "dynamic_code_loading": 0.20, "sms_control": 0.20, "device_admin": 0.15,
        "accessibility_service": 0.20, "installed_app_discovery": 0.10,
    }
    seen_cats = {api["category"] for api in sapis if api["category"] != "reflection"}
    for cat in seen_cats:
        score += weight_by_cat.get(cat, 0.08)

    strs = features["suspicious_strings"]
    bare_ips = [s for s in strs if s["kind"] == "ip"]
    flagged_urls = [
        s for s in strs
        if s["kind"] == "url" and (_url_host_is_bare_ip(s["value"]) or _url_has_nonstandard_port(s["value"]))
    ]
    ip_url = bare_ips + flagged_urls
    if ip_url:
        score += min(len(ip_url) * 0.05, 0.20)

    cert = features["certificate"]
    if cert.get("is_debug"):
        score += 0.05

    return max(0.0, min(score, 1.0))


def _verdict_for(score: float) -> str:
    if score >= 0.65:
        return "malicious"
    elif score >= 0.30:
        return "suspicious"
    return "benign"


def auc(pos_scores, neg_scores) -> float:
    """AUC via Mann-Whitney U rank-sum. pos = higher-score-should-be class
    (e.g. malicious), neg = lower-score-should-be class (e.g. benign/holdout).
    """
    all_scores = [(s, 1) for s in pos_scores] + [(s, 0) for s in neg_scores]
    all_scores.sort(key=lambda x: x[0])
    n = len(all_scores)
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j < n and all_scores[j][0] == all_scores[i][0]:
            j += 1
        avg_rank = (i + 1 + j) / 2.0  # 1-indexed average rank for ties
        for k in range(i, j):
            ranks[k] = avg_rank
        i = j
    rank_sum_pos = sum(r for r, (s, label) in zip(ranks, all_scores) if label == 1)
    n_pos = len(pos_scores)
    n_neg = len(neg_scores)
    u = rank_sum_pos - n_pos * (n_pos + 1) / 2.0
    return u / (n_pos * n_neg)


def load_cache(cache_dir: Path):
    rows = []
    for f in cache_dir.glob("*.json"):
        payload = json.loads(f.read_text())
        rows.append(payload)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache-dir", type=Path, default=Path(__file__).parent / "feature_cache")
    ap.add_argument("--out-csv", type=Path, default=Path(__file__).parent / "results_716.csv")
    args = ap.parse_args()

    rows = load_cache(args.cache_dir)
    print(f"loaded {len(rows)} cached feature sets")

    by_corpus = {"banking_holdout": [], "malicious": [], "benign": []}
    csv_rows = []
    for r in rows:
        feats = r["features"]
        corpus = r["corpus"]
        s_old = _score_old(feats)
        s_new = _score_new(feats)
        row = {
            "sha256": r["sha256"], "corpus": corpus, "source_path": r["source_path"],
            "score_old": round(s_old, 4), "verdict_old": _verdict_for(s_old),
            "score_new": round(s_new, 4), "verdict_new": _verdict_for(s_new),
        }
        csv_rows.append(row)
        by_corpus.setdefault(corpus, []).append(row)

    with open(args.out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(csv_rows[0].keys()))
        w.writeheader()
        w.writerows(csv_rows)
    print(f"wrote {args.out_csv} ({len(csv_rows)} rows)")

    def stats(label, key):
        vals = [r[key] for r in by_corpus[label]]
        n = len(vals)
        if n == 0:
            return None
        capped = sum(1 for v in vals if v >= 1.0)
        return {
            "n": n, "mean": sum(vals) / n, "median": sorted(vals)[n // 2],
            "min": min(vals), "max": max(vals), "capped": capped,
        }

    print("\n=== Score distributions ===")
    for scorer_key, label_name in [("score_old", "OLD"), ("score_new", "NEW")]:
        print(f"\n-- {label_name} scorer --")
        for corpus in ["banking_holdout", "malicious", "benign"]:
            st = stats(corpus, scorer_key)
            if st is None:
                print(f"{corpus}: n=0")
                continue
            print(f"{corpus}: n={st['n']} mean={st['mean']:.3f} median={st['median']:.3f} "
                  f"min={st['min']:.3f} max={st['max']:.3f} capped_at_1.0={st['capped']}")

    print("\n=== AUCs (malicious=positive) ===")
    mal_old = [r["score_old"] for r in by_corpus["malicious"]]
    mal_new = [r["score_new"] for r in by_corpus["malicious"]]
    holdout_old = [r["score_old"] for r in by_corpus["banking_holdout"]]
    holdout_new = [r["score_new"] for r in by_corpus["banking_holdout"]]
    benign_old = [r["score_old"] for r in by_corpus["benign"]]
    benign_new = [r["score_new"] for r in by_corpus["benign"]]

    if mal_old and holdout_old:
        print(f"AUC(malicious vs banking_holdout_16) OLD = {auc(mal_old, holdout_old):.4f}")
        print(f"AUC(malicious vs banking_holdout_16) NEW = {auc(mal_new, holdout_new):.4f}")
    if mal_old and benign_old:
        print(f"AUC(malicious vs fdroid_benign)      OLD = {auc(mal_old, benign_old):.4f}")
        print(f"AUC(malicious vs fdroid_benign)      NEW = {auc(mal_new, benign_new):.4f}")


if __name__ == "__main__":
    main()
