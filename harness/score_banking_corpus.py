"""SetuGuard -- pre-registered banking-corpus AUC measurement. NON-FROZEN.

NOT one of the six frozen PS1 files. Read-only over harness/feature_cache/*.json
(360 malicious CICMalDroid samples) and harness/banking_feature_cache/*.json (the
Tier A extraction from the prior session). Never re-invokes Androguard, never
touches an APK.

Scorer provenance (harness/PREREGISTERED_BANKING_AUC_CLAIMS.md, commit be6a15c,
was written before this file existed): _score_new() is IMPORTED from
harness/rescore_from_cache.py, not reimplemented a third time. That function is
itself a pinned copy of setuguard_app/backend/app.py's _rule_based_verdict()
(commit 89077ef, one minute before the scorer-v2 pruning commit b3ff83b) --
verified line-by-line identical to the live scorer before this file was written.
It is also the exact function that produced the committed AUC 0.9366 F-Droid
figure, so the banking AUC below is methodologically the same measurement,
applied to a different negative class.

Higher score = more malicious throughout. An AUC below 0.5 means legitimate
banking apps scored HIGHER than CICMalDroid malware on this scorer -- that is
not flipped or reframed anywhere in this file.

sha256 case: BANKING_CORPUS_MANIFEST.tsv's sha256 column and
banking_feature_cache/*.json filenames are both already uppercase (verified in
the prior session), but every join key here is still passed through norm_sha()
at the read boundary per CONTEXT.md §5 -- the rule is applied unconditionally at
every read boundary, not skipped because a source is currently believed clean.

Usage:
    python3 score_banking_corpus.py
"""
import csv
import json
import random
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).parent))
from rescore_from_cache import _score_new, _verdict_for, auc  # noqa: E402

MAL_CACHE = REPO_ROOT / "harness" / "feature_cache"
BANK_CACHE = REPO_ROOT / "harness" / "banking_feature_cache"
MANIFEST = REPO_ROOT / "harness" / "BANKING_CORPUS_MANIFEST.tsv"
OUT_JSON = REPO_ROOT / "harness" / "BANKING_AUC_RESULTS.json"

SEED = 42
N_BOOTSTRAP = 10_000
VERDICT_THRESHOLD = 0.30

EXPECTED_PRIMARY_N = 51
EXPECTED_SECONDARY_N = 20

SCORER_PROVENANCE = {
    "function": "rescore_from_cache._score_new (imported, not reimplemented)",
    "pinned_from": "setuguard_app/backend/app.py:_rule_based_verdict",
    "pinned_at_commit": "89077ef (one minute before scorer-v2 pruning b3ff83b)",
    "verified_identical_to_live_scorer_before_this_measurement": True,
    "same_function_produced_committed_auc_0.9366_fdroid_figure": True,
}


def norm_sha(value: str) -> str:
    return value.strip().upper()


def load_manifest():
    """sha256 -> {pkg_name, tier, arm, issuer}"""
    out = {}
    with open(MANIFEST, newline="") as f:
        for row in csv.DictReader(f, delimiter="\t"):
            out[norm_sha(row["sha256"])] = {
                "pkg_name": row["pkg_name"], "tier": row["tier"],
                "arm": row["arm"], "issuer": row["issuer"],
            }
    return out


def load_malicious_scores():
    scores = []
    for f in MAL_CACHE.glob("*.json"):
        d = json.loads(f.read_text())
        if d.get("corpus") != "malicious":
            continue
        scores.append(_score_new(d["features"]))
    return scores


def load_banking_scored(manifest: dict):
    """Returns list of {sha256, pkg_name, tier, arm, issuer, score}. GATE: every
    cached file must join to an issuer -- orphans are fatal, not skipped."""
    rows = []
    orphans = []
    for f in BANK_CACHE.glob("*.json"):
        sha = norm_sha(f.stem)
        d = json.loads(f.read_text())
        m = manifest.get(sha)
        if m is None or not m.get("issuer"):
            orphans.append(sha)
            continue
        rows.append({
            "sha256": sha, "pkg_name": m["pkg_name"], "tier": m["tier"],
            "arm": m["arm"], "issuer": m["issuer"],
            "score": _score_new(d["features"]),
        })
    if orphans:
        print(f"[score] STOP: {len(orphans)} cached banking file(s) failed to join to an issuer:",
              file=sys.stderr)
        for sha in orphans:
            print(f"  {sha}", file=sys.stderr)
        sys.exit(1)
    return rows


def score_stats(scores):
    s = sorted(scores)
    n = len(s)
    q = lambda p: s[min(n - 1, max(0, round(p * (n - 1))))]
    return {"n": n, "min": s[0], "q1": q(0.25), "median": q(0.5), "q3": q(0.75), "max": s[-1]}


def fp_count(scores, threshold=VERDICT_THRESHOLD):
    n_above = sum(1 for s in scores if s >= threshold)
    return {"n_above_threshold": n_above, "n_total": len(scores),
            "pct_above_threshold": round(100 * n_above / len(scores), 1) if scores else None}


def issuer_clustered_bootstrap_auc(mal_scores, neg_rows, n_bootstrap=N_BOOTSTRAP, seed=SEED):
    """95% CI. NEGATIVE class resampled BY ISSUER CLUSTER with replacement: draw
    len(issuers) issuers with replacement, take ALL packages of each drawn
    issuer. POSITIVE class (malicious) resampled by sample with replacement.
    Same seed drives both draws via one RNG, sequentially, per resample."""
    by_issuer = {}
    for r in neg_rows:
        by_issuer.setdefault(r["issuer"], []).append(r["score"])
    issuers = sorted(by_issuer)
    n_issuers = len(issuers)

    rng = random.Random(seed)
    point_estimate = auc(mal_scores, [r["score"] for r in neg_rows])

    boot_aucs = []
    for _ in range(n_bootstrap):
        drawn_issuers = [rng.choice(issuers) for _ in range(n_issuers)]
        neg_sample = [s for iss in drawn_issuers for s in by_issuer[iss]]
        pos_sample = [rng.choice(mal_scores) for _ in range(len(mal_scores))]
        boot_aucs.append(auc(pos_sample, neg_sample))

    boot_aucs.sort()
    lo = boot_aucs[int(0.025 * n_bootstrap)]
    hi = boot_aucs[int(0.975 * n_bootstrap) - 1]
    return {
        "auc": round(point_estimate, 4),
        "ci_95_low": round(lo, 4),
        "ci_95_high": round(hi, 4),
        "n_issuer_clusters": n_issuers,
        "n_bootstrap": n_bootstrap,
        "seed": seed,
    }


BOOTSTRAP_METHOD_STRING = (
    "95% CI, 10,000 resamples, seed=42. NEGATIVE class (legitimate banking apps) "
    "resampled BY ISSUER CLUSTER with replacement: for each resample, draw "
    "n_issuer_clusters issuers with replacement, then take ALL packages belonging "
    "to each drawn issuer (so an issuer with multiple packages can be sampled "
    "as a block, and dropping an issuer means dropping all of its packages at "
    "once). POSITIVE class (360 CICMalDroid malicious samples) resampled by "
    "individual sample with replacement, standard bootstrap. Primary and "
    "secondary arms are resampled independently -- never pooled -- each over "
    "its own issuer-cluster set. Higher score = more malicious throughout; an "
    "AUC below 0.5 means legitimate apps scored higher than malware and is "
    "reported as such, never sign-flipped."
)


def main():
    manifest = load_manifest()
    mal_scores = load_malicious_scores()
    print(f"[score] {len(mal_scores)} malicious scores loaded from {MAL_CACHE}", file=sys.stderr)

    banking_rows = load_banking_scored(manifest)
    primary = [r for r in banking_rows if r["tier"] == "A" and r["arm"] == "current"]
    secondary = [r for r in banking_rows if r["tier"] == "A" and r["arm"] == "era_matched"]

    print(f"[score] primary (Tier A current): {len(primary)} files, "
          f"{len({r['pkg_name'] for r in primary})} packages, "
          f"{len({r['issuer'] for r in primary})} issuer clusters", file=sys.stderr)
    print(f"[score] secondary (Tier A era-matched): {len(secondary)} files, "
          f"{len({r['pkg_name'] for r in secondary})} packages, "
          f"{len({r['issuer'] for r in secondary})} issuer clusters", file=sys.stderr)

    if len(primary) != EXPECTED_PRIMARY_N or len(secondary) != EXPECTED_SECONDARY_N:
        print(f"[score] STOP: expected {EXPECTED_PRIMARY_N} primary / {EXPECTED_SECONDARY_N} "
              f"secondary, got {len(primary)} / {len(secondary)}. Corpus does not match "
              f"committed extraction coverage.", file=sys.stderr)
        sys.exit(1)

    primary_result = issuer_clustered_bootstrap_auc(mal_scores, primary)
    secondary_result = issuer_clustered_bootstrap_auc(mal_scores, secondary)

    primary_neg_scores = [r["score"] for r in primary]
    secondary_neg_scores = [r["score"] for r in secondary]

    out = {
        "convention": "higher score = more malicious; AUC below 0.5 means legitimate apps "
                       "scored higher than malware, never sign-flipped",
        "scorer_provenance": SCORER_PROVENANCE,
        "bootstrap_method": BOOTSTRAP_METHOD_STRING,
        "primary": {
            "label": "AUC(360 malicious vs Tier A current-arm legitimate banking apps)",
            **primary_result,
            "n_files": len(primary), "n_packages": len({r["pkg_name"] for r in primary}),
            "score_distribution_malicious": score_stats(mal_scores),
            "score_distribution_legitimate": score_stats(primary_neg_scores),
            "operational_fp_at_0.30": fp_count(primary_neg_scores),
        },
        "secondary": {
            "label": "AUC(360 malicious vs Tier A era-matched legitimate banking apps)",
            **secondary_result,
            "n_files": len(secondary), "n_packages": len({r["pkg_name"] for r in secondary}),
            "operational_fp_at_0.30": fp_count(secondary_neg_scores),
        },
        "tertiary": {
            "label": "Tier B/C/D",
            "status": "NOT EXTRACTED, deferred by decision -- not attempted",
        },
        "extraction_coverage": {
            "primary_attempted": 53, "primary_cached": 51,
            "primary_timeouts": ["com.Version1 (Punjab National Bank)",
                                  "com.janabank.mtc (Jana Small Finance Bank)"],
            "secondary_attempted": 20, "secondary_cached": 20,
            "tertiary_attempted": 0, "tertiary_deferred_by_decision": True,
        },
        "parse_failure_comparison": {
            "banking_apps_strict_parse_failure_rate_pct": 0.0,
            "banking_apps_including_timeouts_pct": 2.7,
            "cicmaldroid_obfuscated_malware_pct": 9.75,
        },
        "malicious_n": len(mal_scores),
    }
    OUT_JSON.write_text(json.dumps(out, indent=2))
    print(f"[score] wrote {OUT_JSON}", file=sys.stderr)

    print("\n=== PRIMARY: AUC(malicious vs Tier A current arm) ===")
    print(f"AUC = {primary_result['auc']} "
          f"[{primary_result['ci_95_low']}, {primary_result['ci_95_high']}] "
          f"(95% CI, n_issuer_clusters={primary_result['n_issuer_clusters']})")
    print(f"score distribution (malicious, n={len(mal_scores)}): {score_stats(mal_scores)}")
    print(f"score distribution (legitimate, n={len(primary_neg_scores)}): {score_stats(primary_neg_scores)}")
    fp = fp_count(primary_neg_scores)
    print(f"operational FP at 0.30: {fp['n_above_threshold']}/{fp['n_total']} "
          f"({fp['pct_above_threshold']}%)")

    print("\n=== SECONDARY: AUC(malicious vs Tier A era-matched arm) ===")
    print(f"AUC = {secondary_result['auc']} "
          f"[{secondary_result['ci_95_low']}, {secondary_result['ci_95_high']}] "
          f"(95% CI, n_issuer_clusters={secondary_result['n_issuer_clusters']})")
    fp2 = fp_count(secondary_neg_scores)
    print(f"operational FP at 0.30: {fp2['n_above_threshold']}/{fp2['n_total']} "
          f"({fp2['pct_above_threshold']}%)")


if __name__ == "__main__":
    main()
