"""
PS2 repeated-holdout variance estimate. NON-FROZEN (same status as
harness/train_ps2_model.py, which this script imports from and does not
duplicate).

A single 80/20 holdout has only 16 positives -- each one is 6.25% of
recall, so the single seed=42 point estimate (holdout AUCPR 0.4114, AUROC
0.9572, in models/ps2_xgb_v1_metrics.json) carries real sampling noise from
which 16 of the 81 frauds happened to land in that one holdout. This script
does NOT tune anything -- identical pipeline, identical fixed
hyperparameters (copied verbatim from train_ps2_model.py) on every run; only
the stratified 80/20 split's random_state (and, tied to it, the model's own
random_state, exactly as train_ps2_model.py does for its single seed=42 run)
varies, seeds 0-19. Reports the resulting AUCPR/AUROC distribution across
those 20 independent holdouts, and locates seed 0 inside it.

From the seed=0 holdout specifically, also reports the operational curve a
fraud analyst actually cares about: reviewing the top-1%/top-5% of holdout
accounts by predicted score, how many of the holdout's 16 frauds are caught.

Usage:
    python3 harness/ps2_repeated_splits.py [--csv DataSet.csv] [--out models/ps2_repeated_splits_metrics.json]
"""
import argparse
import json
import resource
import time
from pathlib import Path

import numpy as np
import pandas as pd

from train_ps2_model import TARGET_COLUMN, encode_features, load_dataset  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]

# Copied verbatim from train_ps2_model.py's hyperparameters dict (minus
# scale_pos_weight/random_state, which are per-split data-derived/seed
# values, not tuned choices) -- identical on every seed, per instruction.
FIXED_HYPERPARAMETERS = {
    "n_estimators": 200,
    "max_depth": 4,
    "learning_rate": 0.05,
    "subsample": 0.8,
    "colsample_bytree": 0.8,
    "eval_metric": "aucpr",
    "n_jobs": 1,
}


def run_one_split(X, y, seed: int):
    from sklearn.metrics import average_precision_score, roc_auc_score
    from sklearn.model_selection import train_test_split
    from xgboost import XGBClassifier

    X_train, X_hold, y_train, y_hold = train_test_split(
        X, y, test_size=0.2, random_state=seed, stratify=y
    )
    class_counts = {
        "train": {"total": int(len(y_train)), "positive": int((y_train == 1).sum())},
        "holdout": {"total": int(len(y_hold)), "positive": int((y_hold == 1).sum())},
    }
    scale_pos_weight = (y_train == 0).sum() / max((y_train == 1).sum(), 1)
    model = XGBClassifier(random_state=seed, scale_pos_weight=scale_pos_weight, **FIXED_HYPERPARAMETERS)
    model.fit(X_train, y_train)
    hold_proba = model.predict_proba(X_hold)[:, 1]
    return {
        "seed": seed,
        "aucpr": float(average_precision_score(y_hold, hold_proba)),
        "auroc": float(roc_auc_score(y_hold, hold_proba)),
        "class_counts": class_counts,
    }, (y_hold.values, hold_proba)


def operational_curve(y_hold: np.ndarray, scores: np.ndarray, fractions=(0.01, 0.05)):
    n = len(scores)
    order = np.argsort(-scores)
    total_positive = int(y_hold.sum())
    rows = []
    for frac in fractions:
        k = max(1, round(n * frac))
        top_k_idx = order[:k]
        caught = int(y_hold[top_k_idx].sum())
        rows.append({
            "top_fraction_pct": round(frac * 100, 2),
            "accounts_reviewed": k,
            "total_holdout_accounts": n,
            "frauds_caught": caught,
            "total_holdout_frauds": total_positive,
            "recall_pct": round(100 * caught / total_positive, 1) if total_positive else None,
        })
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=str(REPO_ROOT / "DataSet.csv"))
    ap.add_argument("--out", default=str(REPO_ROOT / "models" / "ps2_repeated_splits_metrics.json"))
    ap.add_argument("--n-seeds", type=int, default=20)
    args = ap.parse_args()

    t0 = time.perf_counter()
    df = load_dataset(Path(args.csv))
    X = encode_features(df)
    y = df[TARGET_COLUMN].astype(int)

    per_seed = []
    seed0_holdout = None
    for seed in range(args.n_seeds):
        row, holdout_arrays = run_one_split(X, y, seed)
        per_seed.append(row)
        if seed == 0:
            seed0_holdout = holdout_arrays
        print(f"seed={seed:2d}  AUCPR={row['aucpr']:.4f}  AUROC={row['auroc']:.4f}  "
              f"holdout_pos={row['class_counts']['holdout']['positive']}")

    aucprs = np.array([r["aucpr"] for r in per_seed])
    aurocs = np.array([r["auroc"] for r in per_seed])

    def dist(a):
        return {
            "median": float(np.median(a)),
            "iqr_25": float(np.percentile(a, 25)),
            "iqr_75": float(np.percentile(a, 75)),
            "min": float(np.min(a)),
            "max": float(np.max(a)),
            "mean": float(np.mean(a)),
            "std": float(np.std(a)),
        }

    y_hold0, scores0 = seed0_holdout
    op_curve = operational_curve(y_hold0, scores0)

    seed0_row = next(r for r in per_seed if r["seed"] == 0)

    # models/ps2_xgb_v1_metrics.json (the previously-reported 0.4114/0.9572)
    # was trained with train_ps2_model.py's DEFAULT seed, which is 42, not 0.
    # Run seed=42 too so that specific already-published number can be
    # located honestly, instead of assuming it corresponds to seed 0.
    seed42_row, _ = run_one_split(X, y, 42)
    seed42_aucpr_percentile = float((aucprs < seed42_row["aucpr"]).mean() * 100)
    seed42_auroc_percentile = float((aurocs < seed42_row["auroc"]).mean() * 100)

    out = {
        "n_seeds": args.n_seeds,
        "fixed_hyperparameters": FIXED_HYPERPARAMETERS,
        "note": "No hyperparameter search was performed -- identical fixed hyperparameters "
                "on every seed; only the stratified 80/20 split's random_state (and the "
                "model's own random_state, tied to it) varies.",
        "per_seed": per_seed,
        "aucpr_distribution": dist(aucprs),
        "auroc_distribution": dist(aurocs),
        "seed_0": {
            "aucpr": seed0_row["aucpr"],
            "auroc": seed0_row["auroc"],
        },
        "seed_0_operational_curve": op_curve,
        "seed_42_reference": {
            "note": "train_ps2_model.py's default --seed is 42, not 0 -- this is what actually "
                    "produced the already-published models/ps2_xgb_v1_metrics.json holdout "
                    "numbers (aucpr=0.4114011947584679, auroc=0.9571765685730149). Included here, "
                    "outside the requested seeds 0-19 range, so that specific point estimate can "
                    "be located honestly rather than assumed to be seed 0.",
            "aucpr": seed42_row["aucpr"],
            "auroc": seed42_row["auroc"],
            "aucpr_percentile_within_seeds_0_19": round(seed42_aucpr_percentile, 1),
            "auroc_percentile_within_seeds_0_19": round(seed42_auroc_percentile, 1),
        },
        "peak_rss_kb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "wall_clock_seconds": round(time.perf_counter() - t0, 3),
    }
    Path(args.out).write_text(json.dumps(out, indent=2))

    print(f"\nAUCPR distribution: {json.dumps(out['aucpr_distribution'], indent=2)}")
    print(f"AUROC distribution: {json.dumps(out['auroc_distribution'], indent=2)}")
    print(f"\nseed=0: AUCPR={seed0_row['aucpr']:.4f}  AUROC={seed0_row['auroc']:.4f}")
    print(f"\nseed=42 (train_ps2_model.py's actual default, already published as "
          f"ps2_xgb_v1_metrics.json): AUCPR={seed42_row['aucpr']:.4f} "
          f"({seed42_aucpr_percentile:.0f}th pct of seeds 0-19)  "
          f"AUROC={seed42_row['auroc']:.4f} ({seed42_auroc_percentile:.0f}th pct of seeds 0-19)")
    print(f"\nseed=0 operational curve:")
    for r in op_curve:
        print(f"  top {r['top_fraction_pct']}% ({r['accounts_reviewed']}/{r['total_holdout_accounts']} accounts): "
              f"{r['frauds_caught']}/{r['total_holdout_frauds']} frauds caught ({r['recall_pct']}% recall)")
    print(f"\nPeak RSS: {out['peak_rss_kb'] / 1024:.1f} MB, wall clock {out['wall_clock_seconds']}s")
    print(f"Written to {args.out}")


if __name__ == "__main__":
    main()
