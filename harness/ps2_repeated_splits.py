"""
PS2 repeated-holdout variance estimate. NON-FROZEN (same status as
harness/train_ps2_model.py, which this script imports from and does not
duplicate).

A single 80/20 holdout has only 16 positives -- each one is 6.25% of
recall, so a single point estimate (e.g. the shipped artifact's holdout
AUCPR 0.4114 / AUROC 0.9572, models/ps2_xgb_v1_metrics.json, produced by
train_ps2_model.py's default seed=42) carries real sampling noise from
which 16 of the 81 frauds happened to land in that one holdout. This script
does NOT tune anything -- identical pipeline, identical fixed
hyperparameters (copied verbatim from train_ps2_model.py) on every run; only
the stratified 80/20 split's random_state (and, tied to it, the model's own
random_state, exactly as train_ps2_model.py does for its single-seed run)
varies, seeds 0-19. Reports the resulting AUCPR/AUROC distribution across
those 20 independent holdouts.

For EVERY seed's own holdout (not just one), also reports the operational
curve a fraud analyst actually cares about: reviewing the top-1%/top-5% of
that holdout's accounts by predicted score -- recall (frauds caught / total
frauds), precision (frauds caught / accounts reviewed), and lift over the
holdout's own base rate (precision / (total_frauds / total_accounts)) --
and aggregates recall/precision/lift into their own median/IQR/min/max
distributions across the 20 seeds, exactly as done for AUCPR/AUROC. A
single seed's 3/16 or 8/16 count carries the same sampling noise as a
single seed's AUCPR does; this reports the same 3/16-shaped numbers as a
distribution instead of a single draw.

seed=42 (the trainer's actual default, fixed before evaluation -- not
selected afterward for looking good) is run separately, outside the 0-19
range, and located by percentile within every one of the distributions
above -- AUCPR, AUROC, recall@1%, recall@5%, precision@1%, precision@5%,
lift@1%, lift@5%.

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
    base_rate = total_positive / n if n else None
    rows = []
    for frac in fractions:
        k = max(1, round(n * frac))
        top_k_idx = order[:k]
        caught = int(y_hold[top_k_idx].sum())
        precision = caught / k if k else None
        recall = caught / total_positive if total_positive else None
        lift = (precision / base_rate) if (precision is not None and base_rate) else None
        rows.append({
            "top_fraction_pct": round(frac * 100, 2),
            "accounts_reviewed": k,
            "total_holdout_accounts": n,
            "frauds_caught": caught,
            "total_holdout_frauds": total_positive,
            "recall_pct": round(100 * recall, 1) if recall is not None else None,
            "precision_pct": round(100 * precision, 1) if precision is not None else None,
            "lift_x": round(lift, 2) if lift is not None else None,
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

    fractions = (0.01, 0.05)
    per_seed = []
    for seed in range(args.n_seeds):
        row, (y_hold, scores) = run_one_split(X, y, seed)
        row["operational_curve"] = operational_curve(y_hold, scores, fractions)
        per_seed.append(row)
        oc_str = "  ".join(
            f"top{r['top_fraction_pct']}%: {r['frauds_caught']}/{r['total_holdout_frauds']} "
            f"caught (recall={r['recall_pct']}% prec={r['precision_pct']}% lift={r['lift_x']}x)"
            for r in row["operational_curve"]
        )
        print(f"seed={seed:2d}  AUCPR={row['aucpr']:.4f}  AUROC={row['auroc']:.4f}  {oc_str}")

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

    def percentile_of(value, arr):
        return float((arr < value).mean() * 100)

    # Per-fraction (1%, 5%) distributions of recall/precision/lift across
    # all 20 seeds -- same treatment as AUCPR/AUROC, so a single seed's
    # "3/16 caught" is reported as one draw from a distribution, not as if
    # it were the number.
    op_distributions = {}
    for frac in fractions:
        frac_pct = round(frac * 100, 2)
        recalls = np.array([next(r for r in row["operational_curve"] if r["top_fraction_pct"] == frac_pct)["recall_pct"] for row in per_seed])
        precisions = np.array([next(r for r in row["operational_curve"] if r["top_fraction_pct"] == frac_pct)["precision_pct"] for row in per_seed])
        lifts = np.array([next(r for r in row["operational_curve"] if r["top_fraction_pct"] == frac_pct)["lift_x"] for row in per_seed])
        op_distributions[f"top_{frac_pct}pct"] = {
            "recall_pct_distribution": dist(recalls),
            "precision_pct_distribution": dist(precisions),
            "lift_x_distribution": dist(lifts),
        }

    # seed=42: train_ps2_model.py's DEFAULT seed, fixed before evaluation
    # (not selected afterward for looking good) -- this is what actually
    # produced the shipped artifact's holdout numbers. Run separately,
    # outside the 0-19 range, and located by percentile in every
    # distribution above, not assumed to be any particular seed in 0-19.
    seed42_row, (y_hold42, scores42) = run_one_split(X, y, 42)
    seed42_row["operational_curve"] = operational_curve(y_hold42, scores42, fractions)
    seed42_percentiles = {
        "aucpr": round(percentile_of(seed42_row["aucpr"], aucprs), 1),
        "auroc": round(percentile_of(seed42_row["auroc"], aurocs), 1),
    }
    for r in seed42_row["operational_curve"]:
        frac_pct = r["top_fraction_pct"]
        key = f"top_{frac_pct}pct"
        recalls = np.array([next(rr for rr in row["operational_curve"] if rr["top_fraction_pct"] == frac_pct)["recall_pct"] for row in per_seed])
        precisions = np.array([next(rr for rr in row["operational_curve"] if rr["top_fraction_pct"] == frac_pct)["precision_pct"] for row in per_seed])
        lifts = np.array([next(rr for rr in row["operational_curve"] if rr["top_fraction_pct"] == frac_pct)["lift_x"] for row in per_seed])
        seed42_percentiles[f"{key}_recall"] = round(percentile_of(r["recall_pct"], recalls), 1)
        seed42_percentiles[f"{key}_precision"] = round(percentile_of(r["precision_pct"], precisions), 1)
        seed42_percentiles[f"{key}_lift"] = round(percentile_of(r["lift_x"], lifts), 1)

    def median_iqr(d, decimals=3, suffix=""):
        f = f"{{:.{decimals}f}}"
        return f"{f.format(d['median'])} [{f.format(d['iqr_25'])}-{f.format(d['iqr_75'])}]{suffix}"

    # HEADLINE comes first in this file on purpose (Task 5): this is the
    # number a report/demo should quote -- a 20-seed distribution, not any
    # single split's point estimate, including not the shipped artifact's
    # own seed=42 run (see seed_42_reference below for that, explicitly
    # labeled as one draw).
    headline = {
        "what_this_is": "Median [IQR] across 20 independent stratified 80/20 holdouts (seeds 0-19), "
                         "identical fixed hyperparameters, no tuning. This -- not any single seed's "
                         "point estimate -- is the number to quote.",
        "aucpr": median_iqr(dist(aucprs)),
        "auroc": median_iqr(dist(aurocs)),
        "recall_at_top_1pct": median_iqr(op_distributions["top_1.0pct"]["recall_pct_distribution"], 1, "%"),
        "recall_at_top_5pct": median_iqr(op_distributions["top_5.0pct"]["recall_pct_distribution"], 1, "%"),
        "precision_at_top_1pct": median_iqr(op_distributions["top_1.0pct"]["precision_pct_distribution"], 1, "%"),
        "precision_at_top_5pct": median_iqr(op_distributions["top_5.0pct"]["precision_pct_distribution"], 1, "%"),
        "lift_at_top_1pct": median_iqr(op_distributions["top_1.0pct"]["lift_x_distribution"], 1, "x"),
        "lift_at_top_5pct": median_iqr(op_distributions["top_5.0pct"]["lift_x_distribution"], 1, "x"),
    }

    out = {
        "headline": headline,
        "n_seeds": args.n_seeds,
        "fixed_hyperparameters": FIXED_HYPERPARAMETERS,
        "note": "No hyperparameter search was performed -- identical fixed hyperparameters "
                "on every seed; only the stratified 80/20 split's random_state (and the "
                "model's own random_state, tied to it) varies. seed=42 is train_ps2_model.py's "
                "hardcoded default, fixed before any of this evaluation ran, not chosen "
                "afterward because it scored well.",
        "aucpr_distribution": dist(aucprs),
        "auroc_distribution": dist(aurocs),
        "operational_curve_distributions": op_distributions,
        "per_seed": per_seed,
        "seed_42_reference": {
            "note": "train_ps2_model.py's default --seed is 42 -- this is what actually "
                    "produced the already-published models/ps2_xgb_v1_metrics.json holdout "
                    "numbers (aucpr=0.4114011947584679, auroc=0.9571765685730149). Included here, "
                    "outside the requested seeds 0-19 range, and located by percentile in every "
                    "distribution above rather than assumed to sit anywhere in particular.",
            "aucpr": seed42_row["aucpr"],
            "auroc": seed42_row["auroc"],
            "operational_curve": seed42_row["operational_curve"],
            "percentiles_within_seeds_0_19": seed42_percentiles,
        },
        "peak_rss_kb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "wall_clock_seconds": round(time.perf_counter() - t0, 3),
    }
    Path(args.out).write_text(json.dumps(out, indent=2))

    print(f"\n=== HEADLINE (quote this, not any single seed) ===")
    print(json.dumps(headline, indent=2))
    print(f"\nAUCPR distribution: {json.dumps(out['aucpr_distribution'], indent=2)}")
    print(f"AUROC distribution: {json.dumps(out['auroc_distribution'], indent=2)}")
    print(f"\nOperational curve distributions (across seeds 0-19):")
    print(json.dumps(op_distributions, indent=2))
    print(f"\nseed=42 (train_ps2_model.py's actual default, already published as "
          f"ps2_xgb_v1_metrics.json): AUCPR={seed42_row['aucpr']:.4f} "
          f"({seed42_percentiles['aucpr']:.0f}th pct of seeds 0-19)  "
          f"AUROC={seed42_row['auroc']:.4f} ({seed42_percentiles['auroc']:.0f}th pct of seeds 0-19)")
    for r in seed42_row["operational_curve"]:
        frac_pct = r["top_fraction_pct"]
        key = f"top_{frac_pct}pct"
        print(f"  top {frac_pct}%: {r['frauds_caught']}/{r['total_holdout_frauds']} caught, "
              f"recall={r['recall_pct']}% ({seed42_percentiles[key + '_recall']:.0f}th pct)  "
              f"precision={r['precision_pct']}% ({seed42_percentiles[key + '_precision']:.0f}th pct)  "
              f"lift={r['lift_x']}x ({seed42_percentiles[key + '_lift']:.0f}th pct)")
    print(f"\nPeak RSS: {out['peak_rss_kb'] / 1024:.1f} MB, wall clock {out['wall_clock_seconds']}s")
    print(f"Written to {args.out}")


if __name__ == "__main__":
    main()
