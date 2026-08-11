"""
Offline PS2 (fraud/mule) model trainer. NON-FROZEN -- unlike the six PS1
files under setuguard_ps1/, this script and its output artifacts are
expected to be re-run and revised.

Trains XGBoost on the bank's 18 approved features (BANK_FINALIZED_FEATURES,
see setuguard_app/backend/ps2_features.py) against a stratified train/holdout
split of DataSet.csv, and writes a versioned model artifact plus a metrics
JSON to models/. The live backend (setuguard_app/backend/app.py) loads that
artifact at scoring time -- it never trains, cross-validates, or fits SHAP
inside an HTTP request.

Usage:
    python3 harness/train_ps2_model.py [--csv DataSet.csv] [--out-dir models]
                                        [--version ps2_xgb_v1] [--seed 42]

Determinism: fixed seed everywhere RNG is used (split + XGBoost). Re-running
with the same --csv/--seed reproduces byte-identical metrics (verified by
running twice and diffing the metrics JSON minus the timestamp field).
"""
import argparse
import json
import resource
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "setuguard_app" / "backend"))
from ps2_features import (  # noqa: E402
    BANK_FINALIZED_FEATURES,
    CATEGORICAL_FEATURES,
    EXCLUDED_ALERT_DERIVED,
    EXCLUDED_LEAKY_FEATURES,
    TARGET_COLUMN,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def git_commit_hash() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True
        ).strip()
    except Exception:
        return "unknown"


def load_dataset(csv_path: Path) -> pd.DataFrame:
    usecols = BANK_FINALIZED_FEATURES + [TARGET_COLUMN]
    # Only the 19 needed columns are parsed -- DataSet.csv has 3,925 columns
    # and reading it in full is unnecessary and memory-wasteful for a script
    # that only ever touches the bank's 18 approved features + target.
    df = pd.read_csv(csv_path, usecols=usecols)

    assert_no_excluded_features(df.columns)
    missing = set(usecols) - set(df.columns)
    if missing:
        raise RuntimeError(f"Expected column(s) missing from {csv_path}: {sorted(missing)}")
    return df


def assert_no_excluded_features(columns) -> None:
    """The actual guard, factored out of load_dataset() so it can be called
    directly -- both by load_dataset() itself (against whatever usecols
    happened to read) and by harness/test_leakage_assert.py (against a
    hand-built column list that deliberately includes a leaky feature,
    bypassing usecols entirely -- usecols already makes it structurally
    impossible for load_dataset()'s own CSV read to ever include an
    excluded column, so testing *through* load_dataset() would only prove
    usecols works, not that this guard does). Raises loudly; never drops
    a column silently."""
    excluded = set(EXCLUDED_LEAKY_FEATURES) | set(EXCLUDED_ALERT_DERIVED)
    present_excluded = excluded & set(columns)
    if present_excluded:
        raise RuntimeError(
            f"Excluded leaky/alert-derived feature(s) present in the loaded "
            f"matrix: {sorted(present_excluded)}. This must never happen -- "
            f"check BANK_FINALIZED_FEATURES / usecols."
        )


def encode_features(df: pd.DataFrame) -> pd.DataFrame:
    """One-hot encode the two categorical features; leave the rest as float
    (including NaN -- XGBoost handles missing values natively, so no
    imputation/sentinel-filling happens here)."""
    X = df[BANK_FINALIZED_FEATURES].copy()
    for c in CATEGORICAL_FEATURES:
        X[c] = X[c].astype("object")
    X = pd.get_dummies(X, columns=CATEGORICAL_FEATURES, dummy_na=False)
    numeric_cols = [c for c in X.columns if c not in X.select_dtypes(include="bool").columns]
    X[numeric_cols] = X[numeric_cols].astype(float)
    return X


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=str(REPO_ROOT / "DataSet.csv"))
    ap.add_argument("--out-dir", default=str(REPO_ROOT / "models"))
    ap.add_argument("--version", default="ps2_xgb_v1")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--test-size", type=float, default=0.2)
    args = ap.parse_args()

    t0 = time.perf_counter()
    csv_path = Path(args.csv)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    df = load_dataset(csv_path)
    input_shape = {"rows": df.shape[0], "cols": df.shape[1]}

    X = encode_features(df)
    y = df[TARGET_COLUMN].astype(int)

    from sklearn.model_selection import train_test_split
    from sklearn.metrics import average_precision_score, roc_auc_score
    from xgboost import XGBClassifier

    X_train, X_hold, y_train, y_hold = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed, stratify=y
    )

    class_counts = {
        "train": {
            "total": int(len(y_train)),
            "positive": int((y_train == 1).sum()),
            "negative": int((y_train == 0).sum()),
        },
        "holdout": {
            "total": int(len(y_hold)),
            "positive": int((y_hold == 1).sum()),
            "negative": int((y_hold == 0).sum()),
        },
    }

    scale_pos_weight = class_counts["train"]["negative"] / max(class_counts["train"]["positive"], 1)
    hyperparameters = {
        "n_estimators": 200,
        "max_depth": 4,
        "learning_rate": 0.05,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "scale_pos_weight": scale_pos_weight,
        "eval_metric": "aucpr",
        "random_state": args.seed,
        "n_jobs": 1,  # fixed thread count -- part of what makes this reproducible
    }
    model = XGBClassifier(**hyperparameters)
    model.fit(X_train, y_train)

    hold_proba = model.predict_proba(X_hold)[:, 1]
    holdout_metrics = {
        "aucpr": float(average_precision_score(y_hold, hold_proba)),
        "auroc": float(roc_auc_score(y_hold, hold_proba)),
    }

    # In-sample metrics computed ONLY for the overfit-gap comparison below --
    # explicitly labeled in-sample, never surfaced by the live API.
    train_proba = model.predict_proba(X_train)[:, 1]
    in_sample_train_metrics = {
        "aucpr": float(average_precision_score(y_train, train_proba)),
        "auroc": float(roc_auc_score(y_train, train_proba)),
    }

    import shap
    explainer = shap.TreeExplainer(model)
    shap_values_train = explainer.shap_values(X_train)
    mean_abs_shap = np.abs(shap_values_train).mean(axis=0)
    shap_feature_importance_train = dict(
        sorted(
            {col: float(v) for col, v in zip(X_train.columns, mean_abs_shap)}.items(),
            key=lambda kv: -kv[1],
        )
    )

    version = args.version
    model_path = out_dir / f"{version}.json"
    metrics_path = out_dir / f"{version}_metrics.json"
    model.save_model(str(model_path))

    peak_rss_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss  # KB on Linux
    metrics = {
        "model_version": version,
        "model_file": model_path.name,
        "trained_at_utc": pd.Timestamp.utcnow().isoformat(),
        "git_commit": git_commit_hash(),
        "seed": args.seed,
        "test_size": args.test_size,
        "source_csv": str(csv_path),
        "input_shape": input_shape,
        "class_counts": class_counts,
        "features": {
            "bank_finalized": BANK_FINALIZED_FEATURES,
            "categorical": CATEGORICAL_FEATURES,
            "encoded_feature_names": list(X.columns),
        },
        "holdout_metrics": holdout_metrics,
        "single_split_caveat": (
            "holdout_metrics above is ONE stratified 80/20 split (this run's --seed, "
            f"default {args.seed}) on a holdout of only 16 positives -- do not quote it alone "
            "as a headline result. harness/ps2_repeated_splits.py runs 20 such splits and "
            "reports the resulting median/IQR in models/ps2_repeated_splits_metrics.json's "
            "'headline' field; that file's seed_42_reference block confirms this seed's exact "
            "numbers and reports where they fall in the 20-seed distribution (80th percentile "
            "AUCPR, 100th percentile/best AUROC as of the run that produced that file -- i.e. "
            "this run's holdout_metrics is a favorable draw, not a typical one)."
        ),
        "in_sample_train_metrics_DO_NOT_REPORT_AS_HOLDOUT": in_sample_train_metrics,
        "shap_feature_importance_train_mean_abs": shap_feature_importance_train,
        "hyperparameters": hyperparameters,
        "peak_rss_kb": peak_rss_kb,
        "wall_clock_seconds": round(time.perf_counter() - t0, 3),
    }
    metrics_path.write_text(json.dumps(metrics, indent=2))

    print(f"Model written to {model_path}")
    print(f"Metrics written to {metrics_path}")
    print(f"Input shape: {input_shape}")
    print(f"Class counts: {json.dumps(class_counts)}")
    print(f"HOLDOUT AUCPR={holdout_metrics['aucpr']:.4f}  HOLDOUT AUROC={holdout_metrics['auroc']:.4f}")
    print(f"(in-sample train AUCPR={in_sample_train_metrics['aucpr']:.4f} -- NOT a generalization estimate)")
    print(f"Peak RSS: {peak_rss_kb / 1024:.1f} MB")
    print(f"Wall clock: {metrics['wall_clock_seconds']}s")


if __name__ == "__main__":
    main()
