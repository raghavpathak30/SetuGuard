"""
SetuGuard PS2 — Step 1: Data Integrity Audit
==============================================
Run this FIRST, before any model touches the data.

What it checks:
  1. Class balance on the target column
  2. Target-proxy leakage (a feature ~perfectly correlated with the label)
  3. Temporal cohort separation (does one class cluster in one time window?)
  4. Column sparsity (which features are mostly NA / -1 sentinel)
  5. Near-perfect single-feature separators (features that alone almost solve it)

Usage:
    python 01_data_audit.py --csv path/to/DataSet.csv --target F3924

Notes:
  - The dataset's first column is an unnamed row index — pandas will read it
    as "Unnamed: 0" unless you pass index_col=0. Adjust below if your file
    differs.
  - -1 and "NA" may both mean "not applicable" but could carry different
    meaning (e.g. -1 = "field doesn't apply to this product type" vs.
    NA = "never collected"). This script reports them separately so you
    can decide how to treat each.
"""

import argparse
import pandas as pd
import numpy as np
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import roc_auc_score


def load_data(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path, index_col=0, low_memory=False)
    print(f"Loaded shape: {df.shape[0]} rows x {df.shape[1]} columns")
    return df


def class_balance(df: pd.DataFrame, target: str):
    counts = df[target].value_counts(dropna=False)
    print("\n--- Class balance ---")
    print(counts)
    if len(counts) == 2:
        minority = counts.min()
        majority = counts.max()
        print(f"Imbalance ratio ~ {majority / minority:.1f} : 1")
    return counts


def sparsity_report(df: pd.DataFrame, top_n: int = 20):
    """Which columns are mostly NA, and which are mostly -1 sentinel."""
    na_frac = df.isna().mean().sort_values(ascending=False)
    print(f"\n--- Top {top_n} columns by NA fraction ---")
    print(na_frac.head(top_n))

    # -1 sentinel check only makes sense on numeric columns
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    neg_one_frac = (df[numeric_cols] == -1).mean().sort_values(ascending=False)
    print(f"\n--- Top {top_n} columns by fraction == -1 (possible sentinel) ---")
    print(neg_one_frac.head(top_n))

    return na_frac, neg_one_frac


def target_proxy_check(df: pd.DataFrame, target: str, threshold: float = 0.9):
    """
    Flags any binary/near-binary feature whose value strongly predicts
    the target on its own — a classic sign of post-hoc leakage
    (a field that wouldn't exist at real inference time).
    """
    print(f"\n--- Target-proxy leakage scan (single-feature AUROC > {threshold}) ---")
    y = df[target]
    suspects = []
    for col in df.columns:
        if col == target:
            continue
        series = df[col]
        if series.dtype.kind not in "if":  # numeric only
            continue
        if series.isna().all():
            continue
        try:
            filled = series.fillna(series.median())
            auc = roc_auc_score(y, filled)
            auc = max(auc, 1 - auc)  # direction-agnostic
            if auc > threshold:
                suspects.append((col, round(auc, 4)))
        except Exception:
            continue

    suspects.sort(key=lambda x: -x[1])
    print(f"Found {len(suspects)} suspect columns (AUROC > {threshold}):")
    for col, auc in suspects[:30]:
        print(f"  {col}: single-feature AUROC = {auc}")
    return suspects


def temporal_cohort_check(df: pd.DataFrame, target: str, date_like_cols: list):
    """
    Checks whether classes are drawn from disjoint time windows —
    i.e. does every 'legit' row come from one month and every 'fraud'
    row from different months? That's a cohort-separation leak, not
    a real fraud signal.

    Pass in the column name(s) you suspect carry a date/month token
    (e.g. the "Oct25" pattern you spotted).
    """
    print("\n--- Temporal cohort separation check ---")
    for col in date_like_cols:
        if col not in df.columns:
            print(f"  (column {col} not found, skipping)")
            continue
        cross = pd.crosstab(df[col], df[target])
        print(f"\nColumn: {col}")
        print(cross)


def distributed_separability_check(df: pd.DataFrame, target: str, suspects: list, top_k_exclude: int = None):
    """
    Removes the top-N single-feature separators found above, then checks
    whether a simple model can STILL near-perfectly separate the classes
    using the remaining features. If yes, the leakage isn't confined to
    a few columns -- it's baked into the whole feature set (e.g. two
    different collection cohorts), and needs to be flagged as a
    cautionary finding, not fixed by dropping a few columns.
    """
    from xgboost import XGBClassifier

    exclude_cols = [c for c, _ in suspects]
    if top_k_exclude:
        exclude_cols = exclude_cols[:top_k_exclude]

    feature_cols = [c for c in df.columns
                     if c != target and c not in exclude_cols
                     and df[c].dtype.kind in "if"]

    X = df[feature_cols].fillna(-999)
    y = df[target]

    print(f"\n--- Distributed separability check (excluding {len(exclude_cols)} suspect cols) ---")
    print(f"Remaining numeric features: {len(feature_cols)}")

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    aucs = []
    for train_idx, test_idx in skf.split(X, y):
        model = XGBClassifier(
            n_estimators=100, max_depth=4, eval_metric="logloss",
            use_label_encoder=False, verbosity=0
        )
        model.fit(X.iloc[train_idx], y.iloc[train_idx])
        preds = model.predict_proba(X.iloc[test_idx])[:, 1]
        aucs.append(roc_auc_score(y.iloc[test_idx], preds))

    print(f"Residual CV AUROC: {np.mean(aucs):.4f} +/- {np.std(aucs):.4f}")
    if np.mean(aucs) > 0.95:
        print("WARNING: still near-perfect after removing top separators.")
        print("This suggests leakage is distributed across many features,")
        print("not confined to a handful of columns. Treat as a cautionary")
        print("finding, not something you can 'fix' by dropping columns.")
    return aucs


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", required=True, help="Path to DataSet.csv")
    parser.add_argument("--target", default="F3924", help="Target column name")
    parser.add_argument(
        "--date-cols", nargs="*", default=[],
        help="Column(s) suspected to carry a month/snapshot token (e.g. 'Oct25')"
    )
    args = parser.parse_args()

    date_cols = args.date_cols
    if not date_cols:
        # Auto-detect text/object columns in dataset (e.g. F2230) that might carry cohort strings
        date_cols = [c for c in df.select_dtypes(include=["object"]).columns if c != args.target]
        if date_cols:
            print(f"Auto-detected categorical/date-like columns for temporal cohort check: {date_cols}")

    df = load_data(args.csv)
    class_balance(df, args.target)
    sparsity_report(df)
    suspects = target_proxy_check(df, args.target)
    if date_cols:
        temporal_cohort_check(df, args.target, date_cols)
    distributed_separability_check(df, args.target, suspects, top_k_exclude=len(suspects))

    print("\n--- Audit complete ---")
    print("Next: decide which suspect columns to EXCLUDE from modeling,")
    print("then move to 02_baseline_model.py with the clean feature list.")
