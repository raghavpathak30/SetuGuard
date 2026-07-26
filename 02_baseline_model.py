"""
SetuGuard PS2 — Step 2: Baseline XGBoost + SHAP model
=======================================================
Run this AFTER 01_data_audit.py has told you which columns to exclude.

Trains on the organizer's bank-recommended non-leaky feature list,
evaluates honestly with stratified 5-fold CV (AUCPR is the headline
metric because AUROC overstates performance at ~111:1 imbalance),
and produces SHAP explanations per prediction.

Usage:
    python 02_baseline_model.py --csv path/to/DataSet.csv --target F3924

Fill in BANK_RECOMMENDED_FEATURES below with the actual 18 columns
from the organizer's problem statement brief -- this script cannot
guess that list for you.
"""

import argparse
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import average_precision_score, roc_auc_score
from xgboost import XGBClassifier

# The 18 bank-recommended, non-leaky features named in the organizer's brief.
BANK_RECOMMENDED_FEATURES = [
    "F115", "F321", "F527", "F531", "F670", "F1692", "F2082", "F2122",
    "F2582", "F2678", "F2737", "F2956", "F3043", "F3836", "F3887",
    "F3889", "F3891", "F3894",
]

# Columns confirmed leaky by the audit -- always exclude these regardless
# of whether they appear in the recommended list.
KNOWN_LEAKY_COLUMNS = ["F3912", "F2230"]


def prepare_features(df: pd.DataFrame, target: str) -> tuple[pd.DataFrame, pd.Series, list]:
    if BANK_RECOMMENDED_FEATURES:
        feature_cols = [c for c in BANK_RECOMMENDED_FEATURES if c not in KNOWN_LEAKY_COLUMNS]
    else:
        print("WARNING: BANK_RECOMMENDED_FEATURES is empty -- falling back to")
        print("all numeric columns minus known leaky ones. Fill in the real")
        print("18-feature list from the organizer brief before trusting results.")
        feature_cols = [
            c for c in df.select_dtypes(include=[np.number]).columns
            if c != target and c not in KNOWN_LEAKY_COLUMNS
        ]

    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        raise ValueError(f"These feature columns aren't in the dataset: {missing}")

    X = df[feature_cols].copy()

    # Some 'object'-dtype columns are numbers stored as text (a stray typo
    # or a value like "1,000" with a comma) -- those we coerce to numeric.
    # Others are GENUINELY categorical (e.g. employment type: "selfemployed",
    # "student", "salaried"; or a tenure code like "G365D") -- forcing those
    # to numeric would wipe out every row as NaN, which is what happened
    # with F3889/F3891. We tell the two apart by trying numeric conversion
    # first and checking how much of the column survives: if almost nothing
    # converts, it's categorical and gets one-hot encoded instead.
    object_cols = X.select_dtypes(include="object").columns.tolist()
    categorical_cols = []
    if object_cols:
        print(f"NOTE: these columns were read as text: {object_cols}")
        for col in object_cols:
            converted = pd.to_numeric(X[col], errors="coerce")
            survival_rate = converted.notna().mean()
            if survival_rate > 0.5:
                # Mostly real numbers with a few stray bad values -- coerce.
                X[col] = converted
                print(f"  {col}: treated as numeric ({survival_rate:.0%} of values converted)")
            else:
                # Genuinely categorical (e.g. employment type, tenure code).
                categorical_cols.append(col)
                print(f"  {col}: treated as categorical (only {survival_rate:.0%} "
                      f"looked numeric) -- will one-hot encode")

    if categorical_cols:
        X = pd.get_dummies(X, columns=categorical_cols, dummy_na=True)
        print(f"  One-hot encoded {categorical_cols} into "
              f"{X.shape[1] - (len(feature_cols) - len(categorical_cols))} binary columns")

    y = df[target].astype(int)
    return X, y, feature_cols


def assign_risk_tier(score: float) -> str:
    """Assigns risk tier based on Platt-calibrated probability score."""
    if score <= 0.25:
        return "T1 (No action)"
    elif score <= 0.55:
        return "T2 (Monitor)"
    elif score <= 0.80:
        return "T3 (Enhanced review)"
    else:
        return "T4 (Temporary debit freeze)"


def train_and_evaluate(X: pd.DataFrame, y: pd.Series, n_splits: int = 5):
    """
    Stratified K-fold CV with Platt Calibration & Risk Tier Scoring.
    """
    from sklearn.calibration import CalibratedClassifierCV

    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)

    aucpr_scores, auroc_scores = [], []
    fold_models = []
    oof_raw_preds = np.zeros(len(X))
    oof_calibrated_preds = np.zeros(len(X))

    for fold, (train_idx, test_idx) in enumerate(skf.split(X, y), start=1):
        X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
        y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]

        neg, pos = (y_train == 0).sum(), (y_train == 1).sum()
        scale_pos_weight = neg / pos

        base_model = XGBClassifier(
            n_estimators=200,
            max_depth=4,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            scale_pos_weight=scale_pos_weight,
            eval_metric="aucpr",
            use_label_encoder=False,
            verbosity=0,
        )

        # Platt Calibration (sigmoid)
        calibrated_model = CalibratedClassifierCV(estimator=base_model, method="sigmoid", cv=3)
        calibrated_model.fit(X_train, y_train)

        # Raw base model fit for direct SHAP tree analysis
        base_model.fit(X_train, y_train)

        raw_preds = base_model.predict_proba(X_test)[:, 1]
        cal_preds = calibrated_model.predict_proba(X_test)[:, 1]

        oof_raw_preds[test_idx] = raw_preds
        oof_calibrated_preds[test_idx] = cal_preds

        aucpr = average_precision_score(y_test, cal_preds)
        auroc = roc_auc_score(y_test, cal_preds)

        aucpr_scores.append(aucpr)
        auroc_scores.append(auroc)
        fold_models.append((base_model, calibrated_model))

        print(f"Fold {fold}: AUCPR={aucpr:.4f}  AUROC={auroc:.4f}  "
              f"(train pos={pos}, test pos={y_test.sum()})")

    print(f"\nMean AUCPR: {np.mean(aucpr_scores):.4f} +/- {np.std(aucpr_scores):.4f}")
    print(f"Mean AUROC: {np.mean(auroc_scores):.4f} +/- {np.std(auroc_scores):.4f}")

    baseline_prevalence = y.mean()
    lift = np.mean(aucpr_scores) / baseline_prevalence
    print(f"Prevalence baseline AUCPR ~ {baseline_prevalence:.4f}  "
          f"({lift:.1f}x lift over baseline)")

    return fold_models, oof_raw_preds, oof_calibrated_preds, aucpr_scores, auroc_scores


def explain_with_shap(model, X: pd.DataFrame, sample_size: int = 5):
    import shap

    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X)

    print(f"\n--- SHAP: top drivers for first {sample_size} rows ---")
    for i in range(min(sample_size, len(X))):
        row_shap = pd.Series(shap_values[i], index=X.columns).sort_values(
            key=abs, ascending=False
        )
        print(f"\nRow {X.index[i]}:")
        print(row_shap.head(5))

    return shap_values


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", required=True)
    parser.add_argument("--target", default="F3924")
    parser.add_argument("--output", default="baseline_predictions.csv")
    args = parser.parse_args()

    df = pd.read_csv(args.csv, index_col=0, low_memory=False)
    X, y, feature_cols = prepare_features(df, args.target)

    print(f"Training on {len(feature_cols)} features, {len(X)} rows, "
          f"{y.sum()} positive cases")

    fold_models, oof_raw, oof_cal, aucpr_scores, auroc_scores = train_and_evaluate(X, y)

    # Compute SHAP explanations using final fold base model
    last_base_model = fold_models[-1][0]
    X_filled = X.fillna(-999)
    explain_with_shap(last_base_model, X_filled.iloc[:10])

    # Construct predictions DataFrame with 4-Tier Risk Score
    results_df = pd.DataFrame({
        "account_id": df.index,
        "true_label": y,
        "raw_score": np.round(oof_raw, 4),
        "calibrated_score": np.round(oof_cal, 4),
        "risk_tier": [assign_risk_tier(s) for s in oof_cal]
    })

    results_df.to_csv(args.output, index=False)
    print(f"\nSaved baseline predictions with 4-tier risk scores to '{args.output}'")
    print(f"Risk Tier Breakdown:\n{results_df['risk_tier'].value_counts()}")

    print("\n--- Baseline complete ---")
