"""
SetuGuard PS2 — Step 4: DiCE Counterfactual Explanations
=========================================================
Week 2 Task for PS2 Owner

What it does:
  1. Identifies accounts in Tier 3 (Enhanced Review) and Tier 4 (Debit Freeze)
     or high-risk score brackets from baseline predictions.
  2. Calculates minimum necessary feature changes (counterfactuals) required
     to drop the account risk score down to Tier 2 / Tier 1 (Safe).
  3. Outputs auditable, human-readable counterfactual rules in JSON format:
     e.g., "Account 7f3a...e21 -> T2 if: pass_through_ratio < 0.40 AND new_beneficiary_count_7d < 3"

Usage:
    python 04_dice_counterfactuals.py --csv DataSet.csv --predictions baseline_predictions.csv
"""

import argparse
import json
import numpy as np
import pandas as pd
from xgboost import XGBClassifier
from sklearn.model_selection import StratifiedKFold
import importlib.util
spec = importlib.util.spec_from_file_location("baseline_module", "02_baseline_model.py")
baseline_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline_module)
prepare_features = baseline_module.prepare_features
assign_risk_tier = baseline_module.assign_risk_tier


def generate_tree_counterfactual(model, sample_row: pd.Series, feature_cols: list, target_tier_score: float = 0.25) -> dict:
    """
    Computes actionable feature changes required to reduce the model's
    predicted probability below `target_tier_score`.
    """
    current_val = sample_row.astype(float).copy()
    row_df = current_val.to_frame().T
    current_pred = float(model.predict_proba(row_df)[:, 1][0])
    
    if current_pred <= target_tier_score:
        return {
            "current_score": round(current_pred, 4),
            "target_score": target_tier_score,
            "status": "Already low risk",
            "conditions": []
        }

    # Find feature sensitivity by perturbing each feature toward lower risk
    perturbations = []
    for col in feature_cols:
        val = current_val[col]
        # Skip binary flags or non-numeric if immutable
        if col in ["account_id", "true_label"]:
            continue
            
        # Test reducing value by 25%, 50%, 75% or setting to median/zero
        test_vals = [val * 0.75, val * 0.50, val * 0.25, 0.0]
        best_delta = 0
        best_new_pred = current_pred
        best_val = val
        
        for t_val in test_vals:
            temp_row = current_val.copy()
            temp_row[col] = t_val
            t_pred = float(model.predict_proba(temp_row.to_frame().T)[:, 1][0])
            if t_pred < best_new_pred:
                best_new_pred = t_pred
                best_val = t_val
                best_delta = current_pred - t_pred
                
        if best_delta > 0.01:
            perturbations.append({
                "feature": col,
                "current_value": round(float(val), 4),
                "proposed_value": round(float(best_val), 4),
                "risk_reduction": round(float(best_delta), 4)
            })

    # Sort perturbations by highest risk reduction
    perturbations.sort(key=lambda x: -x["risk_reduction"])
    
    # Formulate compound counterfactual condition
    conditions = []
    simulated_row = current_val.copy()
    simulated_pred = current_pred
    
    for p in perturbations[:3]: # top 3 actionable features
        feat = p["feature"]
        simulated_row[feat] = p["proposed_value"]
        simulated_pred = float(model.predict_proba(simulated_row.to_frame().T)[:, 1][0])
        conditions.append(f"{feat} <= {p['proposed_value']}")
        if simulated_pred <= target_tier_score:
            break
            
    return {
        "current_score": round(current_pred, 4),
        "simulated_score": round(simulated_pred, 4),
        "target_tier": assign_risk_tier(simulated_pred),
        "conditions": conditions,
        "actionable_steps": perturbations[:3]
    }


def run_counterfactual_pipeline(csv_path: str, predictions_path: str, output_json: str):
    print(f"Loading data from {csv_path} and predictions from {predictions_path}...")
    df = pd.read_csv(csv_path, index_col=0, low_memory=False)
    preds_df = pd.read_csv(predictions_path)
    
    X, y, feature_cols = prepare_features(df, "F3924")
    X = X.astype(float)
    
    # Train full baseline XGBoost model
    neg, pos = (y == 0).sum(), (y == 1).sum()
    model = XGBClassifier(
        n_estimators=200, max_depth=4, learning_rate=0.05,
        subsample=0.8, colsample_bytree=0.8, scale_pos_weight=neg/pos,
        eval_metric="aucpr", use_label_encoder=False, verbosity=0
    )
    model.fit(X, y)
    
    # Filter for elevated risk accounts (T2, T3, T4 or top scores)
    high_risk_mask = preds_df["calibrated_score"] > 0.25
    high_risk_accounts = preds_df[high_risk_mask].copy()
    
    if len(high_risk_accounts) == 0:
        print("No T2/T3/T4 accounts found in predictions, taking top 10 highest risk accounts...")
        high_risk_accounts = preds_df.sort_values(by="calibrated_score", ascending=False).head(10)
        
    print(f"Generating counterfactuals for {len(high_risk_accounts)} elevated risk accounts...")
    
    results = {}
    for idx, row in high_risk_accounts.iterrows():
        acc_id = row["account_id"]
        sample_x = X.loc[acc_id]
        cf_res = generate_tree_counterfactual(model, sample_x, X.columns.tolist())
        cf_res["original_tier"] = row["risk_tier"]
        results[str(acc_id)] = cf_res
        
    with open(output_json, "w") as f:
        json.dump(results, f, indent=2)
        
    print(f"\nSaved counterfactual explanations to '{output_json}'")
    
    # Display sample alert report
    sample_acc = list(results.keys())[0]
    print("\n--- SAMPLE INVESTIGATOR COUNTERFACTUAL ALERT ---")
    print(f"Account ID: {sample_acc}")
    print(f"Original Tier: {results[sample_acc]['original_tier']} (Score: {results[sample_acc]['current_score']})")
    print(f"Target Tier: {results[sample_acc]['target_tier']} (Simulated Score: {results[sample_acc]['simulated_score']})")
    print("Actionable Counterfactual Condition:")
    print("  IF " + " AND ".join(results[sample_acc]['conditions']))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", default="DataSet.csv")
    parser.add_argument("--predictions", default="baseline_predictions.csv")
    parser.add_argument("--output", default="counterfactual_explanations.json")
    args = parser.parse_args()

    run_counterfactual_pipeline(args.csv, args.predictions, args.output)
