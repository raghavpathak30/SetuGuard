# DiCE needs three things: data, a trained model, and a query point to explain. 
# Since we don't have your teammate's real fraud model yet, we'll train a tiny throwaway model on fake data just to see DiCE work end-to-end.

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import dice_ml

# --- Step A: fake toy dataset (stand-in for real PS2 data) ---
data = pd.DataFrame({
    "pass_through_ratio": [0.1, 0.8, 0.2, 0.9, 0.15, 0.85, 0.3, 0.75],
    "off_hours_ratio":    [0.1, 0.6, 0.05, 0.7, 0.2, 0.65, 0.1, 0.5],
    "new_beneficiary_count_7d": [1, 6, 0, 8, 2, 7, 1, 5],
    "is_fraud": [0, 1, 0, 1, 0, 1, 0, 1],
})

# --- Step B: train a throwaway model (real project uses your teammate's XGBoost) ---
X = data.drop(columns="is_fraud")
y = data["is_fraud"]
model = RandomForestClassifier(random_state=0).fit(X, y)

# --- Step C: tell DiCE about your data ---
dice_data = dice_ml.Data(
    dataframe=data,
    continuous_features=["pass_through_ratio", "off_hours_ratio", "new_beneficiary_count_7d"],
    outcome_name="is_fraud"
)

# --- Step D: tell DiCE about your model ---
dice_model = dice_ml.Model(model=model, backend="sklearn")

# --- Step E: ask DiCE to explain one specific "risky" account ---
explainer = dice_ml.Dice(dice_data, dice_model, method="random")

query_instance = X.iloc[[1]]  # the account with pass_through_ratio=0.8 (looks risky)
counterfactuals = explainer.generate_counterfactuals(
    query_instance, total_CFs=2, desired_class="opposite"
)
cf_df = counterfactuals.cf_examples_list[0].final_cfs_df
print("\nOriginal account:")
print(query_instance)
print("\nCounterfactuals (what would need to change):")
print(cf_df)