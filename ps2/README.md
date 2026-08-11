# ps2/ — offline research artifacts, not the shipping model

`01_data_audit.py` through `07_ps2_bridge_exporter.py` are offline research artifacts. They produced the leakage audit that informed `BANK_FINALIZED_FEATURES` / `EXCLUDED_LEAKY_FEATURES` / `EXCLUDED_ALERT_DERIVED`. They do not produce any number that appears in the report or the demo.

The shipping PS2 model comes from `harness/train_ps2_model.py` and is served from `models/ps2_xgb_v1.json` by `/api/analyze_dataset`, which is inference-only — no training, cross-validation, or SHAP-explainer fitting happens in that request path.

`06_graph_features.py` assigns graph features using the target label — `map_graph_features_to_dataset()` sorts nodes by betweenness centrality and assigns the top-betweenness nodes to fraud rows via `fraud_mask = combined_df[target_col] == 1`, before any model sees the data. It is label leakage and is excluded from all claims. The "mules sit at network bridges" conclusion is withdrawn.

`07_ps2_bridge_exporter.py` hardcoded `shap_drivers`, `generated_rules`, and `rule_validated` identically across all 9,082 records. It is dead code in the live path.
