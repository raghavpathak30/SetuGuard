# SetuGuard PS2: Banking Mule Account Detection Engine — Technical Report & Verification Summary

**Author**: PS2 Model Owner (Tanishka)  
**Branch**: `tanishka/ps2-mule-detection`  
**Repository**: [`raghavpathak30/SetuGuard`](https://github.com/raghavpathak30/SetuGuard)  
**Last Updated**: August 2026  

---

## Executive Summary

The **PS2 Mule Account Detection Engine** is a core component of SetuGuard designed to identify banking mule accounts operating within transaction networks. PS2 leverages a **22-feature tabular + graph hybrid machine learning pipeline** (18 bank-recommended non-leaky tabular features + 4 graph-topology features derived from transaction networks), Platt-calibrated probability scoring, 4-tier risk classification, and **DiCE actionable counterfactual explainability**.

All 7 core PS2 pipeline stages, statistical benchmarks, non-leaky feature extraction routines, and compliance payload exporters are **100% implemented, verified, and committed**.

---

## Pipeline Architecture & Module Breakdown

| Step | Script File | Status | Description | Core Artifact Output |
|---|---|---|---|---|
| **01** | [`01_data_audit.py`](file:///e:/BOI_hackathon/01_data_audit.py) | **COMPLETE** | Audits target imbalance (~111:1), NA sparsity, $-1$ sentinels, and target-proxy leakage features (`F3912`, `F2230`). | Terminal audit report |
| **02** | [`02_baseline_model.py`](file:///e:/BOI_hackathon/02_baseline_model.py) | **COMPLETE** | Trains XGBoost + SHAP on 18 bank features with Stratified 5-Fold CV & 4-tier risk categorization. | [`baseline_predictions.csv`](file:///e:/BOI_hackathon/baseline_predictions.csv) |
| **03** | [`03_amlworld_risk_spike.py`](file:///e:/BOI_hackathon/03_amlworld_risk_spike.py) | **COMPLETE** | Benchmarks NetworkX graph operations (Louvain communities, betweenness centrality, PageRank) on AMLworld dataset. | Graph performance timings |
| **04** | [`04_dice_counterfactuals.py`](file:///e:/BOI_hackathon/04_dice_counterfactuals.py) | **COMPLETE** | Generates actionable feature modification rules to transition Tier 3/4 accounts to safe tiers (T1/T2). | [`counterfactual_explanations.json`](file:///e:/BOI_hackathon/counterfactual_explanations.json) |
| **05** | [`05_ulb_validation.py`](file:///e:/BOI_hackathon/05_ulb_validation.py) | **COMPLETE** | Reproducibility benchmark validating Stratified 5-Fold CV on ULB Credit-Card Fraud dataset (284,807 transactions). | AUCPR target validation |
| **06** | [`06_graph_features.py`](file:///e:/BOI_hackathon/06_graph_features.py) | **COMPLETE (Refactored)** | Extracts 4 graph topology features (Louvain community, betweenness centrality, PageRank, fan-in/fan-out ratio) and maps them cleanly without target leakage. | [`raw_graph_features.csv`](file:///e:/BOI_hackathon/raw_graph_features.csv) |
| **07** | [`07_ps2_bridge_exporter.py`](file:///e:/BOI_hackathon/07_ps2_bridge_exporter.py) | **COMPLETE** | Formats predictions, Platt risk scores, SHAP drivers, graph metrics, and DiCE rules into DPDP-compliant `AuditTrailRecord` JSON schema. | [`ps2_bridge_payload.json`](file:///e:/BOI_hackathon/ps2_bridge_payload.json) |
| **08** | [`08_ps2_multiseed_benchmark.py`](file:///e:/BOI_hackathon/08_ps2_multiseed_benchmark.py) | **COMPLETE** | Evaluates multi-seed statistical confidence intervals across 5 random seeds (42, 100, 2026, 7, 99). | Statistical variance report |

---

## Technical Audit & Target Leakage Remediation

### The Target Leakage Issue
During code audit, a target-proxy leakage pattern was identified in [`06_graph_features.py`](file:///e:/BOI_hackathon/06_graph_features.py). The original implementation sorted AMLworld graph nodes by betweenness centrality descending and assigned top-betweenness bridge nodes exclusively to rows where `target_col == 1` (`fraud_mask`). This introduced **target leakage** — utilizing ground-truth labels during feature extraction — rendering downstream centrality findings circular.

### The Fix Implemented
In accordance with rigorous ML engineering standards:
1. `map_graph_features_to_dataset()` was refactored to perform **label-independent random sampling mapping**. Graph topology features are mapped onto accounts without inspecting `target_col` (`F3924`).
2. Downstream XGBoost evaluation was re-run to confirm genuine feature importance and non-circular performance metrics.

---

## 4-Tier Risk Categorization Schema

PS2 maps continuous Platt-calibrated risk probabilities $P(\text{Mule} \mid X)$ into 4 operational tiers:

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                           PS2 OPERATIONAL RISK TIERS                           │
├──────────┬──────────────────┬─────────────────┬────────────────────────────────┤
│ Risk Tier│ Risk Score Range │ Risk Status     │ Recommended Operational Action │
├──────────┼──────────────────┼─────────────────┼────────────────────────────────┤
│ Tier 1   │ [0.00, 0.25)     │ Safe            │ Low risk — no action required  │
│ Tier 2   │ [0.25, 0.50)     │ Monitor         │ Automated transaction tracking │
│ Tier 3   │ [0.50, 0.75)     │ Enhanced Review │ Flag for fraud desk analyst    │
│ Tier 4   │ [0.75, 1.00]     │ High Risk / Mule│ Temporary debit freeze         │
└──────────┴──────────────────┴─────────────────┴────────────────────────────────┘
```

---

## Compliance & Interoperability (`ps2_bridge_payload.json`)

PS2 exports data in full compliance with **DPDP Act 2023** using HMAC-SHA256 account pseudonymization (`account_id_hash`). Each record contains:
- `alert_id` (UUIDv4)
- `account_id_hash` (Pseudonymized HMAC digest)
- `model_version` (`v2.0.0-xgb-platt-graph`)
- `risk_score` & `risk_tier`
- `shap_drivers` (Top positive/negative feature drivers)
- `counterfactual` (Actionable DiCE remediation rule)
- `regulatory_refs` (`I4C-2026-ALERT`, `NPCI-MULE-FEED`)
- `recommended_action` & `investigator_status`

This payload is consumed directly by **Part 3 (Bridge)** for cross-modal threat-device linkage and **Part 4 (Dashboard)** for compliance UI rendering.
