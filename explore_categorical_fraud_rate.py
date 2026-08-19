"""
SetuGuard PS2 -- Optional exploration: fraud rate by category
================================================================
Quick check: does fraud concentrate in a specific employment type
or tenure bucket? Purely descriptive -- not part of the model,
just useful context for the report / dashboard.

Usage:
    python explore_categorical_fraud_rate.py --csv DataSet.csv --target F3924
"""

import argparse
import pandas as pd

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", required=True)
    parser.add_argument("--target", default="F3924")
    args = parser.parse_args()

    df = pd.read_csv(args.csv, index_col=0, low_memory=False)

    for col in ["F3889", "F3891"]:
        print(f"\n--- Fraud rate by {col} ---")
        summary = df.groupby(col)[args.target].agg(["count", "sum", "mean"])
        summary.columns = ["total_accounts", "fraud_count", "fraud_rate"]
        summary = summary.sort_values("fraud_rate", ascending=False)
        print(summary)
