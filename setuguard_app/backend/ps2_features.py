"""
PS2 feature universe for the bank's fraud/mule model.

Source of truth: data/Description.xlsx, sheet "Data_Dicitionary" (3,924-row
data dictionary for DataSet.csv). Every constant below cites the dictionary
column it was read from so the list can be re-derived and checked against
the spreadsheet rather than trusted blindly.

This module is imported by both the offline trainer (harness/train_ps2_model.py)
and the live backend (setuguard_app/backend/app.py) so the two can never
drift apart on which columns are "the model's 18 features."
"""

# Column 4 (Bank_Finalized_Variables) of data/Description.xlsx lists exactly
# 18 non-target rows with a value in that column -- the bank's approved
# modelling features. Order matches the dictionary's row order (by F-number).
BANK_FINALIZED_FEATURES = [
    "F115",   # R_CI_NON_CASH_CHQ_TXN_L14_31D
    "F321",   # RA_NON_CASH_CHQ_AMT_L7_14D
    "F527",   # RA_CI_NON_CASH_CHQ_TXN_CR_L7_31D
    "F531",   # RA_CI_NON_CASH_CHQ_AMT_DB_L7_31D
    "F670",   # MIN_UPI_XFER_TXNS_L7D
    "F1692",  # CASH_TXNS_DB_L14D
    "F2082",  # AVG_NET_BNKING_TXNS_DB_L14D
    "F2122",  # AVG_CASH_TXNS_L31D
    "F2582",  # DA_UPI_TXN_CR_L7_14D
    "F2678",  # DA_ELEC_XFER_AMT_L14_31D
    "F2737",  # DA_NON_CASH_CHQ_AMT_L7_31D
    "F2956",  # D_TA_CI_NON_CASH_CHQ_TXN_CR_L14D
    "F3043",  # D_TA_CASH_TXN_L31D
    "F3836",  # AVG_BAL_14DAYS
    "F3887",  # TENURE_AS_OF_ALERT
    "F3889",  # ACCT_OPN_DAYS (bucket code, e.g. "L7D".."G365D")
    "F3891",  # CUST_OCCP (occupation code, e.g. "salaried")
    "F3894",  # AGE_IN_YRS
]

# Column 4's 19th flagged row: the target itself (value "Target Variable").
TARGET_COLUMN = "F3924"  # FRAUD_TGT

# Of the 18 features above, these two are text/category codes, not numbers
# (Description.xlsx "Description" column: F3889 is a tenure bucket like
# "L7D"/"G365D"; F3891 is an occupation code like "salaried"/"student").
# Confirmed by reading DataSet.csv dtypes: both load as pandas 'object'.
CATEGORICAL_FEATURES = ["F3889", "F3891"]

# Post-resolution outcome features (Description.xlsx rows F3898, F3899,
# F3912-F3915). These describe how/whether an alert was resolved, so they
# only have a value once the fraud/no-fraud outcome is already known --
# using them as model inputs leaks the label.
EXCLUDED_LEAKY_FEATURES = [
    "F3898",  # MIN_RESOLVE_DAYS
    "F3899",  # MAX_RESOLVE_DAYS
    "F3912",  # FRAUD_SUSPECTED
    "F3913",  # OTHER_RESOLUTION
    "F3914",  # FALSE_POSITIVE
    "F3915",  # UNATTENDED
]

# F2230 (MNTH) separates classes temporally by construction. F3900-F3911 are
# 12 "Alert description flag" features (Description.xlsx: each described as
# "Alert description flag") encoding a legacy rule engine's decisions, not
# raw customer behavior. F3919-F3923 are alert counts derived from those same
# legacy alerts. None of these are in Bank_Finalized_Variables; excluded
# explicitly so they can never be pulled in by a future "use all numeric
# columns" shortcut.
EXCLUDED_ALERT_DERIVED = (
    ["F2230"]
    + [f"F{i}" for i in range(3900, 3912)]  # F3900..F3911
    + [f"F{i}" for i in range(3919, 3924)]  # F3919..F3923
)
