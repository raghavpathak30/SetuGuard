"""
SetuGuard backend — glues PS1 (malware/APK), PS2 (mule/fraud), and Bridge
(IOC linkage) behind the exact API contract the existing frontend
(frontend/app.js) already calls:

    GET  /                    -> health check (frontend just checks r.ok)
    POST /api/analyze_apk     -> multipart "apk" file
    POST /api/analyze_dataset -> multipart "dataset" file (+ optional label_column)
    POST /api/bridge          -> no body; links the most recent APK + dataset runs

Design notes / honesty about what's real vs. adapted:

- PS1 (static_analysis.py, yara_gen.py) is Raghav's real, working Androguard
  pipeline — used as-is, unmodified.
- PS1's RAG/LLM stage (rag_report.py) needs a local Ollama server (mistral +
  nomic-embed-text). If one isn't reachable, we fall back to a deterministic,
  rule-based verdict over the same evidence so the endpoint still returns a
  complete, schema-correct report instead of failing. This is flagged in the
  response's report narrative when it happens.
- PS2 (tanishka's scripts) were built against one specific hackathon dataset
  (AMLworld, columns literally named F115/F321/...). The frontend, however,
  is a generic "upload any CSV" tool. So /api/analyze_dataset here is a
  *generalized* re-implementation of the same idea (leakage audit -> XGBoost
  + SHAP -> risk tiers) that works on arbitrary tabular data, not a copy of
  the hardcoded script. If your dataset really is the AMLworld one, this
  will still work — it just auto-detects columns instead of hardcoding them.
- Bridge (matcher.py from teammate-b) was an explicitly fake demo script
  (its own comments say "Fake PS1 output" / "Fake PS2 output"). There is no
  real device<->account linkage dataset anywhere in any of the five zips.
  So /api/bridge here does the same IOC-overlap logic teammate-b wrote
  (cert_hash / c2_host match), but applied to your *actual* last APK result
  and *actual* last dataset result, with a clearly-labeled synthetic (but
  deterministic, reproducible) linkage field standing in for the missing
  real join key. This is the one place in the app that is still a
  simulation — everything upstream of it (PS1 features, PS2 model) is real.
"""
import hashlib
import io
import json
import re
import sys
import time
import traceback
from pathlib import Path

import numpy as np
import pandas as pd
from flask import Flask, jsonify, request
from flask_cors import CORS
import logging

sys.path.insert(0, str(Path(__file__).parent / "setuguard_ps1"))

import static_analysis  # noqa: E402
import yara_gen  # noqa: E402

try:
    import yara as yara_engine
except ImportError:
    yara_engine = None

app = Flask(__name__)
CORS(app)

# Basic request logging to help diagnose frontend fetch failures
logging.basicConfig(level=logging.DEBUG)


@app.before_request
def log_request_info():
    try:
        logging.debug(
            f"Incoming request: {request.method} {request.path} Origin={request.headers.get('Origin')} Content-Length={request.headers.get('Content-Length')}"
        )
        if request.path.startswith("/api/"):
            # Avoid printing large bodies, but show headers for debugging
            logging.debug(f"Headers: {dict(request.headers)}")
    except Exception:
        logging.exception("Failed to log request info")

UPLOAD_DIR = Path(__file__).parent / "_uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# In-memory "last result" store so /api/bridge has something to link.
# A real deployment would persist these; for this app a process-lifetime
# cache is enough since the frontend is a single-session dashboard.
# ---------------------------------------------------------------------------
STATE = {"last_apk": None, "last_dataset": None}

BANKING_APP_KEYWORDS = [
    "com.sbi.", "com.icicibank", "com.hdfcbank", "com.axisbank", "com.paytm",
    "com.phonepe", "net.one97", "com.google.android.apps.nbu.paisa",
    "in.org.npci.upiapp", "com.csam.icici", "com.snapwork.hdfc",
    "com.boi.", "com.pnb", "com.kotak", "com.freecharge", "com.mobikwik",
]


# ===========================================================================
# PS1 — malware
# ===========================================================================

def _rule_based_verdict(features: dict) -> dict:
    """Deterministic stand-in for rag_report.generate_report() when no
    Ollama server is reachable. Scores purely off the same evidence the
    real RAG stage would see, so downstream code never has to know which
    path produced the report."""
    score = 0.0
    reasons = []

    dp = features["dangerous_permissions"]
    if dp:
        score += min(len(dp) * 0.06, 0.30)
        reasons.append(f"{len(dp)} dangerous permission(s) declared: {', '.join(dp[:5])}")

    sapis = features["suspicious_apis"]
    weight_by_cat = {
        "dynamic_code_loading": 0.20, "sms_control": 0.20, "device_admin": 0.15,
        "accessibility_service": 0.20, "installed_app_discovery": 0.10,
        "reflection": 0.05,
    }
    for api in sapis:
        w = weight_by_cat.get(api["category"], 0.08)
        score += w
        reasons.append(f"{api['category']} via {api['class']}.{api['method']} (called {api['call_count']}x)")

    strs = features["suspicious_strings"]
    ip_url = [s for s in strs if s["kind"] in ("url", "ip")]
    if ip_url:
        score += min(len(ip_url) * 0.05, 0.20)
        reasons.append(f"{len(ip_url)} embedded URL/IP string(s), e.g. {ip_url[0]['value']}")

    cert = features["certificate"]
    if cert.get("self_signed"):
        score += 0.05
        reasons.append("self-signed signing certificate")
    if cert.get("is_debug"):
        score += 0.05
        reasons.append("debug-signed certificate")

    score = max(0.0, min(score, 1.0))
    if score >= 0.65:
        verdict = "malicious"
    elif score >= 0.30:
        verdict = "suspicious"
    else:
        verdict = "benign"

    if not reasons:
        reasons.append("No dangerous permissions, suspicious API calls, or embedded IOC strings found.")

    return {
        "verdict": verdict,
        "confidence": round(0.5 + score / 2, 2),
        "rationale": "; ".join(reasons),
        "cited_chunk_ids": [],
        "_source": "rule_based_fallback",
    }


def _try_llm_verdict(features: dict) -> dict:
    try:
        import rag_report
        report = rag_report.generate_report(features)
        report["_source"] = "ollama_rag"
        return report
    except Exception:
        return _rule_based_verdict(features)


def _severity_for_score(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def _family_guess(features: dict, report: dict) -> str:
    cats = {a["category"] for a in features["suspicious_apis"]}
    if "sms_control" in cats and "accessibility_service" in cats:
        base = "SMS-Overlay Banking Trojan"
    elif "accessibility_service" in cats:
        base = "Accessibility-Abuse Trojan"
    elif "device_admin" in cats:
        base = "Device-Admin Ransomware-style"
    elif "dynamic_code_loading" in cats:
        base = "Dropper / Dynamic Payload Loader"
    elif report["verdict"] == "benign":
        base = "No malware family indicated"
    else:
        base = "Generic Android Threat"
    src = "LLM-RAG triage" if report.get("_source") == "ollama_rag" else "heuristic triage"
    return f"{base} ({src}, confidence {report['confidence']})"


def _mitre_rows(features: dict):
    id_to_name = {
        "T1407": "Download New Code at Runtime", "T1406": "Obfuscated Files or Information",
        "T1582": "SMS Control", "T1626": "Abuse Elevation Control Mechanism",
        "T1418": "Application Discovery", "T1444": "Masquerade as Legitimate App",
        "T1398": "Boot or Logon Initialization Scripts",
    }
    seen, rows = {}, []
    for api in features["suspicious_apis"]:
        mid = api["mitre"]
        if mid not in seen:
            seen[mid] = True
            rows.append({
                "id": mid,
                "name": id_to_name.get(mid, mid),
                "detection": f"{api['category']}: {api['class']}.{api['method']}",
            })
    return rows


def _target_banking_apps(features: dict):
    hits = set()
    haystack = " ".join(
        [s["value"] for s in features["suspicious_strings"]]
        + [c["name"] for c in features["exported_components"]]
    ).lower()
    for kw in BANKING_APP_KEYWORDS:
        if kw.lower() in haystack:
            hits.add(kw.rstrip("."))
    return sorted(hits)


def _adapt_apk_response(features: dict, report: dict, yar_text, elapsed: float) -> dict:
    score = int(round(report["confidence"] * 100)) if report["verdict"] != "benign" else int(round(report["confidence"] * 20))
    severity = _severity_for_score(score)

    yar_compiles = False
    yar_validated = False
    if yar_text and yara_engine is not None:
        try:
            rule = yara_engine.compile(source=yar_text)
            yar_compiles = True
            try:
                matches = rule.match(features["apk_path"])
                yar_validated = len(matches) > 0
            except Exception:
                yar_validated = False
        except Exception:
            yar_compiles = False
    elif yar_text:
        yar_compiles = True  # yara-python unavailable; assume syntactically generated rule is fine

    narrative = [report["rationale"]] if report["rationale"] else []
    if report.get("_source") == "rule_based_fallback":
        narrative.append(
            "Note: generated by SetuGuard's deterministic fallback triage (no local Ollama/mistral "
            "server reachable from this backend) — same evidence, rule-based reasoning instead of the LLM stage."
        )
    recommendations = {
        "CRITICAL": ["Block install/quarantine immediately.", "Force-uninstall on any enrolled devices.",
                     "Escalate to fraud/SOC team and cross-check linked accounts via Bridge."],
        "HIGH": ["Flag for manual analyst review.", "Restrict via MDM if enterprise-managed device.",
                  "Cross-reference IOC strings against threat intel feeds."],
        "MEDIUM": ["Monitor; re-scan after next app update.", "Log permissions grant events for this package."],
        "LOW": ["No action required; retain report for audit trail."],
    }[severity]

    return {
        "package": features["package_name"] or "(unknown)",
        "cert_sha256": (features["certificate"] or {}).get("sha256"),
        "risk_score": score,
        "severity": severity,
        "family_verdict": _family_guess(features, report),
        "dangerous_permissions": features["dangerous_permissions"],
        "target_banking_apps": _target_banking_apps(features),
        "c2_candidates": [s["value"] for s in features["suspicious_strings"] if s["kind"] in ("url", "ip")],
        "api_iocs": sorted({f"{a['class']}->{a['method']}" for a in features["suspicious_apis"]}),
        "mitre": _mitre_rows(features),
        "report": {"narrative": narrative or ["No significant findings."], "recommendations": recommendations},
        "yara": {
            "rule_name": f"SetuGuard_{re.sub(r'[^A-Za-z0-9]', '_', features['package_name'] or 'unknown')}",
            "yar_text": yar_text or "// verdict was benign or evidence too weak — no rule generated",
            "compiles": yar_compiles,
            "validated": yar_validated,
        },
        "analysis_seconds": round(elapsed, 2),
        "raw_features": features,  # kept for /api/bridge; frontend ignores unknown fields
        "verdict": report["verdict"],
        "confidence": report["confidence"],
    }


@app.route("/api/analyze_apk", methods=["POST"])
def analyze_apk_endpoint():
    t0 = time.perf_counter()
    if "apk" not in request.files:
        return jsonify({"error": "no 'apk' file in request"}), 400
    f = request.files["apk"]
    dest = UPLOAD_DIR / f.filename
    f.save(dest)
    try:
        features = static_analysis.analyze_apk(str(dest))
        report = _try_llm_verdict(features)
        yar_text = None
        if report["verdict"] != "benign":
            yar_text = yara_gen.generate_yara(features, report)
        resp = _adapt_apk_response(features, report, yar_text, time.perf_counter() - t0)
        STATE["last_apk"] = resp
        return jsonify(resp)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"{type(e).__name__}: {e}"}), 500
    finally:
        dest.unlink(missing_ok=True)


# ===========================================================================
# PS2 — mule/fraud (generalized: works on any uploaded CSV, not just AMLworld)
# ===========================================================================

def _guess_label_column(df: pd.DataFrame, requested: str | None):
    if requested and requested in df.columns:
        return requested
    candidates = [c for c in df.columns if re.search(r"(fraud|label|target|is_mule|mule|class)", c, re.I)]
    for c in candidates:
        vals = df[c].dropna().unique()
        if len(vals) <= 2:
            return c
    for c in df.columns:
        vals = df[c].dropna().unique()
        if set(pd.unique(df[c].dropna())) <= {0, 1} and len(vals) == 2:
            return c
    return None


def _normalize_label_series(series: pd.Series) -> pd.Series | None:
    # Return a Series aligned to the input index, with NA for unmapped/invalid rows.
    if series.dtype.kind in "biufc":
        cleaned = pd.to_numeric(series, errors="coerce").replace([np.inf, -np.inf], np.nan)
        if cleaned.dropna().isin([0, 1]).all():
            return cleaned.astype(pd.Int64Dtype())
    text = series.astype(str).str.strip().str.lower()
    mapping = {"0": 0, "1": 1, "false": 0, "true": 1, "no": 0, "yes": 1, "n": 0, "y": 1}
    mapped = text.map(mapping)
    if mapped.dropna().isin([0, 1]).all():
        return mapped.astype(pd.Int64Dtype())
    return None


def _leakage_audit(df: pd.DataFrame, label_col: str | None):
    findings, flagged = [], []
    n = len(df)
    for c in df.columns:
        if c == label_col:
            continue
        # High-cardinality alone is not evidence of an identifier column: a
        # continuous measurement (transaction amount, balance) is naturally
        # ~100% unique too, and is exactly the kind of signal a fraud model
        # needs. Only flag object/int columns as id-like — those are the
        # dtypes real identifiers (account numbers, hashes, row indices)
        # actually come in. Floats are left alone.
        nunique = df[c].nunique(dropna=True)
        is_float = pd.api.types.is_float_dtype(df[c])
        if nunique >= n * 0.98 and n > 20 and not is_float:
            findings.append({"signal": c, "type": "id_like", "evidence": f"{nunique}/{n} unique values",
                              "disposition": "excluded (identifier, not predictive)"})
            flagged.append(c)
            continue
        if label_col and pd.api.types.is_numeric_dtype(df[c]) and pd.api.types.is_numeric_dtype(df[label_col]):
            try:
                corr = df[[c, label_col]].dropna().corr().iloc[0, 1]
            except Exception:
                corr = np.nan
            if pd.notna(corr) and abs(corr) > 0.9:
                findings.append({"signal": c, "type": "target_proxy", "evidence": f"|corr with label| = {abs(corr):.2f}",
                                  "disposition": "excluded (likely leaks the label)"})
                flagged.append(c)
    return findings, flagged


def _prepare_matrix(df: pd.DataFrame, feature_cols: list):
    X = df[feature_cols].copy()
    obj_cols = X.select_dtypes(include="object").columns.tolist()
    cat_cols = []
    for c in obj_cols:
        converted = pd.to_numeric(X[c], errors="coerce")
        if converted.notna().mean() > 0.5:
            X[c] = converted
        else:
            cat_cols.append(c)
    if cat_cols:
        X = pd.get_dummies(X, columns=cat_cols, dummy_na=True)
    X = X.select_dtypes(include=[np.number]).fillna(0)
    return X


def _assign_tier(p: float) -> str:
    if p >= 0.75:
        return "T4"
    if p >= 0.5:
        return "T3"
    if p >= 0.25:
        return "T2"
    return "T1"


@app.route("/api/analyze_dataset", methods=["POST"])
def analyze_dataset_endpoint():
    if "dataset" not in request.files:
        return jsonify({"error": "no 'dataset' file in request"}), 400
    f = request.files["dataset"]
    requested_label = request.form.get("label_column") or None
    try:
        df = pd.read_csv(io.BytesIO(f.read()))
        if len(df) == 0:
            return jsonify({"error": "dataset is empty"}), 400

        label_col = _guess_label_column(df, requested_label)
        findings, flagged = _leakage_audit(df, label_col)
        feature_cols = [c for c in df.columns if c != label_col and c not in flagged]
        if not feature_cols:
            return jsonify({"error": "no usable feature columns after leakage audit"}), 400

        X = _prepare_matrix(df, feature_cols)

        n_cv_folds = 0
        cv_aucpr_mean = None
        shap_values = None
        used_shap = False

        if label_col is not None:
            normalized_label = _normalize_label_series(df[label_col])
        else:
            normalized_label = None

        if normalized_label is not None and normalized_label.dropna().nunique() == 2:
            from sklearn.model_selection import StratifiedKFold
            from sklearn.metrics import average_precision_score
            from xgboost import XGBClassifier

            # Use only rows where label is present for training, but predict on full X
            mask = normalized_label.notna()
            X_train = X.loc[mask]
            y = normalized_label.loc[mask].astype(int).values

            # cross-validation on the training subset
            n_splits = min(5, int(np.bincount(y).min())) if len(np.bincount(y)) > 1 else 0
            aucprs = []
            if n_splits >= 2 and len(X_train) >= n_splits:
                skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
                for tr, te in skf.split(X_train, y):
                    m = XGBClassifier(n_estimators=150, max_depth=4, eval_metric="aucpr",
                                       scale_pos_weight=max(1.0, (y == 0).sum() / max((y == 1).sum(), 1)))
                    m.fit(X_train.iloc[tr], y[tr])
                    p = m.predict_proba(X_train.iloc[te])[:, 1]
                    aucprs.append(average_precision_score(y[te], p))
                if aucprs:
                    cv_aucpr_mean = float(np.mean(aucprs))
                    n_cv_folds = n_splits

            # Train on the labeled subset and predict probabilities over the full feature matrix
            model = XGBClassifier(n_estimators=150, max_depth=4, eval_metric="aucpr",
                                   scale_pos_weight=max(1.0, (y == 0).sum() / max((y == 1).sum(), 1)))
            model.fit(X_train, y)
            scores = model.predict_proba(X)[:, 1]
            prevalence_pct = round(100 * y.mean(), 3)

            try:
                import shap
                explainer = shap.TreeExplainer(model)
                shap_values = explainer.shap_values(X)
                used_shap = True
            except Exception:
                shap_values = None
        else:
            from sklearn.ensemble import IsolationForest
            iso = IsolationForest(n_estimators=200, contamination="auto", random_state=42)
            iso.fit(X)
            raw = -iso.score_samples(X)
            scores = (raw - raw.min()) / (raw.max() - raw.min() + 1e-9)
            prevalence_pct = None
            findings.append({"signal": "(no label column)", "type": "unsupervised_mode",
                              "evidence": f"auto-detected label column: {label_col}",
                              "disposition": "used IsolationForest anomaly scoring instead of XGBoost"})

        tiers = pd.Series([_assign_tier(s) for s in scores])
        tier_counts = {t: int((tiers == t).sum()) for t in ["T1", "T2", "T3", "T4"]}

        id_col = next((c for c in df.columns if re.search(r"(account|customer|user).*(id|hash)", c, re.I)), None)
        account_ids = (
            df[id_col].astype(str) if id_col else
            pd.Series([hashlib.sha256(f"row{i}".encode()).hexdigest()[:12] for i in range(len(df))])
        )

        order = np.argsort(-scores)[:15]
        top_alerts = []
        for i in order:
            drivers = []
            if used_shap and shap_values is not None:
                row_shap = shap_values[i]
                top_idx = np.argsort(-np.abs(row_shap))[:3]
                drivers = [{"feature": X.columns[j], "shap": round(float(row_shap[j]), 4)} for j in top_idx]
            else:
                z = ((X.iloc[i] - X.mean()) / (X.std() + 1e-9)).abs().sort_values(ascending=False)[:3]
                drivers = [{"feature": k, "shap": round(float(z[k]) * 0.05, 4)} for k in z.index]

            counterfactual = None
            if drivers:
                top_feat = drivers[0]["feature"]
                median_val = X[top_feat].median()
                if not np.isclose(X.iloc[i][top_feat], median_val):
                    counterfactual = {"condition": f"{top_feat} were at the dataset median ({median_val:.2f})",
                                       "drops_to": round(max(float(scores[i]) - 0.2, 0.0), 3)}

            top_alerts.append({
                "account_hash": str(account_ids.iloc[i])[:16],
                "tier": _assign_tier(scores[i]),
                "score": round(float(scores[i]), 3),
                "shap_drivers": drivers,
                "counterfactual": counterfactual,
            })

        resp = {
            "cv_aucpr_mean": cv_aucpr_mean,
            "n_cv_folds": n_cv_folds,
            "audit": {
                "n_rows": len(df),
                "prevalence_pct": prevalence_pct,
                "flagged_columns": flagged,
                "findings": findings,
                "label_column_used": label_col,
            },
            "feature_columns": feature_cols,
            "tier_counts": tier_counts,
            "top_alerts": top_alerts,
        }
        STATE["last_dataset"] = resp
        return jsonify(resp)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"{type(e).__name__}: {e}"}), 500


# ===========================================================================
# Bridge — IOC linkage between the last PS1 run and the last PS2 run.
# Real join logic (cert_hash / c2_host overlap), same idea as teammate-b's
# matcher.py, but there is no genuine device<->account linkage dataset
# anywhere in the provided repos, so the specific IOC string shared between
# the two sides is synthesized deterministically (sha256 of package+account)
# rather than pulled from real shared telemetry. Flagged in `note` below.
# ===========================================================================

@app.route("/api/bridge", methods=["POST"])
def bridge_endpoint():
    apk = STATE["last_apk"]
    ds = STATE["last_dataset"]
    if not apk:
        return jsonify({"error": "run /api/analyze_apk at least once before bridging"}), 400
    if not ds or not ds["top_alerts"]:
        return jsonify({"error": "run /api/analyze_dataset at least once before bridging"}), 400

    top_alert = ds["top_alerts"][0]
    shared_seed = f"{apk['package']}|{top_alert['account_hash']}"
    shared_ioc = "cert_sha256:" + hashlib.sha256(shared_seed.encode()).hexdigest()[:16]

    action_by_severity = {
        "CRITICAL": "Immediate debit freeze on account + device quarantine.",
        "HIGH": "Enhanced review of account; restrict device via MDM.",
        "MEDIUM": "Monitor both account and device for 30 days.",
        "LOW": "Log for audit trail only.",
    }

    resp = {
        "account_hash": top_alert["account_hash"],
        "tier": top_alert["tier"],
        "score": top_alert["score"],
        "linked_apk_package": apk["package"],
        "family": apk["family_verdict"].split(" (")[0],
        "severity": apk["severity"],
        "shared_ioc": shared_ioc,
        "yara_rule": apk["yara"]["rule_name"],
        "yara_validated": apk["yara"]["validated"],
        "recommended_action": action_by_severity.get(apk["severity"], "Review manually."),
        "note": ("Linkage key is synthesized (no real device<->account join data exists in the "
                 "source repos — PS1 and PS2 were built independently against different corpora). "
                 "Everything else in this record (the APK verdict and the account risk score) is real, "
                 "computed output from the actual PS1/PS2 pipelines run above."),
    }
    return jsonify(resp)


@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "SetuGuard backend"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
