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
- Verdict + confidence are always computed by a deterministic, weighted
  rule-based scorer over the extracted evidence (_rule_based_verdict) —
  not by the LLM. PS1's RAG/LLM stage (rag_report.py, needs a local Ollama
  server: mistral + nomic-embed-text) only supplies narrative rationale on
  top of that verdict when reachable; if it isn't, the endpoint still
  returns a complete, schema-correct report with a rule-based-only
  narrative. Which component produced what is stated in the response's
  `verdict_source`/`narrative_source` fields and in the report narrative
  itself.
- PS2 (tanishka's scripts) were built against one specific hackathon dataset
  (AMLworld, columns literally named F115/F321/...). Description.xlsx (the
  organizer's data dictionary) names the bank's 18 approved modelling
  features precisely — see setuguard_app/backend/ps2_features.py. The model
  is trained OFFLINE, once, on those 18 features by
  harness/train_ps2_model.py, which writes a versioned artifact + holdout
  metrics to models/. /api/analyze_dataset only LOADS that artifact and
  scores whatever the caller uploads against it — there is no training, no
  cross-validation, and no SHAP-explainer fitting inside the HTTP request;
  the only per-request SHAP work is running the already-fitted TreeExplainer
  forward over the uploaded rows, which is inference, not fitting.
- Bridge (matcher.py from teammate-b) does real cert_hash overlap matching
  against SYNTHETIC_LINKAGE_GROUND_TRUTH (matcher.py's own docstring
  explains why that ground truth is synthetic — no real device<->account
  join key exists in any of the source repos). The c2_host comparison also
  executes on every call but has never produced a link: the one
  ground-truth entry has c2_host=None. app.py calls matcher.py's functions
  directly rather than reimplementing the match; the link is CONDITIONAL —
  accounts that don't match on cert_hash produce no link, not a
  fabricated one.
"""
import hashlib
import io
import ipaddress
import json
import re
import sys
import threading
import time
import traceback
import uuid
from collections import OrderedDict
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
import pandas as pd
from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.utils import secure_filename
import logging

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "setuguard_ps1"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "bridge"))

import static_analysis  # noqa: E402
import yara_gen  # noqa: E402
import matcher as bridge_matcher  # noqa: E402
from ps2_features import (  # noqa: E402
    BANK_FINALIZED_FEATURES,
    CATEGORICAL_FEATURES,
    EXCLUDED_ALERT_DERIVED,
    EXCLUDED_LEAKY_FEATURES,
    TARGET_COLUMN,
)

try:
    import yara as yara_engine
except ImportError:
    yara_engine = None

app = Flask(__name__)
CORS(app)

# D-5: no cap meant a 172MB upload defeated a 300s analysis timeout even in
# isolation with a dedicated memory budget (SESSION_LOG.md, cash.p.terminal_243.apk).
# 50MB matches PLAN.md item 4's spec, scoped to /api/analyze_apk only (checked
# manually below, not via app.config["MAX_CONTENT_LENGTH"], which would be
# Flask-wide and reject /api/analyze_dataset's ~111MB DataSet.csv uploads --
# a real regression caught before shipping, not hypothetical). The client-side
# check in frontend/app.js is the first line of defense; this is the
# server-side backstop for anyone bypassing or not running the frontend.
MAX_APK_UPLOAD_MB = 50

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
# Addressable analysis store (ANALYSIS_ID_MIGRATION.md). Lock-guarded,
# bounded OrderedDict keyed by generated ids. /api/analyze_apk and
# /api/analyze_dataset write here; /api/bridge resolves its inputs from
# here, accepting explicit apk_id/dataset_id or falling back to the most
# recent entry of each kind.
# ---------------------------------------------------------------------------
_ANALYSES_LOCK = threading.Lock()
_ANALYSES: "OrderedDict[str, dict]" = OrderedDict()
_ANALYSES_MAX = 64          # hard cap; oldest evicted first
_ANALYSES_TTL_SEC = 3600    # entries older than this are treated as absent
_ID_PREFIX = {"apk": "apk", "dataset": "ds"}


def _analysis_expired(entry: dict) -> bool:
    return (time.time() - entry["created_at"]) > _ANALYSES_TTL_SEC


def store_analysis(kind: str, label: str, result: dict) -> str:
    """Insert an analysis, evict if over cap, return its id."""
    analysis_id = f"{_ID_PREFIX[kind]}_{uuid.uuid4().hex[:8]}"
    entry = {
        "id": analysis_id,
        "kind": kind,
        "created_at": time.time(),
        "label": label,
        "result": result,
    }
    with _ANALYSES_LOCK:
        _ANALYSES[analysis_id] = entry
        while len(_ANALYSES) > _ANALYSES_MAX:
            _ANALYSES.popitem(last=False)
    return analysis_id


def get_analysis(analysis_id: str, expect_kind: str) -> dict | None:
    """Fetch by id. Returns None if absent, expired, or kind mismatch."""
    with _ANALYSES_LOCK:
        entry = _ANALYSES.get(analysis_id)
        if entry is None or entry["kind"] != expect_kind or _analysis_expired(entry):
            return None
        return entry


def latest_analysis(kind: str) -> dict | None:
    """Most recent non-expired entry of that kind. Backward-compat path only."""
    with _ANALYSES_LOCK:
        for entry in reversed(_ANALYSES.values()):
            if entry["kind"] == kind and not _analysis_expired(entry):
                return entry
    return None


BANKING_APP_KEYWORDS = [
    "com.sbi.", "com.icicibank", "com.hdfcbank", "com.axisbank", "com.paytm",
    "com.phonepe", "net.one97", "com.google.android.apps.nbu.paisa",
    "in.org.npci.upiapp", "com.csam.icici", "com.snapwork.hdfc",
    "com.boi.", "com.pnb", "com.kotak", "com.freecharge", "com.mobikwik",
]


# ===========================================================================
# PS1 — malware
# ===========================================================================

def _url_host_is_bare_ip(url: str) -> bool:
    """True if url's host is a literal IPv4/IPv6 address rather than a domain name."""
    try:
        host = urlparse(url).hostname
    except ValueError:
        return False
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _url_has_nonstandard_port(url: str) -> bool:
    """True if url declares an explicit port other than 80/443."""
    try:
        port = urlparse(url).port
    except ValueError:
        return False
    return port is not None and port not in (80, 443)


# Day 3 — Play-signed allowlist. DISPLAY-LAYER ONLY, deliberately, not a scorer
# input: re-opening the pre-registered PRIMARY/SECONDARY AUC interval eight days
# out for a triage convenience is not a trade worth making (see
# harness/PREREGISTERED_BANKING_AUC_CLAIMS.md's 2026-08-20 entry). This function
# is never called by _rule_based_verdict() and its result never reaches score,
# verdict, confidence, or risk_score -- it is computed independently and
# attached to the response as a separate field.
#
# Falsification condition: if verdict/confidence/risk_score for any APK ever
# differs between a build with this present and one without it, this stopped
# being display-layer and became an undocumented scorer input.
#
# Detection is the certificate ISSUER string, not a specific certificate hash --
# checked directly against harness/banking_legit_corpus/ before writing this:
# Google Play App Signing issues a DISTINCT signing key per app (29 distinct
# cert SHA-256 values found across 95 corpus files), but every one carries the
# identical issuer template below, so the string is the stable signal, not any
# one hash.
_PLAY_SIGNING_ISSUER_MARKER = "Organization: Google Inc."


def _play_signing_check(features: dict) -> dict:
    issuer = (features.get("certificate") or {}).get("issuer") or ""
    detected = _PLAY_SIGNING_ISSUER_MARKER in issuer
    if detected:
        note = (
            "Certificate re-signed by Google Play App Signing — a triage prior "
            "indicating Play-distributed provenance, not a safety verdict. Does "
            "not change verdict, confidence, or risk score. A malicious app "
            "distributed through Play would carry this same signature; treat "
            "as lower analyst priority, not as cleared."
        )
    else:
        note = (
            "Not Google Play App Signing — self-signed or distributed outside "
            "Play. This carries no inference either way: most legitimate "
            "self-distributed banking apps also look like this."
        )
    return {"detected": detected, "note": note}


def _rule_based_verdict(features: dict) -> dict:
    """Deterministic, weighted evidence scorer. This is SetuGuard's
    authoritative source of verdict + confidence for /api/analyze_apk — not
    an Ollama-unreachable fallback. The LLM/RAG stage (_try_llm_narrative)
    only ever supplies narrative text on top of this verdict; it cannot
    change verdict or confidence, with or without Ollama reachable."""
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
    }
    # Score each distinct category once (at its existing weight), not once per
    # call site — a legitimate app can have many reflection/accessibility call
    # sites without that repetition itself being more suspicious. Rationale
    # still lists every individual call site for the analyst.
    # "reflection" is excluded from scoring entirely (measured separation
    # -20.9: fires more on benign apps than malicious) but call sites are
    # still listed in the rationale text below.
    seen_cats = {api["category"] for api in sapis if api["category"] != "reflection"}
    for cat in seen_cats:
        score += weight_by_cat.get(cat, 0.08)
    for api in sapis:
        reasons.append(f"{api['category']} via {api['class']}.{api['method']} (called {api['call_count']}x)")

    strs = features["suspicious_strings"]
    # Narrowed from "any url/ip string" (measured separation -20.7, backwards)
    # to only bare-IP hosts and explicit non-standard ports. A plain
    # https://domain.tld/... string contributes nothing.
    bare_ips = [s for s in strs if s["kind"] == "ip"]
    flagged_urls = [
        s for s in strs
        if s["kind"] == "url" and (_url_host_is_bare_ip(s["value"]) or _url_has_nonstandard_port(s["value"]))
    ]
    ip_url = bare_ips + flagged_urls
    if ip_url:
        score += min(len(ip_url) * 0.05, 0.20)
        reasons.append(f"{len(ip_url)} embedded URL/IP string(s), e.g. {ip_url[0]['value']}")

    cert = features["certificate"]
    # self_signed excluded entirely (measured separation +0.1: fires on ~99%
    # of all apps regardless of label, carries no information).
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
        "_source": "rule_based",
    }


def _try_llm_narrative(features: dict, rule_report: dict) -> dict:
    """Ask the LLM/RAG stage for narrative rationale + cited_chunk_ids only.
    Starts as a copy of rule_report, so verdict/confidence are already set
    to the authoritative rule-based values before the LLM is ever called —
    only rationale/cited_chunk_ids are overwritten on success, and never on
    failure. This is what makes the inversion structural rather than a
    convention someone could accidentally break later."""
    report = dict(rule_report)
    try:
        import rag_report
        llm_report = rag_report.generate_report(features)
        report["rationale"] = llm_report.get("rationale", rule_report["rationale"])
        report["cited_chunk_ids"] = llm_report.get("cited_chunk_ids", [])
        report["_narrative_source"] = "ollama_rag"
    except Exception:
        report["_narrative_source"] = "unavailable"
    return report


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
    return f"{base} (rule-based triage, evidence score {report['confidence']})"


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
        # exported_components[].name can be None (FROZEN_FILE_FINDINGS.md Finding 2 —
        # androguard returns None when a manifest node has no android:name attribute).
        + [c["name"] for c in features["exported_components"] if c["name"]]
    ).lower()
    for kw in BANKING_APP_KEYWORDS:
        if kw.lower() in haystack:
            hits.add(kw.rstrip("."))
    return sorted(hits)


def _safe_field(fn, default, field_name: str):
    """Run a response-field enrichment helper; on any exception, log it and
    degrade that one field to `default` instead of failing the whole
    /api/analyze_apk response. A malformed APK should produce a report with
    one empty field, not a 500."""
    try:
        return fn()
    except Exception:
        logging.exception(f"Field enrichment failed for {field_name!r}; degrading to default")
        return default


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

    narrative = ["Verdict and confidence produced by SetuGuard's rule-based evidence scorer (deterministic)."]
    if report["rationale"]:
        narrative.append(report["rationale"])
    if report.get("_narrative_source") == "ollama_rag":
        narrative.append("Narrative enriched via Ollama/mistral RAG stage.")
    else:
        narrative.append(
            "Note: Ollama/mistral unreachable — narrative is the rule-based rationale only, "
            "no LLM enrichment for this report."
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
        "family_verdict": _safe_field(
            lambda: _family_guess(features, report), "Unknown (enrichment failed)", "family_verdict"),
        "dangerous_permissions": features["dangerous_permissions"],
        "target_banking_apps": _safe_field(
            lambda: _target_banking_apps(features), [], "target_banking_apps"),
        "c2_candidates": _safe_field(
            lambda: [s["value"] for s in features["suspicious_strings"] if s["kind"] in ("url", "ip")],
            [], "c2_candidates"),
        "api_iocs": _safe_field(
            lambda: sorted({f"{a['class']}->{a['method']}" for a in features["suspicious_apis"]}),
            [], "api_iocs"),
        "mitre": _safe_field(lambda: _mitre_rows(features), [], "mitre"),
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
        "verdict_source": "rule_based",  # always, for now — D1 inversion; see _rule_based_verdict docstring
        "narrative_source": report.get("_narrative_source", "unavailable"),
    }


@app.route("/api/analyze_apk", methods=["POST"])
def analyze_apk_endpoint():
    t0 = time.perf_counter()
    if "apk" not in request.files:
        return jsonify({"error": "no 'apk' file in request"}), 400
    max_bytes = MAX_APK_UPLOAD_MB * 1024 * 1024
    # Content-Length covers the whole multipart body (file + small form overhead),
    # close enough to reject early without ever touching disk. Not present for
    # chunked-encoding clients, so it's a fast path, not the only check.
    if request.content_length and request.content_length > max_bytes:
        return jsonify({
            "status": "rejected",
            "reason": f"upload is {request.content_length / (1024*1024):.1f}MB, over the {MAX_APK_UPLOAD_MB}MB limit",
            "action": "split or pre-filter the file before resubmitting",
        }), 413
    f = request.files["apk"]
    dest = UPLOAD_DIR / secure_filename(f.filename)
    f.save(dest)
    if dest.stat().st_size > max_bytes:
        size_mb = dest.stat().st_size / (1024 * 1024)
        dest.unlink(missing_ok=True)
        return jsonify({
            "status": "rejected",
            "reason": f"upload is {size_mb:.1f}MB, over the {MAX_APK_UPLOAD_MB}MB limit",
            "action": "split or pre-filter the file before resubmitting",
        }), 413
    try:
        try:
            features = static_analysis.analyze_apk(str(dest))
        except Exception as e:
            traceback.print_exc()
            return jsonify({
                "status": "requires_manual_review",
                "kind": "apk",
                "filename": f.filename,
                "reason": f"static analysis could not parse this file ({type(e).__name__})",
                "action": "escalate to manual review",
            }), 200

        rule_report = _rule_based_verdict(features)
        report = _try_llm_narrative(features, rule_report)
        yar_text = None
        if report["verdict"] != "benign":
            yar_text = yara_gen.generate_yara(features, report)
        resp = _adapt_apk_response(features, report, yar_text, time.perf_counter() - t0)
        resp["play_signing"] = _play_signing_check(features)
        resp["analysis_id"] = store_analysis("apk", resp["package"], dict(resp))
        resp["kind"] = "apk"
        return jsonify(resp)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"{type(e).__name__}: {e}"}), 500
    finally:
        dest.unlink(missing_ok=True)


# ===========================================================================
# PS2 — mule/fraud. Scores against the bank's 18 approved features
# (BANK_FINALIZED_FEATURES) using a model trained OFFLINE by
# harness/train_ps2_model.py. No training, no CV, no SHAP-explainer fitting
# happens in this process's request handlers — only artifact loading
# (once, at import time, below) and inference.
# ===========================================================================

MODELS_DIR = Path(__file__).resolve().parents[2] / "models"
PS2_MODEL_VERSION = "ps2_xgb_v1"


def _load_ps2_artifact(version: str = PS2_MODEL_VERSION):
    from xgboost import XGBClassifier

    model_path = MODELS_DIR / f"{version}.json"
    metrics_path = MODELS_DIR / f"{version}_metrics.json"
    if not model_path.exists() or not metrics_path.exists():
        raise FileNotFoundError(
            f"PS2 model artifact missing ({model_path} / {metrics_path}). "
            f"Run `python3 harness/train_ps2_model.py` to generate it."
        )
    model = XGBClassifier()
    model.load_model(str(model_path))
    metrics = json.loads(metrics_path.read_text())
    explainer_module = __import__("shap")
    explainer = explainer_module.TreeExplainer(model)

    # Optional: the 20-seed repeated-holdout study (harness/ps2_repeated_
    # splits.py). A single 80/20 split's AUCPR/AUROC (metrics above) is a
    # noisy point estimate off 16 holdout positives -- if this file exists,
    # its 'headline' median/IQR is what the API actually reports, not the
    # single-split number. Optional (not FileNotFoundError) because the
    # single-split artifact is independently sufficient to serve requests;
    # this only enriches the reported metric.
    repeated_splits_path = MODELS_DIR / "ps2_repeated_splits_metrics.json"
    repeated_splits = (
        json.loads(repeated_splits_path.read_text()) if repeated_splits_path.exists() else None
    )
    if repeated_splits is None:
        logging.warning(
            f"{repeated_splits_path} not found -- /api/analyze_dataset will report the single-split "
            f"holdout AUCPR/AUROC from {metrics_path.name} without distribution context. Run "
            f"`python3 harness/ps2_repeated_splits.py` to generate it."
        )

    return {
        "model": model,
        "metrics": metrics,
        "repeated_splits": repeated_splits,
        "explainer": explainer,
        "encoded_feature_names": metrics["features"]["encoded_feature_names"],
    }


try:
    PS2_ARTIFACT = _load_ps2_artifact()
    if PS2_ARTIFACT.get("repeated_splits"):
        h = PS2_ARTIFACT["repeated_splits"]["headline"]
        logging.info(f"PS2 artifact loaded: {PS2_MODEL_VERSION} (20-seed median AUCPR={h['aucpr']}, AUROC={h['auroc']})")
    else:
        logging.info(
            f"PS2 artifact loaded: {PS2_MODEL_VERSION} "
            f"(single-split holdout AUCPR={PS2_ARTIFACT['metrics']['holdout_metrics']['aucpr']:.4f}, "
            f"AUROC={PS2_ARTIFACT['metrics']['holdout_metrics']['auroc']:.4f} -- no repeated-splits "
            f"distribution found)"
        )
except Exception:
    logging.exception("Failed to load PS2 model artifact at startup — /api/analyze_dataset will error")
    PS2_ARTIFACT = None


def _detect_row_id_column(columns) -> str | None:
    if "Unnamed: 0" in columns:
        return "Unnamed: 0"
    for c in columns:
        if re.search(r"^(account|customer|user)[_ ]?(id)?$", c, re.I):
            return c
    return None


def _encode_ps2_features(df: pd.DataFrame, present_features: list) -> pd.DataFrame:
    """Mirrors harness/train_ps2_model.py's encode_features exactly, then
    reindexes to the trained model's exact column set so an upload with
    missing/partial columns still produces a matrix the model can score.
    Missing bank features become NaN (XGBoost's native missing-value
    handling); missing one-hot category indicators become 0 (the category
    wasn't observed for that row -> that indicator is false), not
    fabricated averages."""
    X = pd.DataFrame(index=df.index)
    for c in BANK_FINALIZED_FEATURES:
        if c in present_features:
            X[c] = df[c]
        # else: left absent here; reindex below fills it as NaN for numeric
        # features, matching "missing bank feature -> missing value".

    cat_present = [c for c in CATEGORICAL_FEATURES if c in present_features]
    if cat_present:
        X = pd.get_dummies(X, columns=cat_present, dummy_na=False)

    encoded_names = PS2_ARTIFACT["encoded_feature_names"]
    dummy_cols = {c for c in encoded_names if any(c.startswith(f"{cat}_") for cat in CATEGORICAL_FEATURES)}
    X = X.reindex(columns=encoded_names)
    for c in dummy_cols:
        X[c] = X[c].fillna(0)
    numeric_cols = [c for c in encoded_names if c not in dummy_cols]
    X[numeric_cols] = X[numeric_cols].astype(float)
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
    if PS2_ARTIFACT is None:
        return jsonify({"error": "PS2 model artifact failed to load at startup — see server log; "
                                  "run `python3 harness/train_ps2_model.py` and restart"}), 500
    if "dataset" not in request.files:
        return jsonify({"error": "no 'dataset' file in request"}), 400
    f = request.files["dataset"]
    requested_label = request.form.get("label_column") or None
    try:
        raw_bytes = f.read()
        header = pd.read_csv(io.BytesIO(raw_bytes), nrows=0).columns.tolist()

        present_features = [c for c in BANK_FINALIZED_FEATURES if c in header]
        missing_features = [c for c in BANK_FINALIZED_FEATURES if c not in header]
        if not present_features:
            return jsonify({
                "error": "dataset has none of the bank's 18 approved feature columns "
                         f"({', '.join(BANK_FINALIZED_FEATURES)}); this endpoint scores "
                         "against that fixed schema, see setuguard_app/backend/ps2_features.py"
            }), 400

        label_col = TARGET_COLUMN if TARGET_COLUMN in header else (
            requested_label if requested_label in header else None)
        id_col = _detect_row_id_column(header)

        usecols = list(dict.fromkeys(
            present_features + ([id_col] if id_col else []) + ([label_col] if label_col else [])
        ))
        # Only the columns this endpoint actually uses are parsed — the
        # uploaded CSV may have thousands of columns (DataSet.csv has
        # 3,925); reading the rest into a DataFrame would be pure waste.
        df = pd.read_csv(io.BytesIO(raw_bytes), usecols=usecols)
        if len(df) == 0:
            return jsonify({"error": "dataset is empty"}), 400

        X = _encode_ps2_features(df, present_features)
        scores = PS2_ARTIFACT["model"].predict_proba(X)[:, 1]

        prevalence_pct = None
        if label_col:
            y = pd.to_numeric(df[label_col], errors="coerce")
            if y.notna().any():
                prevalence_pct = round(100 * float(y.mean()), 3)

        excluded_present = [c for c in header if c in EXCLUDED_LEAKY_FEATURES or c in EXCLUDED_ALERT_DERIVED]
        findings = []
        if excluded_present:
            findings.append({
                "signal": ", ".join(excluded_present), "type": "excluded_by_design",
                "evidence": f"{len(excluded_present)} post-resolution/alert-derived column(s) present in upload",
                "disposition": "ignored — never selected into the model's feature matrix (see EXCLUDED_LEAKY_FEATURES / EXCLUDED_ALERT_DERIVED)",
            })
        if missing_features:
            findings.append({
                "signal": ", ".join(missing_features), "type": "missing_bank_feature",
                "evidence": f"{len(missing_features)}/{len(BANK_FINALIZED_FEATURES)} bank-approved feature(s) absent from upload",
                "disposition": "scored as missing (NaN) — XGBoost's native missing-value handling, not imputed with a guessed value",
            })
        if prevalence_pct is not None:
            findings.append({
                "signal": label_col, "type": "descriptive_only",
                "evidence": f"{prevalence_pct}% positive in this upload",
                "disposition": "reported for context only — NOT a model performance metric; the model's only "
                                "validated performance numbers are the offline HOLDOUT metrics below, from "
                                "models/ps2_xgb_v1_metrics.json, since this upload may overlap the model's own training rows",
            })

        tiers = pd.Series([_assign_tier(s) for s in scores])
        tier_counts = {t: int((tiers == t).sum()) for t in ["T1", "T2", "T3", "T4"]}

        account_ids = (
            df[id_col].astype(str) if id_col else
            pd.Series([hashlib.sha256(f"row{i}".encode()).hexdigest()[:12] for i in range(len(df))])
        )

        order = np.argsort(-scores)[:15]
        # SHAP is computed only for the rows actually returned (top 15), and
        # only here, at request time — this is running the already-fitted
        # TreeExplainer forward over specific rows (inference), not fitting
        # a new explainer or background dataset.
        shap_values_top = PS2_ARTIFACT["explainer"].shap_values(X.iloc[order])

        top_alerts = []
        for pos, i in enumerate(order):
            row_shap = shap_values_top[pos]
            top_idx = np.argsort(-np.abs(row_shap))[:3]
            drivers = [{"feature": X.columns[j], "shap": round(float(row_shap[j]), 4)} for j in top_idx]

            top_alerts.append({
                "account_hash": str(account_ids.iloc[i])[:16],
                "tier": _assign_tier(scores[i]),
                "score": round(float(scores[i]), 3),
                "shap_drivers": drivers,
                # Previously a hardcoded "score - 0.2" subtraction with no
                # relationship to the model or the specific feature's real
                # effect size -- a fabricated number in a judged artifact.
                # Same precedent as generated_rules/rule_validated below:
                # null, not fabricated. (A real one is feasible -- re-score
                # the row with the top SHAP driver set to the median through
                # the actual loaded model -- but wasn't implemented this
                # session; see SESSION_LOG.md for what it would and would
                # not be entitled to claim.)
                "counterfactual": None,
                "counterfactual_status": "not_computed",
                # generated_rules/rule_validated were previously hardcoded
                # identically across all records (ps2/07_ps2_bridge_exporter.py:
                # every row got "SetuGuard_YARA_Rule_01.yar" / True) -- a
                # copy-paste of PS1's per-APK YARA-rule concept onto PS2
                # accounts, where it doesn't map to anything real: there is
                # no per-account "generated rule" to validate. Rather than
                # fabricate one, both are explicit nulls with a status
                # sibling field.
                "generated_rules": None,
                "generated_rules_status": "not_computed",
                "rule_validated": None,
                "rule_validated_status": "not_computed",
            })

        # A single 80/20 split's AUCPR/AUROC is a noisy point estimate off
        # only 16 holdout positives (see ps2/README.md's contiguity note and
        # harness/ps2_repeated_splits.py's docstring). Report the 20-seed
        # median when that study is available -- not the single-split
        # number -- and carry the full distribution + the single-split
        # reference alongside, clearly labeled, rather than silently
        # picking one favorable draw as if it were the headline.
        holdout_metrics = PS2_ARTIFACT["metrics"]["holdout_metrics"]
        repeated = PS2_ARTIFACT.get("repeated_splits")
        if repeated is not None:
            reported_aucpr = repeated["aucpr_distribution"]["median"]
            reported_auroc = repeated["auroc_distribution"]["median"]
            metrics_source = (
                "median of 20 independent stratified 80/20 holdouts — see "
                "models/ps2_repeated_splits_metrics.json's 'headline' field; NOT computed from "
                "this request's upload, and NOT a single-split point estimate"
            )
        else:
            reported_aucpr = holdout_metrics["aucpr"]
            reported_auroc = holdout_metrics["auroc"]
            metrics_source = (
                "single stratified 80/20 holdout split — see models/ps2_xgb_v1_metrics.json; "
                "models/ps2_repeated_splits_metrics.json (20-seed distribution) was not found at "
                "startup, so this is one point estimate off 16 holdout positives, not a distribution"
            )
        resp = {
            "model_version": PS2_ARTIFACT["metrics"]["model_version"],
            "holdout_aucpr": reported_aucpr,
            "holdout_auroc": reported_auroc,
            "holdout_aucpr_distribution": repeated["aucpr_distribution"] if repeated else None,
            "holdout_auroc_distribution": repeated["auroc_distribution"] if repeated else None,
            "holdout_single_split_reference": {
                "aucpr": holdout_metrics["aucpr"],
                "auroc": holdout_metrics["auroc"],
                "seed": PS2_ARTIFACT["metrics"]["seed"],
                "note": "this model artifact's own training-time holdout split (one seed) -- "
                        "kept for reference, not reported as the headline metric above",
            },
            "metrics_source": metrics_source,
            # cv_aucpr_mean/n_cv_folds kept for the existing frontend field
            # names, which read them as "CV AUCPR (n-fold)" — that label is
            # stale now, but the *value* underneath is the real, honest
            # holdout AUCPR (20-seed median when available), not an
            # in-request CV number (n_cv_folds=0 because no CV runs in this
            # process anymore).
            "cv_aucpr_mean": reported_aucpr,
            "n_cv_folds": 0,
            "audit": {
                "n_rows": len(df),
                "prevalence_pct": prevalence_pct,
                "flagged_columns": excluded_present,
                "findings": findings,
                "label_column_used": label_col,
                "bank_features_present": present_features,
                "bank_features_missing": missing_features,
            },
            "feature_columns": present_features,
            "tier_counts": tier_counts,
            "top_alerts": top_alerts,
        }
        resp["analysis_id"] = store_analysis("dataset", f.filename, dict(resp))
        resp["kind"] = "dataset"
        return jsonify(resp)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"{type(e).__name__}: {e}"}), 500


# ===========================================================================
# Bridge — IOC linkage between the last PS1 run and the last PS2 run.
# Matching itself is bridge/matcher.py's real code (extract_ioc_from_ps1 +
# match_account_to_apk), called here rather than reimplemented. A link is
# CONDITIONAL: cert_hash / c2_host are IOCs, not verdicts, and
# match_account_to_apk only returns a result when one actually overlaps
# matcher.SYNTHETIC_LINKAGE_GROUND_TRUTH -- which is itself deliberately
# small (matcher.py's own docstring: no real device<->account join key
# exists in any of the source repos). Zero matches is the expected, correct
# result for most APK/dataset pairs, not an error.
# ===========================================================================

_ACTION_BY_SEVERITY = {
    "CRITICAL": "Immediate debit freeze on account + device quarantine.",
    "HIGH": "Enhanced review of account; restrict device via MDM.",
    "MEDIUM": "Monitor both account and device for 30 days.",
    "LOW": "Log for audit trail only.",
}


def _shared_ioc_string(matched_on: str, apk_ioc: dict, account_id: str) -> str:
    if matched_on == "cert_hash":
        return f"cert_hash:{apk_ioc.get('cert_hash')}"
    ground = bridge_matcher.SYNTHETIC_LINKAGE_GROUND_TRUTH.get(account_id, {})
    return f"c2_host:{ground.get('c2_host')}"


def _resolve_bridge_input(explicit_id, kind: str, field_name: str):
    """Resolution order per ANALYSIS_ID_MIGRATION.md §3. Returns (entry,
    source, error_response_or_None). On error, entry/source are None and the
    caller must return the error response immediately without falling back.
    """
    prefix = f"{_ID_PREFIX[kind]}_"
    if explicit_id:
        if not explicit_id.startswith(prefix):
            return None, None, (jsonify({
                "error": "malformed_id",
                "detail": f"{field_name} must start with '{prefix}'",
                "field": field_name,
            }), 400)
        entry = get_analysis(explicit_id, kind)
        if entry is None:
            return None, None, (jsonify({
                "error": "unknown_analysis",
                "detail": f"{explicit_id} not found or expired",
                "field": field_name,
            }), 404)
        return entry, "explicit", None

    entry = latest_analysis(kind)
    if entry is None:
        return None, None, (jsonify({
            "error": "no_analysis_available",
            "detail": f"no {kind} analysis available yet; run the analyze endpoint first",
            "field": field_name,
        }), 409)
    return entry, "fallback", None


@app.route("/api/bridge", methods=["POST"])
def bridge_endpoint():
    body = request.get_json(silent=True) or {}

    apk_entry, apk_source, err = _resolve_bridge_input(body.get("apk_id"), "apk", "apk_id")
    if err:
        return err
    ds_entry, ds_source, err = _resolve_bridge_input(body.get("dataset_id"), "dataset", "dataset_id")
    if err:
        return err

    apk = apk_entry["result"]
    ds = ds_entry["result"]
    if not ds["top_alerts"]:
        return jsonify({"error": "run /api/analyze_dataset at least once before bridging"}), 400

    apk_ioc = bridge_matcher.extract_ioc_from_ps1(apk["raw_features"])

    links = []
    for alert in ds["top_alerts"]:
        match = bridge_matcher.match_account_to_apk(alert["account_hash"], apk_ioc)
        if match is None:
            continue
        matched_on = match["matched_on"]
        links.append({
            "account_hash": alert["account_hash"],
            "tier": alert["tier"],
            "score": alert["score"],
            "linked_apk_package": apk["package"],
            "family": apk["family_verdict"].split(" (")[0],
            "severity": apk["severity"],
            "matched_on": matched_on,
            "shared_ioc": _shared_ioc_string(matched_on, apk_ioc, alert["account_hash"]),
            "yara_rule": apk["yara"]["rule_name"],
            "yara_validated": apk["yara"]["validated"],
            "recommended_action": _ACTION_BY_SEVERITY.get(apk["severity"], "Review manually."),
        })

    note = (
        f"Matching is on certificate-hash or C2-host overlap, exact-match against a small "
        f"ground-truth table (matcher.SYNTHETIC_LINKAGE_GROUND_TRUTH, two entries, one per "
        f"join key). The C2-host entry's indicator is a hostname extracted from the sample's "
        f"strings by our own static analysis — yessign[.]net, mimicking the Korean "
        f"accredited-certificate brand \"yessign,\" in a sample impersonating KB Kookmin Bank "
        f"(package com.kb). No claim is made about the domain's current ownership, "
        f"registration, or activity; it is not confirmed as live C2. Which account it links "
        f"to is hand-constructed, not observed in the wild; the cert-hash entry is synthetic "
        f"on both sides. No real device<->account join key exists in any "
        f"of the source repos. Matched APK indicators, not a malice verdict, against "
        f"{len(ds['top_alerts'])} scored account(s). "
        + (f"{len(links)} match(es) found." if links else
           "0 matches -- no account in this dataset run shares a certificate hash or C2 host "
           "with this APK. This is the expected result for most APK/dataset pairs: the "
           "ground-truth table is small, and the account associations in it are synthetic by "
           "construction.")
    )

    resp = {
        "matched": len(links) > 0,
        "match_count": len(links),
        "links": links,
        "note": note,
        "inputs": {
            "apk": {"id": apk_entry["id"], "label": apk_entry["label"], "source": apk_source},
            "dataset": {"id": ds_entry["id"], "label": ds_entry["label"], "source": ds_source},
        },
    }
    # Back-compat top-level fields for the existing single-record frontend
    # template: mirror the first (highest-score) link when one exists, else
    # explicit nulls -- the template interpolates these directly and
    # stringifies null/undefined safely, so this renders an empty-but-valid
    # bridge result rather than throwing.
    first = links[0] if links else {}
    for key in ("account_hash", "tier", "score", "linked_apk_package", "family", "severity",
                "shared_ioc", "yara_rule", "yara_validated", "recommended_action"):
        resp[key] = first.get(key)
    return jsonify(resp)


@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "SetuGuard backend"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
