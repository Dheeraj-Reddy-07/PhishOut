"""
PhishOut Backend — FastAPI Application v4.0
==============================================
Endpoints:
  POST /scan            — Structural-only scan (UNCHANGED — backward compat)
  POST /scan_extended   — Structural + raw webpage analysis (UNCHANGED)
  POST /phishout/scan   — Full PhishOut pipeline (structural + semantic + fusion)
  GET  /health          — Component health status
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests
from bs4 import BeautifulSoup
import Levenshtein
from urllib.parse import urlparse
import numpy as np
import joblib
import os

from ml_model import (
    extract_features, features_to_array, normalize_features, FEATURE_LABELS
)
from webpage_analyzer import analyze_webpage
from phishout_predictor import get_predictor

WHITELIST_DOMAINS = [
    "facebook.com", "google.com", "paypal.com", "github.com",
    "microsoft.com", "apple.com", "amazon.com", "netflix.com",
    "instagram.com", "linkedin.com", "twitter.com", "x.com",
    "youtube.com", "reddit.com", "wikipedia.org", "yahoo.com",
]

app = FastAPI(
    title="PhishOut Security Engine v4.0",
    description="Adversarially Robust Phishing Webpage Detection using Hybrid Structural and Semantic Analysis",
    version="4.0.0",
)

# ── CORS: read from env for production, wildcard for dev fallback ─────────────
_raw_origins = os.getenv("ALLOWED_ORIGINS", "*")
_origins = [o.strip() for o in _raw_origins.split(",")] if _raw_origins != "*" else ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Load structural ML model (for /scan and /scan_extended) ───────────────────
_base = os.path.dirname(__file__)
MODEL_PATH  = os.path.join(_base, "phishing_model.pkl")
SCALER_PATH = os.path.join(_base, "feature_scaler.pkl")

ml_model  = None
ml_scaler = None

try:
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        ml_model  = joblib.load(MODEL_PATH)
        ml_scaler = joblib.load(SCALER_PATH)
        print("[+] Legacy structural ML model loaded (for /scan)")
    else:
        print("[!] phishing_model.pkl not found — /scan will use rule-based fallback")
except Exception as e:
    print(f"[!] Failed to load legacy ML model: {e}")

# ── Load PhishOut predictor (for /phishout/scan) ──────────────────────────────
phishout = None
try:
    phishout = get_predictor()
    print(f"[+] PhishOut predictor ready (model_type={phishout._model_type})")
except Exception as e:
    print(f"[!] Failed to initialise PhishOut predictor: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# Pydantic models
# ══════════════════════════════════════════════════════════════════════════════

class ScanRequest(BaseModel):
    url: str


# ── /scan response ─────────────────────────────────────────────────────────────
class ScanResult(BaseModel):
    threat_level_pct: int
    ml_confidence: float
    verdict: str
    red_flags: list[str]
    feature_scores: dict
    feature_labels: dict
    raw_features: dict
    is_dangerous: bool


# ── /scan_extended response ────────────────────────────────────────────────────
class WebpageAnalysis(BaseModel):
    success: bool
    error: str | None = None
    page_title: str | None = None
    text_length: int = 0
    password_fields: int = 0
    text_email_fields: int = 0
    forms: int = 0
    form_actions: list[str] = []
    external_links: int = 0
    iframes: int = 0
    scripts: int = 0
    login_indicators: int = 0
    credential_indicators: int = 0
    payment_indicators: int = 0
    urgency_indicators: int = 0
    brand_indicators: int = 0
    evidence: list[str] = []


class ExtendedScanResult(BaseModel):
    url: str
    structural_analysis: ScanResult
    webpage_analysis: WebpageAnalysis | None = None


# ── /phishout/scan response ────────────────────────────────────────────────────
class PhishOutResponse(BaseModel):
    url: str
    risk_score: int
    verdict: str
    structural_score: int
    semantic_score: int
    semantic_probability: float = 0.0
    semantic_rule_score: int = 0
    phishing_probability: float
    webpage_analysis_available: bool
    fusion_mode: str
    fusion_note: str
    model_type: str
    structural_analysis: dict
    structural_evidence: list[str]
    semantic_analysis: dict
    semantic_evidence: list[str]
    reasons: list[str]


# ══════════════════════════════════════════════════════════════════════════════
# Shared helpers
# ══════════════════════════════════════════════════════════════════════════════

def _parse_url(u: str) -> str:
    u = u.strip()
    if not u.startswith("http://") and not u.startswith("https://"):
        u = "http://" + u
    return u


def _check_typosquatting(domain: str) -> list[str]:
    flags = []
    base = ".".join(domain.split(".")[-2:]) if "." in domain else domain
    for safe in WHITELIST_DOMAINS:
        if base == safe:
            return []
        dist = Levenshtein.distance(base, safe)
        if 0 < dist <= 2:
            flags.append(f"Typosquatting: '{base}' resembles '{safe}' (edit distance: {dist})")
            return flags
    return flags


def _check_protocol(url: str) -> list[str]:
    return ["Insecure Protocol: HTTP used instead of HTTPS"] if url.startswith("http://") else []


def _check_structural(url: str, domain: str) -> list[str]:
    import re
    flags = []
    try:
        headers = {"User-Agent": "Mozilla/5.0 Chrome/91.0"}
        r = requests.get(url, timeout=5, headers=headers, allow_redirects=True)
        soup = BeautifulSoup(r.text, "html.parser")
        for form in soup.find_all("form"):
            action = form.get("action", "")
            if action:
                ap = urlparse(action)
                if ap.netloc and ap.netloc != domain:
                    flags.append(f"Credential Harvesting: Form submits to '{ap.netloc}'")
                if re.match(r"^https?://\d{1,3}(\.\d{1,3}){3}", action):
                    flags.append("Form action targets raw IP address")
    except Exception as e:
        flags.append(f"Structural check incomplete: {str(e)[:80]}")
    return flags


def _run_structural_scan(url: str) -> ScanResult:
    """Shared logic for /scan and /scan_extended."""
    parsed = urlparse(url)
    domain = parsed.netloc
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid URL – could not extract domain.")

    red_flags: list[str] = []
    rule_score = 0

    typo = _check_typosquatting(domain)
    red_flags.extend(typo)
    if typo: rule_score += 40

    proto = _check_protocol(url)
    red_flags.extend(proto)
    if proto: rule_score += 20

    struct = _check_structural(url, domain)
    red_flags.extend(struct)
    if struct: rule_score += 40

    rule_score = min(rule_score, 100)

    features = extract_features(url)
    ml_confidence = 0.0
    ml_score = rule_score

    if ml_model is not None and ml_scaler is not None:
        X   = features_to_array(features)
        X_s = ml_scaler.transform(X)
        proba         = ml_model.predict_proba(X_s)[0]
        ml_confidence = float(proba[1])
        ml_score      = int(ml_confidence * 100)

    threat = int(0.7 * ml_score + 0.3 * rule_score) if ml_model else rule_score
    threat = min(100, threat)

    verdict = "PHISHING" if threat >= 60 else "SUSPICIOUS" if threat >= 30 else "SAFE"

    return ScanResult(
        threat_level_pct=threat,
        ml_confidence=round(ml_confidence, 4),
        verdict=verdict,
        red_flags=red_flags,
        feature_scores=normalize_features(features),
        feature_labels=FEATURE_LABELS,
        raw_features={k: round(v, 4) if isinstance(v, float) else v for k, v in features.items()},
        is_dangerous=(threat >= 50),
    )


# ══════════════════════════════════════════════════════════════════════════════
# Endpoints
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/scan", response_model=ScanResult)
async def scan_url(req: ScanRequest):
    """
    Structural-only URL scan.
    UNCHANGED from previous versions — backward compatible.
    """
    return _run_structural_scan(_parse_url(req.url))


@app.post("/scan_extended", response_model=ExtendedScanResult)
async def scan_url_extended(req: ScanRequest):
    """
    Structural scan + raw webpage analysis.
    UNCHANGED from previous versions.
    """
    url = _parse_url(req.url)
    structural = _run_structural_scan(url)
    webpage    = analyze_webpage(url, timeout=10)

    return ExtendedScanResult(
        url=url,
        structural_analysis=structural,
        webpage_analysis=WebpageAnalysis(**{
            k: webpage.get(k, "" if k == "error" else 0)
            for k in WebpageAnalysis.model_fields
        }) if webpage["success"] else None,
    )


@app.post("/phishout/scan", response_model=PhishOutResponse)
async def phishout_scan(req: ScanRequest):
    """
    PhishOut full-pipeline phishing detector.

    Runs the complete 10-step PhishOut pipeline:
      1. Structural analysis (32-feature ML model)
      2. Webpage fetch + semantic feature extraction
      3. Semantic risk scoring (rule-based, config-driven)
      4. Fusion of structural + semantic scores
      5. Verdict assignment
      6. Deterministic explanation generation

    Response fields:
      risk_score                — 0–100 final PhishOut score
      verdict                   — SAFE / SUSPICIOUS / PHISHING
      structural_score          — 0–100 from ML structural model
      semantic_score            — 0–100 from semantic rule engine
      webpage_analysis_available — whether the page was fetched
      fusion_mode               — "combined" or "structural_only"
      reasons                   — ordered list of detected risk indicators
    """
    if phishout is None:
        raise HTTPException(
            status_code=503,
            detail="PhishOut predictor not loaded. Check server startup logs.",
        )

    url = _parse_url(req.url)

    try:
        result = phishout.predict(url, fetch_timeout=10)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PhishOut prediction failed: {e}")

    return PhishOutResponse(**result)


@app.get("/health")
async def health():
    """Report status of all pipeline components."""
    phishout_model = "not_loaded"
    phishout_dataset = "none"
    if phishout is not None:
        phishout_model = phishout._model_type
        if "phish360_v3" in phishout_model:
            phishout_dataset = "phish360_v3"
        elif "phish360_v2" in phishout_model:
            phishout_dataset = "phish360_v2"
        elif "phish360" in phishout_model:
            phishout_dataset = "phish360"

    return {
        "status":              "online",
        "version":             "4.0.0",
        "ml_model_loaded":     ml_model is not None,
        "phishout_model":      phishout_model,
        "phishout_dataset":    phishout_dataset,
        "phishout_ready":      phishout is not None,
        "endpoints": ["/scan", "/scan_extended", "/phishout/scan"],
        "pipeline_components": {
            "structural_analyzer": "ml_model.analyze_structural",
            "webpage_fetcher":     "webpage_analyzer.fetch_webpage",
            "semantic_extractor":  "webpage_analyzer.extract_semantic_features",
            "semantic_scorer":     "phishout_fusion.calculate_semantic_score",
            "fusion_layer":        "phishout_fusion.fuse_scores",
            "explanation_engine":  "explanation_engine.generate_explanations",
            "config":              "config.semantic_rules",
        },
    }



if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
