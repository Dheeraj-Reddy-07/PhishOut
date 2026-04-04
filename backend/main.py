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

WHITELIST_DOMAINS = [
    "facebook.com", "google.com", "paypal.com", "github.com",
    "microsoft.com", "apple.com", "amazon.com", "netflix.com",
    "instagram.com", "linkedin.com", "twitter.com", "x.com",
    "youtube.com", "reddit.com", "wikipedia.org", "yahoo.com",
]

app = FastAPI(title="PhishGuard Security Engine v2")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Load ML model at startup ---
_base = os.path.dirname(__file__)
MODEL_PATH = os.path.join(_base, "phishing_model.pkl")
SCALER_PATH = os.path.join(_base, "feature_scaler.pkl")

ml_model = None
ml_scaler = None

try:
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        ml_model = joblib.load(MODEL_PATH)
        ml_scaler = joblib.load(SCALER_PATH)
        print("[+] ML model loaded successfully")
    else:
        print("[!] phishing_model.pkl not found. Run: python train_model.py")
except Exception as e:
    print(f"[!] Failed to load ML model: {e}")


# --- Pydantic Models ---
class ScanRequest(BaseModel):
    url: str


class ScanResult(BaseModel):
    threat_level_pct: int
    ml_confidence: float
    verdict: str
    red_flags: list[str]
    feature_scores: dict
    feature_labels: dict
    raw_features: dict
    is_dangerous: bool


# --- Rule-based helpers ---
def _parse_url(u: str) -> str:
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
                from urllib.parse import urlparse as _up
                ap = _up(action)
                if ap.netloc and ap.netloc != domain:
                    flags.append(f"Credential Harvesting: Form submits to '{ap.netloc}'")
                if re.match(r"^https?://\d{1,3}(\.\d{1,3}){3}", action):
                    flags.append("Form action targets raw IP address")
    except Exception as e:
        flags.append(f"Structural check incomplete: {str(e)[:80]}")
    return flags


# --- Main scan endpoint ---
@app.post("/scan", response_model=ScanResult)
async def scan_url(req: ScanRequest):
    url = _parse_url(req.url.strip())
    parsed = urlparse(url)
    domain = parsed.netloc

    if not domain:
        raise HTTPException(status_code=400, detail="Invalid URL – could not extract domain.")

    red_flags: list[str] = []
    rule_score = 0

    typo = _check_typosquatting(domain)
    red_flags.extend(typo)
    if typo:
        rule_score += 40

    proto = _check_protocol(url)
    red_flags.extend(proto)
    if proto:
        rule_score += 20

    struct = _check_structural(url, domain)
    red_flags.extend(struct)
    if struct:
        rule_score += 40

    rule_score = min(rule_score, 100)

    # --- ML inference ---
    features = extract_features(url)
    ml_confidence = 0.0
    ml_score = rule_score

    if ml_model is not None and ml_scaler is not None:
        X = features_to_array(features)
        X_s = ml_scaler.transform(X)
        proba = ml_model.predict_proba(X_s)[0]
        ml_confidence = float(proba[1])
        ml_score = int(ml_confidence * 100)

    # Weighted blend: 70% ML, 30% rules
    if ml_model is not None:
        threat = int(0.7 * ml_score + 0.3 * rule_score)
    else:
        threat = rule_score

    threat = min(100, threat)

    if threat >= 60:
        verdict = "PHISHING"
    elif threat >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

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


@app.get("/health")
async def health():
    return {
        "status": "online",
        "ml_model_loaded": ml_model is not None,
        "version": "2.0.0",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
