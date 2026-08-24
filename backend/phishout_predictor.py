"""
PhishOut Predictor — Main Orchestration Layer
==============================================
Coordinates all PhishOut pipeline components to produce a structured
phishing risk assessment for a given URL.

Pipeline (10 steps):
  1.  Validate and normalise URL
  2.  Run structural analysis (32 features → structural model probability)
  3.  Fetch webpage HTML
  4.  Extract semantic features from HTML (12 features → semantic model probability)
  5.  Generate semantic evidence strings
  6.  Inject compound flags into semantic features dict
  7.  Calculate semantic risk score (rule-based, for evidence/display)
  8.  Apply learned score-level fusion (structural_prob + semantic_prob → fusion_prob)
  9.  Assign verdict (SAFE / SUSPICIOUS / PHISHING)
  10. Generate explanations and assemble final result

Model loading priority (Phish360 research models first):
  1. models/phish360/  — Phish360-trained structural + semantic + fusion models
  2. models/           — Legacy PhreshPhish or baseline models (fallback)

Singleton usage:
    from phishout_predictor import get_predictor
    predictor = get_predictor()
    result = predictor.predict("https://example.com")

Or convenience function:
    from phishout_predictor import predict
    result = predict("https://example.com")
"""
import os
import json
import joblib
import numpy as np
from typing import Dict, Optional
from urllib.parse import urlparse

from ml_model import analyze_structural, FEATURE_KEYS, extract_features, features_to_array
from webpage_analyzer import (
    fetch_webpage,
    extract_semantic_features,
    generate_semantic_evidence,
)
from phishout_fusion import calculate_semantic_score, fuse_scores, assign_verdict
from explanation_engine import generate_explanations

# ── Model paths ────────────────────────────────────────────────────────────────
_BASE       = os.path.dirname(os.path.abspath(__file__))
_PHISH360_DIR  = os.path.join(_BASE, "models", "phish360")
_LEGACY_DIR    = os.path.join(_BASE, "models")

# Phish360 research model paths
_P360_STRUCT_MODEL  = os.path.join(_PHISH360_DIR, "structural_model.pkl")
_P360_STRUCT_SCALER = os.path.join(_PHISH360_DIR, "structural_scaler.pkl")
_P360_SEM_MODEL     = os.path.join(_PHISH360_DIR, "semantic_model.pkl")
_P360_SEM_SCALER    = os.path.join(_PHISH360_DIR, "semantic_scaler.pkl")
_P360_FUSION_MODEL  = os.path.join(_PHISH360_DIR, "fusion_model.pkl")
_P360_FUSION_CONFIG = os.path.join(_PHISH360_DIR, "fusion_config.json")
_P360_THRESHOLD_CFG = os.path.join(_PHISH360_DIR, "threshold_config.json")

# Legacy model paths (fallback)
_LEGACY_STRUCT_MODEL  = os.path.join(_LEGACY_DIR, "structural_only_model.pkl")
_LEGACY_STRUCT_SCALER = os.path.join(_LEGACY_DIR, "structural_only_scaler.pkl")

# Semantic feature keys used during training
SEMANTIC_KEYS = [
    'password_fields', 'text_email_fields', 'forms', 'external_links',
    'iframes', 'scripts', 'login_indicators', 'credential_indicators',
    'payment_indicators', 'urgency_indicators', 'brand_indicators', 'text_length',
]

_FETCH_TIMEOUT = 10  # seconds


# ══════════════════════════════════════════════════════════════════════════════
# Predictor class
# ══════════════════════════════════════════════════════════════════════════════

class PhishOutPredictor:
    """
    PhishOut pipeline orchestrator.

    Loads the best available models at startup.

    Priority:
      1. Phish360-trained research models (structural + semantic + learned fusion)
      2. Legacy structural-only model (fallback)
      3. Rule-based fallback (no model file present)
    """

    def __init__(self):
        self._struct_model  = None
        self._struct_scaler = None
        self._sem_model     = None
        self._sem_scaler    = None
        self._fusion_model  = None
        self._fusion_config = {}
        self._threshold_cfg = {}
        self._model_type    = "rule_based"
        self._load_models()

    def _load_models(self):
        """Load the best available models from disk."""
        # ── Priority 1: Phish360 research models ─────────────────────────────
        p360_struct_ok   = (os.path.exists(_P360_STRUCT_MODEL) and
                            os.path.exists(_P360_STRUCT_SCALER))
        p360_sem_ok      = (os.path.exists(_P360_SEM_MODEL) and
                            os.path.exists(_P360_SEM_SCALER))
        p360_fusion_ok   = os.path.exists(_P360_FUSION_MODEL)

        if p360_struct_ok and p360_sem_ok and p360_fusion_ok:
            try:
                self._struct_model  = joblib.load(_P360_STRUCT_MODEL)
                self._struct_scaler = joblib.load(_P360_STRUCT_SCALER)
                self._sem_model     = joblib.load(_P360_SEM_MODEL)
                self._sem_scaler    = joblib.load(_P360_SEM_SCALER)
                self._fusion_model  = joblib.load(_P360_FUSION_MODEL)

                if os.path.exists(_P360_FUSION_CONFIG):
                    with open(_P360_FUSION_CONFIG) as f:
                        self._fusion_config = json.load(f)
                if os.path.exists(_P360_THRESHOLD_CFG):
                    with open(_P360_THRESHOLD_CFG) as f:
                        self._threshold_cfg = json.load(f)

                self._model_type = "phish360_learned_fusion"
                print("[PhishOut] Phish360 research models loaded:")
                print("  structural_model + semantic_model + learned_fusion")
                return
            except Exception as e:
                print(f"[PhishOut] WARNING: Could not load Phish360 models — {e}")

        elif p360_struct_ok:
            try:
                self._struct_model  = joblib.load(_P360_STRUCT_MODEL)
                self._struct_scaler = joblib.load(_P360_STRUCT_SCALER)
                self._model_type = "phish360_structural_only"
                print("[PhishOut] Phish360 structural model loaded (no fusion).")
                return
            except Exception as e:
                print(f"[PhishOut] WARNING: Could not load Phish360 structural model — {e}")

        # ── Priority 2: Legacy structural-only model ──────────────────────────
        if os.path.exists(_LEGACY_STRUCT_MODEL) and os.path.exists(_LEGACY_STRUCT_SCALER):
            try:
                self._struct_model  = joblib.load(_LEGACY_STRUCT_MODEL)
                self._struct_scaler = joblib.load(_LEGACY_STRUCT_SCALER)
                self._model_type = "legacy_structural_only"
                print("[PhishOut] Legacy structural model loaded (fallback).")
                return
            except Exception as e:
                print(f"[PhishOut] WARNING: Could not load legacy model — {e}")

        print("[PhishOut] No trained model found — using rule-based scoring.")
        self._model_type = "rule_based"

    # ── Public interface ───────────────────────────────────────────────────

    def predict(self, url: str, fetch_timeout: int = _FETCH_TIMEOUT) -> Dict:
        """
        Run the full PhishOut pipeline for a URL.

        Args:
            url:           URL to analyse (scheme optional — http:// prepended if missing).
            fetch_timeout: Seconds to wait for webpage fetch.

        Returns:
            Structured result dict with risk_score, verdict, explanations.
        """
        # ── Step 1: Validate + normalise URL ──────────────────────────────
        url = _normalise_url(url)

        # ── Step 2: Structural analysis ────────────────────────────────────
        struct_result  = analyze_structural(url, model=self._struct_model,
                                            scaler=self._struct_scaler)
        struct_feats   = struct_result["features"]
        struct_score   = struct_result["structural_score"]
        struct_prob    = struct_result["phishing_probability"]
        struct_evidence = struct_result["structural_evidence"]

        # ── Step 3: Fetch webpage ──────────────────────────────────────────
        html = fetch_webpage(url, timeout=fetch_timeout)
        webpage_available = html is not None

        # ── Step 4: Extract semantic features ─────────────────────────────
        if webpage_available:
            sem_feats = extract_semantic_features(html, url)
        else:
            sem_feats = _empty_semantic_features()

        # ── Step 5: Generate semantic evidence strings ─────────────────────
        if webpage_available:
            sem_evidence = generate_semantic_evidence(sem_feats, url, struct_feats)
        else:
            sem_evidence = ["Webpage could not be fetched; semantic analysis is unavailable."]

        # ── Step 6: Inject compound flags for scorer ───────────────────────
        sem_feats_scored = _inject_compound_flags(sem_feats, url, struct_feats)

        # ── Step 7: Calculate semantic score (rule-based, for display) ─────
        semantic_rule_score = calculate_semantic_score(sem_feats_scored) if webpage_available else 0
        semantic_score = semantic_rule_score
        semantic_probability = 0.0

        # ── Step 8: Compute final probability / risk score ─────────────────
        if self._model_type == "phish360_learned_fusion" and webpage_available and self._sem_model is not None:
            # Use learned score-level fusion
            sem_arr = _sem_features_to_array(sem_feats)
            sem_arr_s = self._sem_scaler.transform(sem_arr)
            sem_prob = float(self._sem_model.predict_proba(sem_arr_s)[0, 1])
            semantic_probability = sem_prob
            semantic_score = max(0, min(100, int(round(sem_prob * 100))))

            X_fusion = np.array([[struct_prob, sem_prob]])
            fusion_prob = float(self._fusion_model.predict_proba(X_fusion)[0, 1])
            phishout_score = max(0, min(100, int(round(fusion_prob * 100))))
            fusion_mode = "phish360_learned_fusion"
            fusion_note = (
                f"Learned score-level fusion (Phish360): "
                f"P(phish) = sigmoid({self._fusion_config.get('coef_structural', 0):+.2f}×p_struct "
                f"{self._fusion_config.get('coef_semantic', 0):+.2f}×p_sem "
                f"{self._fusion_config.get('intercept', 0):+.2f})"
            )
        elif self._model_type == "phish360_learned_fusion" and not webpage_available:
            # No HTML — structural-only
            phishout_score = struct_score
            fusion_mode = "structural_only"
            fusion_note = "Webpage unavailable; using structural model only."
        else:
            # Legacy: weighted fusion or rule-based
            fusion = fuse_scores(struct_score, semantic_score, webpage_available)
            phishout_score = fusion["phishout_score"]
            fusion_mode = fusion["fusion_mode"]
            fusion_note = fusion["note"]

        # ── Step 9: Assign verdict ─────────────────────────────────────────
        # Use calibrated thresholds if available (Phish360), else default
        if self._threshold_cfg:
            phish_min_score = self._threshold_cfg.get("phishing_min_risk_score", 60)
            safe_max_score  = self._threshold_cfg.get("safe_max_risk_score", 30)
            if phishout_score >= phish_min_score:
                verdict = "PHISHING"
            elif phishout_score >= safe_max_score:
                verdict = "SUSPICIOUS"
            else:
                verdict = "SAFE"
        else:
            verdict = assign_verdict(phishout_score)

        # ── Step 10: Generate explanations + assemble result ──────────────
        reasons = generate_explanations(
            structural_features=struct_feats,
            semantic_features=sem_feats_scored if webpage_available else None,
            webpage_available=webpage_available,
            fusion_note=fusion_note,
            struct_evidence=struct_evidence,
            sem_evidence=sem_evidence if webpage_available else None,
        )

        return {
            # Primary outputs
            "url":                        url,
            "risk_score":                 phishout_score,
            "verdict":                    verdict,
            # Component scores
            "structural_score":           struct_score,
            "semantic_score":             semantic_score,
            "phishing_probability":       round(struct_prob, 4),
            "semantic_probability":        round(semantic_probability, 4),
            "semantic_rule_score":         semantic_rule_score,
            # Availability
            "webpage_analysis_available": webpage_available,
            "fusion_mode":                fusion_mode,
            "fusion_note":                fusion_note,
            # Details
            "model_type":                 self._model_type,
            "structural_analysis":        {
                k: (round(v, 4) if isinstance(v, float) else v)
                for k, v in struct_feats.items()
            },
            "structural_evidence":        struct_evidence,
            "semantic_analysis":          _serialise_semantic(sem_feats),
            "semantic_evidence":          sem_evidence,
            # Unified explanations
            "reasons":                    reasons,
        }


# ── Helper utilities ───────────────────────────────────────────────────────────

def _normalise_url(url: str) -> str:
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    return url


def _sem_features_to_array(sem_feats: Dict) -> np.ndarray:
    """Convert semantic features dict to numpy array for model input."""
    values = []
    for key in SEMANTIC_KEYS:
        v = sem_feats.get(key, 0)
        if isinstance(v, list):
            v = len(v)
        if v is None:
            v = 0
        values.append(float(v))
    return np.array(values).reshape(1, -1)


def _empty_semantic_features() -> Dict:
    return {
        "page_title":            None,
        "text_length":           0,
        "password_fields":       0,
        "text_email_fields":     0,
        "forms":                 0,
        "form_actions":          [],
        "external_links":        0,
        "iframes":               0,
        "scripts":               0,
        "login_indicators":      0,
        "credential_indicators": 0,
        "payment_indicators":    0,
        "urgency_indicators":    0,
        "brand_indicators":      0,
        "_has_external_form_action": False,
        "_brand_mismatch_on_page":   False,
    }


def _inject_compound_flags(sem_feats: Dict, url: str, struct_feats: Dict) -> Dict:
    feats = dict(sem_feats)
    base_domain = urlparse(url).netloc.lower()

    ext_action = False
    for action in feats.get("form_actions", []):
        try:
            action_domain = urlparse(action).netloc.lower()
            if action_domain and action_domain != base_domain:
                ext_action = True
                break
        except Exception:
            pass
    feats["_has_external_form_action"] = ext_action

    brands = feats.get("brand_indicators", 0)
    bis    = struct_feats.get("brand_impersonation_score", 0)
    feats["_brand_mismatch_on_page"] = brands > 0 and bis >= 0.5

    return feats


def _serialise_semantic(sem_feats: Dict) -> Dict:
    return {k: v for k, v in sem_feats.items() if not k.startswith("_")}


# ── Module-level singleton ─────────────────────────────────────────────────────

_predictor: Optional[PhishOutPredictor] = None


def get_predictor() -> PhishOutPredictor:
    global _predictor
    if _predictor is None:
        _predictor = PhishOutPredictor()
    return _predictor


def predict(url: str, fetch_timeout: int = _FETCH_TIMEOUT) -> Dict:
    return get_predictor().predict(url, fetch_timeout=fetch_timeout)
