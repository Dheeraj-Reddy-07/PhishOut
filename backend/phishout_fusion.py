"""
PhishOut Fusion Layer
======================
Combines structural and semantic risk signals into a single PhishOut score.

Fusion strategy
---------------
The fusion layer handles two scenarios explicitly:

  Scenario A — Webpage available:
      phishout_score = (structural_weight × structural_score)
                     + (semantic_weight   × semantic_score)

  Scenario B — Webpage unavailable (fetch failed):
      phishout_score = structural_score
      The response notes that semantic evidence was unavailable.

All weights come from config/semantic_rules.py so they can be adjusted
without touching this module.

IMPORTANT — Calibration status
-------------------------------
The current weights (60% structural / 40% semantic) are PRELIMINARY.
They will be calibrated using the final research dataset when it is
selected and processed. See config/semantic_rules.py for documentation.
"""
from config.semantic_rules import FUSION, VERDICT_THRESHOLDS
from typing import Dict


def calculate_semantic_score(semantic_features: Dict) -> int:
    """
    Compute a 0–100 semantic risk score from the extracted semantic features.

    Uses an additive rule-based approach driven by the weights in
    config/semantic_rules.py. Score is clamped to [0, 100].

    This replaces an ML model for the semantic component until a proper
    live-phishing dataset is available for training.

    Args:
        semantic_features: Output of webpage_analyzer.extract_semantic_features()
                           (or all-zeros dict if fetch failed).

    Returns:
        Integer score 0–100.
    """
    from config.semantic_rules import SEMANTIC_WEIGHTS, THRESHOLDS

    score = 0

    # ── Password field (strongest single signal) ───────────────────────────
    if semantic_features.get("password_fields", 0) > 0:
        score += SEMANTIC_WEIGHTS["password_field"]

    # ── External form action ───────────────────────────────────────────────
    # Check if any form posts to a domain different from the page domain
    if semantic_features.get("_has_external_form_action", False):
        score += SEMANTIC_WEIGHTS["external_form_action"]

    # ── Credential form (form + credential keywords together) ──────────────
    forms = semantic_features.get("forms", 0)
    cred  = semantic_features.get("credential_indicators", 0)
    if forms > 0 and cred >= THRESHOLDS["credential_with_form"]:
        score += SEMANTIC_WEIGHTS["credential_form"]

    # ── Urgency language ───────────────────────────────────────────────────
    urgency = semantic_features.get("urgency_indicators", 0)
    if urgency >= THRESHOLDS["urgency_high"]:
        score += SEMANTIC_WEIGHTS["urgency_language"]
    elif urgency >= THRESHOLDS["urgency_any"]:
        score += SEMANTIC_WEIGHTS["urgency_language"] // 2

    # ── Payment content ────────────────────────────────────────────────────
    payment = semantic_features.get("payment_indicators", 0)
    if payment >= THRESHOLDS["payment_any"]:
        score += SEMANTIC_WEIGHTS["payment_content"]

    # ── Login content ──────────────────────────────────────────────────────
    login = semantic_features.get("login_indicators", 0)
    if login >= THRESHOLDS["login_high"]:
        score += SEMANTIC_WEIGHTS["login_content_high"]
    elif login >= THRESHOLDS["login_moderate"]:
        score += SEMANTIC_WEIGHTS["login_content_moderate"]

    # ── Brand mismatch on page ─────────────────────────────────────────────
    if semantic_features.get("_brand_mismatch_on_page", False):
        score += SEMANTIC_WEIGHTS["brand_mismatch_on_page"]

    # ── Iframes ────────────────────────────────────────────────────────────
    if semantic_features.get("iframes", 0) > 0:
        score += SEMANTIC_WEIGHTS["iframe_present"]

    # ── High external links ────────────────────────────────────────────────
    ext = semantic_features.get("external_links", 0)
    if ext >= THRESHOLDS["external_links_high"]:
        score += SEMANTIC_WEIGHTS["high_external_links"]

    return max(0, min(100, score))


def fuse_scores(
    structural_score: int,
    semantic_score: int,
    webpage_available: bool,
) -> Dict:
    """
    Fuse structural and semantic scores into a final PhishOut risk score.

    Args:
        structural_score:  0–100 score from the structural ML model.
        semantic_score:    0–100 score from the semantic rule engine.
        webpage_available: Whether the webpage was successfully fetched.

    Returns:
        {
            "phishout_score":    int   — final 0–100 risk score,
            "fusion_mode":       str   — "combined" or "structural_only",
            "structural_weight": float — weight applied to structural score,
            "semantic_weight":   float — weight applied to semantic score,
            "note":              str   — human-readable fusion explanation,
        }
    """
    if webpage_available:
        sw = FUSION["structural_weight_with_page"]
        ew = FUSION["semantic_weight_with_page"]
        raw = sw * structural_score + ew * semantic_score
        mode = "combined"
        note = (
            f"Combined structural ({sw:.0%}) and semantic ({ew:.0%}) analysis."
        )
    else:
        sw = FUSION["structural_weight_without_page"]
        ew = FUSION["semantic_weight_without_page"]
        raw = structural_score
        mode = "structural_only"
        note = (
            "Webpage could not be fetched; decision based primarily on URL "
            "structure. Semantic evidence unavailable."
        )

    final_score = max(0, min(100, int(round(raw))))

    return {
        "phishout_score":    final_score,
        "fusion_mode":       mode,
        "structural_weight": sw,
        "semantic_weight":   ew,
        "note":              note,
    }


def assign_verdict(phishout_score: int) -> str:
    """
    Map a 0–100 PhishOut score to a verdict label.

    Thresholds are defined in config/semantic_rules.py and are PRELIMINARY
    pending calibration on the final research dataset.

    Args:
        phishout_score: Integer 0–100.

    Returns:
        "SAFE", "SUSPICIOUS", or "PHISHING".
    """
    if phishout_score >= VERDICT_THRESHOLDS["PHISHING_MIN"]:
        return "PHISHING"
    elif phishout_score >= VERDICT_THRESHOLDS["SAFE_MAX"]:
        return "SUSPICIOUS"
    else:
        return "SAFE"
