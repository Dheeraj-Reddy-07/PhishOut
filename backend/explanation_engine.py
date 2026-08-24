"""
PhishOut Explanation Engine
============================
Generates deterministic, human-readable explanations for PhishOut predictions.

Design principles:
  - ONLY reports signals that are actually detected in the current URL/page.
  - No LLM, no templates with made-up values, no hallucination.
  - Ordered by severity (highest-confidence signals first).
  - Includes a "no webpage" note when semantic analysis was unavailable.
  - Clearly separates structural signals from semantic signals.

This engine is intentionally simple and rule-based. It will remain the
explanation mechanism until the final research dataset is processed and
a proper semantic ML model can be trained with explainability built in.
"""
from typing import Dict, List, Optional
from urllib.parse import urlparse


def generate_explanations(
    structural_features: Dict,
    semantic_features: Optional[Dict],
    webpage_available: bool,
    fusion_note: str,
    struct_evidence: Optional[List[str]] = None,
    sem_evidence: Optional[List[str]] = None,
) -> List[str]:
    """
    Generate an ordered list of human-readable explanation strings.

    Arguments:
        structural_features: Raw 32-feature dict from ml_model.extract_features().
        semantic_features:   Semantic features dict (from webpage_analyzer).
                             May be None or all-zeros if fetch failed.
        webpage_available:   Whether the webpage was successfully fetched.
        fusion_note:         Short string from the fusion layer describing
                             which mode was used.
        struct_evidence:     Pre-computed structural evidence list (optional).
                             If provided, used directly instead of re-deriving.
        sem_evidence:        Pre-computed semantic evidence list (optional).

    Returns:
        Ordered list of explanation strings. High-confidence signals first.
    """
    reasons: List[str] = []

    # ── Structural signals (always present) ────────────────────────────────

    if struct_evidence:
        reasons.extend(struct_evidence)
    else:
        reasons.extend(_derive_structural_reasons(structural_features))

    # ── Semantic signals (only when page was fetched) ──────────────────────

    if webpage_available and semantic_features:
        if sem_evidence:
            reasons.extend(sem_evidence)
        else:
            reasons.extend(_derive_semantic_reasons(semantic_features, structural_features))

    # ── Availability note ──────────────────────────────────────────────────

    if not webpage_available:
        if reasons:
            reasons.append(
                "Webpage could not be fetched — decision based primarily on URL structure."
            )
        else:
            reasons.append(
                "Webpage could not be fetched — URL structure was analysed only."
            )

    return reasons


# ── Internal helpers ───────────────────────────────────────────────────────────

def _derive_structural_reasons(f: Dict) -> List[str]:
    """Derive structural signal reasons from raw feature values."""
    reasons = []

    # Highest-confidence structural signals first
    bis = f.get("brand_impersonation_score", 0)
    lev = f.get("levenshtein_min", 99)

    if 0 < lev <= 1 and bis >= 0.7:
        reasons.append(
            f"Domain closely resembles a known brand "
            f"(impersonation score: {bis:.2f}, edit distance: {lev})."
        )
    elif bis >= 0.7:
        reasons.append(
            f"Domain closely resembles a known brand (impersonation score: {bis:.2f})."
        )
    elif bis >= 0.5:
        reasons.append(
            f"Domain shows possible brand similarity (impersonation score: {bis:.2f})."
        )
    elif 0 < lev <= 2:
        reasons.append(
            f"Typosquatting detected — domain is {lev} edit distance from a known brand."
        )

    if f.get("subdomain_brand_match"):
        reasons.append("Known brand name embedded in subdomain of a different domain.")

    tld = f.get("tld_risk_score", 0)
    if tld >= 0.8:
        reasons.append(f"Very high-risk top-level domain (TLD risk score: {tld:.2f}).")
    elif tld >= 0.5:
        reasons.append(f"Elevated-risk top-level domain (TLD risk score: {tld:.2f}).")

    kw = f.get("suspicious_keywords", 0)
    if kw >= 3:
        reasons.append(f"Multiple suspicious keywords in URL ({kw} found).")
    elif kw >= 1:
        reasons.append(f"Suspicious keyword(s) in URL ({kw} found).")

    lps = f.get("login_path_score", 0)
    if lps >= 0.67:
        reasons.append(f"Login-themed URL path detected (score: {lps:.2f}).")

    if f.get("has_ip"):
        reasons.append("IP address used as hostname instead of a domain name.")

    if f.get("has_at"):
        reasons.append("@ symbol in URL — can redirect browser to a different host.")

    if f.get("punycode_present"):
        reasons.append("Punycode / IDN encoding detected — visual domain spoofing technique.")

    if f.get("is_shortening"):
        reasons.append("URL shortener service used — hides the real destination.")

    if f.get("https_token"):
        reasons.append("'https' keyword embedded in domain name — false security signal.")

    if f.get("double_extension"):
        reasons.append("Double file extension in URL path — content-type spoofing technique.")

    if f.get("hex_encoded"):
        reasons.append("Hex-encoded characters in domain — obfuscation detected.")

    if f.get("has_redirect_param"):
        reasons.append("Open redirect parameter detected in URL.")

    if f.get("prefix_suffix"):
        reasons.append("Hyphen used in domain name — common in phishing domains.")

    sdc = f.get("sub_domain_count", 0)
    if sdc >= 3:
        reasons.append(f"Excessive subdomain nesting ({sdc} levels) — URL obfuscation.")

    url_len = f.get("url_length", 0)
    if url_len > 100:
        reasons.append(f"Unusually long URL ({url_len} characters) — obfuscation technique.")

    return reasons


def _derive_semantic_reasons(f: Dict, struct_f: Dict) -> List[str]:
    """Derive semantic signal reasons from extracted webpage features."""
    reasons = []

    # External form action is the highest-confidence semantic signal
    if f.get("_has_external_form_action"):
        reasons.append("Form submits credentials to an external domain.")

    pwd = f.get("password_fields", 0)
    if pwd > 0:
        reasons.append(f"Password input field(s) detected on page ({pwd}).")

    forms = f.get("forms", 0)
    cred  = f.get("credential_indicators", 0)
    if forms > 0 and cred > 0:
        reasons.append(
            f"Login/credential form detected "
            f"({forms} form(s), {cred} credential keyword(s))."
        )
    elif forms > 0:
        reasons.append(f"Form(s) detected on page ({forms}).")

    urgency = f.get("urgency_indicators", 0)
    if urgency > 3:
        reasons.append(f"Strong urgency / deception language detected ({urgency} occurrences).")
    elif urgency > 0:
        reasons.append(f"Urgency-related language detected ({urgency} occurrences).")

    payment = f.get("payment_indicators", 0)
    if payment > 2:
        reasons.append(f"Payment / financial content detected ({payment} occurrences).")

    login = f.get("login_indicators", 0)
    if login > 6:
        reasons.append(f"High density of login-related language ({login} occurrences).")

    brands = f.get("brand_indicators", 0)
    bis = struct_f.get("brand_impersonation_score", 0) if struct_f else 0
    if brands > 0 and bis >= 0.5:
        reasons.append(
            f"Brand name mentioned on page while domain appears to impersonate it "
            f"({brands} mention(s))."
        )

    iframes = f.get("iframes", 0)
    if iframes > 0:
        reasons.append(f"Iframe(s) detected ({iframes}) — can embed hidden malicious content.")

    ext = f.get("external_links", 0)
    if ext > 15:
        reasons.append(f"Unusually high number of external links ({ext}) — possible cloaking.")

    return reasons
