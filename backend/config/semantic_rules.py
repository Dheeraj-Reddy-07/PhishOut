"""
PhishOut Semantic Rules Configuration
======================================
Central configuration for all scoring weights, thresholds, and fusion
parameters used in the PhishOut pipeline.

IMPORTANT — Calibration Status
--------------------------------
ALL values in this file are PRELIMINARY and based on:
  - Published phishing detection research
  - Conservative expert judgement
  - Order-of-magnitude reasoning about relative signal strength

They have NOT yet been calibrated against a labelled research dataset.
Once the final PhishGuard dataset is selected and processed, these values
should be tuned empirically (e.g. grid search / Bayesian optimisation on
the validation set).

Do NOT treat these weights as final research findings.

Modification guide
------------------
Every weight entry includes:
  - value    : the numeric weight (contribution to semantic score 0–100)
  - rationale: why this weight was chosen
  - source   : academic / heuristic reference

To change a weight, update the value and revise the rationale.
"""

# ══════════════════════════════════════════════════════════════════════════════
# SEMANTIC SIGNAL WEIGHTS
# Budget: 100 points total (individual signals can stack but score is clamped)
# ══════════════════════════════════════════════════════════════════════════════

SEMANTIC_WEIGHTS = {

    # Password field present on page
    # Rationale: A password field on an unfamiliar domain is the single
    # strongest indicator of credential harvesting. Legitimate login pages
    # always exist on known, trusted domains — unknown domains with password
    # fields are almost always malicious.
    # Reference: Marchal et al. (2016), Sahoo et al. (2017)
    "password_field": 25,

    # Form submits to an external domain (different from the page domain)
    # Rationale: Harvesting forms that POST to an attacker-controlled server
    # are a classic phishing technique. This is a high-confidence signal.
    # Reference: Whittaker et al. (2010), APWG reports
    "external_form_action": 22,

    # Form present + credential-related keywords in page text
    # Rationale: A form accompanied by credential language (enter password,
    # confirm PIN, etc.) indicates an active credential collection attempt.
    "credential_form": 15,

    # Urgency / deception language detected (above threshold)
    # Rationale: Phishing pages frequently use psychological manipulation
    # ("Your account has been suspended", "Verify now or lose access").
    # Reference: Cialdini's principles of influence; Vishwanath et al. (2011)
    "urgency_language": 12,

    # Payment / financial content on a non-recognised payment domain
    # Rationale: Requesting credit card or banking details on an unfamiliar
    # domain is a strong indicator of financial phishing.
    "payment_content": 10,

    # Login-related content above threshold (high density of login keywords)
    # Rationale: Very high density of login language with forms suggests the
    # page was constructed specifically to imitate a login interface.
    "login_content_high": 8,

    # Brand name mentioned on page while structural analysis flags impersonation
    # Rationale: Combining brand mentions with domain impersonation creates a
    # compound signal — the page is trying to look like a brand it is not.
    "brand_mismatch_on_page": 8,

    # Iframe present
    # Rationale: Iframes are used to embed external content invisibly.
    # Phishing pages sometimes use iframes to load legitimate-looking content
    # from real sites while capturing form data locally.
    # Reference: Chou et al. (2004)
    "iframe_present": 5,

    # High number of external links (above threshold)
    # Rationale: Cloaked phishing pages sometimes include many external links
    # to appear legitimate while the core credential form is malicious.
    "high_external_links": 3,

    # Login-related content at moderate level (low density)
    # Rationale: Some login language is expected even on legitimate pages;
    # moderate presence alone is a weak signal.
    "login_content_moderate": 3,
}

# ══════════════════════════════════════════════════════════════════════════════
# SIGNAL DETECTION THRESHOLDS
# Controls when a signal is considered "detected"
# ══════════════════════════════════════════════════════════════════════════════

THRESHOLDS = {
    # How many urgency keyword occurrences to trigger HIGH urgency signal
    "urgency_high": 3,

    # How many urgency keyword occurrences to trigger any urgency signal
    "urgency_any": 1,

    # Payment keyword count to trigger payment signal
    "payment_any": 2,

    # Login keyword count to trigger HIGH login content signal
    "login_high": 6,

    # Login keyword count to trigger moderate login content signal
    "login_moderate": 2,

    # Credential keyword count to trigger credential-form signal (with forms)
    "credential_with_form": 1,

    # External link count to trigger "high external links" signal
    "external_links_high": 15,
}

# ══════════════════════════════════════════════════════════════════════════════
# FUSION PARAMETERS
# Controls how structural and semantic scores are combined
# ══════════════════════════════════════════════════════════════════════════════

FUSION = {
    # Weight for structural score when webpage IS available
    # Rationale: Structural features are more reliable for our current training
    # data. Semantic features provide meaningful supplementary evidence but
    # should not dominate when we have a well-calibrated structural model.
    "structural_weight_with_page": 0.60,

    # Weight for semantic score when webpage IS available
    "semantic_weight_with_page": 0.40,

    # Weight for structural score when webpage is NOT available (fetch failed)
    # Rationale: When we have no webpage evidence, we fall back entirely to the
    # structural model. The response clearly notes this limitation.
    "structural_weight_without_page": 1.00,

    # Weight for semantic score when webpage is NOT available
    "semantic_weight_without_page": 0.00,
}

# ══════════════════════════════════════════════════════════════════════════════
# VERDICT THRESHOLDS
# Maps the final PhishOut score (0–100) to a verdict label
# ══════════════════════════════════════════════════════════════════════════════

# IMPORTANT: These thresholds are PRELIMINARY.
# They will be calibrated using ROC analysis on the final research dataset
# to optimise the operating point (e.g. maximise F1 or minimise false negatives
# at a given false-positive rate).

VERDICT_THRESHOLDS = {
    # score < SAFE_MAX              → SAFE
    "SAFE_MAX":       30,

    # SAFE_MAX <= score < PHISHING_MIN → SUSPICIOUS
    # score >= PHISHING_MIN         → PHISHING
    "PHISHING_MIN":   60,
}
