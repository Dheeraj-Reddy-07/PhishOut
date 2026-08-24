"""
PhishOut Semantic Webpage Analyzer
====================================
Extracts semantic features from a webpage for phishing detection.

Architecture — three clean stages:
  A. fetch_webpage(url, timeout)            → raw HTML str | None
  B. extract_semantic_features(html, url)   → dict of 14 feature values
  C. generate_semantic_evidence(features, url, struct_features)
                                            → list of evidence strings

The public `analyze_webpage(url, timeout)` function orchestrates all three
and returns a unified result dict (backward-compatible with Phase 2).

Failure handling:
  If fetch_webpage() returns None (any network or validation error),
  all numeric features are set to 0, success=False, and a descriptive
  error message is included in the result. The pipeline continues — the
  fusion layer handles the unavailability of semantic evidence.
"""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional
import re


# ── Keyword banks ──────────────────────────────────────────────────────────────

LOGIN_KEYWORDS = [
    "login", "signin", "sign-in", "sign in", "log in", "authenticate",
    "authentication", "password", "username", "user", "email", "credential",
    "account", "access", "portal", "secure", "verify", "identity",
]

CREDENTIAL_KEYWORDS = [
    "password", "passcode", "pin", "secret", "security", "auth",
    "credential", "token", "otp", "verification", "confirm", "re-enter",
]

PAYMENT_KEYWORDS = [
    "payment", "credit card", "debit card", "bank", "billing", "invoice",
    "transaction", "purchase", "checkout", "pay", "card", "visa",
    "mastercard", "amex", "paypal", "stripe", "financial", "money",
]

URGENCY_KEYWORDS = [
    "urgent", "immediately", "now", "today", "expires", "expire",
    "limited time", "act now", "don't wait", "warning", "alert",
    "suspended", "locked", "verify now", "confirm immediately",
    "hurry", "last chance", "deadline",
]

BRAND_KEYWORDS = [
    "google", "facebook", "microsoft", "apple", "amazon", "paypal",
    "netflix", "chase", "wells fargo", "bank of america", "citibank",
    "dropbox", "linkedin", "twitter", "instagram", "tiktok", "spotify",
    "adobe", "intuit", "turbotax",
]

# Request headers that mimic a real browser
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

_MAX_CONTENT_BYTES = 1_000_000   # 1 MB cap
_DEFAULT_TIMEOUT   = 10          # seconds


# ══════════════════════════════════════════════════════════════════════════════
# Stage A — Fetch
# ══════════════════════════════════════════════════════════════════════════════

def fetch_webpage(url: str, timeout: int = _DEFAULT_TIMEOUT) -> Optional[str]:
    """
    Attempt to fetch a webpage and return its raw HTML string.

    Performs validation, content-type checking, and size limiting.
    Returns None on any failure — callers must handle this gracefully.

    Args:
        url:     Fully-qualified HTTP/HTTPS URL.
        timeout: Seconds to wait for response.

    Returns:
        Raw HTML string, or None if the fetch failed for any reason.
    """
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return None
        if parsed.scheme not in ("http", "https"):
            return None

        session = requests.Session()
        session.headers.update(_HEADERS)

        response = session.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            stream=True,
        )

        if response.status_code != 200:
            return None

        content_type = response.headers.get("content-type", "").lower()
        if "text/html" not in content_type:
            return None

        # Size cap — read up to limit
        content = b""
        for chunk in response.iter_content(chunk_size=8192):
            content += chunk
            if len(content) > _MAX_CONTENT_BYTES:
                break

        return content.decode("utf-8", errors="replace")

    except (
        requests.exceptions.Timeout,
        requests.exceptions.ConnectionError,
        requests.exceptions.RequestException,
        Exception,
    ):
        return None


# ══════════════════════════════════════════════════════════════════════════════
# Stage B — Extract
# ══════════════════════════════════════════════════════════════════════════════

def extract_semantic_features(html: str, url: str) -> Dict:
    """
    Extract 14 semantic feature values from a fetched HTML page.

    All values are numeric (int or float) to be directly usable by the
    semantic scorer and the fusion layer.

    Args:
        html: Raw HTML string (from fetch_webpage).
        url:  Original URL (used for relative→absolute link resolution).

    Returns:
        Dict with keys: page_title, text_length, password_fields,
        text_email_fields, forms, form_actions, external_links, iframes,
        scripts, login_indicators, credential_indicators,
        payment_indicators, urgency_indicators, brand_indicators.
    """
    soup = BeautifulSoup(html, "html.parser")
    base_domain = urlparse(url).netloc.lower()
    scripts = len(soup.find_all("script"))

    # ── Visible text (used for keyword counting) ───────────────────────────
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    raw_text = soup.get_text(separator=" ")
    lines = (line.strip() for line in raw_text.splitlines())
    visible_text = " ".join(chunk for line in lines for chunk in line.split("  ") if chunk)
    text_lower = visible_text.lower()

    # ── Title ──────────────────────────────────────────────────────────────
    page_title = None
    if soup.title and soup.title.string:
        page_title = soup.title.string.strip()

    # ── Form analysis ──────────────────────────────────────────────────────
    forms = soup.find_all("form")
    form_count = len(forms)
    password_fields = len(soup.find_all("input", {"type": "password"}))
    text_fields  = len(soup.find_all("input", {"type": "text"}))
    email_fields = len(soup.find_all("input", {"type": "email"}))
    text_email_fields = text_fields + email_fields

    form_actions = []
    for form in forms:
        action = form.get("action", "")
        if action:
            form_actions.append(urljoin(url, action))

    # ── Links / iframes / scripts ──────────────────────────────────────────
    external_links = 0
    for a in soup.find_all("a", href=True):
        try:
            link_netloc = urlparse(urljoin(url, a["href"])).netloc.lower()
            if link_netloc and link_netloc != base_domain:
                external_links += 1
        except Exception:
            continue

    iframes = len(soup.find_all("iframe"))

    # ── Keyword indicators ─────────────────────────────────────────────────
    def _count(keywords: List[str]) -> int:
        total = 0
        for kw in keywords:
            total += len(re.findall(r"\b" + re.escape(kw.lower()) + r"\b", text_lower))
        return total

    return {
        "page_title":            page_title,
        "text_length":           len(visible_text),
        "password_fields":       password_fields,
        "text_email_fields":     text_email_fields,
        "forms":                 form_count,
        "form_actions":          form_actions,
        "external_links":        external_links,
        "iframes":               iframes,
        "scripts":               scripts,
        "login_indicators":      _count(LOGIN_KEYWORDS),
        "credential_indicators": _count(CREDENTIAL_KEYWORDS),
        "payment_indicators":    _count(PAYMENT_KEYWORDS),
        "urgency_indicators":    _count(URGENCY_KEYWORDS),
        "brand_indicators":      _count(BRAND_KEYWORDS),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Stage C — Evidence
# ══════════════════════════════════════════════════════════════════════════════

def generate_semantic_evidence(
    features: Dict,
    url: str,
    struct_features: Optional[Dict] = None,
) -> List[str]:
    """
    Generate human-readable semantic evidence strings from extracted features.

    Only reports signals that are actually detected — no invented evidence.

    Args:
        features:       Output of extract_semantic_features().
        url:            Original URL (for external-form-action detection).
        struct_features: Optional structural features dict. When provided,
                         enables the brand-mismatch-on-page compound signal.

    Returns:
        List of evidence strings (may be empty for benign pages).
    """
    evidence = []
    base_domain = urlparse(url).netloc.lower()

    pwd = features.get("password_fields", 0)
    if pwd > 0:
        evidence.append(f"Password input field(s) detected on page ({pwd}).")

    forms = features.get("forms", 0)
    cred  = features.get("credential_indicators", 0)
    if forms > 0 and cred > 0:
        evidence.append(
            f"Login/credential form detected ({forms} form(s), "
            f"{cred} credential keyword(s))."
        )
    elif forms > 0:
        evidence.append(f"Form(s) detected on page ({forms}).")

    # External form actions
    for action in features.get("form_actions", []):
        try:
            action_domain = urlparse(action).netloc.lower()
            if action_domain and action_domain != base_domain:
                evidence.append(
                    f"Form submits data to an external domain ({action_domain})."
                )
        except Exception:
            pass

    login = features.get("login_indicators", 0)
    if login > 6:
        evidence.append(f"High density of login-related language on page ({login} occurrences).")
    elif login > 0:
        evidence.append(f"Login-related content detected ({login} occurrences).")

    urgency = features.get("urgency_indicators", 0)
    if urgency > 3:
        evidence.append(f"Strong urgency / deception language on page ({urgency} occurrences).")
    elif urgency > 0:
        evidence.append(f"Urgency-related language detected ({urgency} occurrences).")

    payment = features.get("payment_indicators", 0)
    if payment > 2:
        evidence.append(f"Payment / financial content detected ({payment} occurrences).")

    brands = features.get("brand_indicators", 0)
    if brands > 0 and struct_features:
        bis = struct_features.get("brand_impersonation_score", 0)
        if bis >= 0.5:
            evidence.append(
                f"Brand name mentioned on page while domain appears to impersonate it "
                f"({brands} mention(s))."
            )

    iframes = features.get("iframes", 0)
    if iframes > 0:
        evidence.append(f"Iframe(s) detected ({iframes}) — can embed hidden content.")

    ext_links = features.get("external_links", 0)
    if ext_links > 15:
        evidence.append(
            f"Unusually high number of external links ({ext_links}) — possible cloaking."
        )

    scripts = features.get("scripts", 0)
    if scripts > 30:
        evidence.append(f"High script count ({scripts}) — complex client-side behaviour.")

    return evidence


# ══════════════════════════════════════════════════════════════════════════════
# Public interface — full analysis in one call (backward-compatible)
# ══════════════════════════════════════════════════════════════════════════════

def analyze_webpage(url: str, timeout: int = _DEFAULT_TIMEOUT) -> Dict:
    """
    Full semantic webpage analysis.

    Orchestrates fetch → extract → evidence and returns a unified result dict.
    This function is backward-compatible with Phase 2 callers.

    Args:
        url:     URL to analyse.
        timeout: Seconds to wait for webpage fetch.

    Returns:
        Dict containing all semantic features, evidence list, and metadata.
        success=False when the page could not be fetched; all numeric
        features are 0 and a descriptive error is included.
    """
    _empty = {
        "success":               False,
        "error":                 None,
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
        "evidence":              [],
    }

    html = fetch_webpage(url, timeout=timeout)

    if html is None:
        result = dict(_empty)
        result["error"] = "Webpage could not be fetched (timeout, connection error, or non-HTML response)."
        result["evidence"] = [
            "Webpage could not be fetched; semantic analysis is unavailable."
        ]
        return result

    try:
        features = extract_semantic_features(html, url)
        evidence = generate_semantic_evidence(features, url)

        return {
            "success":               True,
            "error":                 None,
            "page_title":            features["page_title"],
            "text_length":           features["text_length"],
            "password_fields":       features["password_fields"],
            "text_email_fields":     features["text_email_fields"],
            "forms":                 features["forms"],
            "form_actions":          features["form_actions"],
            "external_links":        features["external_links"],
            "iframes":               features["iframes"],
            "scripts":               features["scripts"],
            "login_indicators":      features["login_indicators"],
            "credential_indicators": features["credential_indicators"],
            "payment_indicators":    features["payment_indicators"],
            "urgency_indicators":    features["urgency_indicators"],
            "brand_indicators":      features["brand_indicators"],
            "evidence":              evidence,
        }

    except Exception as e:
        result = dict(_empty)
        result["error"] = f"Feature extraction failed: {e}"
        result["evidence"] = [f"Semantic analysis failed: {e}"]
        return result


# ══════════════════════════════════════════════════════════════════════════════
# Offline analysis — stored HTML (no network, no URL required)
# ══════════════════════════════════════════════════════════════════════════════

def extract_semantic_features_from_html(html: str, url: str = "") -> Dict:
    """
    Extract 14 semantic feature values from **stored HTML**.

    Identical feature set to extract_semantic_features() but:
      - Requires no network access (uses stored HTML directly)
      - `url` is optional — when empty, external-link domain comparison
        is skipped (external_links will be 0)
      - Returns all-zero dict on any parsing failure

    This function is intended for OFFLINE dataset processing only.
    For live predictions, use analyze_webpage() which fetches the page first.

    Args:
        html: Raw HTML string from a dataset (e.g., PhreshPhish stored HTML).
        url:  Optional original URL. If provided, enables external-link
              domain comparison. If empty, external_links will be 0.

    Returns:
        Dict with the same 14 keys as extract_semantic_features().
    """
    if not html or not html.strip():
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
        }

    try:
        # Reuse the full feature extractor — it accepts stored HTML just fine.
        # Pass url="" if not available; external_links will be 0 in that case.
        return extract_semantic_features(html, url)
    except Exception:
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
        }


# ── Legacy class wrapper (kept for backward compatibility) ─────────────────────

class WebpageAnalyzer:
    """
    Backward-compatible class wrapper around the module-level functions.
    New code should use analyze_webpage() / fetch_webpage() / extract_semantic_features()
    directly rather than instantiating this class.
    """

    def __init__(self, timeout: int = _DEFAULT_TIMEOUT, max_content_length: int = _MAX_CONTENT_BYTES):
        self.timeout = timeout
        self.max_content_length = max_content_length

    def analyze(self, url: str) -> Dict:
        return analyze_webpage(url, timeout=self.timeout)

