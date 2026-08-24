"""
PhishGuard ML Feature Extractor — v3.0
32 engineered features based on academic phishing research.
"""
import re
import math
from urllib.parse import urlparse, unquote
import Levenshtein
import numpy as np

# ── Top brands to check for impersonation ──────────────────────────────────
KNOWN_DOMAINS = [
    "facebook.com", "google.com", "paypal.com", "github.com",
    "microsoft.com", "apple.com", "amazon.com", "netflix.com",
    "instagram.com", "linkedin.com", "twitter.com", "x.com",
    "youtube.com", "reddit.com", "wikipedia.org", "yahoo.com",
    "ebay.com", "dropbox.com", "spotify.com", "twitch.tv",
    "outlook.com", "office.com", "live.com", "onedrive.com",
    "chase.com", "wellsfargo.com", "bankofamerica.com", "citibank.com",
    "steam.com", "discord.com", "tiktok.com", "snapchat.com",
]

BRAND_NAMES = [d.split(".")[0] for d in KNOWN_DOMAINS]

SHORTENING_SERVICES = [
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
    "rebrand.ly", "cutt.ly", "bl.ink", "sh.st", "adf.ly",
    "is.gd", "shorturl.at", "tiny.cc", "snip.ly",
]

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "account", "secure", "security",
    "verify", "verification", "confirm", "update", "banking",
    "password", "credential", "wallet", "authenticate", "auth",
    "webscr", "cmd", "dispatch", "checkout", "support", "helpdesk",
    "service", "portal", "access", "recover", "reset", "unlock",
]

LOGIN_PATH_WORDS = [
    "login", "signin", "sign-in", "logon", "log-in",
    "authenticate", "auth", "session", "account", "password",
    "passwd", "pwd", "credential", "secure", "webscr",
]

REDIRECT_PARAMS = ["redirect", "url", "next", "return", "goto", "redir", "link", "target"]

# TLD risk scoring: 0.0 (safe) → 1.0 (very risky)
TLD_RISK = {
    ".com": 0.1, ".org": 0.1, ".net": 0.15, ".edu": 0.0, ".gov": 0.0,
    ".co.uk": 0.1, ".io": 0.2, ".co": 0.2,
    ".tk": 1.0, ".ml": 1.0, ".ga": 1.0, ".cf": 1.0, ".gq": 1.0,
    ".xyz": 0.8, ".top": 0.85, ".club": 0.7, ".online": 0.75,
    ".site": 0.75, ".info": 0.5, ".biz": 0.5, ".work": 0.8,
    ".click": 0.9, ".link": 0.7, ".shop": 0.4, ".store": 0.4,
    ".live": 0.6, ".app": 0.2, ".dev": 0.15, ".pw": 0.9,
    ".cc": 0.6, ".ws": 0.7, ".ru": 0.5, ".cn": 0.45,
}

FEATURE_KEYS = [
    # — URL structure —
    "url_length", "hostname_length", "path_length", "query_length",
    "url_depth", "num_params",
    # — Domain characteristics —
    "has_ip", "has_at", "has_port", "double_slash",
    "prefix_suffix", "sub_domain_count", "excessive_dots",
    "numeric_subdomain", "punycode_present",
    # — Security signals —
    "https_token", "is_shortening", "tld_risk_score",
    "has_redirect_param", "double_extension", "hex_encoded",
    # — Lexical / entropy —
    "domain_entropy", "digit_ratio", "special_char_count",
    "consonant_ratio", "longest_word_length",
    # — Brand & keyword intelligence —
    "brand_impersonation_score", "subdomain_brand_match",
    "suspicious_keywords", "login_path_score",
    # — Typosquatting —
    "levenshtein_min", "levenshtein_ratio",
]

FEATURE_LABELS = {
    "url_length": "URL Length",
    "hostname_length": "Hostname Length",
    "path_length": "Path Length",
    "query_length": "Query Length",
    "url_depth": "URL Depth",
    "num_params": "Query Parameters",
    "has_ip": "IP Address Used",
    "has_at": "@ Symbol Present",
    "has_port": "Unusual Port",
    "double_slash": "Double Slash in Path",
    "prefix_suffix": "Hyphen in Domain",
    "sub_domain_count": "Subdomain Count",
    "excessive_dots": "Excessive Dots",
    "numeric_subdomain": "Numeric Subdomain",
    "punycode_present": "Punycode (IDN Attack)",
    "https_token": "HTTPS in Domain Name",
    "is_shortening": "URL Shortener Used",
    "tld_risk_score": "TLD Risk Score",
    "has_redirect_param": "Redirect Parameter",
    "double_extension": "Double File Extension",
    "hex_encoded": "Hex Encoding in Domain",
    "domain_entropy": "Domain Entropy",
    "digit_ratio": "Digit Ratio",
    "special_char_count": "Special Characters",
    "consonant_ratio": "Consonant Ratio",
    "longest_word_length": "Longest Token Length",
    "brand_impersonation_score": "Brand Impersonation",
    "subdomain_brand_match": "Brand in Subdomain",
    "suspicious_keywords": "Suspicious Keywords",
    "login_path_score": "Login Path Score",
    "levenshtein_min": "Typosquatting Distance",
    "levenshtein_ratio": "Typosquatting Ratio",
}

FEATURE_NORM = {
    "url_length": 300, "hostname_length": 75, "path_length": 200,
    "query_length": 150, "url_depth": 10, "num_params": 12,
    "has_ip": 1, "has_at": 1, "has_port": 1, "double_slash": 1,
    "prefix_suffix": 1, "sub_domain_count": 6, "excessive_dots": 1,
    "numeric_subdomain": 1, "punycode_present": 1,
    "https_token": 1, "is_shortening": 1, "tld_risk_score": 1.0,
    "has_redirect_param": 1, "double_extension": 1, "hex_encoded": 1,
    "domain_entropy": 5, "digit_ratio": 1, "special_char_count": 25,
    "consonant_ratio": 1, "longest_word_length": 30,
    "brand_impersonation_score": 1.0, "subdomain_brand_match": 1,
    "suspicious_keywords": 6, "login_path_score": 1.0,
    "levenshtein_min": 15, "levenshtein_ratio": 1.0,
}


# ── Helpers ─────────────────────────────────────────────────────────────────

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _consonant_ratio(s: str) -> float:
    consonants = set("bcdfghjklmnpqrstvwxyz")
    letters = [c for c in s.lower() if c.isalpha()]
    if not letters:
        return 0.0
    return sum(1 for c in letters if c in consonants) / len(letters)


def _brand_impersonation_score(hostname: str, base_domain: str) -> float:
    """
    Returns a 0–1 score: how likely this domain is impersonating a brand.
    Combines Levenshtein proximity + brand keyword presence in wrong domain.
    """
    best = 0.0
    for brand_domain in KNOWN_DOMAINS:
        brand_base = brand_domain.split(".")[0]
        # Skip exact matches (those are legitimate)
        if base_domain == brand_domain:
            return 0.0
        dist = Levenshtein.distance(base_domain, brand_domain)
        max_len = max(len(base_domain), len(brand_domain))
        ratio = 1 - (dist / max_len) if max_len > 0 else 0.0
        # High similarity but not exact = suspicious
        if 0.6 < ratio < 1.0:
            best = max(best, ratio)
        # Brand name appearing inside a different domain
        if brand_base in base_domain and base_domain != brand_base:
            best = max(best, 0.85)
    return round(best, 4)


def _login_path_score(path: str) -> float:
    """Returns 0–1 score of how login-like the URL path is."""
    path_lower = path.lower()
    hits = sum(1 for word in LOGIN_PATH_WORDS if word in path_lower)
    return min(hits / 3.0, 1.0)


def _get_tld_risk(hostname: str) -> float:
    for tld, risk in sorted(TLD_RISK.items(), key=lambda x: -len(x[0])):
        if hostname.endswith(tld):
            return risk
    return 0.3  # Unknown TLD — slightly suspicious


def _longest_token(url: str) -> int:
    tokens = re.split(r"[./\-_?&=]", url)
    return max((len(t) for t in tokens if t.isalpha()), default=0)


# ── Main feature extractor ───────────────────────────────────────────────────

def extract_features(url: str) -> dict:
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full_url = url

    parts = hostname.split(".")
    base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    subdomains = parts[:-2] if len(parts) > 2 else []

    # ── Basic structural ──────────────────────────────────────────────────
    has_ip = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0
    has_port = 1 if parsed.port and parsed.port not in (80, 443) else 0
    has_at = 1 if "@" in full_url else 0
    double_slash = 1 if "//" in path else 0
    prefix_suffix = 1 if "-" in hostname else 0
    sub_domain_count = max(0, len(parts) - 2)
    excessive_dots = 1 if hostname.count(".") >= 4 else 0
    numeric_subdomain = 1 if any(s.isdigit() for s in subdomains) else 0
    punycode_present = 1 if "xn--" in hostname else 0
    url_depth = len([p for p in path.split("/") if p])

    # ── Security signals ──────────────────────────────────────────────────
    https_token = 1 if "https" in hostname and not hostname.startswith("https") else 0
    is_shortening = 1 if any(s in hostname for s in SHORTENING_SERVICES) else 0
    tld_risk_score = _get_tld_risk(hostname)

    query_lower = query.lower()
    has_redirect_param = 1 if any(p in query_lower for p in REDIRECT_PARAMS) else 0

    path_lower = path.lower()
    double_extension = 1 if re.search(r"\.\w{2,4}\.\w{2,4}($|\?)", path_lower) else 0
    hex_encoded = 1 if re.search(r"%[0-9a-f]{2}", hostname.lower()) else 0

    # ── Lexical ───────────────────────────────────────────────────────────
    domain_entropy = round(_entropy(hostname), 4)
    digit_ratio = round(sum(c.isdigit() for c in full_url) / max(len(full_url), 1), 4)
    special_char_count = sum(c in "!$%^&*()+=[]{}|;'<>?," for c in full_url)
    consonant_ratio = round(_consonant_ratio(hostname), 4)
    longest_word_length = _longest_token(full_url)

    # ── Brand & keyword intelligence ──────────────────────────────────────
    brand_score = _brand_impersonation_score(hostname, base_domain)

    subdomain_str = ".".join(subdomains)
    subdomain_brand_match = 1 if any(b in subdomain_str for b in BRAND_NAMES) and base_domain not in KNOWN_DOMAINS else 0

    kw_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in full_url.lower())
    login_path_score = round(_login_path_score(path), 4)

    # ── Typosquatting ─────────────────────────────────────────────────────
    distances = [Levenshtein.distance(base_domain, d) for d in KNOWN_DOMAINS]
    min_dist = min(distances)
    # Levenshtein ratio: normalized 0=exact match 1=completely different
    min_domain = KNOWN_DOMAINS[distances.index(min_dist)]
    max_len = max(len(base_domain), len(min_domain))
    lev_ratio = round(min_dist / max_len, 4) if max_len > 0 else 1.0
    # If exact match, no suspicion
    if base_domain in KNOWN_DOMAINS:
        min_dist = 99
        lev_ratio = 1.0
        brand_score = 0.0
        subdomain_brand_match = 0

    return {
        "url_length": len(full_url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "url_depth": url_depth,
        "num_params": len(query.split("&")) if query else 0,
        "has_ip": has_ip,
        "has_at": has_at,
        "has_port": has_port,
        "double_slash": double_slash,
        "prefix_suffix": prefix_suffix,
        "sub_domain_count": sub_domain_count,
        "excessive_dots": excessive_dots,
        "numeric_subdomain": numeric_subdomain,
        "punycode_present": punycode_present,
        "https_token": https_token,
        "is_shortening": is_shortening,
        "tld_risk_score": tld_risk_score,
        "has_redirect_param": has_redirect_param,
        "double_extension": double_extension,
        "hex_encoded": hex_encoded,
        "domain_entropy": domain_entropy,
        "digit_ratio": digit_ratio,
        "special_char_count": special_char_count,
        "consonant_ratio": consonant_ratio,
        "longest_word_length": longest_word_length,
        "brand_impersonation_score": brand_score,
        "subdomain_brand_match": subdomain_brand_match,
        "suspicious_keywords": min(kw_count, 6),
        "login_path_score": login_path_score,
        "levenshtein_min": min_dist,
        "levenshtein_ratio": lev_ratio,
    }


def features_to_array(features: dict) -> np.ndarray:
    return np.array([features[k] for k in FEATURE_KEYS]).reshape(1, -1)


def normalize_features(features: dict) -> dict:
    return {
        k: round(min(v / FEATURE_NORM.get(k, 1), 1.0), 3)
        for k, v in features.items()
    }


# ══════════════════════════════════════════════════════════════════════════════
# Clean structural analysis interface for the PhishOut pipeline
# ══════════════════════════════════════════════════════════════════════════════

def _structural_evidence(features: dict) -> list:
    """
    Derive a list of human-readable structural risk signals from feature values.
    Called internally by analyze_structural(); also used by explanation_engine.
    """
    evidence = []

    if features.get("has_ip"):
        evidence.append("IP address used as hostname instead of a domain name.")
    if features.get("has_at"):
        evidence.append("@ symbol in URL — can redirect browser to a different host.")
    if features.get("punycode_present"):
        evidence.append("Punycode / IDN encoding in domain — visual spoofing technique.")
    if features.get("is_shortening"):
        evidence.append("URL shortener service used — hides the real destination.")
    if features.get("https_token"):
        evidence.append("'https' keyword embedded in domain name — false security signal.")
    if features.get("double_extension"):
        evidence.append("Double file extension in path (e.g., .pdf.html) — content spoofing.")
    if features.get("hex_encoded"):
        evidence.append("Hex-encoded characters in domain — obfuscation detected.")
    if features.get("has_redirect_param"):
        evidence.append("Open redirect parameter detected in URL.")
    if features.get("prefix_suffix"):
        evidence.append("Hyphen in domain name — common in phishing domains.")

    tld = features.get("tld_risk_score", 0)
    if tld >= 0.8:
        evidence.append(f"Very high-risk top-level domain (TLD risk score: {tld:.2f}).")
    elif tld >= 0.5:
        evidence.append(f"Elevated-risk top-level domain (TLD risk score: {tld:.2f}).")

    bis = features.get("brand_impersonation_score", 0)
    if bis >= 0.7:
        evidence.append(
            f"Domain closely resembles a known brand (impersonation score: {bis:.2f})."
        )
    elif bis >= 0.5:
        evidence.append(
            f"Domain shows possible brand similarity (impersonation score: {bis:.2f})."
        )

    if features.get("subdomain_brand_match"):
        evidence.append("Known brand name found in subdomain of a different domain.")

    lev = features.get("levenshtein_min", 99)
    if 0 < lev <= 2:
        evidence.append(
            f"Typosquatting detected — domain edit distance {lev} from a known brand."
        )

    kw = features.get("suspicious_keywords", 0)
    if kw >= 3:
        evidence.append(f"Multiple suspicious keywords in URL ({kw} found).")
    elif kw >= 1:
        evidence.append(f"Suspicious keyword(s) in URL ({kw} found).")

    lps = features.get("login_path_score", 0)
    if lps >= 0.67:
        evidence.append(f"Login-themed URL path detected (score: {lps:.2f}).")

    sdc = features.get("sub_domain_count", 0)
    if sdc >= 3:
        evidence.append(f"Excessive subdomain nesting ({sdc} levels) — obfuscation technique.")

    url_len = features.get("url_length", 0)
    if url_len > 100:
        evidence.append(f"Unusually long URL ({url_len} chars) — obfuscation technique.")

    return evidence


def analyze_structural(url: str, model=None, scaler=None) -> dict:
    """
    Clean structural analysis interface for the PhishOut pipeline.

    Extracts 32 URL features, runs the trained structural ML model (if
    available), and returns a structured dict suitable for the fusion layer.

    Args:
        url:    Fully-qualified URL to analyse (must include scheme).
        model:  Trained sklearn model. If None, uses rule-based score only.
        scaler: Fitted StandardScaler. Required if model is provided.

    Returns:
        {
            "features":            dict  — all 32 raw feature values,
            "structural_score":    int   — 0–100 risk score,
            "phishing_probability": float — model probability or rule estimate,
            "structural_evidence": list  — human-readable signal strings,
        }
    """
    features = extract_features(url)
    evidence = _structural_evidence(features)

    phish_prob = 0.0
    if model is not None and scaler is not None:
        try:
            X = features_to_array(features)
            X_s = scaler.transform(X)
            proba = model.predict_proba(X_s)[0]
            phish_prob = float(proba[1])
        except Exception:
            # Fall through to rule-based estimate
            phish_prob = _rule_based_prob(features)
    else:
        phish_prob = _rule_based_prob(features)

    structural_score = int(round(phish_prob * 100))
    structural_score = max(0, min(100, structural_score))

    return {
        "features": features,
        "structural_score": structural_score,
        "phishing_probability": round(phish_prob, 4),
        "structural_evidence": evidence,
    }


def _rule_based_prob(features: dict) -> float:
    """
    Lightweight rule-based phishing probability estimate.
    Used only when no trained model is available.
    """
    score = 0
    if features.get("has_ip"):          score += 20
    if features.get("has_at"):          score += 20
    if features.get("is_shortening"):   score += 15
    if features.get("punycode_present"): score += 15
    if features.get("tld_risk_score", 0) >= 0.8: score += 20
    if features.get("brand_impersonation_score", 0) >= 0.7: score += 25
    score += features.get("suspicious_keywords", 0) * 5
    lev = features.get("levenshtein_min", 99)
    if 0 < lev <= 1: score += 20
    elif lev == 2:   score += 10
    score = max(0, min(100, score))
    return score / 100.0

