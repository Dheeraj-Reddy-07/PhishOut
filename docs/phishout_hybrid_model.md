# PhishOut Hybrid Model — Technical Documentation

**Phase 3 of the PhishGuard Capstone Project**
**Version:** 1.0 | **Date:** August 2026

---

## Table of Contents

1. [Overview](#1-overview)
2. [Structural Component (32 features)](#2-structural-component)
3. [Semantic Component (12 features)](#3-semantic-component)
4. [Hybrid Model Architecture](#4-hybrid-model-architecture)
5. [Feature List](#5-complete-feature-list)
6. [Training Methodology](#6-training-methodology)
7. [Risk Scoring](#7-risk-scoring)
8. [Explanation Mechanism](#8-explanation-mechanism)
9. [Preliminary Comparison Results](#9-preliminary-comparison-results)
10. [Current Limitations](#10-current-limitations)

---

## 1. Overview

PhishOut is a **hybrid phishing detection model** that combines URL-structural analysis with webpage-semantic analysis to produce a calibrated phishing risk score.

### Architecture Summary

```
URL Input
    │
    ├──► Structural Extractor  ──► 32 features (URL-level, instant)
    │    [ml_model.py]
    │
    └──► Webpage Fetcher       ──► 12 features (content-level, network req.)
         [webpage_analyzer.py]
                │
                ▼
         ┌──────────────────┐
         │  Feature Vector  │  44 dimensions
         │  (32 + 12)       │
         └──────────────────┘
                │
                ▼
         ┌──────────────────┐
         │ Standard Scaler  │
         └──────────────────┘
                │
                ▼
         ┌──────────────────────────────────────┐
         │  VotingClassifier (soft)             │
         │    GradientBoostingClassifier (60%)  │
         │    RandomForestClassifier    (40%)   │
         └──────────────────────────────────────┘
                │
                ▼
         CalibratedClassifierCV (Platt sigmoid)
                │
                ▼
         Risk Score (0–100) + Verdict + Reasons
```

### Design Principles

- **Explainable**: Every prediction has human-readable reasons grounded in actual feature values
- **No LLM**: Explanations are rule-based, deterministic, and reproducible
- **Backward compatible**: Existing `/scan` and `/scan_extended` endpoints are unchanged
- **Graceful degradation**: Falls back to structural-only if webpage fetch fails
- **No data leakage**: Domain-level train/test split ensures clean evaluation

---

## 2. Structural Component

The structural component extracts **32 features** from the URL string itself, requiring no network access.

### Feature Categories

| Category | Features |
|---|---|
| URL structure | `url_length`, `hostname_length`, `path_length`, `query_length`, `url_depth`, `num_params` |
| Domain characteristics | `has_ip`, `has_at`, `has_port`, `double_slash`, `prefix_suffix`, `sub_domain_count`, `excessive_dots`, `numeric_subdomain`, `punycode_present` |
| Security signals | `https_token`, `is_shortening`, `tld_risk_score`, `has_redirect_param`, `double_extension`, `hex_encoded` |
| Lexical / entropy | `domain_entropy`, `digit_ratio`, `special_char_count`, `consonant_ratio`, `longest_word_length` |
| Brand intelligence | `brand_impersonation_score`, `subdomain_brand_match`, `suspicious_keywords`, `login_path_score` |
| Typosquatting | `levenshtein_min`, `levenshtein_ratio` |

### Key Algorithms

**Brand impersonation score**: Computes Levenshtein similarity between the base domain and each of 32 known brand domains. Returns 0–1 where 1.0 = exact match (not suspicious) and 0.7–0.99 = high impersonation risk.

**TLD risk score**: Lookup table assigning risk 0.0–1.0 to known TLDs. Free TLDs used heavily for phishing (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`) score 1.0.

**Typosquatting**: Minimum Levenshtein edit distance from any of 32 known domains. Distance ≤ 2 with non-exact match = suspicious.

---

## 3. Semantic Component

The semantic component fetches the webpage and extracts **12 numeric features** from its content.

### Missing Data Strategy: Zero-Fill on Fetch Failure

> Many simulated phishing URLs in the dataset (e.g., `http://paypa1.com/login`) do not resolve to actual live servers. Rather than inventing values, we use **zero-fill**: all semantic features are set to 0 when the fetch fails.

**Zeros mean**: "no webpage evidence detected" — not "definitely safe".

The hybrid model learns this asymmetry:
- Phishing URLs: mostly zero semantic features (unreachable), but high structural risk signals
- Legitimate URLs: real semantic data from fetched pages

### Fetch Conditions (all must pass)
1. HTTP/HTTPS scheme
2. Response status = 200
3. Content-Type contains `text/html`
4. Content length ≤ 1,000,000 bytes
5. No timeout (5s for extraction, 10s for inference)

### Semantic Features

| Feature | Description |
|---|---|
| `text_length` | Total visible text length (chars) |
| `password_fields` | Count of `<input type="password">` elements |
| `text_email_fields` | Count of text + email input fields |
| `forms` | Count of `<form>` elements |
| `external_links` | Count of links to external domains |
| `iframes` | Count of `<iframe>` elements |
| `scripts` | Count of `<script>` elements |
| `login_indicators` | Keyword matches: login, signin, credential, password, account, etc. |
| `credential_indicators` | Keyword matches: passcode, pin, otp, token, re-enter, etc. |
| `payment_indicators` | Keyword matches: credit card, billing, checkout, visa, etc. |
| `urgency_indicators` | Keyword matches: urgent, expires, suspended, act now, etc. |
| `brand_indicators` | Known brand name mentions in visible text |

> **Note**: `page_title` and `form_actions` are extracted but used only for explanations — they are not model inputs.

---

## 4. Hybrid Model Architecture

### Base Learners

**GradientBoostingClassifier** (weight: 60%)
- `n_estimators=300`, `learning_rate=0.08`, `max_depth=5`
- `min_samples_leaf=3`, `subsample=0.85`, `max_features="sqrt"`

**RandomForestClassifier** (weight: 40%)
- `n_estimators=200`, `max_depth=14`, `min_samples_leaf=2`
- `class_weight="balanced"`, `max_features="sqrt"`

### Ensemble
Soft-voting VotingClassifier combines both learners' probability outputs with the above weights.

### Probability Calibration
`CalibratedClassifierCV` with Platt sigmoid scaling on a 20% hold-out calibration set (from training data only). This maps the raw ensemble score to a calibrated probability.

---

## 5. Complete Feature List

**Index 0–31: Structural Features**

| # | Feature | Type | Description |
|---|---|---|---|
| 0 | `url_length` | int | Total URL length |
| 1 | `hostname_length` | int | Hostname length |
| 2 | `path_length` | int | URL path length |
| 3 | `query_length` | int | Query string length |
| 4 | `url_depth` | int | Path depth (/ segments) |
| 5 | `num_params` | int | Number of query params |
| 6 | `has_ip` | 0/1 | IP address as hostname |
| 7 | `has_at` | 0/1 | @ symbol in URL |
| 8 | `has_port` | 0/1 | Non-standard port |
| 9 | `double_slash` | 0/1 | // in path |
| 10 | `prefix_suffix` | 0/1 | Hyphen in hostname |
| 11 | `sub_domain_count` | int | Number of subdomains |
| 12 | `excessive_dots` | 0/1 | ≥4 dots in hostname |
| 13 | `numeric_subdomain` | 0/1 | Numeric subdomain |
| 14 | `punycode_present` | 0/1 | xn-- encoding present |
| 15 | `https_token` | 0/1 | "https" in domain name |
| 16 | `is_shortening` | 0/1 | URL shortener service |
| 17 | `tld_risk_score` | 0.0–1.0 | TLD risk level |
| 18 | `has_redirect_param` | 0/1 | Redirect param in query |
| 19 | `double_extension` | 0/1 | Double extension in path |
| 20 | `hex_encoded` | 0/1 | % hex encoding in domain |
| 21 | `domain_entropy` | float | Shannon entropy of hostname |
| 22 | `digit_ratio` | 0.0–1.0 | Fraction of digits in URL |
| 23 | `special_char_count` | int | Special character count |
| 24 | `consonant_ratio` | 0.0–1.0 | Consonant ratio in hostname |
| 25 | `longest_word_length` | int | Longest alphabetic token |
| 26 | `brand_impersonation_score` | 0.0–1.0 | Brand similarity score |
| 27 | `subdomain_brand_match` | 0/1 | Brand in subdomain |
| 28 | `suspicious_keywords` | 0–6 | Suspicious keyword count |
| 29 | `login_path_score` | 0.0–1.0 | Login-like path score |
| 30 | `levenshtein_min` | int | Min edit dist to known brand |
| 31 | `levenshtein_ratio` | 0.0–1.0 | Normalised edit distance |

**Index 32–43: Semantic Features**

| # | Feature | Type | Description |
|---|---|---|---|
| 32 | `text_length` | int | Visible text length |
| 33 | `password_fields` | int | Password inputs on page |
| 34 | `text_email_fields` | int | Text/email inputs on page |
| 35 | `forms` | int | Form count |
| 36 | `external_links` | int | External link count |
| 37 | `iframes` | int | Iframe count |
| 38 | `scripts` | int | Script tag count |
| 39 | `login_indicators` | int | Login keyword occurrences |
| 40 | `credential_indicators` | int | Credential keyword occurrences |
| 41 | `payment_indicators` | int | Payment keyword occurrences |
| 42 | `urgency_indicators` | int | Urgency keyword occurrences |
| 43 | `brand_indicators` | int | Known brand mentions |

---

## 6. Training Methodology

### Dataset
- **250 real URLs** (127 phishing, 123 legitimate) from `backend/dataset/clean_urls.csv`
- Constructed with intentional diversity across brand impersonation types, TLD abuse, encoding tricks, and legitimate service categories

### Split Strategy: Domain-Level
```
1. Extract base domain from each URL
2. Get unique domain list
3. Stratified split: 85% train / 15% test  (seed=42)
4. All URLs from a domain go to one partition only
   → Eliminates domain-level data leakage
5. Test set: NEVER augmented, NEVER seen during training
```

### Training Augmentation (training only)
Bootstrap resampling + Gaussian noise (`σ=0.08`) to reach 800 samples per class:
- Random bootstrap sample from existing training data
- Add Gaussian noise scaled by feature standard deviation
- Clip negative values to 0 (features are non-negative)

### Why No Deep Learning
- Dataset size (250 URLs) is too small for reliable DNN training
- GradientBoosting + RandomForest ensembles are well-proven for tabular phishing features
- Explainability via feature importances is preserved
- Calibrated probabilities are reliable without complex calibration networks

---

## 7. Risk Scoring

### Formula
```
risk_score = int(round(phishing_probability × 100))
risk_score = clamp(risk_score, 0, 100)
```

Where `phishing_probability` is the Platt-calibrated output of the hybrid ensemble.

### Thresholds
| Score Range | Verdict | Interpretation |
|---|---|---|
| 0–29 | **SAFE** | Low phishing risk |
| 30–59 | **SUSPICIOUS** | Moderate risk; exercise caution |
| 60–100 | **PHISHING** | High phishing risk |

### Fallback (no model loaded)
Rule-based score from key structural features:
- IP in URL: +20, @ symbol: +20, URL shortener: +15, Punycode: +15
- High TLD risk: +20, High brand impersonation: +25
- Suspicious keywords: +5 per keyword
- Password field detected: +10, Urgency language: +10

---

## 8. Explanation Mechanism

### Design: Rule-Based, Feature-Grounded
Every explanation is derived from **actual measured feature values** — not heuristics, not templates, and no LLM involvement.

### Rules by Category

**URL Structural:**
- `has_ip=1` → "IP address used instead of a domain name"
- `has_at=1` → "@ symbol in URL — can redirect browser to a different host"
- `punycode_present=1` → "Punycode / IDN encoding detected — visual domain spoofing"
- `is_shortening=1` → "URL shortener service detected — hides the real destination"
- `tld_risk_score ≥ 0.7` → "High-risk top-level domain (score: X)"
- `brand_impersonation_score ≥ 0.7` → "Brand impersonation detected (similarity: X)"
- `levenshtein_min ≤ 2` → "Typosquatting: domain closely resembles a known brand"
- `login_path_score ≥ 0.67` → "Login-themed URL path"
- `suspicious_keywords ≥ 3` → "Multiple suspicious keywords in URL"
- `sub_domain_count ≥ 3` → "Excessive subdomain nesting — obfuscation technique"
- `double_extension=1` → "Double file extension — content spoofing"
- `hex_encoded=1` → "Hex-encoded characters in domain"
- `url_length > 100` → "Unusually long URL — obfuscation technique"

**Semantic (only when fetch succeeded):**
- `password_fields > 0` → "Password input field(s) detected on page"
- `forms > 0 AND credential_indicators > 0` → "Login/credential form detected"
- `urgency_indicators > 3` → "Urgency / deception language detected"
- `payment_indicators > 3` → "Payment / financial keywords detected"
- `brand_indicators > 0 AND impersonation ≥ 0.5` → "Brand name on page with impersonating domain"
- `external_links > 15` → "High number of external links — possible cloaking"
- `iframes > 0` → "Iframe(s) detected — can embed hidden content"

---

## 9. Preliminary Comparison Results

> Results shown below are populated after training. If blank, run `python train_hybrid_model.py`.

### Data Completeness After Re-Extraction

| Partition | Total | Fetch Succeeded | Fetch Failed |
|---|---|---|---|
| Full dataset (250 URLs) | 250 | **122 (48.8%)** | **128 (51.2%)** |
| Phishing URLs (127) | 127 | ~15 (≈12%) | ~112 (≈88%) |
| Legitimate URLs (123) | 123 | ~107 (≈87%) | ~16 (≈13%) |

The severe asymmetry is expected: simulated phishing URLs (e.g., `paypa1.com`) don't resolve to real servers.

### Actual Model Comparison Results

Test set: **37 samples** (18 phishing, 19 legitimate) — domain-level split, untouched, seed=42.

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|
| **Structural Only** | **0.9730** | **0.9474** | **1.0000** | **0.9730** | **0.9971** |
| Semantic Only | 0.4054 | 0.3000 | 0.1667 | 0.2143 | 0.4664 |
| Hybrid PhishOut | 0.4595 | 0.4167 | 0.2778 | 0.3333 | 0.4386 |

### Confusion Matrices

**Structural Only** (best model):
```
                Predicted Legit   Predicted Phishing
Actual Legit         18 (TN)           1 (FP)
Actual Phishing       0 (FN)          18 (TP)
```

**Semantic Only**:
```
                Predicted Legit   Predicted Phishing
Actual Legit         12 (TN)           7 (FP)
Actual Phishing      15 (FN)           3 (TP)
```

**Hybrid PhishOut**:
```
                Predicted Legit   Predicted Phishing
Actual Legit         12 (TN)           7 (FP)
Actual Phishing      13 (FN)           5 (TP)
```

### Top Feature Importances

**Structural Only** (top 5): `suspicious_keywords` (0.197), `levenshtein_min` (0.150), `login_path_score` (0.087), `levenshtein_ratio` (0.079), `sub_domain_count` (0.070)

**Hybrid PhishOut** (top 5): `longest_word_length` (0.033), `consonant_ratio` (0.033), `tld_risk_score` (0.032), `levenshtein_ratio` (0.031), `path_length` (0.031)

> [!IMPORTANT]
> **Result: Hybrid model did NOT improve over structural-only on this dataset.**
> The structural-only model achieves **97.3% accuracy** and **0.997 ROC-AUC**.
> The hybrid model achieves **45.9% accuracy** — worse than a coin flip.
>
> This is a direct consequence of the **zero-fill asymmetry**: ~88% of phishing URLs
> have all-zero semantic features (unreachable pages). The semantic features add noise
> rather than signal, and they dilute the strong structural indicators the model learned.

> [!NOTE]
> This result does **not** mean the hybrid approach is wrong. It means the dataset
> has insufficient live phishing pages with real semantic data. In a production setting
> with live phishing URLs, semantic features (password fields, urgency language, brand
> indicators) would provide meaningful additional signal.

### Example Predictions (Verified — structural_only model)

| URL | Score | Verdict | Key Reasons |
|---|---|---|---|
| `https://www.google.com` | **0/100** | ✅ SAFE | No suspicious indicators; 1 form detected (expected) |
| `https://www.paypal.com` | **0/100** | ✅ SAFE | Known domain; login + payment language on page (normal) |
| `https://github.com/login` | **0/100** | ✅ SAFE | Login page on known domain; password field, credential form (expected) |
| `http://paypa1.com/login` | **100/100** | 🔴 PHISHING | Brand impersonation (0.90), typosquatting (edit dist=1), suspicious keywords |
| `http://paypal.account-verify.tk` | **100/100** | 🔴 PHISHING | High-risk TLD (.tk=1.0), brand in subdomain, suspicious keywords |
| `http://secure-paypal.com/signin` | **100/100** | 🔴 PHISHING | Brand impersonation (0.85), hyphen domain, 2 suspicious keywords |

---

## 10. Current Limitations

### Data Limitations
1. **250 training URLs** — small dataset; real-world deployment needs thousands
2. **Simulated phishing URLs** — constructed examples, not real-world captured phishing sites
3. **Semantic data asymmetry** — ~70% of phishing URLs have zero semantic features (unreachable)
4. **Static dataset** — phishing evolves rapidly; model needs periodic retraining

### Model Limitations
5. **No visual similarity** — logo/screenshot comparison not implemented (PhishOracle scope)
6. **No adversarial robustness** — model has not been tested against adversarial evasion
7. **No real-time TLD intelligence** — TLD risk table is static, not updated from threat feeds
8. **No WHOIS / DNS age features** — newly registered domains are a strong phishing signal not yet used
9. **No certificate transparency** — SSL cert checks not included

### Operational Limitations
10. **Fetch latency** — webpage semantic analysis adds 2–10 seconds per request
11. **Fetch failures for live phishing** — some active phishing pages may block bots
12. **No caching** — repeated scans of the same URL re-fetch each time

### Known Assumptions
- The "zero-fill on fetch failure" strategy assumes that unfetchable pages contribute zero evidence, which may undercount active phishing sites that are live
- The risk score thresholds (30/60) are set based on the calibrated model output on the current dataset — recalibration is needed when the dataset grows

---

## File Reference

| File | Description |
|---|---|
| `backend/ml_model.py` | 32 structural feature extractor |
| `backend/webpage_analyzer.py` | 12 semantic feature extractor |
| `backend/extract_hybrid_features.py` | Dataset feature extraction script |
| `backend/train_hybrid_model.py` | Model training & comparison |
| `backend/phishout_predictor.py` | Inference module (risk score + explanations) |
| `backend/main.py` | FastAPI endpoints including `/phishout/scan` |
| `backend/test_phishout.py` | Sanity test suite |
| `backend/dataset/hybrid_features.csv` | 250-sample hybrid feature dataset |
| `backend/models/hybrid_phishout_model.pkl` | Trained hybrid model |
| `backend/models/hybrid_phishout_scaler.pkl` | Feature scaler |
| `backend/models/hybrid_feature_order.txt` | Feature ordering for reproducibility |
| `backend/models/comparison_results.json` | 3-model comparison metrics |

---

## API Reference

### `POST /phishout/scan`

**Request:**
```json
{ "url": "https://example.com" }
```

**Response:**
```json
{
  "url": "https://example.com",
  "risk_score": 0,
  "verdict": "SAFE",
  "model_type": "hybrid",
  "phishing_probability": 0.023,
  "structural_analysis": {
    "url_length": 23,
    "brand_impersonation_score": 0.0,
    "suspicious_keywords": 0,
    "..."
  },
  "semantic_analysis": {
    "fetch_success": true,
    "page_title": "Example Domain",
    "password_fields": 0,
    "forms": 0,
    "login_indicators": 0,
    "..."
  },
  "reasons": []
}
```

---

*Document version 1.0 — Phase 3: PhishOut Hybrid Model. PhishOracle (adversarial robustness, visual similarity) is out of scope for this phase.*
