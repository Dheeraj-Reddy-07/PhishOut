# PhishOut Baseline Documentation

**Date:** August 20, 2026  
**Purpose:** Establish reproducible baseline for PhishOut research transformation  
**Status:** Baseline operational and measured

---

## 1. Current Architecture

### System Components
- **Backend:** FastAPI (Python 3.12) running on `http://localhost:8000`
- **Frontend:** React 19.2.4 + Vite 8.0.3 running on `http://localhost:5173`
- **Extension:** Chrome Manifest V3 extension
- **ML Model:** Ensemble classifier (GradientBoosting + RandomForest)

### Data Flow
```
User Input → Frontend/Extension → FastAPI Backend → Feature Extraction → ML Model → Response
                                                      ↓
                                              Rule-based Checks
                                                      ↓
                                              Blended Scoring (70% ML + 30% Rules)
```

### Communication
- **Frontend → Backend:** HTTP POST to `/scan` endpoint with JSON `{"url": "..."}`
- **Extension → Backend:** Content script → Background service worker → API (avoids mixed-content blocking)
- **Model Loading:** Pickle files loaded at startup (`phishing_model.pkl`, `feature_scaler.pkl`)

---

## 2. Current Dataset

### Dataset Composition
- **Original Real Samples:** 250 URLs (127 phishing, 123 legitimate)
- **After Augmentation:** 1,600 samples (800 phishing, 800 legitimate)
- **Data Source:** Hardcoded in `backend/train_model.py` (lines 20-206)
- **Storage:** Python lists (no external CSV/JSON files)

### Sample Types
**Phishing URLs (127 real samples):**
- Typosquatting examples (paypa1.com, googIe.com, etc.)
- IP-based phishing (192.168.1.1, etc.)
- Suspicious TLDs (.tk, .ml, .ga, .cf, .gq, .xyz, .top, etc.)
- Long subdomain chains with brand impersonation
- Fake banking domains
- URL shorteners (bit.ly, tinyurl.com, etc.)
- Redirect parameter tricks
- Hex encoded domains
- Punycode IDN attacks
- Double extensions

**Legitimate URLs (123 real samples):**
- Major tech companies (Google, Facebook, Microsoft, Apple, Amazon)
- Financial services (PayPal, Chase, Wells Fargo, Bank of America)
- Developer platforms (GitHub, Stack Overflow)
- Social media (Twitter/X, LinkedIn, Reddit, YouTube)
- E-commerce (eBay, Shopify, Stripe)
- News and information sites

### Augmentation Method
- **Technique:** Bootstrap with Gaussian noise
- **Implementation:** Lines 237-268 in `train_model.py`
- **Noise Standard Deviation:** 0.08
- **Target Size:** 800 samples per class (balanced)
- **Random Seed:** 42 (for reproducibility)

---

## 3. Current 32 Features

### URL Structure (6 features)
1. `url_length` - Total URL character count
2. `hostname_length` - Domain name character count
3. `path_length` - URL path character count
4. `query_length` - Query string character count
5. `url_depth` - Number of path segments
6. `num_params` - Number of query parameters

### Domain Characteristics (10 features)
7. `has_ip` - Binary: IP address in hostname
8. `has_at` - Binary: @ symbol present in URL
9. `has_port` - Binary: non-standard port used
10. `double_slash` - Binary: // in path (after protocol)
11. `prefix_suffix` - Binary: hyphen in domain name
12. `sub_domain_count` - Number of subdomains
13. `excessive_dots` - Binary: 4+ dots in hostname
14. `numeric_subdomain` - Binary: numbers in subdomain
15. `punycode_present` - Binary: xn-- prefix (IDN attack)
16. `https_token` - Binary: "https" in domain name (not protocol)

### Security Signals (6 features)
17. `is_shortening` - Binary: known URL shortener used
18. `tld_risk_score` - TLD risk (0.0 safe → 1.0 very risky)
19. `has_redirect_param` - Binary: redirect parameter present
20. `double_extension` - Binary: double file extension
21. `hex_encoded` - Binary: hex encoding in hostname

### Lexical/Entropy (5 features)
22. `domain_entropy` - Shannon entropy of domain characters
23. `digit_ratio` - Ratio of digits in URL
24. `special_char_count` - Count of special characters
25. `consonant_ratio` - Ratio of consonants in hostname
26. `longest_word_length` - Length of longest alphanumeric token

### Brand & Keyword Intelligence (4 features)
27. `brand_impersonation_score` - 0-1 score of brand impersonation likelihood
28. `subdomain_brand_match` - Binary: brand name in subdomain
29. `suspicious_keywords` - Count of suspicious keywords (max 6)
30. `login_path_score` - 0-1 score of login-like path

### Typosquatting (2 features)
31. `levenshtein_min` - Minimum Levenshtein distance to known brands
32. `levenshtein_ratio` - Normalized Levenshtein ratio

### Feature Normalization
- **Method:** StandardScaler (z-score normalization)
- **File:** `feature_scaler.pkl`
- **Implementation:** Lines 279-281 in `train_model.py`

---

## 4. Current ML Model

### Model Architecture
**Ensemble Classifier (VotingClassifier - Soft Voting):**
- **Primary Model:** GradientBoostingClassifier (60% weight)
  - n_estimators: 300
  - learning_rate: 0.08
  - max_depth: 5
  - min_samples_leaf: 3
  - subsample: 0.85
  - max_features: "sqrt"
  - random_state: 42

- **Secondary Model:** RandomForestClassifier (40% weight)
  - n_estimators: 200
  - max_depth: 14
  - min_samples_leaf: 2
  - max_features: "sqrt"
  - class_weight: "balanced"
  - random_state: 42
  - n_jobs: -1

### Probability Calibration
- **Method:** CalibratedClassifierCV with sigmoid (Platt scaling)
- **Calibration Split:** 20% of training data held out for calibration
- **Fallback:** 3-fold CV if prefit calibration fails
- **Implementation:** Lines 316-343 in `train_model.py`

### Model Artifacts
- **File:** `backend/phishing_model.pkl` (6.1 MB)
- **Scaler:** `backend/feature_scaler.pkl` (1.3 KB)
- **Serialization:** joblib

---

## 5. Current Training Methodology

### Training Pipeline
1. **Feature Extraction:** Extract 32 features from all URLs
2. **Augmentation:** Generate synthetic samples via bootstrap with noise
3. **Train/Test Split:** 85% train, 15% test (stratified, random_state=42)
4. **Calibration Split:** 20% of training held out for calibration
5. **Model Training:** Train ensemble on non-calibration portion
6. **Calibration:** Calibrate probabilities on held-out set
7. **Evaluation:** Test on 15% held-out test set

### Cross-Validation
- **Method:** 5-fold stratified cross-validation
- **Scoring:** ROC-AUC
- **Implementation:** Lines 364-367 in `train_model.py`

### Feature Importance
- **Source:** RandomForest component of ensemble
- **Top 10 Features (from training run):**
  1. suspicious_keywords (0.1949)
  2. levenshtein_min (0.1289)
  3. prefix_suffix (0.0852)
  4. levenshtein_ratio (0.0831)
  5. sub_domain_count (0.0701)
  6. login_path_score (0.0643)
  7. url_length (0.0461)
  8. tld_risk_score (0.0432)
  9. path_length (0.0425)
  10. domain_entropy (0.0404)

---

## 6. Current Evaluation Methodology

### Test Set Composition
- **Split:** 15% of total data (240 samples)
- **Stratification:** Maintains class balance (120 phishing, 120 legitimate)
- **Random State:** 42 (fixed for reproducibility)

### Metrics Collected
- **Classification Report:** Precision, Recall, F1-score per class
- **Accuracy:** Overall classification accuracy
- **ROC-AUC:** Area under ROC curve
- **Confusion Matrix:** TN, FP, FN, TP counts
- **Cross-Validation:** 5-fold CV ROC-AUC mean ± std

### Evaluation Script
- **File:** `backend/train_model.py` (lines 345-367)
- **Output:** Printed to console during training

---

## 7. Actual Measured Metrics

### Training Run Results (August 20, 2026)

**Dataset Statistics:**
- Original real samples: 250 (127 phishing, 123 legitimate)
- After augmentation: 1,600 (800 phishing, 800 legitimate)
- Test set size: 240 (120 phishing, 120 legitimate)

**Classification Report:**
```
              precision    recall  f1-score   support

  Legitimate       1.00      1.00      1.00       120
    Phishing       1.00      1.00      1.00       120

    accuracy                           1.00       240
   macro avg       1.00      1.00      1.00       240
weighted avg       1.00      1.00      1.00       240
```

**ROC-AUC Score:** 1.0000

**Confusion Matrix:**
- True Negatives (legit→legit): 120
- False Positives (legit→phish): 0
- False Negatives (phish→legit): 0
- True Positives (phish→phish): 120

**Cross-Validation (5-fold):**
- CV ROC-AUC: 1.0000 ± 0.0000

**Note:** Perfect scores (1.0) indicate potential overfitting due to small dataset and synthetic augmentation.

---

## 8. Known Limitations

### Dataset Limitations
1. **Tiny Real Dataset:** Only 250 real samples (127 phishing, 123 legitimate)
2. **Synthetic Majority:** 1,350 of 1,600 samples (84%) are synthetic augmentations
3. **No Temporal Split:** Random split doesn't simulate real-world temporal evolution
4. **No External Validation:** No independent test set or benchmark comparison
5. **Hardcoded Data:** Dataset embedded in code, not external files
6. **No HTML Content:** Only URLs, no webpage content or screenshots
7. **No Version Control:** No dataset versioning or metadata tracking

### Methodology Limitations
1. **Data Leakage Risk:** Synthetic augmentation may create similar patterns in train/test
2. **No Adversarial Examples:** No robustness evaluation against adversarial attacks
3. **No Held-out Attacks:** Cannot claim adversarial robustness
4. **Overfitting Indicators:** Perfect scores suggest overfitting to augmentation patterns
5. **No Statistical Testing:** No confidence intervals or significance tests
6. **Domain Overlap Risk:** Same brands may appear in both classes

### Model Limitations
1. **URL-Only Analysis:** No semantic or visual analysis
2. **Limited HTML Parsing:** Only checks form action targets
3. **No Deep Learning:** Traditional ML only (no neural networks)
4. **Fixed Architecture:** No support for adversarial training
5. **No Uncertainty Quantification:** No confidence intervals on predictions

### System Limitations
1. **CORS Wide Open:** `allow_origins=["*"]` (security risk)
2. **No Rate Limiting:** Vulnerable to abuse
3. **No Database:** No persistent storage for scans or experiments
4. **No Authentication:** Open API endpoints
5. **Mixed-Content Dependency:** Extension requires HTTP backend
6. **No Experiment Tracking:** No MLflow or similar framework

---

## 9. Current Risk-Scoring Mechanism

### Scoring Formula
```
final_threat = 0.7 * ml_score + 0.3 * rule_score
```

### Components

**ML Score:**
- **Source:** `predict_proba()[1]` from calibrated ensemble
- **Range:** 0.0 to 1.0
- **Conversion to percentage:** `ml_score * 100`

**Rule Score:**
- **Typosquatting:** +40 points if detected
- **Insecure Protocol:** +20 points if HTTP used
- **Structural Issues:** +40 points if form action issues detected
- **Maximum:** 100 points (capped)

**Final Verdict Thresholds:**
- **SAFE:** threat < 30%
- **SUSPICIOUS:** 30% ≤ threat < 60%
- **PHISHING:** threat ≥ 60%

**Danger Flag:**
- `is_dangerous = true` if threat ≥ 50%

### Implementation
- **File:** `backend/main.py` (lines 143-179)
- **Rule Functions:** `_check_typosquatting()`, `_check_protocol()`, `_check_structural()`

---

## 10. System Capabilities and Limitations

### What the System CAN Analyze
- **URL Structure:** Length, depth, parameters, encoding
- **Domain Characteristics:** IP addresses, subdomains, TLD risk
- **Brand Impersonation:** Typosquatting detection, brand matching
- **Security Signals:** HTTPS, shorteners, redirects, certificates
- **Lexical Patterns:** Entropy, character ratios, suspicious keywords
- **Basic HTML:** Form action target analysis (fetches page content)
- **Real-time Scanning:** Via API endpoint or Chrome extension

### What the System CANNOT Currently Analyze
- **HTML Content:** No semantic analysis of page content
- **Visual Similarity:** No screenshot comparison or visual features
- **DOM Structure:** No deep HTML parsing beyond form actions
- **Page Text:** No NLP analysis of page content
- **JavaScript Behavior:** No dynamic content analysis
- **Screenshots:** No visual capture or comparison
- **Adversarial Examples:** No robustness against crafted attacks
- **Temporal Patterns:** No time-based analysis or evolution tracking
- **Cross-Language:** No multi-language support
- **Zero-Day Attacks:** No detection of novel attack patterns

### Input Requirements
- **Minimum:** Valid URL string
- **Protocol:** HTTP or HTTPS (auto-adds http:// if missing)
- **Format:** Single URL per request

### Output Format
```json
{
  "threat_level_pct": int (0-100),
  "ml_confidence": float (0-1),
  "verdict": "SAFE" | "SUSPICIOUS" | "PHISHING",
  "red_flags": [string],
  "feature_scores": {feature: normalized_value},
  "feature_labels": {feature: human_readable_name},
  "raw_features": {feature: actual_value},
  "is_dangerous": bool
}
```

---

## 11. Prediction Test Results

### Test URLs and Results

**Legitimate URLs:**
1. `https://www.google.com`
   - ML Confidence: 0.0037 (0.37%)
   - Rule Score: 0
   - Final Threat: 0%
   - Verdict: SAFE
   - Red Flags: None

2. `https://www.paypal.com`
   - ML Confidence: 0.0037 (0.37%)
   - Rule Score: 0
   - Final Threat: 0%
   - Verdict: SAFE
   - Red Flags: None

**Phishing URLs (from dataset):**
1. `http://paypa1.com/login`
   - ML Confidence: 0.9987 (99.87%)
   - Rule Score: 40 (typosquatting)
   - Final Threat: 87%
   - Verdict: PHISHING
   - Red Flags: ["Typosquatting: 'paypa1.com' resembles 'paypal.com' (edit distance: 1)"]

2. `http://googIe.com/accounts/login`
   - ML Confidence: 0.9995 (99.95%)
   - Rule Score: 40 (typosquatting)
   - Final Threat: 87%
   - Verdict: PHISHING
   - Red Flags: ["Typosquatting: 'googIe.com' resembles 'google.com' (edit distance: 1)"]

3. `http://192.168.1.1/login`
   - ML Confidence: 0.9951 (99.51%)
   - Rule Score: 60 (HTTP + IP address)
   - Final Threat: 87%
   - Verdict: PHISHING
   - Red Flags: ["Insecure Protocol: HTTP used instead of HTTPS", "Structural check incomplete: HTTPConnectionPool(host='192.168.1.1', port=80): Max retries exceeded"]

4. `http://secure-login.tk/account`
   - ML Confidence: 0.9969 (99.69%)
   - Rule Score: 60 (HTTP + suspicious TLD + hyphen)
   - Final Threat: 87%
   - Verdict: PHISHING
   - Red Flags: ["Insecure Protocol: HTTP used instead of HTTPS", "Structural check incomplete: HTTPConnectionPool(host='secure-login.tk', port=80): Max retries exceeded"]

---

## 12. System Status

### Operational Status
- **Backend:** ✅ Running on http://localhost:8000
- **ML Model:** ✅ Loaded successfully
- **Frontend:** ✅ Running on http://localhost:5173
- **Extension:** ✅ Manifest V3 valid, all files present

### Dependencies Installed
**Python:**
- fastapi, uvicorn, pydantic
- requests, beautifulsoup4
- python-Levenshtein
- scikit-learn, joblib, numpy

**Node.js:**
- react 19.2.4, react-dom 19.2.4
- lucide-react 1.7.0
- vite 8.0.1

### Files Verified
- `backend/main.py` - FastAPI application
- `backend/ml_model.py` - Feature extraction
- `backend/train_model.py` - Training pipeline
- `backend/phishing_model.pkl` - Trained model (6.1 MB)
- `backend/feature_scaler.pkl` - Feature scaler (1.3 KB)
- `phishguard-react/src/App.jsx` - React main component (directory name preserved for technical consistency)
- `extension/manifest.json` - Extension manifest
- All extension files present and valid

---

## Conclusion

The PhishOut baseline is fully operational with all components running successfully. The system achieves perfect classification metrics on the current test set, but this is likely due to the small real dataset size and heavy synthetic augmentation. The baseline provides a solid foundation for URL-based phishing detection but requires significant enhancements to support the PhishOut research goals of adversarial robustness and hybrid structural-semantic analysis.
