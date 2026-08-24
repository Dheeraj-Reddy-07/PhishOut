# PhishGuard Baseline V2 — Clean Data Methodology

**Date:** August 20, 2026  
**Purpose:** Establish scientifically valid baseline by fixing data leakage  
**Status:** Complete and verified

---

## Executive Summary

Baseline V2 addresses the critical data leakage issue identified in the original PhishGuard training pipeline. The key changes are:

1. **Dataset externalized** to CSV file for version control
2. **Domain-level split** implemented before augmentation
3. **Test set kept pure** (contains only original real samples)
4. **Training augmented only** (no augmentation of test data)
5. **All leakage checks pass** programmatically

The new baseline shows more realistic performance metrics (97% accuracy vs 100% previously) on a truly independent test set.

---

## 1. Dataset Composition

### Source
- **File:** `backend/dataset/clean_urls.csv`
- **Format:** CSV with columns: `url`, `label`, `source`
- **Source:** Extracted from original hardcoded lists in `train_model.py`

### Statistics
- **Total real samples:** 250 URLs
- **Phishing samples:** 127 (50.8%)
- **Legitimate samples:** 123 (49.2%)
- **Unique domains:** 230
- **Duplicates removed:** 0

### Data Validation
- All URLs validated for proper format (scheme + netloc)
- All labels validated (0 or 1)
- No exact duplicate URLs
- Source column tracks origin ("curated")

---

## 2. Split Methodology

### Domain-Level Split (Before Augmentation)

**Rationale:** Domain-level splitting ensures no domain appears in both training and test sets, preventing the model from learning domain-specific patterns that would artificially boost performance.

**Implementation:**
1. Extract base domain from each URL (e.g., "google.com" from "https://mail.google.com/mail")
2. Group URLs by domain
3. Perform stratified split on domains (not individual URLs)
4. Assign all URLs from a domain to the same split

**Split Statistics:**
- **Unique domains:** 230
- **Train domains:** 195 (84.8%)
- **Test domains:** 35 (15.2%)
- **Train samples:** 213 (109 phishing, 104 legitimate)
- **Test samples:** 37 (18 phishing, 19 legitimate)

**Random Seed:** 42 (fixed for reproducibility)

---

## 3. Augmentation Methodology

### Training-Only Augmentation

**Key Change:** Augmentation is applied ONLY to the training set. The test set remains completely untouched (pure real samples).

**Augmentation Technique:**
- **Method:** Bootstrap with Gaussian noise
- **Noise Standard Deviation:** 0.08
- **Target Size:** 800 samples per class (balanced)
- **Random Seed:** 42 (fixed for reproducibility)

**Augmentation Statistics:**
- **Original training samples:** 213 (109 phishing, 104 legitimate)
- **Augmented phishing samples:** 691
- **Augmented legitimate samples:** 696
- **Final training set:** 1,600 samples (800 phishing, 800 legitimate)
- **Test set:** 37 samples (pure real, no augmentation)

**Process:**
1. Separate training data by class
2. For each class, randomly sample from original training URLs with replacement
3. Add Gaussian noise to feature values
4. Clip negative values to 0
5. Combine original + augmented
6. Shuffle final training set

---

## 4. Leakage Prevention

### Data Leakage Checks

All four leakage checks passed programmatically:

**Check 1: No exact URL in both train and test**
- **Status:** ✓ PASS
- **Result:** 0 overlapping URLs

**Check 2: Test set contains only original real samples**
- **Status:** ✓ PASS
- **Result:** 0 augmented samples in test set

**Check 3: Source URLs don't overlap**
- **Status:** ✓ PASS
- **Result:** Guaranteed by domain-level split

**Check 4: No domain in both splits**
- **Status:** ✓ PASS
- **Result:** 0 overlapping domains

### Verification Code
Location: `backend/train_model_v2.py` (function `check_data_leakage()`)

---

## 5. Model Used

### Architecture (Unchanged from V1)

**Ensemble Classifier (VotingClassifier - Soft Voting):**

**Primary Model:** GradientBoostingClassifier (60% weight)
- n_estimators: 300
- learning_rate: 0.08
- max_depth: 5
- min_samples_leaf: 3
- subsample: 0.85
- max_features: "sqrt"
- random_state: 42

**Secondary Model:** RandomForestClassifier (40% weight)
- n_estimators: 200
- max_depth: 14
- min_samples_leaf: 2
- max_features: "sqrt"
- class_weight: "balanced"
- random_state: 42
- n_jobs: -1

**Probability Calibration:**
- Method: CalibratedClassifierCV with sigmoid (Platt scaling)
- Calibration split: 20% of training data held out
- Fallback: 3-fold CV if prefit fails

### Model Artifacts
- **File:** `backend/phishing_model.pkl` (6.1 MB)
- **Scaler:** `backend/feature_scaler.pkl` (1.3 KB)
- **Serialization:** joblib

---

## 6. Features Used

### 32 Features (Unchanged from V1)

**URL Structure (6):**
1. url_length
2. hostname_length
3. path_length
4. query_length
5. url_depth
6. num_params

**Domain Characteristics (10):**
7. has_ip
8. has_at
9. has_port
10. double_slash
11. prefix_suffix
12. sub_domain_count
13. excessive_dots
14. numeric_subdomain
15. punycode_present
16. https_token

**Security Signals (6):**
17. is_shortening
18. tld_risk_score
19. has_redirect_param
20. double_extension
21. hex_encoded

**Lexical/Entropy (5):**
22. domain_entropy
23. digit_ratio
24. special_char_count
25. consonant_ratio
26. longest_word_length

**Brand & Keyword Intelligence (4):**
27. brand_impersonation_score
28. subdomain_brand_match
29. suspicious_keywords
30. login_path_score

**Typosquatting (2):**
31. levenshtein_min
32. levenshtein_ratio

### Feature Importance (Top 10)
1. suspicious_keywords (0.1970)
2. levenshtein_min (0.1499)
3. login_path_score (0.0873)
4. levenshtein_ratio (0.0793)
5. sub_domain_count (0.0697)
6. prefix_suffix (0.0680)
7. tld_risk_score (0.0540)
8. brand_impersonation_score (0.0380)
9. url_length (0.0371)
10. path_length (0.0358)

---

## 7. Evaluation Metrics

### Test Set Performance (Pure Real Samples)

**Test Set Composition:**
- Total samples: 37
- Phishing: 18
- Legitimate: 19

**Classification Report:**
```
              precision    recall  f1-score   support

  Legitimate       1.00      0.95      0.97        19
    Phishing       0.95      1.00      0.97        18

    accuracy                           0.97        37
   macro avg       0.97      0.97      0.97        37
weighted avg       0.97      0.97      0.97        37
```

**ROC-AUC Score:** 0.9971

**Confusion Matrix:**
- True Negatives (legit→legit): 18
- False Positives (legit→phish): 1
- False Negatives (phish→legit): 0
- True Positives (phish→phish): 18

### Cross-Validation (Training Set)
- **Method:** 5-fold stratified cross-validation
- **CV ROC-AUC:** 1.0000 ± 0.0000

**Note:** CV is still perfect because it's on the augmented training set. The test set metrics (97% accuracy) are the true baseline.

---

## 8. Confusion Matrix Analysis

### Confusion Matrix (Test Set)
```
                Predicted
                Legitimate  Phishing
Actual
Legitimate          18         1
Phishing            0         18
```

### Analysis
- **False Positive:** 1 legitimate URL misclassified as phishing
- **False Negative:** 0 phishing URLs misclassified as legitimate
- **Recall (Phishing):** 100% (all phishing detected)
- **Precision (Phishing):** 95% (1 false positive)
- **Recall (Legitimate):** 95% (1 false positive)
- **Precision (Legitimate):** 100% (no false negatives)

**Interpretation:** The model is slightly biased toward classifying as phishing (conservative), which is appropriate for security applications.

---

## 9. Comparison with Old Results

### V1 (Leaky Baseline)
- **Dataset:** 250 real + 1,350 augmented = 1,600 total
- **Split:** Random split AFTER augmentation
- **Test set:** 240 samples (mixed real + augmented)
- **Accuracy:** 1.00 (100%)
- **Precision:** 1.00 (100%)
- **Recall:** 1.00 (100%)
- **F1-Score:** 1.00 (100%)
- **ROC-AUC:** 1.0000
- **Data Leakage:** YES (critical)

### V2 (Clean Baseline)
- **Dataset:** 250 real (augmented only in training)
- **Split:** Domain-level split BEFORE augmentation
- **Test set:** 37 samples (pure real only)
- **Accuracy:** 0.97 (97%)
- **Precision (Phishing):** 0.95 (95%)
- **Recall (Phishing):** 1.00 (100%)
- **F1-Score (Phishing):** 0.97 (97%)
- **ROC-AUC:** 0.9971
- **Data Leakage:** NO (verified)

### Key Differences
1. **Test set size:** 240 → 37 (smaller but pure)
2. **Accuracy:** 100% → 97% (more realistic)
3. **Data leakage:** Present → Eliminated
4. **Split method:** Random → Domain-level
5. **Test composition:** Mixed → Pure real

---

## 10. Limitations

### Dataset Limitations
1. **Tiny real dataset:** Only 250 real samples
2. **Small test set:** Only 37 samples for evaluation
3. **Synthetic majority:** 1,387 of 1,600 training samples (87%) are augmented
4. **No temporal split:** Domain-level split doesn't simulate temporal evolution
5. **No external validation:** No independent benchmark dataset
6. **No HTML content:** Only URLs, no webpage content or screenshots
7. **No version control:** Single dataset version

### Methodology Limitations
1. **Bootstrap augmentation:** Simple noise addition may not capture real phishing diversity
2. **No adversarial examples:** No robustness evaluation
3. **No held-out attacks:** Cannot claim adversarial robustness
4. **Small test set:** High variance in metrics due to small sample size
5. **No statistical testing:** No confidence intervals on metrics

### Model Limitations
1. **URL-only analysis:** No semantic or visual features
2. **Traditional ML only:** No deep learning
3. **No uncertainty quantification:** No confidence intervals
4. **Fixed architecture:** No support for adversarial training

---

## 11. Reproducibility

### Random Seeds
- **Data loading:** 42 (for augmentation)
- **Domain split:** 42
- **Model training:** 42 (all models)
- **Calibration:** 42

### Files Required for Reproduction
1. `backend/dataset/clean_urls.csv` - Source dataset
2. `backend/data_loader.py` - Data loading and splitting
3. `backend/ml_model.py` - Feature extraction
4. `backend/train_model_v2.py` - Training script

### Reproduction Command
```bash
cd backend
python train_model_v2.py
```

### Expected Output
- Model artifacts: `phishing_model.pkl`, `feature_scaler.pkl`
- Console output with all metrics and leakage checks
- All leakage checks should pass

---

## 12. API Compatibility

### Backend API Status
- **Endpoint:** `/scan` at `http://127.0.0.1:8000`
- **Status:** ✓ Working with new model
- **Response format:** Unchanged
- **Frontend compatibility:** ✓ Compatible
- **Extension compatibility:** ✓ Compatible

### Test Results
- `https://www.google.com`: Threat 0%, SAFE
- `https://www.paypal.com`: Threat 0%, SAFE
- `http://paypa1.com/login`: Threat 87%, PHISHING

All predictions work correctly with the retrained model.

---

## 13. Files Modified/Created

### New Files
1. `backend/dataset/clean_urls.csv` - Externalized dataset
2. `backend/data_loader.py` - Data loading and validation
3. `backend/train_model_v2.py` - Clean training pipeline
4. `docs/baseline_v2.md` - This documentation

### Modified Files
1. `backend/phishing_model.pkl` - Retrained model (overwritten)
2. `backend/feature_scaler.pkl` - Retrained scaler (overwritten)

### Unchanged Files
- `backend/main.py` - API endpoint (unchanged)
- `backend/ml_model.py` - Feature extraction (unchanged)
- `phishguard-react/` - Frontend (unchanged)
- `extension/` - Chrome extension (unchanged)

---

## 14. Next Steps

### Immediate Next Steps
1. **Increase dataset size:** Collect more real phishing and legitimate URLs
2. **Temporal split:** Implement time-based splitting if timestamps available
3. **External validation:** Test on independent benchmark datasets
4. **Statistical testing:** Add confidence intervals to metrics

### For PhishOut Research
1. **PhishOracle integration:** Generate adversarial examples
2. **Held-out attacks:** Create unseen attack types for robustness evaluation
3. **Semantic features:** Add HTML content and visual similarity
4. **Adversarial training:** Train on clean + adversarial data

---

## Conclusion

Baseline V2 establishes a scientifically valid baseline by eliminating data leakage through domain-level splitting and training-only augmentation. The new metrics (97% accuracy, 0.9971 ROC-AUC) are more realistic than the previous perfect scores (100% accuracy, 1.0 ROC-AUC) because they are evaluated on a truly independent test set containing only original real samples.

All data leakage checks pass programmatically, confirming that the new methodology prevents the contamination issues identified in the original baseline. The API remains fully functional with the retrained model, ensuring compatibility with the existing frontend and Chrome extension.

**Status:** BASELINE V2 COMPLETE AND VERIFIED
