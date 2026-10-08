# E5 Webpage-Level Robustness Evaluation

**Date:** 2026-08-24  
**Status:** COMPLETE; offline evaluation executed with frozen Phase 2 models

## 1. Research question

Can controlled modifications to the underlying phishing URL or HTML reduce PhishOut's ability to detect the phishing page? Every transformed sample remains labelled phishing and is kept as an offline artifact.

## 2. Difference between E3 and E5

E3 perturbed extracted feature values by plus or minus 5 percent. E5 starts from stored phishing URL and HTML, applies a controlled transformation, re-extracts the existing 32 structural and 12 semantic features, and scores the result with the frozen learned-fusion model. No E5 feature vector is edited directly.

## 3. Raw dataset source

Raw data was read read-only from `D:\Downloads\phish360_parquet\Phish360_phish.parquet`. It contains `URL`, `full_html`, `Class`, and `folder_name`. The files were not copied into or modified in the repository.

## 4. E5 sample selection

The final evaluation used all 612 phishing rows in the existing 1,533-row processed test split. All 612 IDs joined to non-empty raw HTML. Twenty-four phishing samples from the training split were used only for transformation development and smoke checks.

## 5. Leakage controls

Development samples came from training and evaluation samples came from the existing test split. Sample ID, URL, and registered-domain overlap were each zero. `test_features.parquet` was read only and was not overwritten.

## 6. Transformations

Four deterministic, offline-only transformations were evaluated:

1. **Benign-content padding:** adds harmless informational text in a new section.
2. **Visible-text obfuscation:** changes selected visible phishing-related words, leaving scripts and styles unchanged.
3. **Cosmetic DOM addition:** adds non-functional layout containers marked hidden from assistive technology.
4. **URL lexical query addition:** adds `display=compact` to the query while preserving the host, path, and HTML.

No transformation visits a URL, submits a form, contacts an external service, or creates credential-theft functionality.

## 7. Feature re-extraction methodology

The existing `ml_model.extract_features()` extracted structural features and `webpage_analyzer.extract_semantic_features_from_html()` extracted semantic features from stored HTML. Existing `FEATURE_KEYS` and `SEMANTIC_KEYS` preserved model input order.

## 8. Frozen-model methodology

The existing structural model and scaler, semantic model and scaler, learned fusion model, and calibrated thresholds were loaded from `backend/models/phish360/`. No model was retrained or recalibrated. Thresholds remained SAFE below 15, SUSPICIOUS from 15 through 56, and PHISHING at 57 or above.

## 9. Clean baseline

Clean detection was 572/612, or 93.46%. The remaining 40 clean phishing samples were not counted as eligible evasion denominators. Because this evaluation population contains phishing pages only, precision is not estimable; the reported F1 is the all-positive-population equivalent of recall.

## 10. Per-transformation results

| Transformation             | Samples | Perturbed detection / recall |     F1 | Eligible clean detections | Evasions | Evasion rate | Verdict changes | Mean risk change |
| -------------------------- | ------: | ---------------------------: | -----: | ------------------------: | -------: | -----------: | --------------: | ---------------: |
| Benign-content padding     |     612 |                       93.14% | 93.14% |                       572 |        2 |        0.35% |               4 |           -0.342 |
| Visible-text obfuscation   |     612 |                       88.40% | 88.40% |                       572 |       31 |        5.42% |              36 |           -3.518 |
| Cosmetic DOM addition      |     612 |                       93.46% | 93.46% |                       572 |        0 |        0.00% |               0 |            0.000 |
| URL lexical query addition |     612 |                       92.81% | 92.81% |                       572 |        4 |        0.70% |               6 |           -1.533 |

Evasion rate is the number of originally detected phishing samples that became non-PHISHING divided by 572 originally detected samples.

## 11. Overall evasion results

There were 37 evasion events across 2,448 transformed cases, a pooled event rate of 1.51%. Restricting the denominator to the 2,288 originally detected cases gives the required pooled eligible-case rate of 1.62%. Visible-text obfuscation had the largest effect, reducing detection to 88.40% and producing a 5.42% evasion rate. Cosmetic DOM addition produced no verdict changes.

## 12. Limitations

The phishing-only evaluation cannot estimate false positives or ordinary binary precision. Stored HTML does not model browser rendering, JavaScript execution, network loading, or visual similarity. Only four simple transformations were tested, and the raw source remains an external local dependency. E6 and E7 were evaluated separately.
