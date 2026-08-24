# E6 Adversarial Training Evaluation

**Date:** 2026-08-24  
**Status:** COMPLETE; hypothesis tested with one new adversarially trained model

## 1. E5 audit result

The lightweight E5 audit passed. The 24 development samples came from the training split and were separate from the 612 final E5 phishing test samples. E5 recorded zero sample-ID, URL, and registered-domain overlap. The transformations changed URL or HTML before feature re-extraction, and the stored CSV confirms the visible-text-obfuscation result of 31 evasions divided by 572 eligible clean detections, or 5.42%. The original Phase 2 model files were not overwritten.

The audit corrected one report-only arithmetic issue: E5 has 2,448 transformed rows, while 2,288 is the eligible originally-detected denominator. The all-row pooled rate is 1.51%; the eligible-case pooled rate is 1.62%.

## 2. Research question

Can adversarial training using webpage-level perturbations improve PhishOut robustness against the E5 transformations while preserving clean detection performance?

## 3. Training design

The original Phase 2 models remain untouched. E6 trains one new PhishOut model with the same 32 structural feature extractor, 12 semantic feature extractor, calibrated component-model architecture, and learned score-level fusion. Only the training data differs.

All 3,113 phishing samples in the existing 7,732-row training split were used to generate exactly one adversarial variant each, assigned round-robin across the four audited E5 transformations. This produced 3,113 adversarial training samples and a combined training set of 10,845 rows. The transformation counts were 779 benign-content-padding variants, 778 visible-text-obfuscation variants, 778 cosmetic-DOM variants, and 778 URL-query variants.

The validation split remained clean and was used to calibrate the new component probabilities and fit the new logistic score-level fusion model. The final test split and E5 test results were not used for training or tuning. The original thresholds, SAFE below 15 and PHISHING at 57 or above, were retained as the primary reference.

## 4. Leakage controls

All adversarial training variants originated from training phishing rows. The raw source contained all 3,113 corresponding HTML samples. The E5 test sample IDs were disjoint from E6 training source IDs. Recorded overlap checks were zero for sample IDs, URLs, and registered domains. The final 1,533-row test split remained untouched.

## 5. Clean test performance

| Model                    | Accuracy | Precision | Recall / detection |     F1 | ROC-AUC | Confusion matrix             |
| ------------------------ | -------: | --------: | -----------------: | -----: | ------: | ---------------------------- |
| Original PhishOut        |   95.43% |    95.02% |             93.46% | 94.23% |  98.84% | TN 891, FP 30, FN 40, TP 572 |
| E6 adversarially trained |   95.24% |    94.99% |             92.97% | 93.97% |  98.84% | TN 891, FP 30, FN 43, TP 569 |

Clean recall decreased by 0.49 percentage points and clean F1 decreased by 0.26 percentage points. False positives were unchanged.

## 6. E5-style adversarial test performance

The following table uses the same 612 phishing test samples and the same four transformations as E5. Evasion denominators are each model's originally detected clean phishing cases.

| Transformation             | Original evasion |     E6 evasion |   Change | Original mean risk change | E6 mean risk change |
| -------------------------- | ---------------: | -------------: | -------: | ------------------------: | ------------------: |
| Benign-content padding     |    0.35% (2/572) |  0.18% (1/569) | -0.17 pp |                    -0.342 |              -0.183 |
| Visible-text obfuscation   |   5.42% (31/572) | 4.39% (25/569) | -1.03 pp |                    -3.518 |              -2.788 |
| Cosmetic DOM addition      |    0.00% (0/572) |  0.00% (0/569) |  0.00 pp |                     0.000 |               0.000 |
| URL lexical query addition |    0.70% (4/572) |  0.18% (1/569) | -0.52 pp |                    -1.533 |              +4.534 |

The E6 model reduced evasion for the highest-impact E5 transformation, visible-text obfuscation, by 1.03 percentage points. It also reduced URL-query evasion by 0.52 points and benign-padding evasion by 0.17 points. Cosmetic DOM evasion remained zero.

## 7. Interpretation

The result supports the hypothesis for this four-transformation evaluation. E6 reduced or maintained evasion for all four transformations, including a 1.03-point reduction for visible-text obfuscation, while clean detection declined slightly. Therefore, train-only adversarial augmentation improved measured E5 robustness, but with a small clean-performance tradeoff.

## 8. Limitations

Only one augmentation policy and one model configuration were tested; no hyperparameter search was performed. The E6 evaluation uses phishing-only transformed views for evasion analysis, while clean metrics use the full labeled test set. Stored HTML does not model browser rendering, JavaScript execution, or network behavior. The raw Parquet source remains an external local dependency. E7 was evaluated separately.
