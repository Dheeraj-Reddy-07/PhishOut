# E7 Unseen-Attack Generalization Evaluation

**Date:** 2026-08-24  
**Status:** COMPLETE; final E7 evaluation executed once

## 1. Objective

E7 tests whether the E6 adversarially trained PhishOut model generalizes to a webpage/URL perturbation that was not used during E6 adversarial training.

## 2. E6 training audit

E6 used exactly four transformations for train augmentation: benign-content padding, visible-text obfuscation, cosmetic DOM addition, and URL lexical query addition. E7 used none of those transformations for training or tuning.

The original Phase 2 model and the E6 model were loaded from their existing artifact directories. No model was retrained, refined, or overwritten during E7.

## 3. Unseen transformation

The unseen transformation is **URL percent-encoding of one path/query character**. For example, a path character is represented as its `%XX` form while the stored HTML remains unchanged. Root and host-only URLs use an encoded root slash where necessary. The transformation is deterministic, offline-only, and does not contact a destination or submit data.

This qualifies as unseen because E6 used query-parameter addition, not percent-encoding. It changes URL lexical representation while preserving the conceptual decoded path/destination and phishing label.

## 4. Split and data usage

The existing Phish360 split was preserved exactly:

- Training: not used by E7.
- Validation: not used by E7.
- Final test: existing 1,533-row test split used once for final evaluation.
- E7 transformed 612 phishing rows from that final test split.
- Raw HTML/URLs were read read-only from `D:\Downloads\phish360_parquet\Phish360_phish.parquet`.

E7 did not use test labels/results to train, tune thresholds, or select a model. The original threshold reference remained SAFE below 15 and PHISHING at 57 or above.

## 5. Pairing and leakage controls

Clean and perturbed records retained the original `sample_id`. Assertions checked equal counts, unique IDs, identical ID sets, identical pairing order, phishing labels, and one-to-one joins. Results were calculated after joining clean and perturbed records by `sample_id`, never by incidental dataframe position. The final pairing audit recorded 612 samples, zero duplicate IDs, preserved labels, and zero clean-test/training overlap.

## 6. Clean test performance

| Model                    | Accuracy | Precision | Recall / detection |     F1 | ROC-AUC |
| ------------------------ | -------: | --------: | -----------------: | -----: | ------: |
| Original PhishOut        |   95.43% |    95.02% |             93.46% | 94.23% |  98.84% |
| E6 adversarially trained |   95.24% |    94.99% |             92.97% | 93.97% |  98.84% |

E6 therefore has a 0.26 percentage-point lower clean F1 and a 0.49 percentage-point lower clean recall than the original model.

## 7. Unseen adversarial test performance

The transformed subset contains phishing samples only. The reported adversarial precision and F1 are mechanically computed against an all-positive label vector; they are not ordinary mixed-class precision/F1 estimates. Detection rate/recall and evasion rate are the primary measures.

| Model                    | Accuracy / detection | Precision\* | Recall |   F1\* |  Evasion rate | Verdict changes | Mean risk change |
| ------------------------ | -------------------: | ----------: | -----: | -----: | ------------: | --------------: | ---------------: |
| Original PhishOut        |     93.95% (575/612) |     100.00% | 93.95% | 96.88% | 0.35% (2/572) |              14 |           +1.371 |
| E6 adversarially trained |     94.28% (577/612) |     100.00% | 94.28% | 97.06% | 0.18% (1/569) |              17 |           +1.593 |

\* Precision and F1 here use the phishing-only transformed subset and should not be compared with clean full-test precision/F1 as if they came from the same class composition.

E6 reduced unseen-attack evasion by 0.17 percentage points, from 0.35% to 0.18%, and increased transformed phishing detection by two samples. It also produced three additional verdict changes overall, reflecting changes among SAFE/SUSPICIOUS/PHISHING labels beyond the primary evasion metric.

## 8. Generalization conclusion

E7 provides **limited positive evidence** for unseen-attack generalization: E6 reduced the unseen percent-encoding evasion rate by half relative to the original model, while clean performance decreased slightly. Because the absolute baseline evasion was already low and only one unseen transformation was tested, this is not evidence of broad generalization to all unseen attacks.

## 9. Validation-only refinement

No validation-only refinement was performed. E7 is a direct comparison of the existing original Phase 2 model and the existing E6 adversarially trained model.

## 10. Limitations

Only one unseen transformation was evaluated. Percent-encoding behavior is assessed through the existing offline URL parser and feature extractor; browser normalization and live-server routing were not tested. The transformed evaluation population contains phishing only, so mixed-class adversarial accuracy and false-positive behavior are not estimable for the transformed view. The raw Parquet source remains an external local dependency.

The experimental phase ends here; the next phase is paper and thesis preparation.
