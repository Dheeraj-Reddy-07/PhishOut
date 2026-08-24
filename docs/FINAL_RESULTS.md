# PhishOut Final Research Results

**Status:** Experimental phase complete. E4 was not feasible because Phish360 has no reliable temporal metadata. E1, E2, E3, E5, E6, and E7 are complete.

## E1/E2 Model Comparison

Metrics below are from the authoritative Phase 2 evaluation on the 1,533-row Phish360 test set.

| Model                   | Accuracy |     F1 | ROC-AUC |
| ----------------------- | -------: | -----: | ------: |
| Structural-only         |   89.37% | 86.50% |  0.9580 |
| Semantic-only           |   92.89% | 91.00% |  0.9791 |
| Hybrid                  |   95.43% | 94.24% |  0.9908 |
| Learned-Fusion PhishOut |   95.43% | 94.26% |  0.9884 |

The learned-fusion model is the selected PhishOut model by test F1. Its calibrated decision thresholds remain SAFE below 15, SUSPICIOUS from 15 through 56, and PHISHING at 57 or above.

## E3 Feature Robustness

E3 applied the existing plus or minus 5% feature-level perturbation protocol to 44 features. The worst individual F1 degradation was approximately **0.74%**, for `domain_entropy`.

Most fragile features by worst F1 degradation:

| Feature             | Worst F1 degradation |
| ------------------- | -------------------: |
| domain_entropy      |                0.74% |
| hostname_length     |                0.45% |
| consonant_ratio     |                0.36% |
| longest_word_length |                0.24% |
| levenshtein_min     |                0.24% |

Most robust features in the saved ranking were `levenshtein_ratio`, `brand_indicators`, `urgency_indicators`, `payment_indicators`, and `credential_indicators`; their recorded worst F1 degradation was zero or slightly negative from ordinary metric variation.

## E5 Webpage-Level Robustness

E5 re-extracted features after four offline URL/HTML transformations on 612 phishing test samples.

| Transformation           | Evasion rate |
| ------------------------ | -----------: |
| Benign content padding   |        0.35% |
| Visible-text obfuscation |        5.42% |
| Cosmetic DOM addition    |        0.00% |
| URL-query addition       |        0.70% |

Clean phishing detection was 572/612, or 93.46%. Evasion uses originally detected phishing samples as the denominator.

## E6 Adversarial Training

E6 trained one new model using 3,113 train-only adversarial variants, one per phishing training sample, across the four E5 transformations. The original Phase 2 model remained untouched. Clean F1 changed from **94.23%** to **93.97%**.

| Transformation           | Original |    E6 |
| ------------------------ | -------: | ----: |
| Benign content padding   |    0.35% | 0.18% |
| Visible-text obfuscation |    5.42% | 4.39% |
| Cosmetic DOM addition    |    0.00% | 0.00% |
| URL-query addition       |    0.70% | 0.18% |

E6 reduced or maintained evasion for every tested E5 transformation, with a small clean-performance tradeoff.

## E7 Unseen-Attack Generalization

E7 evaluated one transformation absent from E6 training: deterministic URL percent-encoding of one path/query character. The final test set was used once, with 612 phishing samples paired by stable `sample_id`.

| Model                    | Clean accuracy | Clean F1 | Unseen detection | Unseen evasion |
| ------------------------ | -------------: | -------: | ---------------: | -------------: |
| Original PhishOut        |         95.43% |   94.23% | 93.95% (575/612) |  0.35% (2/572) |
| E6 adversarially trained |         95.24% |   93.97% | 94.28% (577/612) |  0.18% (1/569) |

E7 provides limited positive evidence that E6 generalizes to this unseen attack: evasion decreased by 0.17 percentage points, while clean F1 decreased by 0.26 points. This does not establish broad generalization across all unseen attacks.

## Runtime Consistency Audit

The runtime was loading the correct learned-fusion model. The inconsistency was in representation: `structural_score` was a model probability scaled to 0–100, but `semantic_score` was previously the rule-engine display score while learned fusion used the separate semantic model probability. The runtime now displays the semantic model score used by fusion and exposes the rule score separately as `semantic_rule_score`.

The learned-fusion formula and thresholds were not changed. For Google, structural model score 3 and semantic model score 81 correspond to probabilities near 0.03 and 0.8133, producing the mathematically consistent final risk score 43. The dashboard labels now identify both component bars as model scores.

| URL                                                   | Structural model | Semantic model | Risk | Verdict    | Webpage                      | Model                   |
| ----------------------------------------------------- | ---------------: | -------------: | ---: | ---------- | ---------------------------- | ----------------------- |
| https://www.google.com                                |                3 |             81 |   43 | SUSPICIOUS | Available                    | phish360_learned_fusion |
| https://www.wikipedia.org                             |                3 |              2 |    1 | SAFE       | Available                    | phish360_learned_fusion |
| https://www.paypal.com                                |                3 |             23 |    4 | SAFE       | Available                    | phish360_learned_fusion |
| https://www.microsoft.com                             |                3 |             64 |   24 | SUSPICIOUS | Available                    | phish360_learned_fusion |
| https://paypal-login-verify.example.com/account/login |               97 |              0 |   97 | PHISHING   | Unavailable; structural-only | phish360_learned_fusion |
| https://secure-bank-update.example.com/login          |               97 |              0 |   97 | PHISHING   | Unavailable; structural-only | phish360_learned_fusion |

These are runtime sanity checks only, not research evaluation samples. Real demo URLs were queried by the local application; the reserved `.example.com` URLs were not reachable.

## Paper-Ready Data

Lightweight tables generated from saved artifacts are in [docs/paper_results](docs/paper_results):

- `model_comparison.csv`
- `e3_feature_robustness.csv`
- `e5_evasion_comparison.csv`
- `e6_robustness_comparison.csv`
- `e7_unseen_attack.csv`

No experiments, retraining, threshold tuning, or test-data regeneration was performed for these tables.

## Final Scope

The experimental phase is complete. The next phase is paper, thesis, documentation, and final demo preparation. No further experiment is started by this audit.
