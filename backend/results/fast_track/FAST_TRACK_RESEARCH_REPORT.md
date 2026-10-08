# FAST-TRACK RESEARCH REPORT

## 1. Objective
To perform a focused, scientifically valid Fast-Track evaluation determining if adding semantic intent analysis to structural phishing detection improves resilience to adversarial webpage modifications.

## 2. Models Compared
- **Structural_V2:** URL-only legacy features.
- **Semantic_V4:** Text-embedding only features.
- **Baseline_V3:** Unhardened hybrid model.
- **Hardened_V4:** Adversarially trained hybrid model.

## 3. Dataset
Exactly 25 genuine phishing and 25 genuine legitimate samples held out from training, selected deterministically using seed 42.

## 4. Feature Compatibility Audit
Please refer to `compatibility_audit.md`. Mutations were strictly matched to the features the models can actually parse.

## 5. Experimental Protocol
Each phishing page was targeted individually using Beam Search, Simulated Annealing, and MCTS against all four models.

## 6. Normal Performance
| model         |   accuracy |   precision |   recall |       f1 |   fpr |   detection_rate |   cm_tn |   cm_fp |   cm_fn |   cm_tp |
|:--------------|-----------:|------------:|---------:|---------:|------:|-----------------:|--------:|--------:|--------:|--------:|
| Structural_V2 |       0.96 |    1        |     0.92 | 0.958333 |  0    |             0.92 |      25 |       0 |       2 |      23 |
| Semantic_V4   |       0.92 |    0.862069 |     1    | 0.925926 |  0.16 |             1    |      21 |       4 |       0 |      25 |
| Baseline_V3   |       0.98 |    1        |     0.96 | 0.979592 |  0    |             0.96 |      25 |       0 |       1 |      24 |
| Hardened_V4   |       0.98 |    0.961538 |     1    | 0.980392 |  0.04 |             1    |      24 |       1 |       0 |      25 |

## 7. Adversarial Attack Results
| target_model   | attack_algorithm   |   attacks_attempted |   successful_evasions |   attack_success_rate |   average_queries |   average_mutations |   average_probability_reduction |
|:---------------|:-------------------|--------------------:|----------------------:|----------------------:|------------------:|--------------------:|--------------------------------:|
| Structural_V2  | BeamSearch         |                  23 |                     0 |                  0    |              2    |            0.565217 |                      0.011177   |
| Structural_V2  | SimulatedAnnealing |                  23 |                     0 |                  0    |             50    |            0.565217 |                      0.011177   |
| Structural_V2  | MCTS               |                  23 |                     0 |                  0    |             50    |            0.565217 |                      0.011177   |
| Semantic_V4    | BeamSearch         |                  25 |                     0 |                  0    |             50    |            1.4      |                      0.0587401  |
| Semantic_V4    | SimulatedAnnealing |                  25 |                     0 |                  0    |             50    |           15.32     |                      0.0494461  |
| Semantic_V4    | MCTS               |                  25 |                     0 |                  0    |             50    |            2.2      |                      0.0612388  |
| Baseline_V3    | BeamSearch         |                  25 |                     2 |                  0.08 |             46.56 |            2.2      |                      0.0160446  |
| Baseline_V3    | SimulatedAnnealing |                  25 |                     1 |                  0.04 |             48.04 |           35.4      |                      0.0160428  |
| Baseline_V3    | MCTS               |                  25 |                     2 |                  0.08 |             46.48 |            3.08     |                      0.016684   |
| Hardened_V4    | BeamSearch         |                  25 |                     0 |                  0    |             50    |            1.92     |                      0.00434043 |
| Hardened_V4    | SimulatedAnnealing |                  25 |                     0 |                  0    |             50    |           17.16     |                      0.00230561 |
| Hardened_V4    | MCTS               |                  25 |                     0 |                  0    |             50    |            2.36     |                      0.00450973 |

## 8. Transfer Results (Adversarial Detection Rate)
| source_target   | evaluating_model   |   detection_rate |
|:----------------|:-------------------|-----------------:|
| Structural_V2   | Structural_V2      |         1        |
| Structural_V2   | Semantic_V4        |         1        |
| Structural_V2   | Baseline_V3        |         1        |
| Structural_V2   | Hardened_V4        |         1        |
| Semantic_V4     | Structural_V2      |         0.92     |
| Semantic_V4     | Semantic_V4        |         1        |
| Semantic_V4     | Baseline_V3        |         0.96     |
| Semantic_V4     | Hardened_V4        |         1        |
| Baseline_V3     | Structural_V2      |         0.92     |
| Baseline_V3     | Semantic_V4        |         1        |
| Baseline_V3     | Baseline_V3        |         0.933333 |
| Baseline_V3     | Hardened_V4        |         1        |
| Hardened_V4     | Structural_V2      |         0.92     |
| Hardened_V4     | Semantic_V4        |         1        |
| Hardened_V4     | Baseline_V3        |         0.96     |
| Hardened_V4     | Hardened_V4        |         1        |

## 9. Limitations & Threats to Validity
- **Sample Size:** 25 pages is a small sample; findings indicate trends but are not definitive proof of absolute immunity.
- **Mutation Scope:** The attacks are limited to the implemented classes; novel out-of-distribution attacks may still succeed.

## 10. Findings & Final Conclusion
The empirical evidence demonstrates the measured differences in adversarial robustness between purely structural and semantic-hybrid approaches.