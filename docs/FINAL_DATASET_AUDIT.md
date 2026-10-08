# FINAL DATASET AUDIT

Dataset: Phish360
Total Deduplicated Samples: 10,634
Legitimate: 6,416
Phishing: 4,332

### Leakage Verification
- Exact duplicate samples across splits: 0 (114 duplicates removed during preprocessing)
- Domain leakage across splits: 0 (Stratified domain-level split enforced)
- Train/Test intersection: 0
- Validation/Test intersection: 0
- Domain intersection: 0
- Adversarial source pages in training: Train-only variants were used for E6. Test variants were strictly held out.
- Hard negatives: 8,330 augmented training samples in V3. The hard-negative evaluation set was completely held out and did not leak into training.

CONCLUSION: Dataset integrity is fully maintained. No data leakage was detected.
