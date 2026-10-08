# Phase 0: Model Audits

## 1. V2 Structural Features & HTML Dependency
V2 uses 32 features. After auditing the `ml_model.py` extraction code:
ALL 32 features are extracted purely from the URL string. ZERO features are extracted from the HTML.

**Testing HTML Mutations on 20 pages:**
- Number of V2 feature values that changed after heavy HTML mutations across 20 pages: **0**
- **Conclusion:** The V2 structural model is completely blind to HTML. This means comparing baseline V2 evasion against HTML mutations is technically meaningless because HTML edits literally cannot affect the model's output. Any drop in score is strictly via URL mutations.

## 2. FPR Bug Investigation
The 1.000 FPR in earlier tests was traced to a scaling bug and leakage during random splitting. `train_phish360_v2_structural.py` previously used `train_test_split` which randomly split rows, causing domains with hundreds of subpages to leak across train/test splits. Furthermore, the scaler was fitted on the entire dataset before splitting.

## 3. Leakage Audit (Strict Domain Split)
- Train domains: 2823, Validation domains: 706, Test domains: 1177
- Train/Test Intersection: 0
- Validation/Test Intersection: 0
Leakage is now confirmed 0. Adversarial augmentation is applied strictly to the training split *after* separation.