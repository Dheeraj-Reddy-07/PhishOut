# Data Leakage Analysis: PhishGuard Training Pipeline

**Date:** August 20, 2026  
**File Analyzed:** `backend/train_model.py`  
**Issue:** Synthetic augmentation creates data leakage between train and test splits

---

## Problem Statement

The current training pipeline uses bootstrap augmentation with Gaussian noise to increase the dataset size from 250 real samples to 1,600 total samples. However, the train/test split occurs AFTER augmentation, which means synthetic samples derived from the same original URL can appear in both training and testing sets. This creates data leakage and inflates performance metrics.

---

## Code Analysis

### Augmentation Function (Lines 237-247)

```python
def augment(source_indices, n_aug, noise_std=0.08):
    """Bootstrap augmentation with slight gaussian noise."""
    rows = []
    src = X_real_np[source_indices]
    for _ in range(n_aug):
        sample = src[np.random.randint(len(src))].copy().astype(float)
        noise = np.random.normal(0, noise_std, sample.shape)
        sample = sample + noise
        sample = np.clip(sample, 0, None)
        rows.append(sample)
    return np.array(rows)
```

**Key Issue:** The function randomly selects from `src` (real samples) with replacement and adds Gaussian noise. Multiple synthetic samples can be derived from the same original URL.

### Dataset Building (Lines 249-264)

```python
phish_idx = np.where(y_real_np == 1)[0]
legit_idx = np.where(y_real_np == 0)[0]

# Augment to 800 phishing + 800 legit for a total of ~1700 samples
n_aug_phish = max(0, 800 - len(phish_idx))
n_aug_legit = max(0, 800 - len(legit_idx))

X_aug_phish = augment(phish_idx, n_aug_phish) if n_aug_phish > 0 else np.empty((0, len(FEATURE_KEYS)))
X_aug_legit = augment(legit_idx, n_aug_legit) if n_aug_legit > 0 else np.empty((0, len(FEATURE_KEYS)))

X = np.vstack([X_real_np, X_aug_phish, X_aug_legit])
y = np.concatenate([
    y_real_np,
    np.ones(len(X_aug_phish), dtype=int),
    np.zeros(len(X_aug_legit), dtype=int),
])
```

**Key Issue:** All samples (real + synthetic) are combined into a single array before splitting.

### Train/Test Split (Lines 275-277)

```python
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.15, random_state=42, stratify=y
)
```

**Key Issue:** The split is performed on the combined dataset (real + synthetic), not on the original real samples only.

---

## Leakage Mechanism

### Step-by-Step Leakage Process

1. **Original Real Samples:** 250 URLs (127 phishing, 123 legitimate)
2. **Augmentation:** For each class, generate synthetic samples by:
   - Randomly selecting from real samples with replacement
   - Adding Gaussian noise (std=0.08) to feature values
   - Creating ~673 synthetic phishing samples (800 - 127)
   - Creating ~677 synthetic legitimate samples (800 - 123)

3. **Combined Dataset:** 1,600 samples (250 real + 1,350 synthetic)
4. **Random Split:** 85% train (1,360 samples), 15% test (240 samples)
5. **Leakage:** Since synthetic samples are derived from real samples with replacement:
   - A single real URL (e.g., `http://paypa1.com/login`) may generate multiple synthetic samples
   - Some of these synthetic samples end up in training, others in testing
   - The model learns patterns from synthetic samples in training that are nearly identical to synthetic samples in testing
   - This creates an unrealistic evaluation scenario

### Example Scenario

**Original URL:** `http://paypa1.com/login` (phishing)

**Synthetic Derivatives (with noise):**
- Sample A: features + noise_1 → Training set
- Sample B: features + noise_2 → Training set  
- Sample C: features + noise_3 → Test set
- Sample D: features + noise_4 → Test set

**Problem:** The model learns to recognize the pattern of "paypa1.com with slight noise" during training, then easily recognizes the same pattern with different noise during testing. This is not true generalization.

---

## Impact on Performance Metrics

### Observed Metrics (from training run)

- **Accuracy:** 1.00 (100%)
- **Precision:** 1.00 (100%)
- **Recall:** 1.00 (100%)
- **F1-Score:** 1.00 (100%)
- **ROC-AUC:** 1.0000
- **Cross-Validation ROC-AUC:** 1.0000 ± 0.0000

### Why Perfect Scores Are Suspicious

1. **Tiny Real Dataset:** Only 250 real samples provide limited diversity
2. **Synthetic Majority:** 84% of data is synthetic augmentation
3. **Low Noise:** Gaussian noise std=0.08 is small relative to feature scales
4. **Pattern Repetition:** Same underlying patterns appear in train and test
5. **No Real Challenge:** Model essentially memorizes augmented patterns

### Real-World Implications

- **Overestimated Performance:** The 100% metrics do not reflect real-world performance
- **Poor Generalization:** Model may fail on truly novel phishing patterns
- **Invalid Research Claims:** Cannot claim robustness based on these metrics
- **Misleading Benchmark:** Perfect scores create false confidence

---

## Mathematical Analysis

### Feature Space Overlap

Given:
- Original feature vector: `f_orig` (32 dimensions)
- Noise: `ε ~ N(0, 0.08^2)` per feature
- Synthetic samples: `f_syn = f_orig + ε`

**Distance between synthetic samples:**
```
||f_syn_i - f_syn_j|| = ||(f_orig + ε_i) - (f_orig + ε_j)|| = ||ε_i - ε_j||
```

Since `ε_i, ε_j ~ N(0, 0.08^2)`, the expected distance is small, meaning synthetic samples from the same original are very similar in feature space.

**Train/Test Overlap Probability:**
With 127 phishing URLs generating ~673 synthetic samples:
- Expected synthetic samples per original: 673/127 ≈ 5.3
- Probability that at least one synthetic from same original appears in both splits: ≈ 1 - (0.85^5.3 * 0.15^0 + ...) ≈ very high

---

## Correct Approach (Not Yet Implemented)

### Recommended Fix

1. **Split Original Data First:**
   ```python
   X_real_train, X_real_test, y_real_train, y_real_test = train_test_split(
       X_real_np, y_real_np, test_size=0.15, random_state=42, stratify=y_real_np
   )
   ```

2. **Augment Only Training Data:**
   ```python
   # Augment training set only
   X_train_aug = augment_training_data(X_real_train, y_real_train)
   X_train = np.vstack([X_real_train, X_train_aug])
   ```

3. **Keep Test Set Pure:**
   ```python
   # Test set contains only real samples
   X_test = X_real_test
   y_test = y_real_test
   ```

4. **Domain-Level Split:**
   - Ensure no domain appears in both train and test
   - Group URLs by base domain
   - Split domains, not individual URLs

5. **Temporal Split:**
   - Use date-based split if timestamps available
   - Train on older data, test on newer data

---

## Severity Assessment

**Severity Level:** CRITICAL

**Reasons:**
1. **Invalidates Research Claims:** Any robustness claims based on current metrics are invalid
2. **Misleading Results:** Perfect scores create false confidence in model performance
3. **Reproducibility Issue:** Other researchers cannot reproduce realistic performance
4. **Deployment Risk:** Model may fail catastrophically in real-world deployment
5. **Publication Risk:** Papers based on these metrics would be rejected or retracted

---

## Files Requiring Modification

1. **`backend/train_model.py`** (lines 209-268)
   - Modify `build_dataset()` to split before augmentation
   - Implement domain-level splitting
   - Add temporal splitting option

2. **`backend/data_loader.py`** (new file needed)
   - Externalize dataset loading from CSV
   - Implement proper split logic
   - Add split validation

3. **`backend/dataset/`** (new directory needed)
   - External CSV files for real samples
   - Metadata files for split information
   - Version control for datasets

---

## Conclusion

The current augmentation and splitting methodology creates severe data leakage that invalidates the reported performance metrics. The perfect scores (100% accuracy, 1.0 ROC-AUC) are artifacts of this leakage, not genuine model performance. This issue must be fixed before any PhishOut research can proceed, as adversarial robustness claims require truly independent evaluation sets.

**Status:** DOCUMENTED - NOT YET FIXED (as per instructions)
