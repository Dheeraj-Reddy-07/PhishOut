# Phish360 Dataset Processing Report

**Generated:** 2026-08-23 19:41:03

---

## Dataset Statistics

### Overall
- **Total Samples:** 10634
- **Training Samples:** 7655 (72.0%)
- **Validation Samples:** 1298 (12.2%)
- **Test Samples:** 1681 (15.8%)

### Class Distribution

#### Training Set
- **Phishing:** 3026 (39.5%)
- **Legitimate:** 4629 (60.5%)

#### Validation Set
- **Phishing:** 493 (38.0%)
- **Legitimate:** 805 (62.0%)

#### Test Set
- **Phishing:** 737 (43.8%)
- **Legitimate:** 944 (56.2%)

---

## Feature Statistics

### Structural Features (32)
- **Source:** URL analysis using existing `ml_model.py`
- **Feature Count:** 32

### Semantic Features (12)
- **Source:** HTML content analysis using existing `webpage_analyzer.py`
- **Feature Count:** 12

### HTML Availability
- **Training Set:** 7655/7655 samples (100.0%)
- **Validation Set:** 1298/1298 samples (100.0%)
- **Test Set:** 1681/1681 samples (100.0%)

---

## Leakage Validation Results

### URL Overlap
- **Train-Val:** 0 URLs
- **Train-Test:** 0 URLs
- **Val-Test:** 0 URLs
- **Status:** PASS

### Domain Overlap
- **Train-Val:** 0 domains
- **Train-Test:** 0 domains
- **Val-Test:** 0 domains
- **Status:** PASS

### Test Contamination
- **Is Contaminated:** NO
- **URL Leakage:** NO
- **Domain Leakage:** NO

### Overall Validation
- **Result:** PASS - Leakage-free splits

---

## Processing Information

### Data Source
- **Format:** Parquet files
- **Source Directory:** D:\Downloads\phish360_parquet
- **Files:** Phish360_phish.parquet, Phish360_legit.parquet

### Feature Extraction
- **Structural Features:** 32 features from URLs using existing `ml_model.py`
- **Semantic Features:** 12 features from HTML using existing `webpage_analyzer.py`
- **Total Features:** 44 (32 structural + 12 semantic)

### Splitting Methodology
- **Domain-Aware Splitting:** Used to prevent domain leakage
- **Random Seed:** 42 (for reproducibility)
- **Split Ratios:** ~70% train, ~15% validation, ~15% test

### Output Files
- **Train Features:** `processed/train_features.parquet`
- **Validation Features:** `processed/validation_features.parquet`
- **Test Features:** `processed/test_features.parquet`
- **Leakage Report:** `reports/leakage_report.json`

---

## Notes

- This dataset is ready for model training and evaluation
- All splits have been validated for leakage
- Feature extraction follows the PhishOut architecture (32 structural + 12 semantic)
- Full HTML content was used directly from the dataset (no network requests)
- Original Parquet files remain in source directory (not copied)

---

**END OF REPORT**
