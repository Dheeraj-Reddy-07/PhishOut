# Phish360 Dataset Processing - Final Report

**Date:** 2026-08-23
**Status:** PHASE 1 COMPLETE ✅

---

## DATASET

### Row Counts
- **Legitimate file rows:** 6,416
- **Phishing file rows:** 4,332
- **Total rows:** 10,748
- **After deduplication:** 10,634 (removed 114 duplicate URLs)

### Label Distribution
- **Legitimate:** 6,416 (59.7%)
- **Phishing:** 4,332 (40.3%)
- **Labels:** Numeric (0=legitimate, 1=phishing)

### Actual Columns
- dataset_name, folder_name, Class, brand, URL, TLD, Domain, FLD, Subdomain, SSL
- image_path, translated_tf_text, trafilatura_text, trafilatura_text_language
- translated_bs_text, BeautifulSoup_text, BeautifulSoup_text_language
- html2text_text, lxml_text, html_extract_text, full_html, html_text_language

### HTML Availability
- **full_html available:** ✅ YES
- **HTML null rate:** 0.0%
- **HTML source:** Complete raw HTML (not just extracted text)

### URL Null Rate
- **URL null rate:** 0.0%
- **URL format:** Raw URL strings with some trailing newlines (cleaned during processing)

---

## SPLITS

### Split Rows
- **Train rows:** 7,655 (72.0%)
- **Validation rows:** 1,298 (12.2%)
- **Test rows:** 1,681 (15.8%)

### Split Methodology
- **Method:** Domain-aware stratified splitting
- **Unit of splitting:** Registered domain (tldextract)
- **Stratification:** By majority label per domain
- **Random seed:** 42 (fixed for reproducibility)
- **Approximate ratios:** 70% train, 15% validation, 15% test
- **Priority:** Leakage prevention over exact percentages

### Domain Statistics
- **Unique registered domains:** 8,882
- **Train domains:** 6,416
- **Validation domains:** 1,133
- **Test domains:** 1,333

---

## LEAKAGE

### URL Overlap
- **Train-Val:** 0 URLs ✅
- **Train-Test:** 0 URLs ✅
- **Val-Test:** 0 URLs ✅
- **Total URL overlap:** 0 ✅

### Domain Overlap
- **Train-Val:** 0 registered domains ✅
- **Train-Test:** 0 registered domains ✅
- **Val-Test:** 0 registered domains ✅
- **Total domain overlap:** 0 ✅

### Root Domain Overlap
- **Train-Val:** 2 root domains ⚠️
- **Train-Test:** 1 root domain ⚠️
- **Val-Test:** 1 root domain ⚠️
- **Total root domain overlap:** 4 ⚠️
- **Assessment:** Non-critical (registered domains are leakage-free)

### Source/Hash Overlap
- **Sample ID overlap:** 0 ✅
- **Folder name overlap:** 0 ✅

### Test Contamination
- **URL leakage:** NO ✅
- **Domain leakage:** NO ✅
- **Is contaminated:** NO ✅

### Overall PASS/FAIL
- **Overall result:** PASS ✅
- **Leakage-free splits:** YES ✅

---

## FEATURES

### Feature Counts
- **Structural features:** 32 ✅
- **Semantic features:** 12 ✅
- **Total features:** 44 ✅

### Feature Sources
- **Structural:** Existing `backend/ml_model.py` (32 features)
- **Semantic:** Existing `backend/webpage_analyzer.py` (12 features)
- **HTML source:** Full HTML from dataset (not network requests)

### Extraction Failures
- **Training set:** 0 failures ✅
- **Validation set:** 0 failures ✅
- **Test set:** 0 failures ✅
- **Total processed:** 10,634 samples successfully

---

## FILES

### Created Files
- `backend/process_phish360_parquet.py` — Main processing pipeline (564 lines)
- `backend/dataset/phish360/processed/train_features.parquet` — Training features
- `backend/dataset/phish360/processed/validation_features.parquet` — Validation features
- `backend/dataset/phish360/processed/test_features.parquet` — Test features
- `backend/dataset/phish360/reports/dataset_report.md` — Processing report
- `backend/dataset/phish360/reports/leakage_report.json` — Leakage validation results
- `docs/phish360_processing_final_report.md` — This final report

### Modified Files
- `backend/leakage_validator.py` — Fixed unicode encoding issues for Windows
- `backend/data_loader_phish360.py` — Updated for Parquet format support
- `docs/PROJECT_PLAN.md` — Updated with actual dataset information
- `docs/TASKS.md` — Updated with completed Phase 1 tasks
- `docs/phish360_dataset.md` — Comprehensive dataset documentation

### Legacy Files (Untouched)
- `backend/stream_and_extract.py` — PhreshPhish streaming (legacy)
- `backend/inspect_phreshphish.py` — PhreshPhish inspection (legacy)
- `backend/dataset/phreshphish/` — PhreshPhish checkpoints (legacy)

---

## NEXT STEP

**PHASE 1 COMPLETE — Ready for Model Training**

The dataset is now fully prepared with:
- ✅ Leakage-free train/validation/test splits
- ✅ 32 structural + 12 semantic features extracted
- ✅ All validation checks passed
- ✅ Comprehensive documentation completed

**Exact next step:** Begin PHASE 2 — Model Development

1. Train structural-only model on train_features.parquet
2. Train semantic-only model on train_features.parquet
3. Train hybrid PhishOut model on train_features.parquet
4. Validate all models on validation_features.parquet
5. Implement fusion calibration using validation set
6. Final evaluation on test_features.parquet (E1–E4)

**DO NOT automatically start model training.** Wait for review and approval of Phase 1 results before proceeding to Phase 2.

---

**END OF FINAL REPORT**