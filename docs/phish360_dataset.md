# Phish360 Dataset Documentation

**Last Updated:** 2026-08-23 (Processed)

---

## Dataset Overview

Phish360 is a multimodal phishing detection dataset designed to ensure sample uniqueness, diversity, and standardized screenshot quality. The dataset was introduced in the CrossPhire paper and serves as the primary research dataset for the PhishOut project.

### Dataset Source

- **Origin:** CrossPhire research paper
- **Download Location:** Google Drive
- **Current Local Dataset:** `D:\Downloads\phish360_parquet\`
- **Dataset Version:** Full Phish360 dataset (10,748 samples spanning 2020–2024)
- **Format:** Parquet files (Phish360_legit.parquet, Phish360_phish.parquet)

---

## Dataset Structure

### Parquet Format

The dataset is provided as Parquet files with the following structure:

```
D:\Downloads\phish360_parquet\
├── Phish360_legit.parquet    # Legitimate website records (6,416 rows)
└── Phish360_phish.parquet     # Phishing website records (4,332 rows)
```

### Parquet Schema

Each record contains:
- `dataset_name` — Dataset identifier ("Phish360")
- `folder_name` — Sample ID (e.g., "L01562", "P10001")
- `Class` — Label ("legit" or "phish")
- `brand` — Target brand (e.g., "facebook", "paypal", "unknown")
- `URL` — Raw URL string
- `TLD` — Top-level domain
- `Domain` — Domain name
- `FLD` — First-level domain
- `Subdomain` — Subdomain information
- `SSL` — SSL certificate presence (boolean)
- `image_path` — Relative path to screenshot
- `translated_tf_text` — Translated text (TensorFlow)
- `trafilatura_text` — Extracted text (Trafilatura)
- `trafilatura_text_language` — Language detection
- `translated_bs_text` — Translated text (BeautifulSoup)
- `BeautifulSoup_text` — Extracted HTML body text
- `BeautifulSoup_text_language` — Language detection
- `html2text_text` — Converted text (html2text)
- `lxml_text` — Extracted text (lxml)
- `html_extract_text` — Extracted HTML text
- `full_html` — Complete raw HTML content
- `html_text_language` — HTML language detection

---

## Dataset Statistics

### Overall Statistics

- **Total Samples:** 10,748
- **After Deduplication:** 10,634 (removed 114 duplicate URLs)
- **Dataset Size:** ~0.6 GB (Parquet format)
- **HTML Availability:** 100% (full_html column available)

### Class Distribution

- **Legitimate Samples:** 6,416 (59.7%)
- **Phishing Samples:** 4,332 (40.3%)
- **Brand Coverage:** Multiple brands in phishing (facebook, paypal, chase, etc.)

### Sample Naming Convention

- **Legitimate samples:** `LXXXXX` (e.g., "L01562", "L00001")
- **Phishing samples:** `PXXXXX` (e.g., "P10001", "P02520")
- **ID Ranges:** L00001–L06572 (legitimate), P01000–P19997 (phishing)

---

## Data Availability

### Component Availability

| Component | Availability | Format | Null Rate |
|-----------|-------------|--------|-----------|
| Labels | ✅ Available | String (Class column) | 0% |
| URLs | ✅ Available | String (URL column) | 0% |
| HTML | ✅ Available | String (full_html column) | 0% |
| Screenshots | ✅ Available | String (image_path column) | 0% |
| Domain Info | ✅ Available | Multiple columns | <1% |

### Encryption Status

**NO ENCRYPTION:** Parquet files are fully accessible without password.

- **Status:** Fully accessible
- **Processing:** Complete
- **Feature Extraction:** Successful

---

## Processed Dataset Information

### Leakage-Free Splits

- **Split Method:** Domain-aware stratified splitting
- **Random Seed:** 42 (for reproducibility)
- **Domain Units:** 8,882 unique registered domains

#### Split Statistics

- **Training Set:** 7,655 samples (72.0%)
  - Legitimate: 4,583 (59.8%)
  - Phishing: 3,072 (40.2%)
  - Domains: 6,416 unique registered domains

- **Validation Set:** 1,298 samples (12.2%)
  - Legitimate: 778 (59.9%)
  - Phishing: 520 (40.1%)
  - Domains: 1,133 unique registered domains

- **Test Set:** 1,681 samples (15.8%)
  - Legitimate: 1,005 (59.8%)
  - Phishing: 676 (40.2%)
  - Domains: 1,333 unique registered domains

### Leakage Validation Results

- **URL Overlap:** 0 across all splits ✅
- **Registered Domain Overlap:** 0 across all splits ✅
- **Root Domain Overlap:** 4 minor overlaps (non-critical) ⚠️
- **Sample ID Overlap:** 0 across all splits ✅
- **Test Contamination:** 0 ✅
- **Overall Status:** PASS ✅

---

## Feature Extraction

### Structural Features (32)

**Source:** `backend/ml_model.py` (existing PhishOut implementation)

**Features:**
- URL structure (length, depth, parameters)
- Domain characteristics (IP, subdomains, TLD risk)
- Security signals (HTTPS, shorteners, redirects)
- Lexical features (entropy, character ratios)
- Brand impersonation detection
- Typosquatting detection

### Semantic Features (12)

**Source:** `backend/webpage_analyzer.py` (existing PhishOut implementation)

**Features:**
- Password fields count
- Email fields count
- Forms count
- External links count
- Iframes count
- Scripts count
- Login indicators
- Credential indicators
- Payment indicators
- Urgency indicators
- Brand indicators
- Text length

**HTML Source:** Full HTML content from `full_html` column (not just extracted text)

### Total Features

- **Structural:** 32 features
- **Semantic:** 12 features
- **Total:** 44 features per sample

---

## Processed Data Files

### Output Structure

```
backend/dataset/phish360/
├── processed/
│   ├── train_features.parquet          # 7,655 samples
│   ├── validation_features.parquet     # 1,298 samples
│   └── test_features.parquet           # 1,681 samples
└── reports/
    ├── dataset_report.md               # Comprehensive processing report
    └── leakage_report.json            # Machine-readable leakage validation
```

### Feature File Contents

Each processed row contains:
- `sample_id` — Original sample identifier
- `url` — URL string
- `label` — Numeric label (0=legitimate, 1=phishing)
- `registered_domain` — Extracted registered domain
- `root_domain` — Extracted root domain
- `html_available` — HTML availability flag
- 32 structural features (url_length, hostname_length, etc.)
- 12 semantic features (password_fields, forms, etc.)

---

## Data Quality Characteristics

### Content Uniqueness

- **URL Uniqueness:** 99.0% (after removing 114 duplicates)
- **Domain Uniqueness:** 83.4% (8,882 unique registered domains)
- **HTML Availability:** 100% (all samples have full_html)

### Temporal Coverage

- **Time Span:** 2020–2024
- **Temporal Diversity:** Multi-year collection reduces temporal bias

### Brand Coverage

- **Phishing Brands:** facebook (219), paypal (211), chase (182), office (179), wells fargo (125), apple (108), etc.
- **Legitimate:** Mostly "unknown" brand (general web)

---

## Research Considerations

### Leakage Prevention

- **Domain-Aware Splitting:** Implemented to prevent domain leakage
- **Stratified Sampling:** Maintains class balance across splits
- **Fixed Random Seed:** Uses seed 42 for reproducibility
- **Test Set Preservation:** Final test set completely untouched

### Feature Extraction Quality

- **Structural Features:** Uses proven PhishOut implementation
- **Semantic Features:** Extracted from full HTML (not just body text)
- **Local Processing:** No network requests made during extraction
- **Failure Handling:** Graceful degradation for parsing errors

---

## Processing Decisions

### Why Parquet Format?

1. **No Password:** Immediate access to data
2. **Full HTML:** Contains complete HTML content (not just extracted text)
3. **Size:** Much smaller than ZIP (0.6 GB vs 4.95 GB)
4. **Schema:** Well-documented and consistent
5. **Metadata:** Includes domain, brand, and language information

### Why Domain-Aware Splitting?

1. **Leakage Prevention:** Prevents same domain appearing in multiple splits
2. **Realistic Evaluation:** Mimics real-world deployment scenarios
3. **Reproducibility:** Fixed random seed ensures consistent splits

### Why Full HTML vs Extracted Text?

1. **Complete Analysis:** Full HTML enables more comprehensive semantic analysis
2. **Feature Quality:** Better feature extraction from complete HTML structure
3. **Future Research:** Preserves flexibility for advanced semantic analysis

---

## Limitations

### Current Limitations

1. **Root Domain Overlap:** 4 minor overlaps in root domains (non-critical for research)
2. **Brand Imbalance:** Legitimate samples mostly "unknown" brand
3. **Temporal Metadata:** Limited temporal information in dataset
4. **Original Split:** Parquet doesn't preserve original trainval/test folder structure

### Mitigation Strategies

1. **Domain-Aware Splitting:** Minimizes leakage risk
2. **Stratified Sampling:** Maintains class balance
3. **Full HTML:** Preserves maximum information for analysis
4. **Documentation:** Clear tracking of all processing decisions

---

## Reproducibility

### Random Seed

- **Splitting Seed:** 42
- **Consistent Splits:** Same seed produces identical train/validation/test splits

### Processing Pipeline

- **Script:** `backend/process_phish360_parquet.py`
- **Dependencies:** tldextract, pandas, pyarrow, beautifulsoup4
- **Feature Extractors:** Existing PhishOut implementations
- **Validation:** Comprehensive leakage checking

---

## Next Steps

### Completed

- ✅ Dataset inspection and loading
- ✅ Data cleaning and deduplication
- ✅ Domain extraction and analysis
- ✅ Leakage-safe split creation
- ✅ Feature extraction (32 structural + 12 semantic)
- ✅ Leakage validation
- ✅ Processed data saving
- ✅ Comprehensive documentation

### Next Phase (Model Training)

1. Train structural-only model
2. Train semantic-only model
3. Train hybrid PhishOut model
4. Implement fusion calibration
5. Run E1–E4 research evaluations

---

## References

- **CrossPhire Paper:** "CrossPhire: Benefiting Multimodality for Robust Phishing Web Page Identification" (MDPI, 2025)
- **GitHub Repository:** https://github.com/almakhamreh/Multimodal-Phishing-Benchmarks
- **Example Implementation:** https://github.com/Jahnavi292006/multimodal-phishing-detection
- **LinkedIn Announcement:** https://www.linkedin.com/posts/selman-bozkir_the-phish360-dataset-is-out-activity-7422218587760754688-_kD0

---

**END OF PHISH360 DATASET DOCUMENTATION**