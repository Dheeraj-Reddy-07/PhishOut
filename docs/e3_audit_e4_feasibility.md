# E3 Audit and E4 Feasibility Report

**Date:** 2026-08-23  
**Purpose:** Audit E3 sample count discrepancy and determine E4 temporal feasibility

---

## STEP 1 — E3 SAMPLE COUNT AUDIT

### Audit Findings

**Actual Processed Files:**
- `backend/dataset/phish360/processed/train_features.parquet`: 7,732 rows
- `backend/dataset/phish360/processed/validation_features.parquet`: 1,369 rows  
- `backend/dataset/phish360/processed/test_features.parquet`: 1,533 rows
- **Total:** 10,634 rows

**E3 Usage:**
- E3 correctly used 1,533 test samples from `test_features.parquet`
- This matches the actual file content

**Discrepancy Explanation:**
The Phase 1 processing report (`docs/phish360_processing_final_report.md`) contained outdated/incorrect split numbers:
- **Reported:** Train 7,655, Validation 1,298, Test 1,681 (Total 10,634)
- **Actual:** Train 7,732, Validation 1,369, Test 1,533 (Total 10,634)

**Root Cause:**
The Phase 1 report appeared to contain estimated/target split numbers rather than the actual processed file counts. The total (10,634) was correct, but the individual split proportions were not accurately reflected in the report.

**E3 Correctness:**
- ✅ E3 used the correct actual test file (1,533 samples)
- ✅ No samples were excluded by E3
- ✅ No bias introduced by the count discrepancy
- ✅ The Phase 1 report documentation was simply outdated

**Conclusion:** E3 results are valid. The discrepancy was a documentation error in the Phase 1 report, not an implementation issue in E3.

---

## STEP 2 — TEMPORAL METADATA CHECK

### Available Phish360 Schema

**Columns in Phish360 Parquet Files:**
- dataset_name, folder_name, Class, brand, URL, TLD, Domain, FLD, Subdomain, SSL
- image_path, translated_tf_text, trafilatura_text, trafilatura_text_language
- translated_bs_text, BeautifulSoup_text, BeautifulSoup_text_language
- html2text_text, lxml_text, html_extract_text, full_html, html_text_language

### Temporal Metadata Assessment

**Date/Time Fields:** ❌ NONE
- No date column
- No timestamp column  
- No collection date
- No registration date
- No crawl date
- No publication date

**Sample IDs:** ❌ NOT TEMPORAL
- folder_name contains IDs like "P10001", "L01562"
- These are sequential sample identifiers, not dates
- Cannot be used for temporal ordering

**Image Paths:** ❌ NOT TEMPORAL  
- Paths show structure: "Phish360\\trainval\\P10001_brand\\SCREEN-SHOT\\screen_shoot.png"
- "trainval" vs "test" indicates original split, not time
- No temporal information in paths

**Brand Column:** ❌ NOT TEMPORAL
- Contains categorical brand information (facebook, paypal, etc.)
- No temporal ordering
- Cannot be used for chronological splitting

**Documentation Claim:** 
- Dataset documentation mentions "2020–2024 temporal coverage"
- However, **no actual temporal metadata exists** in the data files
- This appears to be general dataset description, not per-sample timestamps

### Temporal E4 Feasibility

**Conclusion:** ❌ **TEMPORAL E4 IS NOT POSSIBLE**

**Reason:** Phish360 dataset does not contain reliable temporal metadata (dates, timestamps, or chronological information) that could support a meaningful temporal generalization experiment.

**Cannot Use:**
- Sample IDs (P10001, L01562) - these are identifiers, not dates
- File structure (trainval/test) - this indicates original split, not time
- Brand categories - these are targets, not temporal indicators
- Arbitrary ordering - not scientifically defensible as time

---

## STEP 3 — ALTERNATIVE E4 METHODOLOGY

### Available Metadata for Generalization

**Potential Generalization Splits:**

1. **Brand-Held-Out Generalization** ⚠️ LIMITED
   - **Available:** Yes (brand column)
   - **Feasibility:** Limited - phishing has many brands, legitimate is mostly "unknown"
   - **Concern:** Legitimate samples are almost all "unknown" brand, making brand split unbalanced

2. **Source-Held-Out Generalization** ❌ NOT AVAILABLE
   - **Available:** No source/collection metadata
   - **Feasibility:** Not possible

3. **Domain-Family-Held-Out Generalization** ⚠️ LIMITED
   - **Available:** Partial (domain information exists)
   - **Feasibility:** Complex to define meaningful "domain families"
   - **Concern:** May overlap with existing domain-aware leakage prevention

### Decision

**DO NOT PROCEED WITH E4**

**Reasoning:**
1. No legitimate temporal metadata exists for temporal E4
2. Alternative generalization splits are either not available or scientifically weak
3. Forcing a weak generalization experiment would not provide meaningful research insights
4. The project plan explicitly states: "If E4 is NOT scientifically supportable from the available dataset: STOP after documenting why"

---

## FINAL DECISION

### E3 Audit Result
- **Processed test count:** 1,533 samples (actual file)
- **E3 test count:** 1,533 samples (correct usage)
- **Explanation:** Phase 1 report had outdated numbers; E3 used correct actual file
- **E3 validity:** ✅ VALID - no bias or exclusion issues

### Temporal Data Result
- **Available:** ❌ NO reliable temporal metadata
- **Evidence:** No date/timestamp columns in schema; sample IDs are identifiers not dates; documentation claim of "2020–2024" not reflected in actual data

### E4 Result
- **Performed:** ❌ NOT PERFORMED
- **Reason:** No scientifically defensible generalization split available
- **Methodology:** None - temporal not possible, alternatives too weak

### Research Conclusion
**E3 successfully demonstrated feature-level robustness of PhishOut. E4 cannot be legitimately performed due to lack of temporal metadata in Phish360 dataset. No scientifically defensible alternative generalization experiment is available with the current metadata.**

### Next Step
**STOP** - E4 cannot be performed. Do not proceed to E5/E6/E7 unless explicitly approved as stretch phases.

---

**Files Updated:**
- docs/e3_audit_e4_feasibility.md (this report)
- docs/PROJECT_PLAN.md (to reflect E4 infeasibility)
- docs/TASKS.md (to reflect E4 infeasibility)