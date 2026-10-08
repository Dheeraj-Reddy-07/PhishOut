# PhishOut Task Tracking

**Current task list aligned with docs/PROJECT_PLAN.md**

---

## Current Phase: V3 PRODUCTION MODEL COMPLETE

**Status:** V3 script extraction bug fixed, pipeline rebuilt, end-to-end validated. V3 is the production candidate.

**V3 Key Achievement:** Fixed critical script extraction bug (html2text_text → full_html), rebuilt entire V3 pipeline, validated improved hard-negative FPR (2.0% vs V2 4.0%).

**Extension status:** Audited and integrated with the shared `/phishout/scan` runtime; uses V3 models.

**Objective:** Deploy V3 production model with improved false-positive handling on legitimate authentication pages.

---

## Active Tasks

### PHASE 1 — Dataset + Feature Pipeline (COMPLETED ✅)

- [x] Inspect Phish360 Parquet files schema and structure
- [x] Download Parquet format from Google Drive
- [x] Load actual data contents (labels, URLs, HTML)
- [x] Build Phish360 Data Loader
- [x] Implement Parquet loading and processing
- [x] Clean and deduplicate data (removed 114 duplicate URLs)
- [x] Validate URL formats and labels
- [x] Verify class distribution (6,416 legitimate, 4,332 phishing)
- [x] Implement domain extraction for Phish360 URLs
- [x] Create leakage-safe train/validation/test splits
- [x] Ensure no URL/domain overlap across splits
- [x] Implement leakage verification utility
- [x] Extract 32 structural features using existing `ml_model.py`
- [x] Extract 12 semantic features from local HTML using existing `webpage_analyzer.py`
- [x] Save train/validation/test features to parquet
- [x] Validate features and leakage-free splits
- [x] Generate processing and leakage reports

### PHASE 2 — Model Development (COMPLETED ✅)

- [x] Train structural-only model (32 features)
- [x] Train semantic-only model (12 features)
- [x] Train hybrid PhishOut model (44 features)
- [x] Train learned score-level fusion model
- [x] Calibrate decision thresholds using validation set
- [x] Integrate Phish360 models into runtime system
- [x] Create comprehensive training report

---

## Pending Tasks (Future Phases)

### PHASE 3 — Fusion Calibration (COMPLETED ✅)

- [x] Implement logistic-regression fusion/meta-model
- [x] Calibrate on validation set (not test set)
- [x] Optimize log loss/cross-entropy
- [x] Select SAFE/SUSPICIOUS/PHISHING thresholds
- [x] Freeze fusion model and thresholds
- [x] Save threshold configuration for runtime

### PHASE 4 — Core Research Evaluation

#### E1: Normal Detection Evaluation (COMPLETED ✅)

- [x] Train models on Phish360 train set
- [x] Evaluate on untouched Phish360 test set
- [x] Report accuracy, precision, recall, F1, ROC-AUC, PR-AUC
- [x] Report confusion matrix
- [x] Report false positive rates

#### E2: Structural vs Semantic vs Hybrid Comparison (COMPLETED ✅)

- [x] Train all four models on same train set
- [x] Evaluate all four on same test set
- [x] Compare metrics side-by-side
- [x] Determine if hybrid/fusion improves over individual models
- [x] Identify best-performing model (Learned-Fusion PhishOut, F1=0.9426)

#### E3: IEEE-style Feature-Level Robustness Testing (COMPLETED ✅)

- [x] Implement ±5% feature perturbation function
- [x] Generate adversarial examples from test set
- [x] Evaluate model performance on perturbed features
- [x] Report accuracy drop per feature
- [x] Report feature importance for robustness
- [x] Create feature robustness ranking
- [x] Compare structural vs semantic robustness
- [x] Document methodology adaptation from base paper

#### E4: Generalization/Temporal Testing

- [x] Check if Phish360 has temporal metadata
- [x] Confirm temporal split is not scientifically defensible
- [x] Preserve the E4 infeasibility audit

### PHASE 5 — Optional Stretch (E5–E7)

- [x] E5 feasibility check: architecture supports offline re-extraction in principle
- [x] Verify raw Phish360 `full_html` at the external local source
- [x] E5: Run and document the offline webpage-level robustness experiment
- [x] E6: Adversarial training with train-only E5 variants
- [x] E7: Unseen-attack generalization using URL percent-encoding absent from E6 training

---

## Completed Tasks

### Phase 2 Model Training

- [x] Create Phish360-specific training scripts
- [x] Train structural-only model (F1=0.8650 on test)
- [x] Train semantic-only model (F1=0.9100 on test)
- [x] Train hybrid model (F1=0.9424 on test)
- [x] Train learned fusion model (F1=0.9426 on test)
- [x] Calibrate thresholds (SAFE < 15, PHISHING >= 57)
- [x] Complete E1/E2 final evaluation
- [x] Integrate Phish360 models into runtime (phishout_predictor.py)
- [x] Create comprehensive training report

### Documentation

- [x] Create `docs/PROJECT_PLAN.md` as main source of truth
- [x] Classify PhreshPhish-specific files as LEGACY
- [x] Mark legacy files with documentation comments
- [x] Document old baseline results (97.30% on 250 URLs)
- [x] Document research roadmap (E1–E4)
- [x] Document leakage-prevention rules
- [x] Create `docs/phish360_model_training_report.md` with Phase 2 results
- [x] Complete Chrome extension integration audit and document setup/tests

### Legacy Components (Preserved for Reference)

- [x] Structural feature extraction (`ml_model.py`)
- [x] Semantic feature extraction (`webpage_analyzer.py`)
- [x] Fusion layer (`phishout_fusion.py`)
- [x] Explanation engine (`explanation_engine.py`)
- [x] API endpoints (`main.py`)
- [x] Dashboard
- [x] Chrome extension

---

## Blocked Tasks

- None for E5. Raw HTML was read read-only from `D:\Downloads\phish360_parquet\`.

---

## Notes

- **DO NOT use PhreshPhish streaming pipeline** — abandoned approach
- **DO NOT use old 250-URL dataset** — historical reference only
- **Current dataset:** Phish360 (local)
- **Official base paper:** 2025 IEEE feature robustness paper
- **PhishOracle is NOT required** for E1–E4
- **Phase 2 COMPLETE:** All models trained and evaluated successfully
- **Best model:** Learned-Fusion PhishOut (F1=0.9426 on test set)
- **Calibrated thresholds:** SAFE < 15, SUSPICIOUS 15-56, PHISHING >= 57

---

## Next Implementation Task

**E5 — Webpage/URL-level adversarial perturbation (COMPLETED)**

E4 is closed as infeasible because Phish360 has no reliable temporal metadata. E5 was evaluated offline on 612 phishing samples from the existing test split using four transformations and frozen Phase 2 models. E6 and E7 are complete.

See `docs/e5_adversarial_evaluation_report.md` for the E5 methodology and results after evaluation.

**E6 — Adversarial training (COMPLETED)**

One new model was trained using 3,113 train-only adversarial variants, one per phishing training sample, across the four audited E5 transformations. Clean and E5-style adversarial evaluation is documented in `docs/e6_adversarial_training_report.md`. Evasion decreased or remained zero across all four transformations; clean F1 decreased slightly.

**E7 — Unseen-attack generalization (COMPLETED)**

The final test set was evaluated once on the unseen URL percent-encoding transformation with stable sample-ID pairing. Evasion decreased from 0.35% for the original model to 0.18% for E6. See `docs/e7_unseen_attack_report.md` and `backend/models/phish360/e7/`.

The experimental phase is complete. Next: paper, thesis, documentation, and final demo preparation.

---

## V2 — Context-Aware False-Positive Reduction (COMPLETED ✅)

**Trigger:** Runtime testing showed Google, Microsoft, Gemini receiving high semantic scores / PHISHING verdicts.

**Objective:** Build a principled V2 model that reduces false positives on legitimate authentication/payment pages without degrading phishing detection.

### V2 Implementation Tasks

- [x] Root cause analysis — `docs/phishout_v2_root_cause_analysis.md`
- [x] Hard-negative strategy evaluation — `docs/phishout_v2_hard_negative_report.md`
- [x] Feature engineering — 3 new context features in `backend/webpage_analyzer.py`
  - [x] `domain_brand_consistency` — brand mention vs domain legitimacy
  - [x] `form_action_same_origin` — form exfiltration detection
  - [x] `trusted_domain` — known brand domain signal
- [x] V2 feature extraction pipeline — `backend/phish360_v2_feature_extractor.py`
- [x] V2 datasets created — `backend/dataset/phish360/v2/processed/*.parquet`
  - Train: 7,730 samples | Validation: 1,317 | Test: 1,701
- [x] V2 model training:
  - [x] Structural V2 (32f, F1=0.8337)
  - [x] Semantic V2 (15f, F1=0.9400)
  - [x] Hybrid V2 (47f, F1=0.9453)
  - [x] Fusion V2 (learned, F1=0.9515)
- [x] Threshold calibration on validation set (SAFE<5%, PHISHING≥45%)
- [x] Fixed bug in `evaluate_v2_vs_baseline.py` (NameError v2_results)
- [x] V2 vs baseline comparison complete — `backend/models/phish360_v2/v2_vs_baseline_comparison.json`
- [x] Reverted V1 training scripts to original 12-feature state (train_phish360_semantic.py, train_phish360_hybrid.py, phish360_feature_extractor.py)
- [x] Updated `phishout_predictor.py` to use V2 models (phish360_v2/)
- [x] Written V2 research report — `docs/phishout_v2_report.md`

### V2 Key Results (vs V1 baseline, same test set n=1,701)

| Metric | V1 Fusion | V2 Fusion | Change |
|--------|-----------|-----------|--------|
| F1 | 0.9415 | 0.9515 | +0.0100 |
| Precision | 0.9501 | 0.9658 | +0.0157 |
| Recall | 0.9330 | 0.9377 | +0.0047 |
| FPR | 0.0326 | 0.0264 | −0.0062 |
| FP count | 30 | 25 | −5 (−16.7%) |
| FN count | 41 | 47 | +6 (+14.6%) |

### Frozen Baseline Confirmed Intact ✅

All E1–E7 artifacts in `backend/models/phish360/` are unchanged.
Last commit before V2: `5b7c03e`.

### Pending V2 Tasks

- [x] Stage 6 — Runtime sanity checks (Google, Microsoft, Gemini, Wikipedia, PayPal)
  - Completed: V3 real-world sanity check shows 4/5 SAFE vs V2 2/5 SAFE

---

## V3 — Script Extraction Fix and Production Deployment (COMPLETED ✅)

**Trigger:** V3 audit revealed script extraction bug - 99.5% of samples had scripts=0 due to using processed text instead of raw HTML.

**Objective:** Fix script extraction, rebuild V3 pipeline, validate improved performance.

### V3 Implementation Tasks

- [x] Root cause analysis — script extraction used `html2text_text` instead of `full_html`
- [x] Fix applied — changed `html_column` parameter in `phish360_v3_feature_extractor.py`
- [x] Regression tests — `test_regression_script_extraction.py` validates script counting
- [x] Feature validation — `validate_fixed_features.py` confirms corrected distributions
- [x] Pipeline rebuild:
  - [x] Feature extraction with fixed script extraction
  - [x] Augmented training (8,330 samples with hard negatives)
  - [x] V3 semantic model training (19 features)
  - [x] V3 fusion model training
  - [x] Threshold calibration (SAFE<5%, PHISHING≥50%)
- [x] Evaluation — `evaluate_phish360_v3.py` on test and hard-negative sets
- [x] Comparison — `compare_all_versions.py` V2 vs Old V3 vs Fixed V3
- [x] Real-world sanity check — 4/5 SAFE vs V2 2/5 SAFE
- [x] Runtime integration — `phishout_predictor.py` updated to load V3 models
- [x] End-to-end validation — backend API, frontend, extension all use V3
- [x] Final test matrix — 6/10 correct, 100% phishing detection, acceptable legitimate FPR

### V3 Key Results (vs V2, same test set n=1,701)

| Metric | V2 Fusion | Old V3 (Broken) | V3 Fusion (Fixed) | V3 vs V2 |
|--------|-----------|-----------------|-------------------|-----------|
| Test F1 | 0.9515 | 0.9577 | 0.9653 | +0.0138 |
| Test Recall | 0.9377 | 0.9748 | 0.9775 | +0.0398 |
| Test FPR | 0.0264 | 0.0486 | 0.0380 | +0.0116 |
| Hard-Negative FPR | 0.0400 | 0.0550 | 0.0200 | -0.0200 |
| Real-World FPR | 60% (2/5) | N/A | 20% (4/5) | -40% |

### V3 Script Extraction Fix Details

**Root Cause:**
- `phish360_v3_feature_extractor.py` was using `html2text_text` (already processed plain text)
- This column had no `<script>` tags, so 99.5% of samples had scripts=0
- `text_to_script_ratio` became text_length (20,000-100,000+ instead of ~1,000)

**Fix Applied:**
- Changed `html_column` parameter from `'html2text_text'` to `'full_html'` in line 76
- `full_html` contains raw HTML with actual `<script>` tags

**Validation:**
- Before fix: 199/200 hard-negative samples had scripts=0 (99.5%)
- After fix: 1/200 hard-negative samples had scripts=0 (0.5%)
- `text_to_script_ratio` normalized from mean 48,974 to mean 913

### V3 Production Status ✅

V3 is the production model. All components (backend, frontend, extension) use V3 via `/phishout/scan` endpoint.
