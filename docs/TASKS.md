# PhishOut Task Tracking

**Current task list aligned with docs/PROJECT_PLAN.md**

---

## Current Phase: E7 UNSEEN-ATTACK GENERALIZATION COMPLETE

**Status:** E1-E7 complete except E4, which is not feasible because Phish360 has no reliable temporal metadata; E7 showed limited positive unseen-attack generalization

**Extension status:** Audited and integrated with the shared `/phishout/scan` runtime; manual Chrome loading checks remain.

**Objective:** Evaluate feature-level robustness using ±5% perturbation methodology

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
