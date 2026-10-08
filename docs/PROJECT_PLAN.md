# PhishOut — Project Plan

**Project:** PhishOut — Adversarially Robust Phishing Webpage Detection Using Hybrid Structural and Semantic Analysis

**Current Phase:** V3 PRODUCTION MODEL COMPLETE

**Last Updated:** 2026-08-24

---

## 1. Project Overview

PhishOut is a research-focused phishing detection system that combines structural URL analysis with semantic webpage content analysis to produce a single fused risk score. The project aims to develop and evaluate an adversarially robust phishing detector using feature-level perturbation analysis inspired by the 2025 IEEE paper on feature robustness and adversarial resilience ranking.

### Current State

- **Architecture:** Complete — 32 structural features + 19 semantic features → ONE fused PhishOut score
- **API:** Fully functional FastAPI backend with `/scan`, `/scan_extended`, `/phishout/scan` endpoints
- **Frontend:** React dashboard and Chrome extension operational
- **Research Status:** E1-E7 complete; V1, V2, V3 models all preserved and validated
- **V3 Status:** COMPLETE — Script extraction bug fixed, pipeline rebuilt, end-to-end validated
- **V3 Fix:** Changed `html_column` from `html2text_text` to `full_html` in feature extractor
- **V3 Features:** 19 semantic features (15 V2 + 4 new V3: link_to_form_ratio, text_to_script_ratio, credential_density, brand_context_score)
- **V3 Model:** phish360_v3_learned_fusion (F1=0.9653, Recall=0.9775, Hard-Negative FPR=0.0200)
- **V3 Thresholds:** SAFE < 5%, SUSPICIOUS 5-50%, PHISHING >= 50%
- **V2 Status:** PRESERVED — Context-aware model with 15 semantic features
- **V1 Status:** PRESERVED — Original Phish360 baseline with 12 semantic features
- **E4 Status:** NOT FEASIBLE — No temporal metadata available in Phish360
- **E5-E7 Status:** COMPLETE — Webpage-level adversarial evaluation complete
- **Extension Status:** AUDITED AND INTEGRATED — MV3 popup and content script use the shared `/phishout/scan` runtime with V3 models
- **Production Model:** V3 Fusion (Fixed script extraction, hard-negative training)
- **Robustness:** High feature-level robustness (max 0.74% F1 degradation under ±5% perturbation)
- **Dataset:** Phish360 (10,634 samples, leakage-free splits)
- **Core Research:** E1-E7 complete; V1-V3 evolution complete; V3 production-ready

---

## 2. Research Objective

**Primary Goal:** Develop and evaluate an adversarially robust phishing webpage detection system using hybrid structural and semantic analysis, with feature-level robustness testing following IEEE 2025 methodology.

**Secondary Goals:**

- Compare structural-only, semantic-only, and hybrid approaches
- Implement genuine fusion calibration (not hand-picked weights)
- Evaluate generalization across temporal splits where metadata supports it
- Optionally explore webpage-level adversarial attacks (E5–E7, not blocking)

---

## 3. Official Base Paper

**Title:** "An Optimized Machine Learning Framework for Phishing Website Detection Integrating Feature Robustness and Adversarial Resilience Ranking"

**Source:** IEEE, 2025

**Relevant Methodology:**

- Engineered phishing-detection features
- Feature robustness analysis (±5% perturbation)
- Robustness/degradation measurement
- Generalization evaluation

**IMPORTANT:** This is the OFFICIAL base paper for our research methodology.

---

## 4. Role of PhishOracle

**PhishOracle (ACM paper)** is NOT our base paper. It is related work/inspiration only and may be used later for webpage-level adversarial attack ideas (E5–E7 optional stretch).

**Do NOT describe PhishOracle as the methodology or source of the official base paper.**

---

## 5. Current Architecture

### Fusion Architecture (NOT Sequential Two-Layer)

```
32 structural features + 12 semantic features → ONE fused PhishOut score → risk score 0–100 → SAFE/SUSPICIOUS/PHISHING → explanations
```

**Key Points:**

- This is a FUSION architecture
- It is NOT a sequential two-layer model
- Do NOT describe structural analysis as "layer 1" followed by semantic "layer 2"

### Existing Product Components (Preserve These)

- FastAPI backend (`main.py`)
- `/scan` endpoint
- `/scan_extended` endpoint
- `/phishout/scan` endpoint
- Dashboard (React + HTML/CSS/JS versions)
- Chrome extension
- Structural feature extraction (`ml_model.py`)
- Semantic HTML analysis (`webpage_analyzer.py`)
- Risk scoring (`phishout_fusion.py`)
- Explanation engine (`explanation_engine.py`)

**Do NOT redesign these components.**

---

## 6. Current Dataset: Phish360

**IMPORTANT CHANGE:** The old project direction was based on streaming PhreshPhish from Hugging Face. We have ABANDONED that as the final dataset pipeline.

**NEW PRIMARY DATASET:** PHISH360 — downloaded locally.

The final research pipeline must use the locally downloaded Phish360 dataset.

### Current Status

- ✅ Phish360 Parquet dataset inspected and processed
- ✅ Local Phish360 data loader built and tested
- ✅ File structure and format documented
- ✅ Leakage-safe train/validation/test splits created
- ✅ 32 structural + 12 semantic features extracted
- ✅ Processed feature datasets saved and validated

### Dataset Information

- **Source:** D:\Downloads\phish360_parquet\
- **Files:** Phish360_legit.parquet (6,416 rows), Phish360_phish.parquet (4,332 rows)
- **Total samples:** 10,748 (after deduplication: 10,634)
- **Class distribution:** 6,416 legitimate (59.7%), 4,332 phishing (40.3%)
- **HTML availability:** 100% (full_html column available)
- **Format:** Parquet files with full HTML content
- **Processing:** Complete with leakage-free domain-aware splits

### Dataset Structure (ZIP Archive)

```
Phish360/
├── trainval/ (7,977 samples)
│   ├── L01562_legitimate/
│   │   ├── Label/label.txt
│   │   ├── RAW-HTML/index.html
│   │   ├── SCREEN-SHOT/screen_shoot.png
│   │   └── URL/url.txt
│   └── ...
└── test/ (2,771 samples)
    ├── L00001_legitimate/
    │   ├── Label/label.txt
    │   ├── RAW-HTML/index.html
    │   ├── SCREEN-SHOT/screen_shoot.png
    │   └── URL/url.txt
    └── ...
```

### Alternative Format (USED)

**Parquet Format:**

- ✅ Downloaded and processed
- Size: ~0.6 GB (much smaller than ZIP)
- No password protection
- Full HTML content available (not just extracted text)
- Files: `Phish360_phish.parquet` and `Phish360_legit.parquet`
- Source: https://drive.google.com/drive/u/1/folders/1ulQYtb63pZlhgcKMuTeiDze1onsY1yKT

### Data Availability

- Labels: ✅ Available (Class column in Parquet)
- URLs: ✅ Available (URL column in Parquet)
- HTML: ✅ Available (full_html column in Parquet)
- Screenshots: ✅ Available (image_path column in Parquet)
- **Access:** ✅ Parquet files fully accessible

### Next Steps

1. ✅ Download Parquet format (completed)
2. ✅ Load and inspect actual data contents (completed)
3. ✅ Validate class distribution (completed)
4. ✅ Create leakage-safe train/validation/test splits (completed)
5. ✅ Extract 32 structural + 12 semantic features (completed)
6. ⏳ Model training (next phase)

### Do NOT Continue/Restart

- `stream_and_extract.py`
- PhreshPhish streaming
- PhreshPhish downloading
- PhreshPhish-based final training

---

## 7. Legacy Dataset: PhreshPhish

**Status:** LEGACY/EXPERIMENTAL/REFERENCE ONLY

PhreshPhish is no longer the primary research dataset. Some partial PhreshPhish checkpoint/feature files may exist in the repository from previous work.

**DO NOT delete them automatically.** Mark them as legacy/experimental/reference only.

### Legacy Files

- `backend/stream_and_extract.py` — LEGACY (PhreshPhish streaming pipeline)
- `backend/inspect_phreshphish.py` — LEGACY (PhreshPhish inspection tool)
- `backend/dataset/phreshphish/train_checkpoint.parquet` — LEGACY (partial checkpoint)
- `docs/final_dataset_and_training.md` — LEGACY (PhreshPhish-based documentation)

---

## 8. Current Implementation Status

### Completed Components

- ✅ FastAPI backend with three scan endpoints
- ✅ 32 structural feature extraction
- ✅ 12 semantic feature extraction
- ✅ Fusion scoring mechanism
- ✅ Explanation engine
- ✅ React dashboard
- ✅ Chrome extension
- ✅ Basic ML model training (legacy small dataset)

### Research Components (In Progress)

- ⏳ Phish360 dataset inspection
- ⏳ Local Phish360 data loader
- ⏳ Leakage-safe train/validation/test splits
- ⏳ Feature extraction pipeline for Phish360
- ⏳ Model training comparison (structural vs semantic vs hybrid)
- ⏳ Fusion calibration
- ⏳ Feature-level robustness testing

---

## 9. Research Roadmap

### PHASE 1 — Dataset + Research Pipeline (COMPLETED ✅)

1. ✅ Inspect local Phish360 dataset
2. ✅ Build local Phish360 data loader
3. ✅ Clean/deduplicate data
4. ✅ Preserve URL, HTML, label, domain/source/date metadata where available
5. ✅ Create leakage-safe train/validation/test splits
6. ✅ Extract 32 structural features + 12 semantic features
7. ✅ Save reproducible feature datasets

### PHASE 2 — Model Development (COMPLETED ✅)

Train and compare:

- ✅ **A.** Structural-only model (32 features)
- ✅ **B.** Semantic-only model (12 features)
- ✅ **C.** Hybrid PhishOut model (44 features)
- ✅ **D.** Learned-fusion PhishOut model (score-level fusion)

The final hybrid system combines structural and semantic information into ONE score through learned fusion.

**Fusion Implementation:**

- ✅ Structural model probability
- ✅ Semantic model probability
- ✅ Logistic-regression fusion/meta-model
- ✅ Learned coefficients: struct=4.3084, sem=5.0940, intercept=-4.5671
- ✅ Calibrated thresholds: SAFE < 15, PHISHING >= 57

### PHASE 3 — Fusion Calibration (COMPLETED ✅)

Implement genuine calibration:

- ✅ Structural model probability
- ✅ Semantic model probability
- ✅ Logistic-regression fusion/meta-model
- ✅ Optimize log loss/cross-entropy
- ✅ Use validation data for SAFE/SUSPICIOUS/PHISHING threshold selection
- ✅ Freeze the fusion model and thresholds
- ✅ Never tune using final test data

### PHASE 4 — Core Research Evaluation (CURRENT: E3)

**E1 — Normal detection evaluation (COMPLETED ✅)**

- ✅ Standard metrics: accuracy, precision, recall, F1, ROC-AUC, PR-AUC
- ✅ Confusion matrices for all models
- ✅ Test set evaluation only (no tuning)

**E2 — Structural vs Semantic vs Hybrid comparison (COMPLETED ✅)**

- ✅ Compare all four approaches on same test set
- ✅ Side-by-side metrics comparison
- ✅ Best model: Learned-Fusion PhishOut (F1=0.9426)

**E3 — IEEE-style feature-level robustness testing (COMPLETED ✅)**

- ✅ Implement ±5% feature perturbation function
- ✅ Generate adversarial examples from test set
- ✅ Evaluate model performance degradation under perturbation
- ✅ Report accuracy drop per feature
- ✅ Create adversarial resilience ranking
- ✅ Compare structural vs semantic robustness
- ✅ Document methodology adaptation

**E4 — Generalization / temporal testing**

- [x] Audit Phish360 for reliable temporal metadata
- [x] Document infeasibility; do not manufacture chronological ordering

**E5 — Webpage/URL-level adversarial perturbation**

- [x] Confirm existing extractors and frozen models support the method
- [x] Verify raw `full_html` source at `D:\Downloads\phish360_parquet\`
- [x] Select leakage-controlled train development and test evaluation samples
- [x] Implement and run the small offline E5 experiment
- [x] Report per-transformation and overall evasion results

### PHASE 5 — Optional Stretch (E5–E7)

Only after E1–E4 are complete and stable, with raw HTML available locally:

**E5 — Webpage-level adversarial attacks**

- Actually modify HTML/URL → re-extract features → test PhishOut
- Current result: COMPLETE; 612 phishing test samples evaluated offline

**E6 — Adversarial training**

- Train one new model using train-only E5 variants
- Compare clean and E5-style adversarial test performance against original PhishOut
- Current result: COMPLETE; visible-text evasion decreased 1.03 percentage points, URL-query evasion decreased 0.52 points, with a 0.26-point clean F1 decrease

**E7 — Unseen-attack generalization**

- [x] Evaluate one transformation absent from E6 training
- [x] Preserve stable sample-ID pairing for clean and perturbed results
- [x] Complete the final test evaluation without training or tuning on test data
- Current result: E6 evasion decreased from 0.35% to 0.18%

**These are OPTIONAL and must never block completion of the core project.**

---

## 10. E1–E4 Core Scope

These are REQUIRED for project completion:

- **E1:** Normal detection evaluation on held-out test set
- **E2:** Model comparison (structural vs semantic vs hybrid)
- **E3:** Feature-level robustness testing (±5% perturbation)
- **E4:** Temporal feasibility audit; evaluation only where metadata supports it

**Do NOT proceed to E5–E7 until E1–E3 are complete and E4 has been audited.**

---

## 11. E5–E7 Optional Scope

These are stretch goals that must NOT block the core project:

- **E5:** Webpage-level adversarial attacks
- **E6:** Adversarial training
- **E7:** Unseen-attack generalization

---

## 12. Leakage-Prevention Rules

**Non-negotiable research rules:**

Before training/augmentation/adversarial generation:

- No exact URL overlap across splits
- No duplicate URL overlap
- No registered/root-domain overlap across splits
- No source/hash overlap where available
- No derived variants crossing splits
- Final test set remains completely untouched
- Test data must never be used for:
  - Training
  - Fusion calibration
  - Threshold selection
  - Feature selection
  - Model selection

**Splitting must occur BEFORE augmentation or adversarial generation.**

**Implementation:** Create one reusable leakage-validation utility instead of implementing separate ad-hoc checks in different scripts.

---

## 13. Evaluation Metrics

**Primary Metrics:**

- Accuracy
- Precision
- Recall
- F1-Score
- ROC-AUC

**Secondary Metrics:**

- False Positive Rate
- Confusion Matrix
- Calibration metrics (log loss, Brier score)

**Robustness Metrics (E3):**

- Performance degradation under ±5% feature perturbation
- Feature importance stability
- Adversarial resilience ranking

---

## 14. Model/Fusion Methodology

### Current Preliminary Configuration

- 60% structural weight
- 40% semantic weight
- Hand-picked thresholds

**This is NOT the final research result.**

### Required Calibration Approach

- Train separate structural and semantic models
- Generate out-of-fold predictions
- Train logistic regression fusion meta-model
- Optimize for log loss/cross-entropy
- Select thresholds on validation set only
- Freeze all parameters before test evaluation

---

## 15. Current Phase

**CURRENT PHASE:** E7 UNSEEN-ATTACK GENERALIZATION COMPLETE

**Status:** E1-E7 complete except E4, which is not feasible because Phish360 has no reliable temporal metadata; E7 showed limited positive unseen-attack generalization

**Next Action:** Complete final Chrome extension loading checks, then begin paper, thesis, documentation, and final demo preparation

---

## 16. Next Action

**Immediate Next Phase:**

1. Review the E7 unseen-attack report and comparison artifacts
2. Keep the original Phase 2 and E6 models frozen
3. Prepare the final paper/thesis narrative and demo

**Do NOT jump to:**

- PhishOracle
- Additional robustness experiments without explicit research review

---

## 17. Future Work

**After completing E7:**

- Prepare paper, thesis, documentation, and final demo materials
- Publish results with IEEE-style feature robustness analysis

**Implementation Guidelines:**

- Prefer large coherent changes over many tiny prompts/tests
- Maintain leakage-free evaluation throughout
- Document all calibration decisions
- Preserve reproducibility

---

## 18. Old Baseline (Historical Only)

**Legacy 250-URL Structural Baseline:**

- Accuracy: 97.30%
- F1: 97.30%
- ROC-AUC: 0.9971
- Status: Leakage-free but from old tiny dataset
- Historical context only

**Old Hybrid Experiment:**

- Achieved 45.95% accuracy
- Reason: Most phishing URLs had no live webpage/semantic data
- This explains WHY we moved to Phish360

**Do not present old results as final research results.**

---

## 19. Credit/Compute Constraints

**Limited AI Credits — Therefore:**

- Make minimal necessary changes
- No full dataset processing
- No model training
- No expensive tests
- No repeated experiments
- No unnecessary dependency installation
- No architectural redesign

**This task is primarily documentation, project-state cleanup, and research-plan alignment.**

---

## 20. HOW TO CONTINUE THIS PROJECT

### For Future AI/Developer Handoff

**CURRENT DATASET:**

- Phish360 (locally downloaded)
- Location: To be documented after inspection

**DO NOT USE:**

- PhreshPhish streaming pipeline
- `stream_and_extract.py`
- PhreshPhish-based final training

**CURRENT ARCHITECTURE:**

- 32 structural features + 12 semantic features → ONE fused PhishOut score
- Fusion architecture (NOT sequential two-layer)
- All existing API endpoints and components preserved

**OFFICIAL BASE PAPER:**

- 2025 IEEE feature robustness paper
- Feature-level perturbation methodology
- NOT PhishOracle (that's related work only)

**CURRENT NEXT IMPLEMENTATION:**

1. Restore raw Phish360 HTML locally
2. Reassess E5 implementation feasibility

**DO NOT JUMP TO:**

- PhishOracle implementation
- Webpage-level attacks
- Adversarial training
- E5–E7 before completing E1–E4

**Implementation Preference:**

- Prefer large coherent changes over many tiny prompts/tests
- Use reusable leakage-validation utilities
- Maintain reproducibility throughout

**Documentation Updates:**

- Update this PROJECT_PLAN.md as phases complete
- Mark legacy files clearly
- Document all calibration decisions
- Preserve research history

---

## 21. File Classification

### Active Files (Current Architecture)

- `backend/main.py` — FastAPI backend
- `backend/ml_model.py` — Structural feature extraction
- `backend/webpage_analyzer.py` — Semantic analysis
- `backend/phishout_fusion.py` — Fusion scoring
- `backend/explanation_engine.py` — Explanation generation
- `backend/phishout_predictor.py` — Prediction orchestrator
- `backend/config/semantic_rules.py` — Configuration
- `dashboard/` — UI components
- `extension/` — Chrome extension

### Legacy Files (PhreshPhish-related)

- `backend/stream_and_extract.py` — LEGACY (PhreshPhish streaming)
- `backend/inspect_phreshphish.py` — LEGACY (PhreshPhish inspection)
- `backend/dataset/phreshphish/` — LEGACY (partial checkpoints)
- `docs/final_dataset_and_training.md` — LEGACY (PhreshPhish docs)

### Reusable Files

- `backend/data_loader.py` — Adaptable for Phish360
- `backend/train_model_v2.py` — Training pipeline reference
- `docs/baseline_v2.md` — Methodology reference
- `docs/data_leakage_analysis.md` — Leakage prevention reference

### Obsolete Files

- None clearly obsolete at this time
- Do not delete without explicit user confirmation

---

## 22. Key Documentation Files

### Primary Documentation

- `docs/PROJECT_PLAN.md` — **THIS FILE** (main source of truth)
- `docs/phishout_architecture.md` — Architecture details
- `docs/baseline_v2.md` — Historical baseline (legacy)
- `docs/data_leakage_analysis.md` — Leakage prevention methodology

### Legacy Documentation

- `docs/final_dataset_and_training.md` — PhreshPhish-based (legacy)
- `docs/baseline.md` — Original baseline (superseded)
- `docs/semantic_analysis.md` — Semantic feature documentation
- `docs/phishout_hybrid_model.md` — Hybrid model documentation

---

## 23. Project Configuration

### Model Files

- `backend/models/structural_only_model.pkl` — Current structural model
- `backend/models/structural_only_scaler.pkl` — Structural feature scaler
- `backend/models/hybrid_phishout_model.pkl` — Experimental hybrid (legacy)
- `backend/models/semantic_only_model.pkl` — Experimental semantic (legacy)

### Dataset Files

- `backend/dataset/clean_urls.csv` — Legacy small dataset (250 URLs)
- `backend/dataset/hybrid_features.csv` — Legacy hybrid features
- `backend/dataset/phreshphish/` — Legacy PhreshPhish checkpoints

### Configuration Files

- `backend/config/semantic_rules.py` — Fusion weights and thresholds
- `backend/requirements.txt` — Python dependencies

---

## 24. Success Criteria

**Project Completion Requirements:**

1. ✅ Phish360 dataset inspected and loaded
2. ✅ Leakage-safe train/validation/test splits created
3. ✅ 32 structural + 12 semantic features extracted
4. ✅ Structural, semantic, and hybrid models trained
5. ✅ Fusion calibrated (not hand-picked weights)
6. ✅ E1–E3 evaluations completed; E4 feasibility audited and closed
7. ✅ Results documented and reproducible

**Stretch Goals (Optional):**

- E5–E7 adversarial robustness evaluation, only if raw HTML is restored
- Webpage-level attack simulation
- Adversarial training implementation

---

## 25. Contact and Support

**Project Repository:** PhishOut — Adversarially Robust Phishing Webpage Detection

**Research Focus:** Feature-level robustness following IEEE 2025 methodology

**Base Paper:** "An Optimized Machine Learning Framework for Phishing Website Detection Integrating Feature Robustness and Adversarial Resilience Ranking" (IEEE, 2025)

**For questions about implementation:** Refer to this PROJECT_PLAN.md first, then architecture documentation.

---

**END OF PROJECT PLAN**
