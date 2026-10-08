# PhishOut V3 — Read-Only Audit & Research Design

## Overview

This document covers the complete read-only audit of the V2 pipeline, the root-cause analysis of the false-positive problem, an honest data-availability assessment, and the proposed V3 experiment design.

**No model changes have been made. This is a pre-implementation plan for review.**

---

## Audit Findings

### 1. V2 Training Pipeline

**Data flow:**
```
Phish360 Parquet (raw HTML + URL)
    → phish360_v2_feature_extractor.py    [32 struct + 15 sem features]
    → dataset/phish360/v2/processed/      [train/val/test .parquet]
    → train_phish360_v2_structural.py     [GBM+RF VotingClassifier, calibrated]
    → train_phish360_v2_semantic.py       [GBM+RF VotingClassifier, calibrated]
    → train_phish360_v2_fusion.py         [LogisticRegression on val set probabilities]
    → calibrate_phish360_v2_thresholds.py [Grid search on val set, F1-maximized]
```

**Key procedural observation:**
The fusion model is **trained on the validation set** (not the training set). This is the standard "meta-learner" approach — valid, but it means:
- The fusion LR has seen the validation set labels during training
- The validation set cannot serve as a truly independent evaluation
- Threshold calibration **also** uses the validation set → double use

This is a known limitation of the current pipeline. V3 should address this with a **3-way split**: train → semantic/structural models, val → fusion model, **separate held-out val2** → threshold calibration. But the test set remains untouched.

---

### 2. V2 Feature Extractor

**Architecture (phish360_v2_feature_extractor.py):**
- 32 structural features extracted from URL string via `ml_model.extract_features()`
- 15 semantic features extracted from stored HTML via `extract_semantic_features_from_html()`
- 3 V2 context features: `domain_brand_consistency`, `form_action_same_origin`, `trusted_domain`
- Leakage-free domain-stratified split via `LeakageValidator`

**Critical finding:** The V2 feature extractor writes features for ALL samples including ones **without HTML** (it sets semantic features to 0). The parquet has `html_available` column to track this.

---

### 3. V2 Semantic/Context Features — Root Cause Analysis

**Feature distributions (training set):**

| Feature | Legit mean | Phish mean | Ratio | Note |
|---------|-----------|-----------|-------|------|
| `password_fields` | 0.120 | 0.743 | **6.21×** | Best discriminator |
| `credential_indicators` | 0.941 | 2.049 | 2.18× | Good |
| `login_indicators` | 3.594 | 4.988 | 1.39× | Weak |
| `brand_indicators` | 2.955 | 2.386 | **0.81×** | ⚠️ Reversed — legit pages mention MORE brands |
| `urgency_indicators` | 1.550 | 0.338 | **0.22×** | ⚠️ Reversed — legit pages use more urgency language |
| `external_links` | 27.449 | 11.363 | **0.41×** | ⚠️ Reversed — legit pages have more external links |
| `scripts` | 23.677 | 10.102 | **0.43×** | ⚠️ Reversed — legit pages have more scripts |
| `text_length` | 8111 | 1397 | **0.17×** | ⚠️ Reversed — legit pages are longer |
| `domain_brand_consistency` | 0.564 | 0.574 | 1.02× | Nearly identical — not discriminating |
| `form_action_same_origin` | 0.861 | 0.892 | 1.04× | Nearly identical — not discriminating |
| `trusted_domain` | 0.002 | 0.020 | **10.29×** | ⚠️ Backwards — phishing sites appear MORE trusted |

> **⚠️ Critical finding:** The `trusted_domain` feature is **backwards** for legitimate large sites. The TRUSTED_BRAND_DOMAINS dictionary only covers ~20 brands. Sites like paypal.com, google.com, microsoft.com ARE in the list and correctly get `trusted_domain=1.0`. But because phishing samples in Phish360 include phishing sites **hosted on Google Sites, Microsoft Forms, etc.**, they ALSO get `trusted_domain=1.0`. This means the feature fires MORE for phishing in training (2.0% vs 0.2% for legit), causing the model to learn `trusted_domain=1 → slightly more suspicious`.

**False-positive anatomy (V2 test set, FPR=2.64%, 25 FP samples):**

| Feature | FP mean | TN mean | Ratio |
|---------|---------|---------|-------|
| `password_fields` | 0.720 | 0.095 | **7.5×** |
| `p_sem` | 0.815 | 0.056 | **14.5×** |
| `p_struct` | 0.433 | 0.135 | **3.2×** |
| `login_indicators` | 4.360 | 3.163 | 1.4× |

**Conclusion:** False positives are driven almost entirely by **high `p_sem`** (0.815 vs 0.056), which is itself driven by **password fields** (0.72 vs 0.095). The V2 legitimate samples that appear as FPs look semantically like phishing because they have real login forms with password inputs.

**Runtime observation:** Google/Microsoft/PayPal score p_sem ≈ 0.85–0.95. Their live HTML is richer and more login-dense than dataset snapshots.

---

### 4. V2 Model Architecture

| Component | Architecture | Training data | Notes |
|-----------|-------------|--------------|-------|
| Structural | GBM(300)+RF(200) VotingClassifier + Sigmoid calibration | Train set (7,730 samples) | |
| Semantic | GBM(300)+RF(200) VotingClassifier + Sigmoid calibration | Train set (7,730 samples) | |
| Fusion | Logistic Regression | **Validation set** (1,317 samples) | Meta-learner |
| Threshold | Grid search F1-max | **Validation set** (1,317 samples) | PHISHING_MIN=45 |

---

### 5. Train/Val/Test Splits

| Split | N | Legit | Phish | Use |
|-------|---|-------|-------|-----|
| Train | 7,730 | 4,660 (60.3%) | 3,070 (39.7%) | Train struct + sem models |
| Validation | 1,317 | 809 (61.4%) | 508 (38.6%) | Train fusion + calibrate thresholds |
| Test | 1,701 | 947 (55.7%) | 754 (44.3%) | Final evaluation only |

Splits are **domain-stratified** (registered-domain level) using `leakage_validator.py`. No URL or domain overlap confirmed.

---

### 6. Class Distribution

Overall Phish360 dataset:
- Phishing: 4,332 samples — **all 4,332 have HTML**
- Legitimate: 6,416 samples — **all 6,416 have HTML**
- Total: 10,748 samples

Phish360 Parquet columns: `dataset_name`, `folder_name`, `Class`, `brand`, `URL`, `TLD`, `Domain`, `full_html`, `BeautifulSoup_text`, etc.

---

### 7. Frozen E1–E7 Artifacts

**Confirmed intact at:** `backend/models/phish360/`
- `structural_model.pkl`, `structural_scaler.pkl`, `structural_results.json`
- `semantic_model.pkl`, `semantic_scaler.pkl`, `semantic_results.json`
- `fusion_model.pkl`, `fusion_config.json`, `fusion_results.json`
- `hybrid_model.pkl`, `hybrid_scaler.pkl`, `hybrid_results.json`
- `threshold_config.json`, `final_evaluation_results.json`
- `e5/`, `e6/`, `e7/`, `robustness/` subdirectories

**Git diff confirms zero changes to these files since the frozen commit.**

---

### 8. Runtime False-Positive Diagnostic

From the live runtime sanity check:

| URL | semantic_score | structural_score | Verdict | V2 context |
|-----|------------|--------------|---------|-----------|
| google.com | 85 | 4 | PHISHING | dbc=1, faos=1, td=1 |
| microsoft.com | 87 | 3 | PHISHING | dbc=1, faos=1, td=1 |
| gemini.google.com | 95 | 4 | PHISHING | dbc=1, faos=1, td=1 |
| wikipedia.org | 3 | 3 | **SAFE** | dbc=0, faos=1, td=0 |
| paypal.com | 87 | 3 | PHISHING | dbc=1, faos=1, td=1 |

**Observation:** All 3 context features are 1.0 for the FP sites, meaning they ARE correctly identified as trusted. Yet the model still produces PHISHING. This means the V2 context features do not have sufficient weight in the fusion model to override the high `p_sem`.

The semantic model is **primarily driven by login/payment/password indicators** that are abundant on legitimate auth pages. The 3 context features cannot compensate because they have weak individual discriminative power (near-zero separation in the training set as shown above).

---

### 9. Backend Predictor

**Current state (post-integration audit fix):**
- Loads from `backend/models/phish360_v2/`
- SEMANTIC_KEYS: 15 features, correct ordering
- struct_scaler: 32f ✅, sem_scaler: 15f ✅
- fusion_mode: `"phish360_v2_learned_fusion"` ✅
- No V1/V2 mismatch

---

## Data Availability Assessment for Hard Negatives

### What we have (no downloads needed)

**Phish360 Parquet (`D:/Downloads/phish360_parquet/`):**

| File | Samples | HTML available |
|------|---------|---------------|
| `Phish360_legit.parquet` | 6,416 | **6,416 (100%)** |
| `Phish360_phish.parquet` | 4,332 | **4,332 (100%)** |

The legitimate parquet contains **stored full HTML** for ALL 6,416 legitimate pages. The `brand` column identifies the brand each page is associated with.

**Sampling from 200 legit pages showed:**
- 73/200 (36.5%) contain "login"
- 36/200 (18%) contain "password"
- 100/200 (50%) contain "account"
- 24/200 (12%) contain "signin"

This means a substantial fraction of the legitimate dataset is **already composed of legitimate auth/login/account pages** — exactly the hard-negative category we need.

**The hard-negative data already exists within Phish360's legit split.**

---

## V3 Research Design

### Core Hypothesis

The V2 false-positive problem is caused by the semantic model having **no way to distinguish between**:
1. A phishing page that mimics a login page
2. A real login page on a legitimate domain

Both have: password fields, login indicators, credential indicators, brand mentions, forms. The V2 context features attempt to address this but have insufficient discriminative power because the training set's legitimate pages are **not representative enough of hard-negative authentication pages**.

**V3 Hypothesis:** If we enrich the semantic model's training set with **hard-negative legitimate auth/login/payment pages** (drawn from the Phish360 legitimate HTML that already exists on disk), the model will learn to distinguish these two categories.

### What V3 Will Do

**V3 is a single focused experiment:**

1. **Identify hard-negative samples** within the existing Phish360 legit HTML pool
2. **Augment the training set** with an upsampled subset of these hard-negative legit pages
3. **Add 5 new V3 features** that better capture contextual legitimacy signals
4. **Retrain the semantic and fusion models** with the augmented dataset
5. **Evaluate strictly** on the original untouched test set + a separate hard-negative evaluation split

### V3 Feature Engineering (5 New Features)

> [!IMPORTANT]
> These features address the core gap: the model needs to measure "how much does this page look like a real login page on a real domain" vs "how much does it look like a credential harvester".

| Feature | Description | Why |
|---------|------------|-----|
| `link_to_form_ratio` | `external_links / (forms + 1)` | Real login pages have few external links relative to forms; phishing cloaking sites have many external links |
| `text_to_script_ratio` | `text_length / (scripts + 1)` | Legitimate pages are content-rich; phishing pages are script-heavy relative to content |
| `credential_density` | `(password_fields + credential_indicators) / (text_length/1000 + 1)` | Normalizes credential signals by page richness |
| `brand_context_score` | Combines `domain_brand_consistency × trusted_domain + (1 - brand_indicators/(brand_indicators+10)) × form_action_same_origin` | Rewards pages where brand/domain/form all align as legitimate |
| `structural_semantic_alignment` | Binary: 1 if structural_score > 50 AND p_sem > 0.5 (BOTH suspicious), 0 otherwise | When used in fusion, discriminates from "legit page with auth content" where structural is clean |

> [!NOTE]
> `structural_semantic_alignment` is only available at the fusion level (it requires both model scores). The other 4 are page-content features extractable from HTML.

**Total V3 semantic features: 15 + 4 = 19** (content-level only; `structural_semantic_alignment` is fusion-level)

### Hard-Negative Extraction Methodology

From the **Phish360 legit split only** (no external data):

1. Load `Phish360_legit.parquet`
2. Filter samples where HTML contains ANY of: `password`, `login`, `signin`, `authenticate`, `oauth`
3. From those, sample to create a **hard-negative pool** of ~800–1,200 samples
4. These are labelled as `0` (legitimate) — their true labels
5. Hard-negative pool is **split separately** from the main train/val/test:
   - Hard-negative train: 60% (mixed into V3 training set)
   - Hard-negative val: 20% (for fusion calibration)
   - Hard-negative eval: 20% (held out, never seen during training)

> [!IMPORTANT]
> Data leakage rules:
> - Hard-negative samples drawn from legitimate HTML already in train split → permitted (same domain stratification applies)
> - Hard-negative samples drawn from legitimate HTML in the test split → **prohibited**
> - No sample from the hard-negative eval set is used during training or threshold calibration
> - URL provenance is recorded per sample (sample_id from Phish360 parquet)

### Training Protocol

```
V2 frozen baseline:
  → Struct: GBM+RF on train_7730
  → Semantic: GBM+RF on train_7730
  → Fusion: LR on val_1317
  → Threshold: grid-search on val_1317

V3 new pipeline:
  → Struct: GBM+RF on train_7730 (UNCHANGED from V2 — structural model is not the problem)
  → Semantic V3: GBM+RF on (train_7730 + hard_neg_train_N) with 19 features
  → Fusion V3: LR on val_1317 (UNCHANGED split — for comparability)
  → Threshold V3: grid-search on val_1317 (UNCHANGED split)
```

> [!NOTE]
> The structural model is NOT retrained for V3. The false positive problem is purely in the semantic layer (p_sem drives FPs). Keeping the structural model identical eliminates one variable.

### Directory Structure

```
backend/models/phish360_v3/
    structural_model.pkl        ← symlink or copy from phish360_v2 (unchanged)
    structural_scaler.pkl       ← copy from phish360_v2 (unchanged)
    semantic_model.pkl          ← V3 retrained
    semantic_scaler.pkl         ← V3 new
    fusion_model.pkl            ← V3 retrained
    fusion_config.json          ← V3
    threshold_config.json       ← V3 calibrated
    semantic_results.json       ← V3 results
    fusion_results.json         ← V3 results
    hybrid_results.json         ← V3 combined metrics
    v3_vs_v2_comparison.json    ← comparison report
    hard_negative_manifest.csv  ← provenance of all hard-negative samples

backend/dataset/phish360/v3/
    processed/
        train_features.parquet      ← V3 training set (augmented with hard-negatives)
        validation_features.parquet ← same as V2 validation (same split)
        test_features.parquet       ← same as V2 test (same split, untouched)
        hard_neg_eval.parquet       ← held-out hard-negative evaluation set
    hard_negatives/
        hard_neg_manifest.csv       ← sample_id, url, label=0, extraction_date, filter_criteria
```

### Evaluation Plan

**Evaluate V2 and V3 on ALL of the following:**

**A. Original Phish360 test set (n=1,701, unchanged):**
- Accuracy, Precision, Recall, F1, ROC-AUC, FPR, FNR
- Confusion matrix

**B. Hard-negative evaluation set (held-out legit auth pages):**
- False positive rate on hard negatives specifically
- This is the primary V3 success metric

**C. Phish360 test set phishing-only:**
- Recall on phishing specifically (must not regress)

**D. Runtime sanity check (qualitative only, not for tuning):**
- google.com, microsoft.com, gemini.google.com, paypal.com, wikipedia.org
- Document verdicts and scores — do not use these to change anything

### Success Criteria

V3 is declared an improvement if AND ONLY IF:

| Criterion | Threshold |
|-----------|-----------|
| FP rate on hard-negative eval | **< V2 rate on same set** |
| F1 on Phish360 test | **≥ V2 F1 − 0.005 (within 0.5%)** |
| Recall on phishing (Phish360 test) | **≥ V2 recall − 0.01 (within 1%)** |
| No test-set leakage | Confirmed by LeakageValidator |

If any criterion fails: **keep V2 as production model**, document V3 as a negative result.

### Application Integration

V3 is integrated into the backend **only after** research comparison confirms V3 wins. Until then:
- V2 remains the active model
- V3 runs in a separate directory
- Rollback to V2 is a one-line path change in `phishout_predictor.py`

---

## Open Questions

> [!IMPORTANT]
> **Q1: Hard-negative pool size.** The 200-sample scan showed ~36% of legit pages contain "login". From the full 6,416 legit samples, this suggests ~2,300+ hard negatives are available. We should use all that pass the filter, with domain-stratified sampling to avoid overrepresenting any single brand. **Your call on whether to use all ~2,300 or cap at a fixed number (e.g., 1,200) to keep augmentation bounded.**

> [!IMPORTANT]
> **Q2: Structural model.** V3 plan keeps the structural model frozen from V2. The rationale: FPs are driven by p_sem (14.5× higher in FPs vs TNs), not p_struct (3.2×). However, we could also re-examine whether retraining the structural model with a higher regularization or different class weight could help. **Do you want to retrain structural too, or only the semantic model?**

> [!NOTE]
> **Q3: Fusion model architecture.** The current LR fusion is minimal. V3 could experiment with a calibrated GBM fusion or add the `structural_semantic_alignment` feature directly at the fusion level. This is a small change but could help the fusion discriminate from cases where structural is clean but semantic is high (legitimate auth pages). **Include or exclude?**

> [!NOTE]
> **Q4: Should V3 include a separate threshold optimization objective?** Currently V2 maximizes F1. For V3, we could optimize `F-beta (beta=0.5)` which weights precision more heavily (fewer FPs). This directly targets the stated problem. Trade-off: recall may drop. **Use F1 or F-beta?**

---

## Proposed Implementation Steps (pending approval)

- `[ ]` **Step 1:** Extract hard-negative samples from Phish360 legit HTML (filter by auth keywords), record provenance manifest
- `[ ]` **Step 2:** Extract V3 features (19 semantic) for full train+val+test + hard-negative pool
- `[ ]` **Step 3:** Build augmented V3 training set (original train + hard-neg train split)
- `[ ]` **Step 4:** Train V3 semantic model (GBM+RF, same architecture as V2)
- `[ ]` **Step 5:** Train V3 fusion model (on validation set)
- `[ ]` **Step 6:** Calibrate V3 thresholds (on validation set)
- `[ ]` **Step 7:** Evaluate V3 vs V2 on test set + hard-neg eval set
- `[ ]` **Step 8:** Write V3 research report
- `[ ]` **Step 9:** Integrate V3 into application (only if V3 wins)
- `[ ]` **Step 10:** Final verification (frozen artifacts, no leakage, feature ordering)

---

## What V3 Will NOT Do

- ❌ Whitelist google.com, microsoft.com, or any specific domain
- ❌ Hard-code any site as safe
- ❌ Tune based on the runtime observations (Google/PayPal FPs)
- ❌ Modify V1 E1–E7 frozen artifacts
- ❌ Overwrite V2 models
- ❌ Use external data without provenance
- ❌ Fabricate HTML or label data
- ❌ Claim success without quantitative evidence
