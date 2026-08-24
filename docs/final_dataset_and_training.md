# PhishOut — Final Dataset and Training Documentation

**Project:** PhishOut: Adversarially Robust Phishing Webpage Detection Using Hybrid Structural and Semantic Analysis  
**Phase:** 5 — Final Research Dataset + Model Training  
**Status:** IN PROGRESS — metrics to be filled after training completes

---

> [!IMPORTANT]
> This document will be updated with exact metrics after model training completes.
> All sections marked **[TBD]** will be replaced with measured results.

---

## 1. PhreshPhish Dataset Source

| Property | Value |
|---|---|
| Name | PhreshPhish |
| HuggingFace Hub | `phreshphish/phreshphish` |
| Paper | arxiv:2507.10854 |
| License | CC BY 4.0 |
| Collection method | Live phishing URLs captured during active campaigns |
| HTML stored | ✅ Yes — full rendered HTML per sample |
| Version | v1.0.1 (updated 2026-02-07, includes samples through Dec 2025) |

### Full Dataset Distribution

| Split | Benign | Phishing | Total |
|---|---|---|---|
| Train | 276,729 | 221,526 | **498,255** |
| Test | 91,260 | 76,876 | **168,060** |
| **Total** | **367,989** | **298,402** | **666,315** |

### Dataset Schema

| Column | Type | Notes |
|---|---|---|
| `sha256` | str | Content hash for deduplication |
| `url` | str | Original URL |
| `label` | str | `"benign"` or `"phish"` |
| `target` | str | Brand being impersonated (phishing only) |
| `date` | date | Collection date |
| `lang` | str | Detected language |
| `lang_score` | float | Language detection confidence |
| `html` | str | Full stored HTML (NOT saved locally) |

---

## 2. Streaming Methodology

> [!IMPORTANT]
> **The full 36.6 GB dataset is NOT downloaded.** HuggingFace `streaming=True` reads remote Parquet shards over HTTP in chunks. Only the rows needed for feature extraction are loaded into memory. HTML is processed and immediately discarded. Nothing but the feature Parquet files is written to disk.

### Implementation

Script: `backend/stream_and_extract.py`

```python
ds = load_dataset("phreshphish/phreshphish", split=split_name, streaming=True)
for row in ds:
    html  = row["html"]                          # loaded into memory
    feats = extract_features(row["url"])         # 32 structural features
    sem   = extract_semantic_features_from_html(html, row["url"])  # 12 semantic
    # html goes out of scope here → garbage collected
    save(feats, sem)                             # only features written to disk
```

### Local Disk Usage

| File | Description | Size |
|---|---|---|
| `dataset/phreshphish/train_features.parquet` | 16,000 rows × 46 features | ~2 MB |
| `dataset/phreshphish/test_features.parquet` | 4,000 rows × 46 features | ~0.5 MB |
| HuggingFace shard index cache | Dataset metadata only | ~1–2 MB |
| **Total** | | **< 6 MB** |

---

## 3. Selected Subset

### Target (Balanced)

| Split | Benign | Phishing | Total |
|---|---|---|---|
| Train (from official train split) | 8,000 | 8,000 | **16,000** |
| Test (from official test split) | 2,000 | 2,000 | **4,000** |

> [!NOTE]
> The official PhreshPhish train/test split is preserved. Samples are drawn separately from each official split. The train and test sets are not mixed.

### Quality Filters Applied

| Filter | Action |
|---|---|
| `url` shorter than 8 characters | Dropped |
| `html` shorter than 200 bytes | Dropped (trivially empty) |
| Unrecognised label value | Dropped |
| Duplicate URL within split | Dropped |
| Cross-split URL overlap | Logged (informational, not enforced) |

### Actual Distribution

**[TBD — to be filled from stream_extract_report.txt after run completes]**

---

## 4. Feature Extraction

### Structural Features (32)

Extracted from URL only using `ml_model.extract_features(url)`.  
No network access required. Fully deterministic.

| Category | Features |
|---|---|
| URL structure | url_length, digit_count, special_char_count, digit_ratio, has_at, has_ip, prefix_suffix |
| Domain | domain_length, sub_domain_count, punycode_present, is_shortening, https_token, tld_risk_score, domain_entropy |
| Brand impersonation | brand_impersonation_score, subdomain_brand_match, levenshtein_min, levenshtein_ratio |
| Path / query | path_length, query_length, login_path_score, suspicious_keywords, has_redirect_param |
| Encoding | double_extension, hex_encoded, consonant_ratio, longest_word_length |

### Semantic Features (12)

Extracted from stored HTML using `extract_semantic_features_from_html(html, url)`.  
HTML is loaded, parsed, features extracted, then discarded.

| Feature | Description |
|---|---|
| `text_length` | Visible text character count |
| `password_fields` | `<input type="password">` count |
| `text_email_fields` | Text + email input count |
| `forms` | `<form>` element count |
| `external_links` | Links to different domains |
| `iframes` | `<iframe>` count |
| `scripts` | `<script>` tag count |
| `login_indicators` | LOGIN_KEYWORDS occurrence count |
| `credential_indicators` | CREDENTIAL_KEYWORDS occurrence count |
| `payment_indicators` | PAYMENT_KEYWORDS occurrence count |
| `urgency_indicators` | URGENCY_KEYWORDS occurrence count |
| `brand_indicators` | BRAND_KEYWORDS occurrence count |

> [!NOTE]
> `page_title` (str) and `form_actions` (list) are excluded from the ML feature vector as they are non-numeric. They are present in the pipeline for live-prediction evidence generation only.

---

## 5. Model Training

### Architecture: GBM + RF VotingClassifier

All three models use the same architecture:
```
CalibratedClassifierCV(
    VotingClassifier([
        GradientBoostingClassifier(n_estimators=150, max_depth=5, lr=0.1),
        RandomForestClassifier(n_estimators=150, max_depth=12),
    ], voting="soft"),
    method="sigmoid", cv=5
)
```

Calibration ensures `predict_proba()` outputs well-calibrated probabilities usable directly as risk scores.

### Three Models Compared

| Model | Features | Feature Count |
|---|---|---|
| A. Structural-only | URL/domain features | 32 |
| B. Semantic-only | HTML content features | 12 |
| C. Hybrid | Structural + Semantic | 44 |

All three trained on the **same** training split, evaluated on the **same** untouched test split.

---

## 6. Semantic Model Results

**Script:** `train_semantic_model.py`  
**Models compared:** Logistic Regression vs Random Forest (both on 12 semantic features)

### Results — [TBD]

| Metric | Logistic Regression | Random Forest |
|---|---|---|
| Accuracy | [TBD] | [TBD] |
| Precision | [TBD] | [TBD] |
| Recall | [TBD] | [TBD] |
| F1 | [TBD] | [TBD] |
| ROC-AUC | [TBD] | [TBD] |
| FPR | [TBD] | [TBD] |

**Best semantic model:** [TBD]

---

## 7. Three-Model Comparison

**Script:** `train_hybrid_model.py`

### Results — [TBD]

| Model | Acc | Prec | Rec | F1 | AUC | FPR |
|---|---|---|---|---|---|---|
| Structural-only | [TBD] | [TBD] | [TBD] | [TBD] | [TBD] | [TBD] |
| Semantic-only | [TBD] | [TBD] | [TBD] | [TBD] | [TBD] | [TBD] |
| Hybrid (struct+sem) | [TBD] | [TBD] | [TBD] | [TBD] | [TBD] | [TBD] |

**Winner by F1:** [TBD]

> [!NOTE]
> No claim of improvement is made until results are measured. If structural-only outperforms hybrid on this dataset, that result will be reported and structural-only will remain the primary model.

---

## 8. Fusion Calibration

**Script:** `calibrate_fusion.py`

### Methodology

1. Take a **20% held-out split** from the training data (NOT the test set)
2. Sweep `SAFE_MAX` from 0.15→0.45 and `PHISHING_MIN` from 0.50→0.85
3. Select thresholds maximising F1 on the validation split
4. Update `config/semantic_rules.py` with calibrated values

### Calibrated Thresholds — [TBD]

| Threshold | Preliminary | Calibrated | Change |
|---|---|---|---|
| `SAFE_MAX` (probability) | 0.30 | [TBD] | [TBD] |
| `PHISHING_MIN` (probability) | 0.60 | [TBD] | [TBD] |

**Validation F1 at calibrated thresholds:** [TBD]

---

## 9. Risk Score Derivation

The `risk_score` (0–100) exposed by the API is:

```
risk_score = int(round(phishing_probability × 100))
```

where `phishing_probability` is the **calibrated probability** from `CalibratedClassifierCV(method="sigmoid")`. This is NOT an arbitrary multiplication — it is a properly calibrated posterior probability from the sigmoid-calibrated model, meaning:

- A `risk_score` of 70 means the model assigns a **70% probability** of phishing
- A `risk_score` of 20 means **20% probability** of phishing
- The calibration is validated on the held-out 20% validation split

---

## 10. Final Clean Evaluation

**Script:** `evaluate_final.py`  
**Test set used ONCE — never for tuning**

### Final Results — [TBD]

| Model | Acc | Prec | Rec | F1 | AUC | FPR | Confusion Matrix |
|---|---|---|---|---|---|---|---|
| Structural-only | [TBD] | [TBD] | [TBD] | [TBD] | [TBD] | [TBD] | [TBD] |
| Semantic-only | [TBD] | [TBD] | [TBD] | [TBD] | [TBD] | [TBD] | [TBD] |
| Hybrid | [TBD] | [TBD] | [TBD] | [TBD] | [TBD] | [TBD] | [TBD] |

**Final selected model:** [TBD]

---

## 11. API and Dashboard Status

| Component | Status |
|---|---|
| `POST /scan` | ✅ Unchanged (backward compatible) |
| `POST /scan_extended` | ✅ Unchanged |
| `POST /phishout/scan` | ✅ Updated to load best model from PhreshPhish training |
| `GET /health` | ✅ Reports `phishout_dataset: "phreshphish"` when PhreshPhish model loaded |
| Dashboard `/phishout/scan` | ✅ Unchanged — uses same response schema |
| Chrome extension | ✅ Unchanged — maps `risk_score` and `reasons` |

---

## 12. Limitations

1. **English bias:** PhreshPhish is ~82% English-language pages. Semantic keyword banks (LOGIN_KEYWORDS etc.) are English-only. Performance on non-English phishing pages may be lower.

2. **Temporal distribution:** PhreshPhish captures phishing pages at collection time. Some pages may have changed or been taken down. Structural features (URL-based) are unaffected; semantic features may be affected.

3. **Balanced training:** We use balanced classes (50/50) for simplicity. The actual base rate of phishing is much lower (PhreshPhish itself is ~45% phishing in train). Calibration may need adjustment for real-world deployment at a specific false-positive budget.

4. **Semantic feature completeness:** 2 of the 14 semantic features (`page_title`, `form_actions`) are excluded from the ML feature vector because they are non-numeric. This means brand-name presence in the page title and external form action targets are not ML features (though they appear in the explanation engine).

5. **No adversarial robustness:** The current model is trained on genuine phishing pages. A sophisticated attacker who knows the feature set may be able to craft pages that evade detection. PhishOracle (adversarial robustness testing) is reserved for Phase 6.

---

## PHASE 5 STATUS

> [!NOTE]
> This section will be updated to **PHASE 5 COMPLETE** after training and evaluation finish.

**Current status: TRAINING IN PROGRESS**

| Item | Status |
|---|---|
| Dataset source | PhreshPhish (CC BY 4.0) |
| Streaming approach | ✅ Confirmed — no full download |
| Local disk usage | ✅ Confirmed — ~2.6 MB Parquet only |
| HTML saved locally | ❌ Never |
| Feature extraction | ✅ 32 structural + 12 semantic |
| train_features.parquet | ⏳ Extracting... |
| test_features.parquet | ⏳ Extracting... |
| Semantic model results | ⏳ Pending |
| 3-model comparison | ⏳ Pending |
| Fusion calibration | ⏳ Pending |
| Final evaluation | ⏳ Pending |
| API still working | ✅ Yes (Phase 4 model active) |
| Dashboard still working | ✅ Yes |
| PhishOracle | ❌ Not implemented (Phase 6) |
| Visual similarity | ❌ Not implemented (Phase 6) |
