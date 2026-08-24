# PhishOut Architecture Documentation

**PhishOut: Adversarially Robust Phishing Webpage Detection Using Hybrid Structural and Semantic Analysis**

Version: 4.0.0 | Status: Architecture Complete — Pending Final Dataset

---

> [!IMPORTANT]
> **Calibration Notice:** All semantic scoring weights, fusion parameters, and verdict thresholds in this document are **preliminary**. They are based on academic references and conservative expert judgement. They will be calibrated and evaluated using the final research dataset before publication. See `config/semantic_rules.py` for full documentation of each value.

---

## 1. Overall Architecture

```
                         URL
                          │
           ┌──────────────┴──────────────┐
           ▼                             ▼
  Structural Analysis            Webpage Analysis
  ml_model.analyze_structural()  webpage_analyzer.fetch_webpage()
  32 URL/domain features         webpage_analyzer.extract_semantic_features()
           │                             │
           ▼                             ▼
  Structural Signal              Semantic Signal
  structural_score (0–100)       semantic_score (0–100)
  structural_evidence[]          semantic_evidence[]
           │                             │
           └──────────────┬──────────────┘
                          ▼
                    Fusion Layer
                phishout_fusion.fuse_scores()
                          │
                          ▼
                  PhishOut Score
                     0–100
                          │
           ┌──────────────┴──────────────┐
           ▼                             ▼
        Verdict                    Explanations
 SAFE / SUSPICIOUS /         explanation_engine.generate_explanations()
      PHISHING                 ordered, evidence-grounded list
```

### Pipeline Steps (phishout_predictor.py)

| Step | Operation | Module |
|---|---|---|
| 1 | Validate + normalise URL | `phishout_predictor._normalise_url()` |
| 2 | Run structural analysis | `ml_model.analyze_structural()` |
| 3 | Fetch webpage HTML | `webpage_analyzer.fetch_webpage()` |
| 4 | Extract semantic features | `webpage_analyzer.extract_semantic_features()` |
| 5 | Generate semantic evidence | `webpage_analyzer.generate_semantic_evidence()` |
| 6 | Inject compound flags | `phishout_predictor._inject_compound_flags()` |
| 7 | Calculate semantic score | `phishout_fusion.calculate_semantic_score()` |
| 8 | Fuse scores | `phishout_fusion.fuse_scores()` |
| 9 | Assign verdict | `phishout_fusion.assign_verdict()` |
| 10 | Generate explanations | `explanation_engine.generate_explanations()` |

---

## 2. Structural Component

**Module:** `backend/ml_model.py`  
**Interface:** `analyze_structural(url, model, scaler)`

Extracts 32 engineered URL/domain features and runs the trained Random Forest + GBM ensemble.

### Feature Categories

| Category | Features |
|---|---|
| URL structure | `url_length`, `digit_count`, `special_char_count`, `digit_ratio`, `has_at`, `has_ip`, `prefix_suffix` |
| Domain | `domain_length`, `sub_domain_count`, `punycode_present`, `is_shortening`, `https_token`, `tld_risk_score`, `domain_entropy` |
| Brand impersonation | `brand_impersonation_score`, `subdomain_brand_match`, `levenshtein_min`, `levenshtein_ratio` |
| Path / query | `path_length`, `query_length`, `login_path_score`, `suspicious_keywords`, `has_redirect_param` |
| Encoding | `double_extension`, `hex_encoded`, `consonant_ratio`, `longest_word_length` |

### Interface

```python
result = analyze_structural(url, model=model, scaler=scaler)
# Returns:
{
  "features":             dict,   # 32 raw feature values
  "structural_score":     int,    # 0–100
  "phishing_probability": float,  # 0.0–1.0
  "structural_evidence":  list,   # human-readable signal strings
}
```

### Fallback

When no trained model is available, `_rule_based_prob()` produces a rule-based estimate from the most discriminative features (IP hostname, typosquatting, high-risk TLD, brand impersonation).

---

## 3. Semantic Component

**Module:** `backend/webpage_analyzer.py`

Separated into three explicit stages:

### Stage A — Fetch (`fetch_webpage`)

```python
html: str | None = fetch_webpage(url, timeout=10)
```

- Validates scheme (HTTP/HTTPS only)
- Sets browser-like headers to avoid bot rejection
- Enforces 1 MB content cap
- Returns `None` on any failure — caller must handle gracefully

### Stage B — Extract (`extract_semantic_features`)

```python
features: dict = extract_semantic_features(html, url)
```

Extracts 14 features from parsed HTML:

| Feature | Type | Description |
|---|---|---|
| `page_title` | str\|None | HTML `<title>` content |
| `text_length` | int | Visible text character count |
| `password_fields` | int | `<input type="password">` count |
| `text_email_fields` | int | text + email input count |
| `forms` | int | `<form>` element count |
| `form_actions` | list | Absolute URLs of form `action` attributes |
| `external_links` | int | Links to different domains |
| `iframes` | int | `<iframe>` count |
| `scripts` | int | `<script>` count |
| `login_indicators` | int | LOGIN_KEYWORDS occurrence count |
| `credential_indicators` | int | CREDENTIAL_KEYWORDS occurrence count |
| `payment_indicators` | int | PAYMENT_KEYWORDS occurrence count |
| `urgency_indicators` | int | URGENCY_KEYWORDS occurrence count |
| `brand_indicators` | int | BRAND_KEYWORDS occurrence count |

### Stage C — Evidence (`generate_semantic_evidence`)

```python
evidence: list[str] = generate_semantic_evidence(features, url, struct_features)
```

Generates human-readable evidence strings grounded only in detected feature values. Only reports signals that are actually present. Compound signals (e.g., brand mismatch) require corroboration from both structural and semantic features.

### Backward Compatibility

The `analyze_webpage(url, timeout)` function orchestrates all three stages and returns a unified dict compatible with Phase 2 callers. The `WebpageAnalyzer` class is a thin wrapper kept for backward compatibility.

---

## 4. Semantic Scoring

**Module:** `backend/phishout_fusion.py`  
**Config:** `backend/config/semantic_rules.py`

### Method

Rule-based additive scorer — no ML model for semantic scoring at this stage. This is intentional: a proper live-phishing dataset is needed before training a reliable semantic model.

### Weights (Preliminary)

| Signal | Weight | Rationale |
|---|---|---|
| Password field | 25 | Strongest single indicator of credential harvesting |
| External form action | 22 | Classic phishing — form posts to attacker server |
| Credential form | 15 | Form + credential keywords together |
| Urgency language | 12 | Psychological manipulation (Vishwanath 2011) |
| Payment content | 10 | Financial phishing indicator |
| High login content | 8 | Very dense login language on page |
| Brand mismatch | 8 | Brand on page + structural impersonation |
| Iframe present | 5 | Hidden content injection |
| High external links | 3 | Possible cloaking |
| Moderate login content | 3 | Weak signal alone |

Score is clamped to [0, 100]. Signals are additive.

> [!NOTE]
> **Calibration required:** These weights will be revised using ROC/PR analysis on the final research dataset.

---

## 5. Fusion Mechanism

**Module:** `backend/phishout_fusion.py`  
**Config:** `backend/config/semantic_rules.py` → `FUSION`

### Scenario A — Webpage Available

```
phishout_score = (0.60 × structural_score) + (0.40 × semantic_score)
```

Rationale: Structural features are trained on a labelled dataset (97.3% accuracy). Semantic features are rule-based and not yet validated on a live-phishing dataset. The 60/40 split reflects the relative confidence in each component at this stage.

### Scenario B — Webpage Unavailable

```
phishout_score = structural_score
```

When `fetch_webpage()` returns `None`, we fall back entirely to structural analysis. The response field `fusion_mode = "structural_only"` and the explanation always includes a note about unavailable semantic evidence.

### Configuration

All weights are in `config/semantic_rules.py`:
```python
FUSION = {
    "structural_weight_with_page":    0.60,
    "semantic_weight_with_page":      0.40,
    "structural_weight_without_page": 1.00,
    "semantic_weight_without_page":   0.00,
}
```

---

## 6. Risk Scoring

The final `risk_score` (0–100) is a continuous integer representing phishing risk:

| Range | Meaning |
|---|---|
| 0–29 | Low risk — SAFE |
| 30–59 | Moderate risk — SUSPICIOUS |
| 60–100 | High risk — PHISHING |

The score is monotonically related to the phishing probability from the structural model and the semantic rule engine. A score of 0 means both components found no indicators. A score of 100 means both components independently flag the URL as highly likely phishing.

---

## 7. Verdict Thresholds

**Config:** `backend/config/semantic_rules.py` → `VERDICT_THRESHOLDS`

```python
VERDICT_THRESHOLDS = {
    "SAFE_MAX":    30,   # risk_score < 30  → SAFE
    "PHISHING_MIN": 60,  # risk_score >= 60 → PHISHING
                         # 30 ≤ score < 60  → SUSPICIOUS
}
```

> [!WARNING]
> **These thresholds are PRELIMINARY.** They will be calibrated using ROC curve analysis on the final labelled dataset to optimise the trade-off between false positives (blocking legitimate sites) and false negatives (missing phishing sites). The research paper will report the calibrated thresholds and the resulting precision/recall/F1.

---

## 8. Explanation Engine

**Module:** `backend/explanation_engine.py`

### Design Principles

1. **Evidence-only:** Only reports signals that are actually detected in the URL or page. No invented or template-filled explanations.
2. **Ordered by confidence:** High-confidence signals (brand impersonation, external form action) appear first.
3. **Source-labelled:** Explanations are tagged as structural or semantic in the API response.
4. **No LLM:** Fully deterministic rule-based generation. Reproducible and auditable.

### Example Outputs

**Structural signals:**
- `"Domain closely resembles a known brand (impersonation score: 0.90, edit distance: 1)."`
- `"Very high-risk top-level domain (TLD risk score: 0.95)."`
- `"Typosquatting detected — domain is 1 edit distance from a known brand."`
- `"Hyphen used in domain name — common in phishing domains."`

**Semantic signals:**
- `"Password input field(s) detected on page (1)."`
- `"Form submits credentials to an external domain."`
- `"Strong urgency / deception language detected (5 occurrences)."`
- `"Brand name mentioned on page while domain appears to impersonate it."`

**Unavailability note:**
- `"Webpage could not be fetched — decision based primarily on URL structure."`

---

## 9. API Flow

**Server:** `backend/main.py` (FastAPI v4.0.0)

### `POST /phishout/scan`

```
Client → POST /phishout/scan { "url": "..." }
       → PhishOutPredictor.predict(url)
         1. structural analysis
         2. webpage fetch
         3. semantic extraction
         4. semantic scoring
         5. fusion
         6. verdict
         7. explanations
       → PhishOutResponse {
           risk_score, verdict,
           structural_score, semantic_score,
           webpage_analysis_available, fusion_mode,
           structural_analysis, structural_evidence,
           semantic_analysis, semantic_evidence,
           reasons, model_type, phishing_probability
         }
       → 200 OK
```

### `POST /scan` (UNCHANGED)

Returns the original `ScanResult` schema. Fully backward-compatible with dashboard v3, extension v3, and any existing API consumers.

### `POST /scan_extended` (UNCHANGED)

Returns structural scan + raw webpage analysis features. Unchanged from Phase 2.

### `GET /health`

```json
{
  "status": "online",
  "version": "4.0.0",
  "ml_model_loaded": true,
  "phishout_model": "structural_only",
  "phishout_ready": true,
  "endpoints": ["/scan", "/scan_extended", "/phishout/scan"],
  "pipeline_components": { ... }
}
```

---

## 10. Failure Handling

| Failure | Behaviour |
|---|---|
| URL has no scheme | `http://` prepended automatically |
| Invalid URL (no domain) | HTTP 400 returned |
| Webpage fetch timeout | `webpage_analysis_available=false`, structural-only fusion |
| Webpage returns non-HTML | Same as fetch timeout |
| Webpage > 1 MB | Download capped at 1 MB and processed |
| ML model not found | Rule-based structural scoring used, clearly logged |
| Semantic scorer exception | Score defaults to 0; exception logged; pipeline continues |
| Structural model exception | Rule-based fallback; response `model_type="rule_based"` |
| PhishOut predictor crash | HTTP 500 with descriptive error message |

---

## 11. Current Limitations

1. **Semantic model is rule-based:** The semantic scorer uses manually crafted weights, not a trained classifier. This means it cannot automatically adapt to new phishing patterns and may have suboptimal precision/recall.

2. **No visual similarity:** Brand impersonation via screenshot comparison (favicon, logo detection) is not implemented. This is reserved for Phase 5.

3. **No WHOIS / domain age:** Domain registration age is a strong phishing indicator but requires an external API call. Not implemented to avoid external dependencies.

4. **Dataset asymmetry (known):** The Phase 3 experimental hybrid model performed poorly because ~88% of phishing URLs in the training set were unreachable. The current architecture uses the structural model (97.3% accuracy) as the primary signal, which avoids this issue.

5. **Fusion weights not calibrated:** The 60/40 structural/semantic weight is a principled starting point, not a research result. Calibration requires a live-phishing dataset with fetchable pages.

6. **No caching layer:** Repeated scans of the same URL re-fetch the webpage. A simple TTL cache could improve throughput.

---

## 12. Future Model-Training Plan

### Phase 5A — Dataset Selection

Select a live-phishing dataset where phishing pages are actually reachable (e.g., PhreshPhish, OpenPhish live snapshots, or a controlled crawl during an active phishing campaign window).

Criteria:
- ≥ 1,000 labelled samples per class
- Semantic features extractable (pages fetchable)
- Domain-level train/test split

### Phase 5B — Semantic ML Model

Train a proper semantic classifier (e.g., Logistic Regression or lightweight gradient boosting on the 14 semantic features). Compare against the current rule-based scorer.

### Phase 5C — Fusion Calibration

Use Bayesian search or grid search to calibrate:
- `structural_weight` / `semantic_weight` split
- `SAFE_MAX` and `PHISHING_MIN` verdict thresholds
- Semantic signal detection thresholds

Evaluation: Precision, Recall, F1, ROC-AUC reported separately for the structural, semantic, and hybrid components.

### Phase 5D — PhishOracle (Adversarial Robustness)

Implement adversarial attack simulation to test whether the hybrid model is robust against a sophisticated attacker who knows the feature set. Reserved for Phase 5.

---

## File Map

```
backend/
├── ml_model.py                    # 32 structural features + analyze_structural()
├── webpage_analyzer.py            # fetch_webpage(), extract_semantic_features(),
│                                  #   generate_semantic_evidence(), analyze_webpage()
├── phishout_fusion.py             # calculate_semantic_score(), fuse_scores(),
│                                  #   assign_verdict()
├── explanation_engine.py          # generate_explanations()
├── phishout_predictor.py          # PhishOutPredictor (10-step orchestrator)
├── main.py                        # FastAPI app v4.0.0
├── test_phishout.py               # Sanity test suite
├── config/
│   ├── __init__.py
│   └── semantic_rules.py          # All weights, thresholds, fusion params
└── models/
    ├── structural_only_model.pkl  # PRIMARY — 97.3% accuracy
    ├── structural_only_scaler.pkl
    ├── hybrid_phishout_model.pkl  # Experimental artifact (Phase 3)
    └── comparison_results.json

dashboard/
├── index.html    # 4-panel layout (input, gauge, terminal, PhishOut panel)
├── script.js     # Uses /phishout/scan; renders component scores + reasons
└── style.css     # Verdict badges, score bars, reasons list

extension/
├── background.js # Uses /phishout/scan; maps to legacy fields for overlay
├── content.js    # Unchanged — overlay still works via legacy field mapping
└── popup.js      # Unchanged — reads from chrome.storage
```
