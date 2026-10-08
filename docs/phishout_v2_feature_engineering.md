# PhishOut V2 Feature Engineering

**Generated:** 2026-08-24

---

## New Features Added

### 1. domain_brand_consistency (0.0 or 1.0)
**Purpose:** Distinguish legitimate brand domains from brand impersonation

**Logic:**
- If brand keywords are detected on page AND the domain is in the trusted brand list → 1.0 (consistent)
- If brand keywords are detected BUT the domain is NOT trusted → 0.0 (inconsistent/suspicious)
- If no brand keywords detected → 1.0 (neutral)

**Why this helps:** Google.com mentioning "google" is normal. A typosquatting domain like "goog1e.com" mentioning "google" is suspicious.

### 2. form_action_same_origin (0.0 or 1.0)
**Purpose:** Detect forms that submit data to external domains

**Logic:**
- If any form action points to a different domain → 0.0 (suspicious)
- If all form actions are same-origin or no forms → 1.0 (normal)

**Why this helps:** Legitimate login forms submit to the same domain. Phishing forms often submit to attacker-controlled external domains.

### 3. trusted_domain (0.0 or 1.0)
**Purpose:** Explicitly mark known trusted domains

**Logic:**
- If domain is in TRUSTED_BRAND_DOMAINS list → 1.0 (trusted)
- Otherwise → 0.0 (not in trusted list)

**Why this helps:** Provides a strong signal for legitimate major services (Google, Microsoft, etc.)

---

## Trusted Brand Domains List

Added to `webpage_analyzer.py`:

```python
TRUSTED_BRAND_DOMAINS = {
    "google": ["google.com", "accounts.google.com", "gmail.com", "youtube.com"],
    "facebook": ["facebook.com", "m.facebook.com"],
    "microsoft": ["microsoft.com", "login.microsoftonline.com", "office.com", "outlook.com", "live.com"],
    "apple": ["apple.com", "id.apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.in"],
    "paypal": ["paypal.com"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "wells fargo": ["wellsfargo.com"],
    "bank of america": ["bankofamerica.com"],
    "citibank": ["citibank.com"],
    "dropbox": ["dropbox.com"],
    "linkedin": ["linkedin.com"],
    "twitter": ["twitter.com", "x.com"],
    "instagram": ["instagram.com"],
    "tiktok": ["tiktok.com"],
    "spotify": ["spotify.com"],
    "adobe": ["adobe.com"],
    "github": ["github.com"],
    "slack": ["slack.com"],
    "salesforce": ["salesforce.com", "login.salesforce.com"],
    "zoom": ["zoom.us"],
}
```

---

## Feature Count Changes

**Before (V1):**
- Structural: 32 features
- Semantic: 12 features
- Total: 44 features

**After (V2):**
- Structural: 32 features (unchanged)
- Semantic: 15 features (+3 context features)
- Total: 47 features

---

## Files Modified

1. `backend/webpage_analyzer.py`
   - Added TRUSTED_BRAND_DOMAINS dictionary
   - Added domain_brand_consistency feature extraction
   - Added form_action_same_origin feature extraction
   - Added trusted_domain feature extraction
   - Updated docstring to reflect 17 features

2. `backend/phishout_predictor.py`
   - Updated SEMANTIC_KEYS to include 3 new context features

3. `backend/phish360_feature_extractor.py`
   - Updated semantic_keys to include 3 new context features

4. `backend/train_phish360_semantic.py`
   - Updated SEMANTIC_FEATURES to include 3 new context features

5. `backend/train_phish360_hybrid.py`
   - Updated SEMANTIC_FEATURES to include 3 new context features
   - Updated HYBRID_FEATURES to now be 47 features (32 + 15)

---

## Critical Blocker: Phish360 ZIP is Password-Protected

**Issue:** The Phish360 dataset at `D:\Downloads\phish360.zip` is encrypted and requires a password to extract.

**Impact:** The existing processed feature files (`backend/dataset/phish360/processed/*.parquet`) do NOT contain the new context features. To train V2 models with the new features, we need to:

1. Extract the Phish360 ZIP (requires password)
2. Re-run feature extraction with the updated `webpage_analyzer.py`
3. Generate new parquet files with 47 features instead of 44

**Current state:** Existing parquet files have 48 columns (including metadata), but only 44 feature columns (32 structural + 12 semantic). The new context features are missing.

---

## Options to Proceed

### Option A: Obtain Phish360 ZIP Password
- User provides the password for `D:\Downloads\phish360.zip`
- Re-extract and re-process the dataset with new features
- Proceed with V2 training

### Option B: Synthetic Feature Addition (Fallback)
- Add the 3 new context features to existing parquet files with default values
- For domain_brand_consistency: compute from URL (no HTML needed)
- For form_action_same_origin: set to 1.0 (conservative, since we don't have HTML)
- For trusted_domain: compute from URL (no HTML needed)
- This would be incomplete but allows testing the feature engineering approach

### Option C: Use Only URL-Based Context Features
- Only implement domain_brand_consistency and trusted_domain (URL-based)
- Skip form_action_same_origin (requires HTML analysis which we don't have access to)
- This would be a partial solution

---

## Recommended Path

**Option A is preferred** for a complete solution. However, if the password is not available, **Option B** allows us to proceed with a partial implementation.

Given the user's instruction to not stop unless there's a critical external dependency issue, this IS a critical blocker. The dataset is encrypted and cannot be re-processed without the password.

---

## Next Steps

**Await user decision on how to proceed with the encrypted Phish360 dataset.**

Options:
1. Provide the password for Phish360.zip
2. Approve Option B (synthetic feature addition)
3. Approve Option C (partial implementation)
4. Provide alternative dataset source
