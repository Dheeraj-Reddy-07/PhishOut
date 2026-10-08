# PhishOut V2 Hard-Negative Data Strategy

**Generated:** 2026-08-24

---

## Objective

Add legitimate hard-negative samples to the training data to teach the model that:
- Legitimate authentication/account/payment UI ≠ phishing
- Legitimate brand domains with login features ≠ phishing

---

## Current Problem

Phish360 legitimate samples (n=4,619) likely underrepresent:
- Modern authentication pages (Google, Microsoft, etc.)
- Banking login pages
- SaaS application login pages
- Payment checkout pages
- Account management portals

This causes the semantic model to treat password fields, login keywords, and brand mentions as phishing indicators even on legitimate domains.

---

## Hard-Negative Categories

### 1. Major Brand Authentication Pages
- Google (accounts.google.com)
- Microsoft (login.microsoftonline.com, account.microsoft.com)
- Apple (id.apple.com)
- Amazon (amazon.com/ap/signin)
- Facebook (facebook.com/login)
- LinkedIn (linkedin.com/login)

### 2. Banking & Financial Services
- Chase (chase.com)
- Wells Fargo (wellsfargo.com)
- Bank of America (bankofamerica.com)
- Citibank (citibank.com)

### 3. SaaS Applications
- GitHub (github.com/login)
- Dropbox (dropbox.com/login)
- Slack (slack.com/signin)
- Salesforce (login.salesforce.com)
- Zoom (zoom.us/signin)

### 4. Payment Services
- PayPal (paypal.com/signin)
- Stripe (dashboard.stripe.com/login)
- Square (squareup.com/login)

### 5. Email Services
- Gmail (accounts.google.com)
- Outlook (outlook.live.com)
- Yahoo (yahoo.com)

---

## Data Collection Strategy

### Option A: Live Collection (Preferred if feasible)
- Use `webpage_analyzer.py` to fetch and extract features from live URLs
- Respect robots.txt and rate limits
- Use appropriate timeouts (10s)
- Handle failures gracefully

**Pros:** Real-time data, reflects current web state
**Cons:** Rate limits, network dependencies, may not be reproducible

### Option B: Static/Cached Collection (Fallback)
- Use known stable URLs that are unlikely to change
- Cache HTML locally for reproducibility
- Document collection date and source

**Pros:** Reproducible, no network dependency during training
**Cons:** May become stale, requires maintenance

### Option C: Synthetic Hard Negatives (Last Resort)
- Manually curate a list of legitimate authentication URLs
- Extract features once and store
- Document as "synthetic hard negatives"

**Pros:** Fully controlled, reproducible
**Cons:** Limited coverage, manual effort

---

## Recommended Approach: Option B (Static/Cached)

Given the constraints (limited AI credits, need for reproducibility), use Option B:

1. **Curate a list of 50-100 legitimate authentication URLs** from major brands
2. **Fetch and cache HTML** using `webpage_analyzer.py`
3. **Extract features** and save to a hard-negative dataset
4. **Add to training set** with proper leakage-safe splitting

---

## Hard-Negative Dataset Structure

```python
hard_negatives = [
    {
        "url": "https://accounts.google.com",
        "label": 0,  # legitimate
        "category": "brand_authentication",
        "html": "<cached HTML>",
        "source": "manual_curation",
        "collection_date": "2026-08-24"
    },
    # ... more samples
]
```

---

## Leakage Prevention

**Critical:** Hard-negative domains must NOT appear in the test set.

1. **Extract domains** from hard negatives
2. **Check against test set domains**
3. **Remove any overlapping domains** from hard negatives
4. **Add hard negatives ONLY to training set** (not validation or test)

---

## Integration with Phish360

### Option 1: Augment Phish360 Training Set
- Add hard negatives to `train_features.parquet`
- Rebalance class distribution if needed
- Retrain models with augmented data

### Option 2: Separate Hard-Negative Training
- Create separate hard-negative dataset
- Train a separate model or fine-tune existing model
- Compare performance

**Recommended:** Option 1 (augment Phish360) for simplicity and reproducibility.

---

## Implementation Plan

1. **Curate URL list** (50-100 legitimate authentication URLs)
2. **Fetch and cache HTML** using `webpage_analyzer.fetch_webpage()`
3. **Extract features** using existing feature extractors
4. **Save to parquet** as `hard_negatives_features.parquet`
5. **Validate leakage** against Phish360 test set
6. **Augment training set** by concatenating with Phish360 train data
7. **Retrain models** with augmented data
8. **Evaluate** on untouched test set

---

## Limitations

1. **Manual curation required** - not fully automated
2. **Limited coverage** - 50-100 samples may not cover all legitimate patterns
3. **Potential staleness** - cached HTML may become outdated
4. **Domain-specific** - may not generalize to new legitimate domains

---

## Alternative: Feature Engineering Instead of Hard Negatives

Given the limitations of hard-negative collection, a more principled approach may be to:

**Improve semantic features with context:**
- Add `domain_brand_consistency` feature (is the domain actually the brand it mentions?)
- Add `form_action_same_origin` feature (does form submit to same domain?)
- Add `trusted_domain` feature (is the domain in a known trusted list?)
- Add `https_valid` feature (valid SSL certificate?)

This approach:
- Does not require additional data collection
- Is more generalizable
- Addresses the root cause (lack of context)

**Recommended:** Prioritize feature engineering (PHASE D) over hard-negative collection (PHASE C).

---

## Decision

**Proceed with PHASE D (Feature Engineering) as the primary solution.**

Hard-negative collection (PHASE C) will be implemented only if feature engineering alone is insufficient.

---

## Next Steps

Proceed to PHASE D: Feature Engineering
