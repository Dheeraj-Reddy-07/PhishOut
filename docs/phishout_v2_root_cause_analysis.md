# PhishOut V2 Root Cause Analysis

**Generated:** 2026-08-24

---

## Problem Statement

Runtime testing revealed systematic false positives on legitimate modern websites:
- Google can receive a high semantic probability
- Microsoft can receive a suspicious result
- Gemini can receive an extremely high semantic score and even a phishing verdict

These are legitimate authentication/account/payment websites being misclassified as phishing.

---

## PHASE A: Pipeline Audit Results

### Dataset Statistics (Phish360)
- **Train:** 7,732 samples (4,619 legitimate, 3,113 phishing)
- **Validation:** 1,369 samples
- **Test:** 1,533 samples
- **Features:** 44 total (32 structural + 12 semantic)

### Model Configuration
- **Hybrid Model:** GradientBoosting + RandomForest ensemble
- **Fusion:** Learned logistic regression
  - coef_structural: 4.31
  - coef_semantic: 5.09
  - intercept: -4.57
- **Thresholds (calibrated):**
  - SAFE < 15
  - SUSPICIOUS 15-56
  - PHISHING >= 57

### Semantic Features (12)
1. password_fields
2. text_email_fields
3. forms
4. external_links
5. iframes
6. scripts
7. login_indicators
8. credential_indicators
9. payment_indicators
10. urgency_indicators
11. brand_indicators
12. text_length

### Pipeline Flow
```
URL → Structural features (32) → Structural model → p_struct
     ↓
Webpage fetch → Semantic features (12) → Semantic model → p_sem
     ↓
Fusion: sigmoid(4.31×p_struct + 5.09×p_sem - 4.57) → p_fusion
     ↓
Risk score (0-100) → Verdict (SAFE/SUSPICIOUS/PHISHING)
```

---

## PHASE B: Root Cause Analysis

### Semantic Feature Distribution Analysis

#### Legitimate Samples (n=4,619)
| Feature | Mean | Std | Max | % > 0 |
|---------|------|-----|-----|-------|
| password_fields | 0.12 | 0.46 | 6 | 9% |
| forms | 1.55 | 3.14 | 101 | 62% |
| login_indicators | 3.65 | 9.75 | 157 | 48% |
| credential_indicators | 0.96 | 4.43 | 146 | 18% |
| payment_indicators | 1.74 | 6.71 | 150 | 28% |
| brand_indicators | 3.07 | 15.82 | 568 | 44% |

#### Phishing Samples (n=3,113)
| Feature | Mean | Std | Max | % > 0 |
|---------|------|-----|-----|-------|
| password_fields | 0.71 | 0.91 | 20 | 55% |
| forms | 1.27 | 1.19 | 34 | 72% |
| login_indicators | 4.90 | 6.42 | 105 | 58% |
| credential_indicators | 1.95 | 3.03 | 40 | 42% |
| payment_indicators | 2.52 | 7.28 | 93 | 35% |
| brand_indicators | 2.11 | 4.87 | 97 | 44% |

### Key Findings

**1. Brand Indicators are NOT discriminative**
- Legitimate: 44% have brand_indicators > 0
- Phishing: 44% have brand_indicators > 0
- **No separation power** - legitimate sites ARE brands (Google, Microsoft, etc.)

**2. Password Fields have some separation but high overlap**
- Legitimate: 9% have password_fields > 0
- Phishing: 55% have password_fields > 0
- **But legitimate login pages exist** (Google, Microsoft, banking, SaaS)

**3. Login Indicators have weak separation**
- Legitimate mean: 3.65
- Phishing mean: 4.90
- **High overlap** - legitimate authentication pages use login language

**4. Forms are common in both**
- Legitimate: 62% have forms
- Phishing: 72% have forms
- **Forms are normal** for legitimate web applications

### The Core Problem

**The semantic model has learned:**
```
login/form/credential presence → phishing
```

**But the correct distinction should be:**
```
credential harvesting + suspicious context → phishing
legitimate authentication on trusted domain → safe
```

### Why This Happens

1. **Phish360 legitimate samples may not adequately represent modern legitimate login/account/payment pages**
   - The dataset's legitimate samples might be mostly content pages, not authentication pages
   - Modern SaaS, banking, and authentication flows may be underrepresented

2. **Semantic features lack context**
   - `password_fields > 0` is treated as suspicious regardless of domain
   - `brand_indicators > 0` is treated as suspicious even when the domain IS the brand
   - No feature for "domain legitimacy" or "domain-brand consistency"
   - No feature for "form action destination" (same-origin vs cross-origin)

3. **Fusion overweights semantic**
   - coef_semantic (5.09) > coef_structural (4.31)
   - Semantic model has high influence on final score
   - When semantic model is wrong, fusion amplifies the error

### Evidence from Keyword Banks

The semantic feature extraction uses these keyword banks:

**LOGIN_KEYWORDS:** login, signin, sign-in, sign in, log in, authenticate, authentication, password, username, user, email, credential, account, access, portal, secure, verify, identity

**CREDENTIAL_KEYWORDS:** password, passcode, pin, secret, security, auth, credential, token, otp, verification, confirm, re-enter

**PAYMENT_KEYWORDS:** payment, credit card, debit card, bank, billing, invoice, transaction, purchase, checkout, pay, card, visa, mastercard, amex, paypal, stripe, financial, money

**BRAND_KEYWORDS:** google, facebook, microsoft, apple, amazon, paypal, netflix, chase, wells fargo, bank of america, citibank, dropbox, linkedin, twitter, instagram, tiktok, spotify, adobe, intuit, turbotax

**Problem:** These keywords appear on legitimate authentication pages (Google login, Microsoft account, etc.) and are counted as "suspicious."

---

## Conclusion

**Root Cause:** The semantic model treats legitimate authentication UI (password fields, login keywords, brand mentions) as phishing indicators because:

1. **Phish360's legitimate samples likely underrepresent modern login/account/payment pages**
2. **Semantic features lack context** (domain legitimacy, domain-brand consistency, form action destination)
3. **Fusion overweights semantic** relative to structural features
4. **Keyword-based detection is too naive** - legitimate sites use the same keywords as phishing sites

**The model has learned:**
```
"has password field" + "has login keywords" + "has brand name" = phishing
```

**But legitimate sites like Google, Microsoft, Gemini naturally have:**
```
password field + login keywords + brand name (because they ARE the brand)
```

---

## Recommended Solution Direction

1. **Add context features:**
   - Domain-brand consistency (is the domain actually the brand it mentions?)
   - Form action destination (same-origin vs cross-origin)
   - Domain legitimacy (is the domain a known trusted domain?)

2. **Rebalance fusion:**
   - Reduce semantic weight relative to structural
   - Structural features (typosquatting, impersonation) are more reliable

3. **Add hard-negative training data:**
   - Include legitimate login/account/payment pages from major services
   - Ensure the model learns that legitimate authentication ≠ phishing

4. **Improve semantic features:**
   - Distinguish "credential harvesting" from "ordinary login UI"
   - Add context around password fields (is it on a trusted domain?)
   - Add form action analysis (does it submit to the same domain?)

---

## Next Steps

Proceed to PHASE C: Hard-negative data strategy
