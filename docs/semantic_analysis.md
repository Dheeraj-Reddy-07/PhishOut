# Semantic Webpage Analysis Documentation

**Date:** August 20, 2026  
**Purpose:** Document webpage content analysis pipeline for PhishOut  
**Status:** Phase 2 Complete

---

## Overview

The semantic webpage analysis module extracts content-based features from webpages to complement the existing URL-based structural analysis. This provides a foundation for hybrid structural-semantic phishing detection in PhishOut.

**Key Principle:** The analyzer is designed as a safe, read-only fetcher that does not interact with forms, execute JavaScript, or submit credentials.

---

## Webpage Information Extracted

### 1. Page Title
- **What:** The HTML `<title>` tag content
- **Why:** Phishing pages often use titles mimicking legitimate brands (e.g., "Sign in to PayPal")
- **Example:** "Sign in to GitHub · GitHub" vs "Secure Login - PayPal"

### 2. Visible Textual Content
- **What:** Text content visible to users (scripts, styles, noscript removed)
- **Why:** Analyzed for keyword patterns indicating login, credentials, payment, urgency
- **Metric:** `text_length` - character count of visible text

### 3. Form Analysis
- **Forms count:** Total number of `<form>` elements
- **Password fields:** Number of `<input type="password">` fields
- **Text/email fields:** Number of `<input type="text">` and `<input type="email">` fields
- **Form actions:** URLs where forms submit data
- **Why:** Phishing pages typically have login forms with password inputs
- **Example:** Legitimate login page has 1 form with 1 password field

### 4. External Links
- **What:** Count of links pointing to external domains
- **Why:** High external link count may indicate link farms or suspicious redirect patterns
- **Threshold:** >10 external links flagged in evidence

### 5. Iframes
- **What:** Number of `<iframe>` elements
- **Why:** Iframes can hide malicious content or load external resources
- **Risk:** Used in some phishing attacks to embed legitimate content while stealing credentials

### 6. Scripts
- **What:** Number of `<script>` elements
- **Why:** High script count may indicate obfuscation or malicious JavaScript
- **Threshold:** >20 scripts flagged in evidence

### 7. Login Indicators
- **What:** Count of login-related keywords in visible text
- **Keywords:** login, signin, sign-in, authenticate, password, username, email, credential, account, access, portal, secure, verify, identity
- **Why:** Phishing pages are almost always login pages
- **Example:** GitHub login page has 8 login keyword occurrences

### 8. Credential Indicators
- **What:** Count of credential-related keywords
- **Keywords:** password, passcode, pin, secret, security, auth, credential, token, otp, verification, confirm, re-enter
- **Why:** Direct evidence of credential harvesting intent
- **Example:** Login page with "Enter your password" triggers this indicator

### 9. Payment Indicators
- **What:** Count of payment/financial keywords
- **Keywords:** payment, credit card, debit card, bank, account, billing, invoice, transaction, purchase, checkout, pay, card, visa, mastercard, amex, paypal, stripe, financial, money
- **Why:** Financial phishing targets payment information
- **Example:** PayPal homepage has 21 payment keyword occurrences

### 10. Urgency Indicators
- **What:** Count of urgency/deception keywords
- **Keywords:** urgent, immediately, now, today, expires, expire, limited time, act now, don't wait, warning, alert, suspended, locked, verify now, confirm immediately, hurry, last chance, deadline
- **Why:** Phishing often uses urgency to pressure victims
- **Example:** "Your account will be suspended immediately" triggers urgency indicators

### 11. Brand Indicators
- **What:** Count of brand names in visible text
- **Keywords:** google, facebook, microsoft, apple, amazon, paypal, netflix, chase, wells fargo, bank of america, citibank, dropbox, linkedin, twitter, instagram, tiktok, spotify, adobe, intuit, turbotax
- **Why:** Brand impersonation is a common phishing tactic
- **Example:** Phishing page claiming to be PayPal will have "paypal" in text

---

## Structural vs Semantic Features

### Structural Features (Existing - URL-based)
- **Source:** URL string only
- **Examples:** URL length, domain entropy, typosquatting distance, TLD risk, IP address presence
- **Analysis:** Performed without fetching the webpage
- **Model:** Current ML model (32 features)

### Semantic Features (New - Content-based)
- **Source:** HTML webpage content
- **Examples:** Password fields, login keywords, payment keywords, form actions, external links
- **Analysis:** Requires fetching and parsing HTML
- **Model:** Not yet trained (feature extraction only at this stage)

### Hybrid Approach (Future - PhishOut)
- **Goal:** Combine structural + semantic features
- **Architecture:** Multi-modal fusion layer
- **Benefit:** Detect phishing that looks legitimate structurally but has suspicious content

---

## Feature Relevance to Phishing Detection

### High-Indicative Features
1. **Password fields:** Strong indicator of login page (phishing targets)
2. **Login keywords:** Confirms login intent
3. **Credential keywords:** Direct evidence of credential harvesting
4. **Typosquatting + brand indicators:** Combined evidence of impersonation
5. **Urgency keywords:** Psychological manipulation indicator

### Medium-Indicative Features
1. **Payment keywords:** Relevant for financial phishing
2. **External links:** May indicate link farms
3. **Form actions to external domains:** Credential harvesting
4. **Iframes:** Can hide malicious content

### Contextual Features
1. **Page title:** Brand impersonation check
2. **Text length:** Very short pages may be suspicious
3. **Scripts count:** High count may indicate obfuscation

---

## Limitations of Static HTML Analysis

### 1. No JavaScript Execution
- **Limitation:** Cannot analyze dynamic content loaded via JavaScript
- **Impact:** Modern single-page applications (SPAs) may not render fully
- **Example:** React/Vue apps that load content after fetch

### 2. No Screenshot/Visual Analysis
- **Limitation:** Cannot analyze visual similarity to legitimate sites
- **Impact:** Pixel-perfect visual clones may evade detection
- **Future:** Will add visual similarity analysis in later phases

### 3. No DOM Interaction
- **Limitation:** Cannot trigger events or interact with page elements
- **Impact:** Cannot detect malicious behavior that requires user interaction
- **Example:** Malware that downloads on button click

### 4. No Network Traffic Analysis
- **Limitation:** Cannot analyze HTTP requests or responses
- **Impact:** Cannot detect exfiltration or malicious redirects
- **Future:** May add network analysis in later phases

### 5. No CAPTCHA Handling
- **Limitation:** Cannot bypass CAPTCHAs
- **Impact:** Some legitimate sites may block automated analysis
- **Mitigation:** Graceful failure with error reporting

### 6. No Authentication
- **Limitation:** Cannot access password-protected pages
- **Impact:** Cannot analyze behind-login content
- **Mitigation:** Focus on login pages (pre-authentication)

### 7. Content Obfuscation
- **Limitation:** Cannot decode heavily obfuscated content
- **Impact:** Sophisticated phishing may hide text in images or encoded formats
- **Mitigation:** Multiple feature types provide redundancy

---

## Cases Where Webpage Fetching Fails

### 1. Connection Timeouts
- **Cause:** Server not responding, network issues
- **Timeout:** 10 seconds (configurable)
- **Handling:** Returns error message, analysis marked as failed
- **Example:** `error: "Analysis failed: timeout"`

### 2. Connection Errors
- **Cause:** DNS resolution failure, refused connections
- **Handling:** Returns error message
- **Example:** `error: "Analysis failed: connection error"`

### 3. Invalid URLs
- **Cause:** Malformed URLs, missing scheme or netloc
- **Handling:** Returns error message
- **Example:** `error: "Analysis failed: invalid URL"`

### 4. Non-HTML Content
- **Cause:** URL returns PDF, image, video, or other non-HTML content
- **Content-Type Check:** Only processes `text/html`
- **Handling:** Returns error message
- **Example:** `error: "Analysis failed: non-HTML content"`

### 5. HTTP Errors
- **Cause:** 404 Not Found, 403 Forbidden, 500 Server Error
- **Status Code Check:** Only processes 200 OK
- **Handling:** Returns error message
- **Example:** `error: "Analysis failed: HTTP 404"`

### 6. Content Too Large
- **Cause:** Page exceeds size limit (1 MB default)
- **Handling:** Returns error message
- **Example:** `error: "Analysis failed: content too large"`

### 7. Malformed HTML
- **Cause:** Invalid HTML structure
- **Handling:** BeautifulSoup handles most malformed HTML gracefully
- **Impact:** May miss some features but unlikely to crash

### 8. Blocked by WAF/Security
- **Cause:** Web Application Firewall blocks automated requests
- **Handling:** Returns error message
- **Mitigation:** User-Agent header set to browser-like string

---

## Security and Reliability Features

### 1. Request Timeout
- **Default:** 10 seconds
- **Purpose:** Prevent hanging on slow servers
- **Configurable:** Via `timeout` parameter

### 2. Content Length Limit
- **Default:** 1 MB
- **Purpose:** Prevent memory exhaustion on large pages
- **Configurable:** Via `max_content_length` parameter

### 3. Content-Type Validation
- **Check:** Only processes `text/html` content
- **Purpose:** Prevent processing binary files as HTML
- **Security:** Avoids processing potentially malicious binaries

### 4. Scheme Validation
- **Allowed:** HTTP and HTTPS only
- **Blocked:** file://, javascript:, data://, etc.
- **Security:** Prevents local file access or protocol attacks

### 5. No Form Submission
- **Policy:** Analyzer never submits forms or credentials
- **Security:** Prevents accidental credential leakage
- **Scope:** Read-only analysis only

### 6. No JavaScript Execution
- **Policy:** Analyzer does not execute JavaScript
- **Security:** Prevents XSS or malicious code execution
- **Scope:** Static HTML parsing only

### 7. No File Downloads
- **Policy:** Analyzer does not download files
- **Security:** Prevents malware download
- **Scope:** HTML content only

### 8. Graceful Error Handling
- **Policy:** All exceptions caught and reported
- **Reliability:** API never crashes due to webpage analysis failure
- **Fallback:** Returns error message in result

---

## API Integration

### New Endpoint: `/scan_extended`

**Purpose:** Returns both structural and webpage analysis

**Request:**
```json
{
  "url": "https://github.com/login"
}
```

**Response:**
```json
{
  "url": "https://github.com/login",
  "structural_analysis": {
    "threat_level_pct": 0,
    "ml_confidence": 0.0037,
    "verdict": "SAFE",
    "red_flags": [],
    "feature_scores": {...},
    "feature_labels": {...},
    "raw_features": {...},
    "is_dangerous": false
  },
  "webpage_analysis": {
    "success": true,
    "error": null,
    "page_title": "Sign in to GitHub · GitHub",
    "text_length": 613,
    "password_fields": 1,
    "text_email_fields": 2,
    "forms": 1,
    "form_actions": ["https://github.com/session"],
    "external_links": 4,
    "iframes": 0,
    "scripts": 0,
    "login_indicators": 8,
    "credential_indicators": 2,
    "payment_indicators": 1,
    "urgency_indicators": 1,
    "brand_indicators": 0,
    "evidence": [
      "Password input field(s) detected (1)",
      "Form(s) detected (1)",
      "Text/email input field(s) detected (2)",
      "Login-related keywords detected (8 occurrences)",
      "Credential-related keywords detected (2 occurrences)",
      "Payment/financial keywords detected (1 occurrences)",
      "Urgency/deception keywords detected (1 occurrences)",
      "Page title: 'Sign in to GitHub · GitHub'"
    ]
  }
}
```

### Existing Endpoint: `/scan` (Unchanged)

**Purpose:** Returns structural analysis only (backward compatible)

**Request:**
```json
{
  "url": "https://github.com/login"
}
```

**Response:** Same as before (structural analysis only)

**Status:** ✓ Existing predictions remain unchanged

---

## Example Output Analysis

### Example 1: GitHub Login Page (Legitimate)

**URL:** `https://github.com/login`

**Structural Analysis:**
- Threat: 0%
- Verdict: SAFE
- ML Confidence: 0.37%

**Webpage Analysis:**
- Password fields: 1
- Forms: 1
- Login indicators: 8
- Credential indicators: 2
- Evidence: Login page with password field detected

**Interpretation:** Legitimate login page correctly identified as SAFE by structural analysis. Webpage analysis confirms it's a login page (expected for GitHub).

### Example 2: PayPal Homepage (Legitimate)

**URL:** `https://www.paypal.com`

**Structural Analysis:**
- Threat: 0%
- Verdict: SAFE

**Webpage Analysis:**
- Login indicators: 5
- Payment indicators: 21
- Brand indicators: 9
- Evidence: Payment/financial site with login options

**Interpretation:** Legitimate payment site with high payment keyword count (expected for PayPal).

### Example 3: Google Homepage (Legitimate)

**URL:** `https://www.google.com`

**Structural Analysis:**
- Threat: 0%
- Verdict: SAFE

**Webpage Analysis:**
- Forms: 1
- Brand indicators: 1
- Evidence: Simple homepage with brand name

**Interpretation:** Legitimate homepage with minimal content (expected for Google).

---

## Test Results

### Test URLs Analyzed

1. **https://www.google.com**
   - Success: ✓
   - Title: "Google"
   - Forms: 1
   - Password fields: 0
   - Login indicators: 0
   - Evidence: Brand detected

2. **https://www.paypal.com**
   - Success: ✓
   - Title: "Send & Request Money, Shop, Manage Payments & More | PayPal RO"
   - Forms: 0
   - Password fields: 0
   - Login indicators: 5
   - Payment indicators: 21
   - Evidence: Payment/financial site

3. **https://github.com/login**
   - Success: ✓
   - Title: "Sign in to GitHub · GitHub"
   - Forms: 1
   - Password fields: 1
   - Login indicators: 8
   - Credential indicators: 2
   - Evidence: Login page with password field

4. **https://www.facebook.com**
   - Success: ✓
   - Title: "Facebook"
   - Forms: 0
   - Password fields: 0
   - Login indicators: 0
   - Evidence: Brand detected (minimal content due to SPA)

5. **http://paypa1.com/login** (Phishing from dataset)
   - Success: ✓
   - Note: Successfully fetched despite being a phishing URL
   - Analysis completed without errors

### Failure Cases Tested

- **Invalid URLs:** Handled gracefully with error messages
- **Timeouts:** Configured 10-second timeout prevents hanging
- **Non-HTML content:** Content-Type validation prevents processing binaries

---

## Current Limitations

### Dataset Limitations
- No semantic features in current training dataset
- No HTML content stored for existing URLs
- Semantic features not yet integrated into ML model

### Technical Limitations
- Static HTML analysis only (no JavaScript execution)
- No visual similarity analysis
- No screenshot capture
- No DOM interaction
- No network traffic analysis

### Integration Limitations
- Semantic features not yet combined with structural features
- No fusion layer implemented
- No training on semantic features
- Webpage analysis is optional (not required for predictions)

---

## Files Created

1. **backend/webpage_analyzer.py**
   - WebpageAnalyzer class
   - Feature extraction functions
   - Security and reliability features
   - Evidence generation

2. **docs/semantic_analysis.md**
   - This documentation

## Files Modified

1. **backend/main.py**
   - Added import: `from webpage_analyzer import analyze_webpage`
   - Added Pydantic models: `WebpageAnalysis`, `ExtendedScanResult`
   - Added new endpoint: `/scan_extended`
   - Original `/scan` endpoint unchanged (backward compatible)

## Files Unchanged

- `backend/ml_model.py` - Structural feature extraction unchanged
- `backend/train_model_v2.py` - Training pipeline unchanged
- `phishguard-react/` - Frontend unchanged (directory name preserved for technical consistency)
- `extension/` - Chrome extension unchanged

---

## Next Steps for PhishOut

### Phase 3: Semantic Feature Integration
1. Extract semantic features for all URLs in dataset
2. Combine structural (32) + semantic (14) = 46 features
3. Train hybrid model on combined features
4. Evaluate performance improvement

### Phase 4: Visual Analysis
1. Add screenshot capture capability
2. Implement visual similarity detection
3. Add CNN-based visual features

### Phase 5: PhishOracle Integration
1. Integrate PhishOracle for adversarial example generation
2. Create adversarial semantic examples
3. Train on clean + adversarial data

---

## Conclusion

The semantic webpage analysis module successfully extracts content-based features from webpages in a safe, reliable manner. The analyzer is integrated via a new `/scan_extended` endpoint while preserving the original `/scan` endpoint for backward compatibility. All security and reliability requirements are met, and the existing structural predictions remain unchanged.

**Status:** SEMANTIC ANALYSIS PHASE COMPLETE
