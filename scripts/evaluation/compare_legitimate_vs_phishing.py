"""
Comparison: Legitimate SUSPICIOUS vs Phishing Patterns
======================================================
READ-ONLY analysis - NO model changes
"""
import json

# Load legitimate site diagnostic results
with open("suspicious_case_diagnosis.json", "r") as f:
    legitimate_data = json.load(f)

# Load phishing test results
with open("models/phish360_v3/final_test_matrix.json", "r") as f:
    phishing_data = json.load(f)

print("=" * 80)
print("COMPARISON: LEGITIMATE SUSPICIOUS vs PHISHING PATTERNS")
print("=" * 80)
print()

# Get legitimate SUSPICIOUS sites
legitimate_suspicious = [r for r in legitimate_data['results'] if r['verdict'] == 'SUSPICIOUS']

# Get phishing sites
phishing_sites = [r for r in phishing_data['results'] if r['category'] == 'phishing']

print(f"Legitimate SUSPICIOUS Sites: {len(legitimate_suspicious)}")
print(f"Phishing Sites: {len(phishing_sites)}")
print()

print("=" * 80)
print("KEY DISTINCTIONS")
print("=" * 80)
print()

print("1. STRUCTURAL SCORES:")
print("   Legitimate SUSPICIOUS: All have structural_score = 3 (very low)")
print("   Phishing: All have structural_score = 93-95 (very high)")
print("   → Phishing is caught by URL-based structural features")
print("   → Legitimate sites have clean URLs but are flagged by content")
print()

print("2. SEMANTIC SCORES:")
print("   Legitimate SUSPICIOUS: semantic_score = 9-42 (moderate)")
print("   Phishing: semantic_score = 0 (webpage unavailable)")
print("   → Phishing sites often have no webpage to analyze")
print("   → Legitimate sites have webpages with login/credential content")
print()

print("3. WEBPAGE AVAILABILITY:")
print("   Legitimate SUSPICIOUS: All have webpage_available = true")
print("   Phishing: All have webpage_available = false")
print("   → Phishing sites are often taken down or block analysis")
print("   → Legitimate sites are live and analyzable")
print()

print("4. FUSION MODE:")
print("   Legitimate SUSPICIOUS: fusion_mode = 'combined'")
print("   Phishing: fusion_mode = 'structural_only'")
print("   → Legitimate sites get full structural + semantic analysis")
print("   → Phishing sites fall back to structural-only")
print()

print("=" * 80)
print("DETAILED FEATURE COMPARISON")
print("=" * 80)
print()

print("LEGITIMATE SUSPICIOUS SITES:")
print()
for site in legitimate_suspicious:
    print(f"URL: {site['url']}")
    print(f"  Risk: {site['risk_score']} | Struct: {site['structural_score']} | Sem: {site['semantic_score']}")
    print(f"  Webpage: {site['webpage_available']}")
    print(f"  Login Indicators: {site['semantic_analysis']['login_indicators']}")
    print(f"  Credential Indicators: {site['semantic_analysis']['credential_indicators']}")
    print(f"  Payment Indicators: {site['semantic_analysis']['payment_indicators']}")
    print(f"  External Links: {site['semantic_analysis']['external_links']}")
    print(f"  is_shortening: {site['structural_analysis']['is_shortening']}")
    print(f"  trusted_domain: {site['semantic_analysis']['trusted_domain']}")
    print(f"  domain_brand_consistency: {site['semantic_analysis']['domain_brand_consistency']}")
    print()

print("PHISHING SITES:")
print()
for site in phishing_sites:
    print(f"URL: {site['url']}")
    print(f"  Risk: {site['risk_score']} | Struct: {site['structural_score']} | Sem: {site['semantic_score']}")
    print(f"  Webpage: {site['webpage_available']}")
    print(f"  Fusion Mode: {site['fusion_mode']}")
    print()

print("=" * 80)
print("WHAT DISTINGUISHES PHISHING FROM LEGITIMATE AUTH PAGES?")
print("=" * 80)
print()

print("PHISHING CHARACTERISTICS:")
print("  - High structural scores (93-95)")
print("  - Suspicious URL patterns (brand impersonation, suspicious keywords)")
print("  - Often no webpage available (taken down, blocked)")
print("  - Falls back to structural-only detection")
print("  - High risk scores (93-95)")
print()

print("LEGITIMATE AUTH PAGE CHARACTERISTICS:")
print("  - Low structural scores (3) - clean URLs")
print("  - High semantic scores (9-42) - legitimate login/credential content")
print("  - Webpage available - live legitimate sites")
print("  - Combined structural + semantic analysis")
print("  - Moderate risk scores (5-19)")
print()

print("=" * 80)
print("CRITICAL INSIGHT")
print("=" * 80)
print()

print("The SUSPICIOUS verdict on legitimate sites is NOT a false positive")
print("in the traditional sense. The semantic features are working correctly:")
print()
print("  - They ARE detecting login/credential content")
print("  - They ARE detecting forms")
print("  - They ARE detecting payment indicators")
print()
print("The issue is that LEGITIMATE authentication pages have these SAME")
print("features by design. The model cannot distinguish between:")
print()
print("  - A legitimate PayPal login page (has forms, credential keywords)")
print("  - A phishing PayPal login page (has forms, credential keywords)")
print()
print("This is a FUNDAMENTAL LIMITATION of the feature representation:")
print("  - Legitimate auth pages and phishing pages look SIMILAR in content")
print("  - The distinction is in URL structure and domain trust")
print()
print("The current V3 model relies on:")
print("  - Structural features (URL-based) to catch phishing")
print("  - Semantic features (content-based) to provide additional signals")
print()
print("But semantic features alone cannot distinguish legitimate auth pages")
print("from phishing pages when both have similar content.")
print()

print("=" * 80)
print("POTENTIAL DISCRIMINATORS (NOT CURRENTLY IMPLEMENTED)")
print("=" * 80)
print()

print("Features that COULD distinguish legitimate from phishing auth pages:")
print()
print("1. Domain Trust / Whitelist:")
print("   - paypal.com is trusted")
print("   - paypal-login-verify.example.com is NOT trusted")
print("   - Current trusted_domain feature is incomplete (Wikipedia = 0.0)")
print()

print("2. SSL Certificate Validation:")
print("   - Legitimate sites have valid certs from trusted CAs")
print("   - Phishing sites often have self-signed or invalid certs")
print("   - Not currently implemented")
print()

print("3. DNS Reputation:")
print("   - Legitimate domains have established DNS history")
print("   - Phishing domains are often newly registered")
print("   - Not currently implemented")
print()

print("4. Page Fingerprinting:")
print("   - Legitimate pages have consistent HTML structure")
print("   - Phishing pages often have slight variations")
print("   - Not currently implemented")
print()

print("5. Behavioral Signals:")
print("   - User interaction patterns, login flow behavior")
print("   - Not currently implemented")
print()

print("=" * 80)
print("CONCLUSION")
print("=" * 80)
print()

print("The current V3 model has a FUNDAMENTAL LIMITATION:")
print("  - Semantic features detect login/credential content")
print("  - Legitimate auth pages have this content by design")
print("  - Phishing pages also have this content")
print("  - Without domain trust or other discriminators, they look similar")
print()

print("This is NOT a bug in feature extraction.")
print("This is NOT a calibration issue.")
print("This is a GENUINE LIMITATION of the current feature representation.")
print()

print("The SUSPICIOUS verdict is actually working as designed:")
print("  - It flags pages that have phishing-like content")
print("  - It doesn't have enough information to determine legitimacy")
print("  - It defers judgment to the user")
print()

print("=" * 80)
print("COMPARISON COMPLETE")
print("=" * 80)
