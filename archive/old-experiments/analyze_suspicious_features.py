"""
Feature Analysis: What Drives SUSPICIOUS Verdicts on Legitimate Sites
====================================================================
READ-ONLY analysis - NO model changes
"""
import json
from collections import defaultdict

# Load diagnostic results
with open("suspicious_case_diagnosis.json", "r") as f:
    data = json.load(f)

print("=" * 80)
print("FEATURE ANALYSIS: SUSPICIOUS VERDICT DRIVERS")
print("=" * 80)
print()

# Separate sites by verdict
suspicious_sites = [r for r in data['results'] if r['verdict'] == 'SUSPICIOUS']
safe_sites = [r for r in data['results'] if r['verdict'] == 'SAFE']

print(f"SUSPICIOUS Sites: {len(suspicious_sites)}")
print(f"SAFE Sites: {len(safe_sites)}")
print()

# Analyze structural features for SUSPICIOUS sites
print("=" * 80)
print("A. STRUCTURAL/DOMAIN SIGNALS")
print("=" * 80)
print()

struct_features = [
    'url_length', 'hostname_length', 'path_length', 'query_length', 'url_depth',
    'num_params', 'has_ip', 'has_at', 'has_port', 'double_slash', 'prefix_suffix',
    'sub_domain_count', 'excessive_dots', 'numeric_subdomain', 'punycode_present',
    'https_token', 'is_shortening', 'tld_risk_score', 'has_redirect_param',
    'double_extension', 'hex_encoded', 'domain_entropy', 'digit_ratio',
    'special_char_count', 'consonant_ratio', 'longest_word_length',
    'brand_impersonation_score', 'subdomain_brand_match', 'suspicious_keywords',
    'login_path_score', 'levenshtein_min', 'levenshtein_ratio'
]

for site in suspicious_sites:
    print(f"URL: {site['url']}")
    print(f"  Risk Score: {site['risk_score']} | Structural: {site['structural_score']} | Semantic: {site['semantic_score']}")
    print(f"  Key Structural Features:")
    struct = site['structural_analysis']
    
    # Highlight non-zero or unusual values
    unusual = []
    for feat in struct_features:
        val = struct[feat]
        if val != 0 and feat not in ['url_length', 'hostname_length', 'domain_entropy', 'consonant_ratio', 'longest_word_length', 'levenshtein_min', 'levenshtein_ratio']:
            unusual.append(f"    {feat}: {val}")
    
    if unusual:
        for u in unusual:
            print(u)
    else:
        print("    No unusual structural signals")
    print()

# Analyze semantic features for SUSPICIOUS sites
print("=" * 80)
print("B. SEMANTIC/CONTENT SIGNALS")
print("=" * 80)
print()

semantic_features = [
    'text_length', 'password_fields', 'text_email_fields', 'forms',
    'external_links', 'iframes', 'scripts', 'login_indicators',
    'credential_indicators', 'payment_indicators', 'urgency_indicators',
    'brand_indicators', 'domain_brand_consistency', 'form_action_same_origin',
    'trusted_domain', 'link_to_form_ratio', 'text_to_script_ratio',
    'credential_density', 'brand_context_score'
]

for site in suspicious_sites:
    print(f"URL: {site['url']}")
    print(f"  Key Semantic Features:")
    sem = site['semantic_analysis']
    
    # Highlight non-zero or unusual values
    unusual = []
    for feat in semantic_features:
        val = sem[feat]
        if val != 0 and feat not in ['text_length', 'domain_brand_consistency', 'form_action_same_origin', 'trusted_domain', 'brand_context_score']:
            unusual.append(f"    {feat}: {val}")
    
    if unusual:
        for u in unusual:
            print(u)
    else:
        print("    No unusual semantic signals")
    print()

# Analyze webpage/form signals
print("=" * 80)
print("C. WEBPAGE/FORM SIGNALS")
print("=" * 80)
print()

for site in suspicious_sites:
    print(f"URL: {site['url']}")
    sem = site['semantic_analysis']
    print(f"  Forms: {sem['forms']}")
    print(f"  Password Fields: {sem['password_fields']}")
    print(f"  Email Fields: {sem['text_email_fields']}")
    print(f"  Login Indicators: {sem['login_indicators']}")
    print(f"  Credential Indicators: {sem['credential_indicators']}")
    print(f"  Payment Indicators: {sem['payment_indicators']}")
    print(f"  Urgency Indicators: {sem['urgency_indicators']}")
    print()

# Analyze brand/impersonation signals
print("=" * 80)
print("D. BRAND/IMPERSONATION SIGNALS")
print("=" * 80)
print()

for site in suspicious_sites:
    print(f"URL: {site['url']}")
    struct = site['structural_analysis']
    sem = site['semantic_analysis']
    print(f"  Brand Impersonation Score: {struct['brand_impersonation_score']}")
    print(f"  Subdomain Brand Match: {struct['subdomain_brand_match']}")
    print(f"  Brand Indicators: {sem['brand_indicators']}")
    print(f"  Domain Brand Consistency: {sem['domain_brand_consistency']}")
    print(f"  Trusted Domain: {sem['trusted_domain']}")
    print(f"  Brand Context Score: {sem['brand_context_score']}")
    print()

# Compare with SAFE sites
print("=" * 80)
print("E. COMPARISON WITH SAFE SITES")
print("=" * 80)
print()

print("SAFE Sites:")
for site in safe_sites:
    print(f"  {site['url']}: risk={site['risk_score']}, struct={site['structural_score']}, sem={site['semantic_score']}")
    print(f"    login_indicators={site['semantic_analysis']['login_indicators']}")
    print(f"    credential_indicators={site['semantic_analysis']['credential_indicators']}")
    print(f"    external_links={site['semantic_analysis']['external_links']}")
    print(f"    is_shortening={site['structural_analysis']['is_shortening']}")
    print()

# Identify patterns
print("=" * 80)
print("F. REPEATING PATTERNS IN SUSPICIOUS SITES")
print("=" * 80)
print()

patterns = {
    'high_login_indicators': [],
    'high_credential_indicators': [],
    'high_external_links': [],
    'is_shortening_flag': [],
    'low_trusted_domain': [],
    'low_domain_brand_consistency': []
}

for site in suspicious_sites:
    sem = site['semantic_analysis']
    struct = site['structural_analysis']
    
    if sem['login_indicators'] >= 5:
        patterns['high_login_indicators'].append(site['url'])
    if sem['credential_indicators'] >= 5:
        patterns['high_credential_indicators'].append(site['url'])
    if sem['external_links'] >= 30:
        patterns['high_external_links'].append(site['url'])
    if struct['is_shortening'] == 1:
        patterns['is_shortening_flag'].append(site['url'])
    if sem['trusted_domain'] == 0:
        patterns['low_trusted_domain'].append(site['url'])
    if sem['domain_brand_consistency'] == 0:
        patterns['low_domain_brand_consistency'].append(site['url'])

for pattern, urls in patterns.items():
    if urls:
        print(f"{pattern}:")
        for url in urls:
            print(f"  - {url}")
    print()

# Critical findings
print("=" * 80)
print("CRITICAL FINDINGS")
print("=" * 80)
print()

print("1. URL SHORTENER BUG:")
print("   Microsoft (www.microsoft.com) has is_shortening=1")
print("   This is INCORRECT - Microsoft is NOT a URL shortener service")
print("   This is a FALSE POSITIVE in structural feature extraction")
print()

print("2. TRUSTED DOMAIN BUG:")
print("   Wikipedia (www.wikipedia.org) has trusted_domain=0.0")
print("   This is INCORRECT - Wikipedia is a well-known trusted domain")
print("   This suggests the trusted domain whitelist is incomplete")
print()

print("3. DOMAIN BRAND CONSISTENCY BUG:")
print("   Wikipedia (www.wikipedia.org) has domain_brand_consistency=0.0")
print("   This is INCORRECT - Wikipedia is a legitimate brand")
print("   This suggests the brand detection logic has issues")
print()

print("4. LEGITIMATE AUTHENTICATION PAGES:")
print("   GitHub, PayPal, Microsoft have high login/credential indicators")
print("   These are LEGITIMATE authentication pages, NOT phishing")
print("   The semantic features are working correctly - detecting login pages")
print("   The issue is that legitimate login pages are being flagged as SUSPICIOUS")
print()

print("5. EXTERNAL LINKS COUNT:")
print("   Wikipedia has 374 external links - flagged as 'cloaking'")
print("   This is a legitimate content-rich site, not cloaking")
print("   The external_links threshold may be too aggressive")
print()

print("=" * 80)
print("ANALYSIS COMPLETE")
print("=" * 80)
