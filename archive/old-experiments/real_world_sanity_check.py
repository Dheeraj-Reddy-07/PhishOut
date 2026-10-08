"""
Real-World Sanity Check for V2 vs V3
======================================
Tests V2 and V3 on known legitimate URLs to verify V3 doesn't degrade
real-world false positive performance.

Test URLs:
- Google
- Microsoft
- Gemini
- PayPal
- Wikipedia
"""
import os
import json
import joblib
import numpy as np
import requests
from bs4 import BeautifulSoup
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

from ml_model import extract_features as extract_structural_features
from webpage_analyzer import extract_semantic_features

# Paths
V2_MODELS_DIR = "models/phish360_v2"
V3_MODELS_DIR = "models/phish360_v3"

# Test URLs
TEST_URLS = [
    "https://www.google.com",
    "https://www.microsoft.com",
    "https://gemini.google.com",
    "https://www.paypal.com",
    "https://www.wikipedia.org"
]

# Structural features
STRUCTURAL_FEATURES = [
    'url_length', 'hostname_length', 'path_length', 'query_length', 'url_depth',
    'num_params', 'has_ip', 'has_at', 'has_port', 'double_slash', 'prefix_suffix',
    'sub_domain_count', 'excessive_dots', 'numeric_subdomain', 'punycode_present',
    'https_token', 'is_shortening', 'tld_risk_score', 'has_redirect_param',
    'double_extension', 'hex_encoded', 'domain_entropy', 'digit_ratio',
    'special_char_count', 'consonant_ratio', 'longest_word_length',
    'brand_impersonation_score', 'subdomain_brand_match', 'suspicious_keywords',
    'login_path_score', 'levenshtein_min', 'levenshtein_ratio'
]

# V2 Semantic features (15)
SEMANTIC_FEATURES_V2 = [
    'password_fields', 'text_email_fields', 'forms', 'external_links',
    'iframes', 'scripts', 'login_indicators', 'credential_indicators',
    'payment_indicators', 'urgency_indicators', 'brand_indicators', 'text_length',
    'domain_brand_consistency', 'form_action_same_origin', 'trusted_domain'
]

# V3 Semantic features (19)
SEMANTIC_FEATURES_V3 = [
    'password_fields', 'text_email_fields', 'forms', 'external_links',
    'iframes', 'scripts', 'login_indicators', 'credential_indicators',
    'payment_indicators', 'urgency_indicators', 'brand_indicators', 'text_length',
    'domain_brand_consistency', 'form_action_same_origin', 'trusted_domain',
    'link_to_form_ratio', 'text_to_script_ratio', 'credential_density', 'brand_context_score'
]

def fetch_html(url):
    """Fetch HTML from URL."""
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"  Error fetching {url}: {e}")
        return None

def main():
    print("=" * 80)
    print("Real-World Sanity Check: V2 vs V3")
    print("=" * 80)
    
    # Load V2 models
    print("\n[*] Loading V2 models...")
    v2_struct_model = joblib.load(os.path.join(V2_MODELS_DIR, "structural_model.pkl"))
    v2_struct_scaler = joblib.load(os.path.join(V2_MODELS_DIR, "structural_scaler.pkl"))
    v2_sem_model = joblib.load(os.path.join(V2_MODELS_DIR, "semantic_model.pkl"))
    v2_sem_scaler = joblib.load(os.path.join(V2_MODELS_DIR, "semantic_scaler.pkl"))
    v2_fusion_model = joblib.load(os.path.join(V2_MODELS_DIR, "fusion_model.pkl"))
    
    with open(os.path.join(V2_MODELS_DIR, "threshold_config.json")) as f:
        v2_threshold_config = json.load(f)
    v2_phishing_min = v2_threshold_config['phishing_min_probability']
    
    # Load V3 models
    print("[*] Loading V3 models...")
    v3_sem_model = joblib.load(os.path.join(V3_MODELS_DIR, "semantic_model.pkl"))
    v3_sem_scaler = joblib.load(os.path.join(V3_MODELS_DIR, "semantic_scaler.pkl"))
    v3_fusion_model = joblib.load(os.path.join(V3_MODELS_DIR, "fusion_model.pkl"))
    
    with open(os.path.join(V3_MODELS_DIR, "threshold_config.json")) as f:
        v3_threshold_config = json.load(f)
    v3_phishing_min = v3_threshold_config['phishing_min_probability']
    
    print(f"V2 PHISHING_MIN: {v2_phishing_min}")
    print(f"V3 PHISHING_MIN: {v3_phishing_min}")
    
    # Test each URL
    results = []
    for url in TEST_URLS:
        print(f"\n{'=' * 80}")
        print(f"Testing: {url}")
        print('=' * 80)
        
        # Fetch HTML
        html = fetch_html(url)
        if html is None:
            print(f"  Skipping {url} - failed to fetch")
            continue
        
        # Extract features
        try:
            struct_feats = extract_structural_features(url)
            sem_feats_v2 = extract_semantic_features(html, url)
            sem_feats_v3 = extract_semantic_features(html, url)  # Same extraction, V3 has extra features
        except Exception as e:
            print(f"  Error extracting features: {e}")
            continue
        
        # Prepare feature vectors
        X_struct = np.array([struct_feats.get(f, 0) for f in STRUCTURAL_FEATURES]).reshape(1, -1).astype(np.float32)
        X_sem_v2 = np.array([sem_feats_v2.get(f, 0) for f in SEMANTIC_FEATURES_V2]).reshape(1, -1).astype(np.float32)
        X_sem_v3 = np.array([sem_feats_v3.get(f, 0) for f in SEMANTIC_FEATURES_V3]).reshape(1, -1).astype(np.float32)
        
        # V2 predictions
        X_struct_scaled = v2_struct_scaler.transform(X_struct)
        p_struct = v2_struct_model.predict_proba(X_struct_scaled)[:, 1]
        
        X_sem_v2_scaled = v2_sem_scaler.transform(X_sem_v2)
        p_sem_v2 = v2_sem_model.predict_proba(X_sem_v2_scaled)[:, 1]
        
        X_fusion_v2 = np.column_stack([p_struct, p_sem_v2])
        p_fusion_v2 = v2_fusion_model.predict_proba(X_fusion_v2)[:, 1]
        v2_verdict = "PHISHING" if p_fusion_v2[0] >= v2_phishing_min else "SAFE"
        
        # V3 predictions
        X_sem_v3_scaled = v3_sem_scaler.transform(X_sem_v3)
        p_sem_v3 = v3_sem_model.predict_proba(X_sem_v3_scaled)[:, 1]
        
        X_fusion_v3 = np.column_stack([p_struct, p_sem_v3])
        p_fusion_v3 = v3_fusion_model.predict_proba(X_fusion_v3)[:, 1]
        v3_verdict = "PHISHING" if p_fusion_v3[0] >= v3_phishing_min else "SAFE"
        
        # Record results
        result = {
            "url": url,
            "v2_struct_prob": float(p_struct[0]),
            "v2_sem_prob": float(p_sem_v2[0]),
            "v2_fusion_prob": float(p_fusion_v2[0]),
            "v2_verdict": v2_verdict,
            "v3_sem_prob": float(p_sem_v3[0]),
            "v3_fusion_prob": float(p_fusion_v3[0]),
            "v3_verdict": v3_verdict,
            "v3_new_features": {
                "link_to_form_ratio": sem_feats_v3.get("link_to_form_ratio", 0),
                "text_to_script_ratio": sem_feats_v3.get("text_to_script_ratio", 0),
                "credential_density": sem_feats_v3.get("credential_density", 0),
                "brand_context_score": sem_feats_v3.get("brand_context_score", 0),
            },
            "script_count": sem_feats_v3.get("scripts", 0),
            "text_length": sem_feats_v3.get("text_length", 0)
        }
        results.append(result)
        
        # Print results
        print(f"  V2: struct={result['v2_struct_prob']:.3f}, sem={result['v2_sem_prob']:.3f}, fusion={result['v2_fusion_prob']:.3f}, verdict={v2_verdict}")
        print(f"  V3: struct={result['v2_struct_prob']:.3f}, sem={result['v3_sem_prob']:.3f}, fusion={result['v3_fusion_prob']:.3f}, verdict={v3_verdict}")
        print(f"  V3 new features:")
        print(f"    link_to_form_ratio: {result['v3_new_features']['link_to_form_ratio']:.2f}")
        print(f"    text_to_script_ratio: {result['v3_new_features']['text_to_script_ratio']:.2f}")
        print(f"    credential_density: {result['v3_new_features']['credential_density']:.4f}")
        print(f"    brand_context_score: {result['v3_new_features']['brand_context_score']:.4f}")
        print(f"  Script count: {result['script_count']}")
        print(f"  Text length: {result['text_length']}")
    
    # Summary
    print("\n" + "=" * 80)
    print("Summary")
    print("=" * 80)
    
    v2_safe = sum(1 for r in results if r['v2_verdict'] == "SAFE")
    v3_safe = sum(1 for r in results if r['v3_verdict'] == "SAFE")
    
    print(f"V2 SAFE: {v2_safe}/{len(results)}")
    print(f"V3 SAFE: {v3_safe}/{len(results)}")
    
    if v3_safe < v2_safe:
        print(f"\nWARNING: V3 has MORE false positives on real-world URLs")
        for r in results:
            if r['v2_verdict'] == "SAFE" and r['v3_verdict'] == "PHISHING":
                print(f"  {r['url']}: V2 SAFE -> V3 PHISHING")
    
    # Save results
    sanity_check_path = os.path.join(V3_MODELS_DIR, "real_world_sanity_check.json")
    with open(sanity_check_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Sanity check results saved: {sanity_check_path}")


if __name__ == "__main__":
    main()
