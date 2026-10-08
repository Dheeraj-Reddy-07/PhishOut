"""
V3 Results Audit Script
=======================
Performs detailed read-only investigation of V3 vs V2 comparison.

Investigates:
1. Whether V2/V3 comparison is valid
2. Why V3 produces 11 hard-negative false positives
3. Hard-negative dataset quality
4. Sample alignment between V2 and V3 datasets
"""
import os
import json
import joblib
import numpy as np
import pandas as pd

# Paths
V2_MODELS_DIR = os.path.join(os.path.dirname(__file__), "models", "phish360_v2")
V3_MODELS_DIR = os.path.join(os.path.dirname(__file__), "models", "phish360_v3")
V3_DATA_DIR = os.path.join(os.path.dirname(__file__), "dataset", "phish360", "v3", "processed")
V2_DATA_DIR = os.path.join(os.path.dirname(__file__), "dataset", "phish360", "v2", "processed")

# Structural features (32 - same for V2 and V3)
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

def main():
    print("=" * 80)
    print("V3 Results Audit")
    print("=" * 80)

    # 1. Verify V2 saved artifacts
    print("\n" + "=" * 80)
    print("1. Verify V2 Saved Artifacts")
    print("=" * 80)
    
    with open(os.path.join(V2_MODELS_DIR, "threshold_config.json")) as f:
        v2_threshold_config = json.load(f)
    print(f"V2 PHISHING_MIN: {v2_threshold_config['phishing_min_probability']}")
    print(f"V2 saved test recall: {v2_threshold_config['test_recall']:.4f}")
    print(f"V2 saved test F1: {v2_threshold_config['test_f1']:.4f}")

    with open(os.path.join(V2_MODELS_DIR, "fusion_results.json")) as f:
        v2_fusion_results = json.load(f)
    print(f"V2 fusion test recall: {v2_fusion_results['test_metrics']['recall']:.4f}")
    print(f"V2 fusion test F1: {v2_fusion_results['test_metrics']['f1']:.4f}")
    print(f"V2 fusion test FPR: {v2_fusion_results['test_metrics']['confusion_matrix']['fp'] / (v2_fusion_results['test_metrics']['confusion_matrix']['tn'] + v2_fusion_results['test_metrics']['confusion_matrix']['fp']):.4f}")

    # 2. Check if V2 and V3 test sets are the same
    print("\n" + "=" * 80)
    print("2. Check V2 vs V3 Test Set Alignment")
    print("=" * 80)
    
    v2_test_path = os.path.join(V2_DATA_DIR, "test_features.parquet")
    v3_test_path = os.path.join(V3_DATA_DIR, "test_features.parquet")
    
    if os.path.exists(v2_test_path):
        v2_test_df = pd.read_parquet(v2_test_path)
        print(f"V2 test set: {len(v2_test_df)} samples")
        print(f"V2 test columns: {len(v2_test_df.columns)}")
        print(f"V2 test label distribution: {v2_test_df['label'].value_counts().to_dict()}")
    else:
        print("V2 test set not found - V2 and V3 may use different test sets")
        v2_test_df = None
    
    v3_test_df = pd.read_parquet(v3_test_path)
    print(f"V3 test set: {len(v3_test_df)} samples")
    print(f"V3 test columns: {len(v3_test_df.columns)}")
    print(f"V3 test label distribution: {v3_test_df['label'].value_counts().to_dict()}")

    if v2_test_df is not None:
        # Check if they have the same samples (by URL if available)
        if 'url' in v2_test_df.columns and 'url' in v3_test_df.columns:
            v2_urls = set(v2_test_df['url'].tolist())
            v3_urls = set(v3_test_df['url'].tolist())
            print(f"URL overlap: {len(v2_urls & v3_urls)} / {len(v2_urls)} V2 samples")
        else:
            print("Cannot compare by URL - URL column not available")

    # 3. Check hard-negative dataset
    print("\n" + "=" * 80)
    print("3. Hard-Negative Dataset Analysis")
    print("=" * 80)
    
    hn_manifest_path = os.path.join(V3_DATA_DIR, "../hard_negatives/hard_neg_manifest.json")
    if os.path.exists(hn_manifest_path):
        with open(hn_manifest_path) as f:
            hn_manifest = json.load(f)
        print(f"Hard-negative source: {hn_manifest['source_file']}")
        print(f"Filter criteria: {hn_manifest['filter_criteria']}")
        print(f"Pool statistics: {hn_manifest['pool_statistics']}")
        print(f"Split statistics: {hn_manifest['split_statistics']}")
    else:
        print("Hard-negative manifest not found")

    hn_eval_path = os.path.join(V3_DATA_DIR, "hard_neg_eval_features.parquet")
    hn_eval_df = pd.read_parquet(hn_eval_path)
    print(f"\nHard-negative eval set: {len(hn_eval_df)} samples")
    print(f"Label distribution: {hn_eval_df['label'].value_counts().to_dict()}")
    
    if 'url' in hn_eval_df.columns:
        print(f"Sample URLs (first 10):")
        for i, url in enumerate(hn_eval_df['url'].head(10).tolist()):
            print(f"  {i+1}. {url}")

    # 4. Investigate the 11 V3 false positives
    print("\n" + "=" * 80)
    print("4. Investigate V3 Hard-Negative False Positives")
    print("=" * 80)
    
    # Load V3 models
    v2_struct_model = joblib.load(os.path.join(V2_MODELS_DIR, "structural_model.pkl"))
    v2_struct_scaler = joblib.load(os.path.join(V2_MODELS_DIR, "structural_scaler.pkl"))
    v2_sem_model = joblib.load(os.path.join(V2_MODELS_DIR, "semantic_model.pkl"))
    v2_sem_scaler = joblib.load(os.path.join(V2_MODELS_DIR, "semantic_scaler.pkl"))
    v2_fusion_model = joblib.load(os.path.join(V2_MODELS_DIR, "fusion_model.pkl"))
    
    v3_sem_model = joblib.load(os.path.join(V3_MODELS_DIR, "semantic_model.pkl"))
    v3_sem_scaler = joblib.load(os.path.join(V3_MODELS_DIR, "semantic_scaler.pkl"))
    v3_fusion_model = joblib.load(os.path.join(V3_MODELS_DIR, "fusion_model.pkl"))
    
    v2_phishing_min = v2_threshold_config['phishing_min_probability']
    
    with open(os.path.join(V3_MODELS_DIR, "threshold_config.json")) as f:
        v3_threshold_config = json.load(f)
    v3_phishing_min = v3_threshold_config['phishing_min_probability']
    
    print(f"V2 PHISHING_MIN: {v2_phishing_min}")
    print(f"V3 PHISHING_MIN: {v3_phishing_min}")
    
    # Get V3 predictions on hard-negatives
    X_hn_struct = hn_eval_df[STRUCTURAL_FEATURES].fillna(0).values.astype(np.float32)
    X_hn_sem_v3 = hn_eval_df[SEMANTIC_FEATURES_V3].fillna(0).values.astype(np.float32)
    
    X_hn_struct_scaled = v2_struct_scaler.transform(X_hn_struct)
    p_hn_struct = v2_struct_model.predict_proba(X_hn_struct_scaled)[:, 1]
    
    X_hn_sem_v3_scaled = v3_sem_scaler.transform(X_hn_sem_v3)
    p_hn_sem_v3 = v3_sem_model.predict_proba(X_hn_sem_v3_scaled)[:, 1]
    
    X_fusion_hn_v3 = np.column_stack([p_hn_struct, p_hn_sem_v3])
    p_fusion_hn_v3 = v3_fusion_model.predict_proba(X_fusion_hn_v3)[:, 1]
    
    y_pred_hn_v3 = (p_fusion_hn_v3 >= v3_phishing_min).astype(int)
    
    # Get V2 predictions on hard-negatives (using V2 semantic features)
    X_hn_sem_v2 = hn_eval_df[SEMANTIC_FEATURES_V2].fillna(0).values.astype(np.float32)
    X_hn_sem_v2_scaled = v2_sem_scaler.transform(X_hn_sem_v2)
    p_hn_sem_v2 = v2_sem_model.predict_proba(X_hn_sem_v2_scaled)[:, 1]
    
    X_fusion_hn_v2 = np.column_stack([p_hn_struct, p_hn_sem_v2])
    p_fusion_hn_v2 = v2_fusion_model.predict_proba(X_fusion_hn_v2)[:, 1]
    
    y_pred_hn_v2 = (p_fusion_hn_v2 >= v2_phishing_min).astype(int)
    
    # Identify V3 false positives
    v3_fp_mask = (y_pred_hn_v3 == 1) & (hn_eval_df['label'].values == 0)
    v3_fp_indices = np.where(v3_fp_mask)[0]
    
    print(f"\nV3 false positives on hard-negatives: {len(v3_fp_indices)}")
    
    # Analyze each false positive
    fp_analysis = []
    for idx in v3_fp_indices:
        fp_info = {
            "index": int(idx),
            "url": hn_eval_df.iloc[idx]['url'] if 'url' in hn_eval_df.columns else "N/A",
            "domain": hn_eval_df.iloc[idx]['domain'] if 'domain' in hn_eval_df.columns else "N/A",
            "v2_struct_prob": float(p_hn_struct[idx]),
            "v2_sem_prob": float(p_hn_sem_v2[idx]),
            "v2_fusion_prob": float(p_fusion_hn_v2[idx]),
            "v2_verdict": "PHISHING" if y_pred_hn_v2[idx] == 1 else "SAFE",
            "v3_sem_prob": float(p_hn_sem_v3[idx]),
            "v3_fusion_prob": float(p_fusion_hn_v3[idx]),
            "v3_verdict": "PHISHING" if y_pred_hn_v3[idx] == 1 else "SAFE",
        }
        
        # Add V3 new features
        for feat in ['link_to_form_ratio', 'text_to_script_ratio', 'credential_density', 'brand_context_score']:
            if feat in hn_eval_df.columns:
                fp_info[feat] = float(hn_eval_df.iloc[idx][feat])
        
        fp_analysis.append(fp_info)
    
    # Print false positive analysis
    print("\nV3 False Positive Details:")
    for i, fp in enumerate(fp_analysis[:11]):  # Show all 11
        print(f"\nFP {i+1}: {fp['url'][:80]}")
        print(f"  V2: struct={fp['v2_struct_prob']:.3f}, sem={fp['v2_sem_prob']:.3f}, fusion={fp['v2_fusion_prob']:.3f}, verdict={fp['v2_verdict']}")
        print(f"  V3: struct={fp['v2_struct_prob']:.3f}, sem={fp['v3_sem_prob']:.3f}, fusion={fp['v3_fusion_prob']:.3f}, verdict={fp['v3_verdict']}")
        print(f"  V3 new features:")
        print(f"    link_to_form_ratio: {fp.get('link_to_form_ratio', 'N/A')}")
        print(f"    text_to_script_ratio: {fp.get('text_to_script_ratio', 'N/A')}")
        print(f"    credential_density: {fp.get('credential_density', 'N/A')}")
        print(f"    brand_context_score: {fp.get('brand_context_score', 'N/A')}")

    # 5. Check V2 vs V3 semantic feature correlation
    print("\n" + "=" * 80)
    print("5. V2 vs V3 Semantic Model Correlation on Hard-Negatives")
    print("=" * 80)
    
    correlation = np.corrcoef(p_hn_sem_v2, p_hn_sem_v3)[0, 1]
    print(f"Correlation between V2 and V3 semantic probabilities: {correlation:.4f}")
    
    # Check which samples V3 semantic model is more aggressive on
    v3_more_aggressive = p_hn_sem_v3 > p_hn_sem_v2
    print(f"V3 semantic more aggressive than V2: {v3_more_aggressive.sum()} / {len(v3_more_aggressive)} samples")
    print(f"Mean V2 semantic prob: {p_hn_sem_v2.mean():.4f}")
    print(f"Mean V3 semantic prob: {p_hn_sem_v3.mean():.4f}")

    # Save audit results
    audit_results = {
        "v2_artifacts_verified": {
            "threshold": v2_threshold_config,
            "fusion_results": v2_fusion_results
        },
        "test_set_alignment": {
            "v2_exists": v2_test_df is not None,
            "v2_samples": len(v2_test_df) if v2_test_df is not None else 0,
            "v3_samples": len(v3_test_df),
            "same_size": len(v2_test_df) == len(v3_test_df) if v2_test_df is not None else False
        },
        "hard_negative_dataset": {
            "manifest": hn_manifest if os.path.exists(hn_manifest_path) else None,
            "eval_samples": len(hn_eval_df),
            "v3_false_positives": len(v3_fp_indices)
        },
        "v3_false_positive_analysis": fp_analysis,
        "semantic_correlation": {
            "correlation": float(correlation),
            "v3_more_aggressive_count": int(v3_more_aggressive.sum()),
            "v3_more_aggressive_pct": float(v3_more_aggressive.mean()),
            "v2_mean_prob": float(p_hn_sem_v2.mean()),
            "v3_mean_prob": float(p_hn_sem_v3.mean())
        }
    }
    
    audit_path = os.path.join(V3_MODELS_DIR, "audit_results.json")
    with open(audit_path, "w") as f:
        json.dump(audit_results, f, indent=2)
    print(f"\n[+] Audit results saved: {audit_path}")

    print("\n" + "=" * 80)
    print("Audit Complete")
    print("=" * 80)


if __name__ == "__main__":
    main()
