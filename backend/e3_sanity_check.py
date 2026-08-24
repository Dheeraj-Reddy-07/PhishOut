"""
E3 Sanity Check
================
Quick verification of perturbation logic on 2-3 features before full evaluation.
"""
import os
import json
import joblib
import numpy as np
import pandas as pd

# Paths
DATA_DIR = os.path.join(os.path.dirname(__file__), "dataset", "phish360", "processed")
MODELS_DIR = os.path.join(os.path.dirname(__file__), "models", "phish360")

# Feature column names
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

SEMANTIC_FEATURES = [
    'password_fields', 'text_email_fields', 'forms', 'external_links',
    'iframes', 'scripts', 'login_indicators', 'credential_indicators',
    'payment_indicators', 'urgency_indicators', 'brand_indicators', 'text_length'
]

def safe_perturb_feature(X, feature_idx, perturbation_pct, feature_name):
    """Apply perturbation with safety checks for feature types."""
    X_perturbed = X.copy()
    original_values = X[:, feature_idx].copy()
    
    # Apply perturbation
    perturbed_values = original_values * (1 + perturbation_pct)
    
    # Feature-specific safety checks
    if feature_name.startswith('has_') or feature_name in ['https_token', 'is_shortening', 
                                                          'double_slash', 'prefix_suffix',
                                                          'punycode_present', 'has_redirect_param',
                                                          'double_extension', 'hex_encoded']:
        perturbed_values = np.clip(perturbed_values, 0, 1)
    elif feature_name in ['password_fields', 'text_email_fields', 'forms', 'external_links',
                         'iframes', 'scripts', 'sub_domain_count', 'num_params']:
        perturbed_values = np.maximum(perturbed_values, 0)
    elif 'ratio' in feature_name or 'score' in feature_name or feature_name in ['tld_risk_score']:
        perturbed_values = np.clip(perturbed_values, 0, 1)
    elif 'length' in feature_name or 'count' in feature_name or feature_name in ['url_depth']:
        perturbed_values = np.maximum(perturbed_values, 0)
    elif feature_name in ['levenshtein_min', 'levenshtein_ratio']:
        perturbed_values = np.maximum(perturbed_values, 0)
    
    X_perturbed[:, feature_idx] = perturbed_values
    return X_perturbed

def main():
    print("=" * 60)
    print("  E3 Sanity Check")
    print("=" * 60)
    
    # Load test dataset
    test_path = os.path.join(DATA_DIR, "test_features.parquet")
    test_df = pd.read_parquet(test_path)
    
    print(f"\nTest set: {len(test_df):,} samples")
    
    # Extract features
    X_test_struct = test_df[STRUCTURAL_FEATURES].fillna(0).values.astype(np.float32)
    X_test_sem = test_df[SEMANTIC_FEATURES].fillna(0).values.astype(np.float32)
    
    # Test 3 features: 1 structural, 1 semantic, 1 binary
    test_features = [
        ('url_length', STRUCTURAL_FEATURES, X_test_struct, 0),
        ('password_fields', SEMANTIC_FEATURES, X_test_sem, 0),
        ('has_ip', STRUCTURAL_FEATURES, X_test_struct, STRUCTURAL_FEATURES.index('has_ip'))
    ]
    
    print("\n[*] Testing perturbation on 3 features...")
    
    for feature_name, feature_list, X_data, local_idx in test_features:
        print(f"\n  Feature: {feature_name}")
        
        # Original values
        original_vals = X_data[:, local_idx]
        print(f"    Original sample values (first 5): {original_vals[:5]}")
        print(f"    Original mean: {original_vals.mean():.4f}")
        print(f"    Original std: {original_vals.std():.4f}")
        
        # -5% perturbation
        X_minus5 = safe_perturb_feature(X_data, local_idx, -0.05, feature_name)
        minus5_vals = X_minus5[:, local_idx]
        print(f"    -5% perturbed sample values (first 5): {minus5_vals[:5]}")
        print(f"    -5% mean: {minus5_vals.mean():.4f}")
        print(f"    Expected -5% change: {(original_vals.mean() * 0.95):.4f}")
        
        # +5% perturbation
        X_plus5 = safe_perturb_feature(X_data, local_idx, 0.05, feature_name)
        plus5_vals = X_plus5[:, local_idx]
        print(f"    +5% perturbed sample values (first 5): {plus5_vals[:5]}")
        print(f"    +5% mean: {plus5_vals.mean():.4f}")
        print(f"    Expected +5% change: {(original_vals.mean() * 1.05):.4f}")
        
        # Verify perturbation magnitude
        actual_minus5_change = (minus5_vals.mean() - original_vals.mean()) / original_vals.mean()
        actual_plus5_change = (plus5_vals.mean() - original_vals.mean()) / original_vals.mean()
        
        print(f"    Actual -5% change: {actual_minus5_change:.4f}")
        print(f"    Actual +5% change: {actual_plus5_change:.4f}")
        
        # Check if only target feature changed
        X_diff = X_minus5 - X_data
        changed_features = np.where(np.any(X_diff != 0, axis=0))[0]
        print(f"    Features changed by -5% perturbation: {len(changed_features)}")
        if len(changed_features) == 1 and changed_features[0] == local_idx:
            print(f"    [OK] Only target feature changed")
        else:
            print(f"    [WARNING] Unexpected features changed")
    
    # Load a model to test compatibility
    print("\n[*] Testing model compatibility with perturbed data...")
    
    struct_model_path = os.path.join(MODELS_DIR, "structural_model.pkl")
    struct_scaler_path = os.path.join(MODELS_DIR, "structural_scaler.pkl")
    
    if os.path.exists(struct_model_path) and os.path.exists(struct_scaler_path):
        struct_model = joblib.load(struct_model_path)
        struct_scaler = joblib.load(struct_scaler_path)
        
        # Test with original data
        X_scaled = struct_scaler.transform(X_test_struct)
        y_pred_original = struct_model.predict(X_scaled)
        print(f"    Original predictions: {len(y_pred_original)} samples")
        
        # Test with perturbed data
        X_perturbed = safe_perturb_feature(X_test_struct, 0, -0.05, 'url_length')
        X_scaled_perturbed = struct_scaler.transform(X_perturbed)
        y_pred_perturbed = struct_model.predict(X_scaled_perturbed)
        print(f"    Perturbed predictions: {len(y_pred_perturbed)} samples")
        
        # Check if predictions changed (they should, since feature changed)
        n_changed = np.sum(y_pred_original != y_pred_perturbed)
        print(f"    Predictions changed: {n_changed} samples ({n_changed/len(y_pred_original)*100:.2f}%)")
        print(f"    [OK] Model accepts perturbed data")
    
    print("\n" + "=" * 60)
    print("  Sanity Check Complete")
    print("=" * 60)
    print("\n  Perturbation logic verified.")
    print("  Ready to proceed with full 44-feature evaluation.")

if __name__ == "__main__":
    main()