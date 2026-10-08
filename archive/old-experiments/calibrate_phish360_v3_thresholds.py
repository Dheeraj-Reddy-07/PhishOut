"""
Phish360 V3 Threshold Calibration
===================================
Calibrates verdict thresholds (SAFE_MAX, PHISHING_MIN) for V3 fusion model.

Uses grid search on validation set to maximize F1 score.

Usage:
    python calibrate_phish360_v3_thresholds.py
"""
import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, precision_score, recall_score

# Paths
V2_MODELS_DIR = os.path.join(os.path.dirname(__file__), "models", "phish360_v2")
V3_MODELS_DIR = os.path.join(os.path.dirname(__file__), "models", "phish360_v3")
V3_DATA_DIR = os.path.join(os.path.dirname(__file__), "dataset", "phish360", "v3", "processed")

# Structural feature column names (32 features - same as V2)
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

# Semantic feature column names (V3: 19 features including V2 context + V3 new features)
SEMANTIC_FEATURES_V3 = [
    'password_fields', 'text_email_fields', 'forms', 'external_links',
    'iframes', 'scripts', 'login_indicators', 'credential_indicators',
    'payment_indicators', 'urgency_indicators', 'brand_indicators', 'text_length',
    # V2 context features
    'domain_brand_consistency', 'form_action_same_origin', 'trusted_domain',
    # V3 new features
    'link_to_form_ratio', 'text_to_script_ratio', 'credential_density', 'brand_context_score'
]


def assign_verdict(risk_score, safe_max, phishing_min):
    """Assign verdict based on risk score and thresholds."""
    if risk_score >= phishing_min:
        return "PHISHING"
    elif risk_score >= safe_max:
        return "SUSPICIOUS"
    else:
        return "SAFE"


def main():
    print("=" * 70)
    print("  Phish360 V3 Threshold Calibration")
    print("=" * 70)

    # Load V3 validation set
    val_path = os.path.join(V3_DATA_DIR, "validation_features.parquet")
    
    if not os.path.exists(val_path):
        print("[ERROR] V3 validation features not found.")
        print(f"Expected: {val_path}")
        return

    val_df = pd.read_parquet(val_path)
    print(f"\nValidation set: {len(val_df):,} samples")

    # Load V2 structural model (frozen)
    struct_model_path = os.path.join(V2_MODELS_DIR, "structural_model.pkl")
    struct_scaler_path = os.path.join(V2_MODELS_DIR, "structural_scaler.pkl")

    # Load V3 semantic model
    sem_model_path = os.path.join(V3_MODELS_DIR, "semantic_model.pkl")
    sem_scaler_path = os.path.join(V3_MODELS_DIR, "semantic_scaler.pkl")
    fusion_model_path = os.path.join(V3_MODELS_DIR, "fusion_model.pkl")

    if not all(os.path.exists(p) for p in [struct_model_path, struct_scaler_path, sem_model_path, sem_scaler_path, fusion_model_path]):
        print("[ERROR] V3 models not found.")
        return

    print("\n[*] Loading V2 structural model (frozen)...")
    struct_model = joblib.load(struct_model_path)
    struct_scaler = joblib.load(struct_scaler_path)

    print("[*] Loading V3 semantic model...")
    sem_model = joblib.load(sem_model_path)
    sem_scaler = joblib.load(sem_scaler_path)

    print("[*] Loading V3 fusion model...")
    fusion_model = joblib.load(fusion_model_path)

    # Extract features
    X_val_struct = val_df[STRUCTURAL_FEATURES].fillna(0).values.astype(np.float32)
    X_val_sem = val_df[SEMANTIC_FEATURES_V3].fillna(0).values.astype(np.float32)
    y_val = val_df['label'].values.astype(int)

    # Get probabilities
    print("[*] Computing probabilities...")
    X_val_struct_scaled = struct_scaler.transform(X_val_struct)
    p_val_struct = struct_model.predict_proba(X_val_struct_scaled)[:, 1]

    X_val_sem_scaled = sem_scaler.transform(X_val_sem)
    p_val_sem = sem_model.predict_proba(X_val_sem_scaled)[:, 1]

    # Get fusion probabilities
    X_fusion_val = np.column_stack([p_val_struct, p_val_sem])
    p_fusion_val = fusion_model.predict_proba(X_fusion_val)[:, 1]

    # Grid search for optimal thresholds
    print("\n[*] Grid search for optimal thresholds...")
    best_f1 = 0
    best_safe_max = 15
    best_phishing_min = 57
    best_precision = 0
    best_recall = 0

    # Search space
    safe_max_values = range(5, 30, 5)  # 5, 10, 15, 20, 25
    phishing_min_values = range(40, 80, 5)  # 40, 45, 50, ..., 75

    for safe_max in safe_max_values:
        for phishing_min in phishing_min_values:
            if safe_max >= phishing_min:
                continue
            
            # Convert probabilities to risk scores (0-100)
            risk_scores = (p_fusion_val * 100).astype(int)
            
            # Assign verdicts
            y_pred = (risk_scores >= phishing_min).astype(int)
            
            # Calculate F1
            f1 = f1_score(y_val, y_pred)
            precision = precision_score(y_val, y_pred)
            recall = recall_score(y_val, y_pred)
            
            if f1 > best_f1:
                best_f1 = f1
                best_safe_max = safe_max
                best_phishing_min = phishing_min
                best_precision = precision
                best_recall = recall

    print(f"\n[*] Best thresholds found:")
    print(f"    SAFE_MAX: {best_safe_max}")
    print(f"    PHISHING_MIN: {best_phishing_min}")
    print(f"    Validation F1: {best_f1:.4f}")
    print(f"    Validation Precision: {best_precision:.4f}")
    print(f"    Validation Recall: {best_recall:.4f}")

    # Save threshold config
    threshold_config = {
        "safe_max_probability": best_safe_max / 100.0,
        "phishing_min_probability": best_phishing_min / 100.0,
        "safe_max_risk_score": best_safe_max,
        "phishing_min_risk_score": best_phishing_min,
        "validation_f1": best_f1,
        "validation_precision": best_precision,
        "validation_recall": best_recall,
        "calibration_set_size": len(val_df),
        "calibration_method": "grid_search_maximize_f1"
    }

    threshold_config_path = os.path.join(V3_MODELS_DIR, "threshold_config.json")
    with open(threshold_config_path, "w") as f:
        json.dump(threshold_config, f, indent=2)
    print(f"\n[+] Threshold config saved: {threshold_config_path}")

    # Evaluate on test set with new thresholds
    print("\n" + "=" * 70)
    print("  Test Set Evaluation with Calibrated Thresholds")
    print("=" * 70)

    test_path = os.path.join(V3_DATA_DIR, "test_features.parquet")
    test_df = pd.read_parquet(test_path)
    print(f"Test set: {len(test_df):,} samples")

    X_test_struct = test_df[STRUCTURAL_FEATURES].fillna(0).values.astype(np.float32)
    X_test_sem = test_df[SEMANTIC_FEATURES_V3].fillna(0).values.astype(np.float32)
    y_test = test_df['label'].values.astype(int)

    X_test_struct_scaled = struct_scaler.transform(X_test_struct)
    p_test_struct = struct_model.predict_proba(X_test_struct_scaled)[:, 1]

    X_test_sem_scaled = sem_scaler.transform(X_test_sem)
    p_test_sem = sem_model.predict_proba(X_test_sem_scaled)[:, 1]

    X_fusion_test = np.column_stack([p_test_struct, p_test_sem])
    p_fusion_test = fusion_model.predict_proba(X_fusion_test)[:, 1]

    risk_scores = (p_fusion_test * 100).astype(int)
    y_pred_test = (risk_scores >= best_phishing_min).astype(int)

    test_f1 = f1_score(y_test, y_pred_test)
    test_precision = precision_score(y_test, y_pred_test)
    test_recall = recall_score(y_test, y_pred_test)

    print(f"    Test F1: {test_f1:.4f}")
    print(f"    Test Precision: {test_precision:.4f}")
    print(f"    Test Recall: {test_recall:.4f}")

    # Update threshold config with test results
    threshold_config["test_f1"] = test_f1
    threshold_config["test_precision"] = test_precision
    threshold_config["test_recall"] = test_recall

    with open(threshold_config_path, "w") as f:
        json.dump(threshold_config, f, indent=2)

    print("\n" + "=" * 70)
    print("  V3 Threshold calibration complete.")
    print("=" * 70)


if __name__ == "__main__":
    main()
