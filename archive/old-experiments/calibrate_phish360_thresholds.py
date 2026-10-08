"""
Phish360 Threshold Calibration
===============================
Calibrates decision thresholds using the validation set only.

This script:
1. Uses the learned fusion model to generate validation probabilities
2. Finds optimal thresholds for SAFE/SUSPICIOUS/PHISHING categories
3. Saves threshold configuration for runtime use

The test set is NOT used for any threshold decisions.

Usage:
    python calibrate_phish360_thresholds.py
"""
import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, precision_score, recall_score

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


def find_optimal_thresholds(y_true, y_prob):
    """
    Find optimal SAFE_MAX and PHISHING_MIN thresholds using grid search.
    
    Maximizes F1 score on validation set.
    
    Returns:
        dict with optimal thresholds and corresponding metrics
    """
    best_f1 = -1
    best_thresholds = {}
    
    # Grid search over threshold combinations
    safe_candidates = np.arange(0.15, 0.46, 0.01)  # 15% to 45%
    phishing_candidates = np.arange(0.50, 0.86, 0.01)  # 50% to 85%
    
    print("[*] Grid searching over threshold combinations...")
    print(f"    SAFE_MAX range:     {safe_candidates[0]:.2f} - {safe_candidates[-1]:.2f}")
    print(f"    PHISHING_MIN range: {phishing_candidates[0]:.2f} - {phishing_candidates[-1]:.2f}")
    
    for safe_max in safe_candidates:
        for phishing_min in phishing_candidates:
            if safe_max >= phishing_min:
                continue
            
            # Convert probabilities to 3-class verdict
            # For F1 calculation, treat SUSPICIOUS as PHISHING (conservative)
            y_pred_binary = (y_prob >= phishing_min).astype(int)
            
            try:
                f1 = f1_score(y_true, y_pred_binary, zero_division=0)
                prec = precision_score(y_true, y_pred_binary, zero_division=0)
                rec = recall_score(y_true, y_pred_binary, zero_division=0)
            except:
                continue
            
            if f1 > best_f1:
                best_f1 = f1
                best_thresholds = {
                    'safe_max': safe_max,
                    'phishing_min': phishing_min,
                    'f1': f1,
                    'precision': prec,
                    'recall': rec
                }
    
    return best_thresholds


def main():
    print("=" * 70)
    print("  Phish360 Threshold Calibration")
    print("=" * 70)
    
    # Load validation dataset
    val_path = os.path.join(DATA_DIR, "validation_features.parquet")
    
    if not os.path.exists(val_path):
        print("[ERROR] Validation features not found.")
        print(f"Expected: {val_path}")
        return
    
    val_df = pd.read_parquet(val_path)
    print(f"\nValidation set: {len(val_df):,} samples")
    
    # Load trained models
    struct_model_path = os.path.join(MODELS_DIR, "structural_model.pkl")
    struct_scaler_path = os.path.join(MODELS_DIR, "structural_scaler.pkl")
    sem_model_path = os.path.join(MODELS_DIR, "semantic_model.pkl")
    sem_scaler_path = os.path.join(MODELS_DIR, "semantic_scaler.pkl")
    fusion_model_path = os.path.join(MODELS_DIR, "fusion_model.pkl")
    
    if not all(os.path.exists(p) for p in [struct_model_path, struct_scaler_path, 
                                            sem_model_path, sem_scaler_path, fusion_model_path]):
        print("[ERROR] Trained models not found.")
        print("Please run the training scripts first.")
        return
    
    print("[*] Loading models...")
    struct_model = joblib.load(struct_model_path)
    struct_scaler = joblib.load(struct_scaler_path)
    sem_model = joblib.load(sem_model_path)
    sem_scaler = joblib.load(sem_scaler_path)
    fusion_model = joblib.load(fusion_model_path)
    
    # Extract features
    X_val_struct = val_df[STRUCTURAL_FEATURES].fillna(0).values.astype(np.float32)
    X_val_sem = val_df[SEMANTIC_FEATURES].fillna(0).values.astype(np.float32)
    y_val = val_df['label'].values.astype(int)
    
    print(f"    Label distribution: Legit={sum(y_val==0):,}, Phish={sum(y_val==1):,}")
    
    # Generate probabilities
    print("\n[*] Generating probabilities...")
    X_val_struct_scaled = struct_scaler.transform(X_val_struct)
    struct_prob = struct_model.predict_proba(X_val_struct_scaled)[:, 1]
    
    X_val_sem_scaled = sem_scaler.transform(X_val_sem)
    sem_prob = sem_model.predict_proba(X_val_sem_scaled)[:, 1]
    
    # Apply learned fusion
    X_fusion = np.column_stack([struct_prob, sem_prob])
    fusion_prob = fusion_model.predict_proba(X_fusion)[:, 1]
    
    print(f"    Probability statistics:")
    print(f"      Mean:     {fusion_prob.mean():.4f}")
    print(f"      Std:      {fusion_prob.std():.4f}")
    print(f"      Min:      {fusion_prob.min():.4f}")
    print(f"      Max:      {fusion_prob.max():.4f}")
    print(f"      Median:   {np.median(fusion_prob):.4f}")
    
    # Find optimal thresholds
    print("\n[*] Finding optimal thresholds...")
    optimal = find_optimal_thresholds(y_val, fusion_prob)
    
    if not optimal:
        print("[ERROR] Could not find optimal thresholds.")
        return
    
    # Convert to risk scores (0-100)
    safe_max_score = int(round(optimal['safe_max'] * 100))
    phishing_min_score = int(round(optimal['phishing_min'] * 100))
    
    print("\n" + "=" * 70)
    print("  Optimal Thresholds (Validation Set)")
    print("=" * 70)
    print(f"  SAFE_MAX (probability):     {optimal['safe_max']:.2f}")
    print(f"  SAFE_MAX (risk score):      {safe_max_score}")
    print(f"  PHISHING_MIN (probability): {optimal['phishing_min']:.2f}")
    print(f"  PHISHING_MIN (risk score):  {phishing_min_score}")
    print(f"\n  Validation F1:    {optimal['f1']:.4f}")
    print(f"  Validation Precision: {optimal['precision']:.4f}")
    print(f"  Validation Recall:    {optimal['recall']:.4f}")
    
    print(f"\n  Interpretation:")
    print(f"    Risk score < {safe_max_score}       -> SAFE")
    print(f"    {safe_max_score} <= score < {phishing_min_score}  -> SUSPICIOUS")
    print(f"    Risk score >= {phishing_min_score}      -> PHISHING")
    
    # Save threshold configuration
    threshold_config = {
        "safe_max_probability": optimal['safe_max'],
        "phishing_min_probability": optimal['phishing_min'],
        "safe_max_risk_score": safe_max_score,
        "phishing_min_risk_score": phishing_min_score,
        "validation_f1": optimal['f1'],
        "validation_precision": optimal['precision'],
        "validation_recall": optimal['recall'],
        "calibration_set_size": len(y_val),
        "calibration_method": "grid_search_maximize_f1"
    }
    
    threshold_config_path = os.path.join(MODELS_DIR, "threshold_config.json")
    with open(threshold_config_path, "w") as f:
        json.dump(threshold_config, f, indent=2)
    
    print(f"\n[+] Threshold config saved: {threshold_config_path}")
    
    print("\n" + "=" * 70)
    print("  Threshold calibration complete.")
    print("=" * 70)


if __name__ == "__main__":
    main()