"""
Phish360 V2 Fusion Model Trainer
================================
Trains a learned fusion model that combines structural and semantic probabilities.

V2 Changes:
- Uses V2 structural and semantic models (with context features)
- Trains fusion on V2 validation set

Usage:
    python train_phish360_v2_fusion.py
"""
import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix,
)

# Paths - V2 specific
DATA_DIR = os.path.join(os.path.dirname(__file__), "dataset", "phish360", "v2", "processed")
MODELS_DIR = os.path.join(os.path.dirname(__file__), "models", "phish360_v2")

# Structural feature column names (32 features)
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

# Semantic feature column names (V2: 15 features including context)
SEMANTIC_FEATURES = [
    'password_fields', 'text_email_fields', 'forms', 'external_links',
    'iframes', 'scripts', 'login_indicators', 'credential_indicators',
    'payment_indicators', 'urgency_indicators', 'brand_indicators', 'text_length',
    # V2 context features
    'domain_brand_consistency', 'form_action_same_origin', 'trusted_domain'
]


def evaluate_fusion(y_true, y_pred, y_prob, model_name):
    """Evaluate fusion model and return metrics dict."""
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()

    return {
        "model": model_name,
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "precision": round(precision_score(y_true, y_pred), 4),
        "recall": round(recall_score(y_true, y_pred), 4),
        "f1": round(f1_score(y_true, y_pred), 4),
        "roc_auc": round(roc_auc_score(y_true, y_prob), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def print_metrics(metrics):
    """Print evaluation metrics."""
    print(f"\n  {metrics['model']} Results:")
    print(f"    Accuracy:  {metrics['accuracy']:.4f}")
    print(f"    Precision: {metrics['precision']:.4f}")
    print(f"    Recall:    {metrics['recall']:.4f}")
    print(f"    F1:        {metrics['f1']:.4f}")
    print(f"    ROC-AUC:   {metrics['roc_auc']:.4f}")
    cm = metrics['confusion_matrix']
    print(f"    Confusion: TN={cm['tn']}, FP={cm['fp']}, FN={cm['fn']}, TP={cm['tp']}")


def main():
    print("=" * 70)
    print("  Phish360 V2 Fusion Model Training")
    print("=" * 70)

    # Load V2 datasets
    val_path = os.path.join(DATA_DIR, "validation_features.parquet")
    test_path = os.path.join(DATA_DIR, "test_features.parquet")

    if not all(os.path.exists(p) for p in [val_path, test_path]):
        print("[ERROR] Phish360 V2 feature files not found.")
        print(f"Expected: {val_path}, {test_path}")
        return

    val_df = pd.read_parquet(val_path)
    test_df = pd.read_parquet(test_path)

    print(f"\nDataset sizes:")
    print(f"  Validation: {len(val_df):,} samples")
    print(f"  Test:       {len(test_df):,} samples")

    # Load V2 models
    struct_model_path = os.path.join(MODELS_DIR, "structural_model.pkl")
    struct_scaler_path = os.path.join(MODELS_DIR, "structural_scaler.pkl")
    sem_model_path = os.path.join(MODELS_DIR, "semantic_model.pkl")
    sem_scaler_path = os.path.join(MODELS_DIR, "semantic_scaler.pkl")

    if not all(os.path.exists(p) for p in [struct_model_path, struct_scaler_path, sem_model_path, sem_scaler_path]):
        print("[ERROR] V2 models not found. Train structural and semantic models first.")
        return

    print("\n[*] Loading V2 structural model...")
    struct_model = joblib.load(struct_model_path)
    struct_scaler = joblib.load(struct_scaler_path)

    print("[*] Loading V2 semantic model...")
    sem_model = joblib.load(sem_model_path)
    sem_scaler = joblib.load(sem_scaler_path)

    # Extract features
    X_val_struct = val_df[STRUCTURAL_FEATURES].fillna(0).values.astype(np.float32)
    X_val_sem = val_df[SEMANTIC_FEATURES].fillna(0).values.astype(np.float32)
    y_val = val_df['label'].values.astype(int)

    X_test_struct = test_df[STRUCTURAL_FEATURES].fillna(0).values.astype(np.float32)
    X_test_sem = test_df[SEMANTIC_FEATURES].fillna(0).values.astype(np.float32)
    y_test = test_df['label'].values.astype(int)

    # Get probabilities from both models
    print("\n[*] Getting probabilities from structural model...")
    X_val_struct_scaled = struct_scaler.transform(X_val_struct)
    p_val_struct = struct_model.predict_proba(X_val_struct_scaled)[:, 1]

    X_test_struct_scaled = struct_scaler.transform(X_test_struct)
    p_test_struct = struct_model.predict_proba(X_test_struct_scaled)[:, 1]

    print("[*] Getting probabilities from semantic model...")
    X_val_sem_scaled = sem_scaler.transform(X_val_sem)
    p_val_sem = sem_model.predict_proba(X_val_sem_scaled)[:, 1]

    X_test_sem_scaled = sem_scaler.transform(X_test_sem)
    p_test_sem = sem_model.predict_proba(X_test_sem_scaled)[:, 1]

    # Prepare fusion training data
    X_fusion_val = np.column_stack([p_val_struct, p_val_sem])
    X_fusion_test = np.column_stack([p_test_struct, p_test_sem])

    # Train fusion model on validation set
    print("\n[*] Training fusion model (logistic regression) on validation set...")
    fusion_model = LogisticRegression(random_state=42, max_iter=1000)
    fusion_model.fit(X_fusion_val, y_val)

    # Get fusion predictions
    p_fusion_val = fusion_model.predict_proba(X_fusion_val)[:, 1]
    y_pred_val = (p_fusion_val >= 0.5).astype(int)

    p_fusion_test = fusion_model.predict_proba(X_fusion_test)[:, 1]
    y_pred_test = (p_fusion_test >= 0.5).astype(int)

    # Evaluate
    print("\n" + "=" * 70)
    print("  Validation Set Evaluation")
    print("=" * 70)
    val_metrics = evaluate_fusion(y_val, y_pred_val, p_fusion_val, "V2 Fusion (Validation)")
    print_metrics(val_metrics)

    print("\n" + "=" * 70)
    print("  Test Set Evaluation (Final)")
    print("=" * 70)
    test_metrics = evaluate_fusion(y_test, y_pred_test, p_fusion_test, "V2 Fusion (Test)")
    print_metrics(test_metrics)

    # Save fusion model
    fusion_model_path = os.path.join(MODELS_DIR, "fusion_model.pkl")
    joblib.dump(fusion_model, fusion_model_path)
    print(f"\n[+] V2 Fusion model saved: {fusion_model_path}")

    # Save fusion config
    coef_struct = fusion_model.coef_[0][0]
    coef_sem = fusion_model.coef_[0][1]
    intercept = fusion_model.intercept_[0]

    fusion_config = {
        "coef_structural": float(coef_struct),
        "coef_semantic": float(coef_sem),
        "intercept": float(intercept),
        "formula": f"P(phish) = sigmoid({coef_struct:.4f}×p_struct + {coef_sem:.4f}×p_sem + {intercept:.4f})"
    }

    fusion_config_path = os.path.join(MODELS_DIR, "fusion_config.json")
    with open(fusion_config_path, "w") as f:
        json.dump(fusion_config, f, indent=2)
    print(f"[+] Fusion config saved: {fusion_config_path}")

    # Save results
    results = {
        "model_type": "v2_fusion",
        "validation_metrics": val_metrics,
        "test_metrics": test_metrics,
        "fusion_config": fusion_config,
    }

    results_path = os.path.join(MODELS_DIR, "fusion_results.json")
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[+] Results saved: {results_path}")

    print("\n" + "=" * 70)
    print("  V2 Fusion model training complete.")
    print("=" * 70)


if __name__ == "__main__":
    main()
