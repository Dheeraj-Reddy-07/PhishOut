"""
Phish360 Learned Score-Level Fusion Trainer
============================================
Trains a learned score-level fusion model using validation probabilities from
structural and semantic models.

This implements the PhishOut architecture:
- Structural probability (from structural model)
- Semantic probability (from semantic model)
- Learned fusion: P(phishing | structural_prob, semantic_prob)

The fusion model is a Logistic Regression that learns the optimal combination
of structural and semantic probabilities.

Usage:
    python train_phish360_fusion.py
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


def evaluate_model(model, X_test, y_test, model_name):
    """Evaluate model and return metrics dict."""
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    return {
        "model": model_name,
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred), 4),
        "recall": round(recall_score(y_test, y_pred), 4),
        "f1": round(f1_score(y_test, y_pred), 4),
        "roc_auc": round(roc_auc_score(y_test, y_prob), 4),
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
    print("  Phish360 Learned Score-Level Fusion Training")
    print("=" * 70)

    # Load validation and test datasets
    val_path = os.path.join(DATA_DIR, "validation_features.parquet")
    test_path = os.path.join(DATA_DIR, "test_features.parquet")

    if not all(os.path.exists(p) for p in [val_path, test_path]):
        print("[ERROR] Phish360 feature files not found.")
        print(f"Expected: {val_path}, {test_path}")
        return

    val_df = pd.read_parquet(val_path)
    test_df = pd.read_parquet(test_path)

    print(f"\nDataset sizes:")
    print(f"  Validation: {len(val_df):,} samples")
    print(f"  Test:       {len(test_df):,} samples")

    # Load trained models
    struct_model_path = os.path.join(MODELS_DIR, "structural_model.pkl")
    struct_scaler_path = os.path.join(MODELS_DIR, "structural_scaler.pkl")
    sem_model_path = os.path.join(MODELS_DIR, "semantic_model.pkl")
    sem_scaler_path = os.path.join(MODELS_DIR, "semantic_scaler.pkl")

    if not all(os.path.exists(p) for p in [struct_model_path, struct_scaler_path, 
                                            sem_model_path, sem_scaler_path]):
        print("[ERROR] Trained models not found.")
        print("Please run train_phish360_structural.py and train_phish360_semantic.py first.")
        return

    print("[*] Loading structural model...")
    struct_model = joblib.load(struct_model_path)
    struct_scaler = joblib.load(struct_scaler_path)

    print("[*] Loading semantic model...")
    sem_model = joblib.load(sem_model_path)
    sem_scaler = joblib.load(sem_scaler_path)

    # Extract features and labels
    X_val_struct = val_df[STRUCTURAL_FEATURES].fillna(0).values.astype(np.float32)
    X_val_sem = val_df[SEMANTIC_FEATURES].fillna(0).values.astype(np.float32)
    y_val = val_df['label'].values.astype(int)

    X_test_struct = test_df[STRUCTURAL_FEATURES].fillna(0).values.astype(np.float32)
    X_test_sem = test_df[SEMANTIC_FEATURES].fillna(0).values.astype(np.float32)
    y_test = test_df['label'].values.astype(int)

    print(f"\nLabel distributions:")
    print(f"  Validation: Legit={sum(y_val==0):,}, Phish={sum(y_val==1):,}")
    print(f"  Test:       Legit={sum(y_test==0):,}, Phish={sum(y_test==1):,}")

    # Generate probabilities from structural and semantic models
    print("\n[*] Generating structural probabilities...")
    X_val_struct_scaled = struct_scaler.transform(X_val_struct)
    struct_prob_val = struct_model.predict_proba(X_val_struct_scaled)[:, 1]

    X_test_struct_scaled = struct_scaler.transform(X_test_struct)
    struct_prob_test = struct_model.predict_proba(X_test_struct_scaled)[:, 1]

    print("[*] Generating semantic probabilities...")
    X_val_sem_scaled = sem_scaler.transform(X_val_sem)
    sem_prob_val = sem_model.predict_proba(X_val_sem_scaled)[:, 1]

    X_test_sem_scaled = sem_scaler.transform(X_test_sem)
    sem_prob_test = sem_model.predict_proba(X_test_sem_scaled)[:, 1]

    # Prepare fusion training data (validation set)
    print("\n[*] Preparing fusion training data...")
    X_fusion_val = np.column_stack([struct_prob_val, sem_prob_val])

    # Train logistic regression fusion model
    print("[*] Training Logistic Regression fusion model...")
    fusion_model = LogisticRegression(
        C=1.0,
        max_iter=1000,
        random_state=42,
        solver='lbfgs'
    )
    fusion_model.fit(X_fusion_val, y_val)

    # Print learned coefficients
    print("\n[*] Learned fusion coefficients:")
    print(f"    Structural coefficient: {fusion_model.coef_[0][0]:.4f}")
    print(f"    Semantic coefficient:   {fusion_model.coef_[0][1]:.4f}")
    print(f"    Intercept:              {fusion_model.intercept_[0]:.4f}")

    # Evaluate on validation set
    print("\n" + "=" * 70)
    print("  Validation Set Evaluation (Learned Fusion)")
    print("=" * 70)
    val_metrics = evaluate_model(fusion_model, X_fusion_val, y_val, "Learned Fusion (Validation)")
    print_metrics(val_metrics)

    # Evaluate on test set
    X_fusion_test = np.column_stack([struct_prob_test, sem_prob_test])
    print("\n" + "=" * 70)
    print("  Test Set Evaluation (Learned Fusion)")
    print("=" * 70)
    test_metrics = evaluate_model(fusion_model, X_fusion_test, y_test, "Learned Fusion (Test)")
    print_metrics(test_metrics)

    # Save fusion model and config
    fusion_model_path = os.path.join(MODELS_DIR, "fusion_model.pkl")
    joblib.dump(fusion_model, fusion_model_path)

    fusion_config = {
        "coef_structural": float(fusion_model.coef_[0][0]),
        "coef_semantic": float(fusion_model.coef_[0][1]),
        "intercept": float(fusion_model.intercept_[0]),
        "formula": f"P(phish) = sigmoid({fusion_model.coef_[0][0]:.4f}×p_struct + {fusion_model.coef_[0][1]:.4f}×p_sem + {fusion_model.intercept_[0]:.4f})"
    }

    fusion_config_path = os.path.join(MODELS_DIR, "fusion_config.json")
    with open(fusion_config_path, "w") as f:
        json.dump(fusion_config, f, indent=2)

    print(f"\n[+] Fusion model saved:  {fusion_model_path}")
    print(f"[+] Fusion config saved: {fusion_config_path}")

    # Save results
    results = {
        "model_type": "learned_score_level_fusion",
        "fusion_coefficients": fusion_config,
        "validation_size": len(X_fusion_val),
        "test_size": len(X_fusion_test),
        "validation_metrics": val_metrics,
        "test_metrics": test_metrics,
    }

    results_path = os.path.join(MODELS_DIR, "fusion_results.json")
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"[+] Results saved: {results_path}")

    print("\n" + "=" * 70)
    print("  Learned score-level fusion training complete.")
    print("=" * 70)


if __name__ == "__main__":
    main()