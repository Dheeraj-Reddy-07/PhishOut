"""
Phish360 V3 Comprehensive Evaluation
====================================
Evaluates V3 fusion model on:
1. Untouched test set (same as V2)
2. Hard-negative eval set (legitimate auth/payment pages)

Usage:
    python evaluate_phish360_v3.py
"""
import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix,
)

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


def evaluate_model(y_true, y_pred, y_prob, model_name):
    """Evaluate model and return metrics dict."""
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
        "false_positive_rate": fp / (tn + fp) if (tn + fp) > 0 else 0,
        "false_negative_rate": fn / (fn + tp) if (fn + tp) > 0 else 0,
    }


def print_metrics(metrics):
    """Print evaluation metrics."""
    print(f"\n  {metrics['model']} Results:")
    print(f"    Accuracy:  {metrics['accuracy']:.4f}")
    print(f"    Precision: {metrics['precision']:.4f}")
    print(f"    Recall:    {metrics['recall']:.4f}")
    print(f"    F1:        {metrics['f1']:.4f}")
    print(f"    ROC-AUC:   {metrics['roc_auc']:.4f}")
    print(f"    FPR:       {metrics['false_positive_rate']:.4f}")
    print(f"    FNR:       {metrics['false_negative_rate']:.4f}")
    cm = metrics['confusion_matrix']
    print(f"    Confusion: TN={cm['tn']}, FP={cm['fp']}, FN={cm['fn']}, TP={cm['tp']}")


def main():
    print("=" * 70)
    print("  Phish360 V3 Comprehensive Evaluation")
    print("=" * 70)

    # Load V3 structural model (retrained)
    struct_model_path = os.path.join(V3_MODELS_DIR, "structural_model.pkl")
    struct_scaler_path = os.path.join(V3_MODELS_DIR, "structural_scaler.pkl")

    # Load V3 semantic model
    sem_model_path = os.path.join(V3_MODELS_DIR, "semantic_model.pkl")
    sem_scaler_path = os.path.join(V3_MODELS_DIR, "semantic_scaler.pkl")
    fusion_model_path = os.path.join(V3_MODELS_DIR, "fusion_model.pkl")
    threshold_config_path = os.path.join(V3_MODELS_DIR, "threshold_config.json")

    if not all(os.path.exists(p) for p in [struct_model_path, struct_scaler_path, sem_model_path, sem_scaler_path, fusion_model_path, threshold_config_path]):
        print("[ERROR] V3 models or threshold config not found.")
        return

    print("\n[*] Loading V2 structural model (frozen)...")
    struct_model = joblib.load(struct_model_path)
    struct_scaler = joblib.load(struct_scaler_path)

    print("[*] Loading V3 semantic model...")
    sem_model = joblib.load(sem_model_path)
    sem_scaler = joblib.load(sem_scaler_path)

    print("[*] Loading V3 fusion model...")
    fusion_model = joblib.load(fusion_model_path)

    print("[*] Loading threshold config...")
    with open(threshold_config_path) as f:
        threshold_config = json.load(f)
    phishing_min_prob = threshold_config['phishing_min_probability']
    print(f"    PHISHING_MIN threshold: {phishing_min_prob:.2f}")

    # Evaluate on test set
    print("\n" + "=" * 70)
    print("  Test Set Evaluation (Untouched)")
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

    y_pred_test = (p_fusion_test >= phishing_min_prob).astype(int)

    test_metrics = evaluate_model(y_test, y_pred_test, p_fusion_test, "V3 Fusion (Test)")
    print_metrics(test_metrics)

    # Evaluate on hard-negative eval set
    print("\n" + "=" * 70)
    print("  Hard-Negative Eval Set Evaluation")
    print("=" * 70)

    hard_neg_eval_path = os.path.join(V3_DATA_DIR, "hard_neg_eval_features.parquet")
    hard_neg_eval_df = pd.read_parquet(hard_neg_eval_path)
    print(f"Hard-negative eval set: {len(hard_neg_eval_df):,} samples")

    X_hn_struct = hard_neg_eval_df[STRUCTURAL_FEATURES].fillna(0).values.astype(np.float32)
    X_hn_sem = hard_neg_eval_df[SEMANTIC_FEATURES_V3].fillna(0).values.astype(np.float32)
    y_hn = hard_neg_eval_df['label'].values.astype(int)

    X_hn_struct_scaled = struct_scaler.transform(X_hn_struct)
    p_hn_struct = struct_model.predict_proba(X_hn_struct_scaled)[:, 1]

    X_hn_sem_scaled = sem_scaler.transform(X_hn_sem)
    p_hn_sem = sem_model.predict_proba(X_hn_sem_scaled)[:, 1]

    X_fusion_hn = np.column_stack([p_hn_struct, p_hn_sem])
    p_fusion_hn = fusion_model.predict_proba(X_fusion_hn)[:, 1]

    y_pred_hn = (p_fusion_hn >= phishing_min_prob).astype(int)

    hn_metrics = evaluate_model(y_hn, y_pred_hn, p_fusion_hn, "V3 Fusion (Hard-Negative)")
    print_metrics(hn_metrics)

    # Save comprehensive results
    results = {
        "model_type": "v3_fusion_comprehensive",
        "threshold_config": threshold_config,
        "test_metrics": test_metrics,
        "hard_negative_metrics": hn_metrics,
        "test_set_size": len(test_df),
        "hard_negative_set_size": len(hard_neg_eval_df),
    }

    results_path = os.path.join(V3_MODELS_DIR, "comprehensive_evaluation_results.json")
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Comprehensive results saved: {results_path}")

    print("\n" + "=" * 70)
    print("  V3 Comprehensive evaluation complete.")
    print("=" * 70)


if __name__ == "__main__":
    main()
