"""
V2 vs V3 Comparison
====================
Compares V2 and V3 models on:
1. Untouched test set
2. Hard-negative eval set

Usage:
    python compare_v2_v3.py
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

# V2 Semantic features (15 features)
SEMANTIC_FEATURES_V2 = [
    'password_fields', 'text_email_fields', 'forms', 'external_links',
    'iframes', 'scripts', 'login_indicators', 'credential_indicators',
    'payment_indicators', 'urgency_indicators', 'brand_indicators', 'text_length',
    'domain_brand_consistency', 'form_action_same_origin', 'trusted_domain'
]

# V3 Semantic features (19 features)
SEMANTIC_FEATURES_V3 = [
    'password_fields', 'text_email_fields', 'forms', 'external_links',
    'iframes', 'scripts', 'login_indicators', 'credential_indicators',
    'payment_indicators', 'urgency_indicators', 'brand_indicators', 'text_length',
    'domain_brand_consistency', 'form_action_same_origin', 'trusted_domain',
    'link_to_form_ratio', 'text_to_script_ratio', 'credential_density', 'brand_context_score'
]


def evaluate_model(y_true, y_pred, y_prob, model_name):
    """Evaluate model and return metrics dict."""
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    if cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
    else:
        # Handle single-class case (e.g., hard-negative set with only legitimate)
        tn = cm[0, 0] if cm.shape[0] > 0 else 0
        fp = 0
        fn = 0
        tp = 0

    return {
        "model": model_name,
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_true, y_pred, zero_division=0), 4),
        "roc_auc": round(roc_auc_score(y_true, y_prob) if len(np.unique(y_true)) > 1 else float('nan'), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "false_positive_rate": round(fp / (tn + fp) if (tn + fp) > 0 else 0, 4),
        "false_negative_rate": round(fn / (fn + tp) if (fn + tp) > 0 else 0, 4),
    }


def print_metrics(metrics):
    """Print evaluation metrics."""
    print(f"\n  {metrics['model']}:")
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
    print("  V2 vs V3 Model Comparison")
    print("=" * 70)

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
    print(f"    V2 PHISHING_MIN: {v2_phishing_min:.2f}")

    # Load V3 models
    print("[*] Loading V3 models...")
    v3_sem_model = joblib.load(os.path.join(V3_MODELS_DIR, "semantic_model.pkl"))
    v3_sem_scaler = joblib.load(os.path.join(V3_MODELS_DIR, "semantic_scaler.pkl"))
    v3_fusion_model = joblib.load(os.path.join(V3_MODELS_DIR, "fusion_model.pkl"))
    
    with open(os.path.join(V3_MODELS_DIR, "threshold_config.json")) as f:
        v3_threshold_config = json.load(f)
    v3_phishing_min = v3_threshold_config['phishing_min_probability']
    print(f"    V3 PHISHING_MIN: {v3_phishing_min:.2f}")

    # Load test set
    print("\n" + "=" * 70)
    print("  Test Set Comparison")
    print("=" * 70)
    test_df = pd.read_parquet(os.path.join(V3_DATA_DIR, "test_features.parquet"))
    print(f"Test set: {len(test_df):,} samples")

    y_test = test_df['label'].values.astype(int)
    X_test_struct = test_df[STRUCTURAL_FEATURES].fillna(0).values.astype(np.float32)
    X_test_sem_v2 = test_df[SEMANTIC_FEATURES_V2].fillna(0).values.astype(np.float32)
    X_test_sem_v3 = test_df[SEMANTIC_FEATURES_V3].fillna(0).values.astype(np.float32)

    # V2 predictions
    X_test_struct_scaled = v2_struct_scaler.transform(X_test_struct)
    p_test_struct = v2_struct_model.predict_proba(X_test_struct_scaled)[:, 1]

    X_test_sem_v2_scaled = v2_sem_scaler.transform(X_test_sem_v2)
    p_test_sem_v2 = v2_sem_model.predict_proba(X_test_sem_v2_scaled)[:, 1]

    X_fusion_test_v2 = np.column_stack([p_test_struct, p_test_sem_v2])
    p_fusion_test_v2 = v2_fusion_model.predict_proba(X_fusion_test_v2)[:, 1]
    y_pred_test_v2 = (p_fusion_test_v2 >= v2_phishing_min).astype(int)

    # V3 predictions
    X_test_sem_v3_scaled = v3_sem_scaler.transform(X_test_sem_v3)
    p_test_sem_v3 = v3_sem_model.predict_proba(X_test_sem_v3_scaled)[:, 1]

    X_fusion_test_v3 = np.column_stack([p_test_struct, p_test_sem_v3])
    p_fusion_test_v3 = v3_fusion_model.predict_proba(X_fusion_test_v3)[:, 1]
    y_pred_test_v3 = (p_fusion_test_v3 >= v3_phishing_min).astype(int)

    # Evaluate
    v2_test_metrics = evaluate_model(y_test, y_pred_test_v2, p_fusion_test_v2, "V2 Fusion (Test)")
    v3_test_metrics = evaluate_model(y_test, y_pred_test_v3, p_fusion_test_v3, "V3 Fusion (Test)")
    
    print_metrics(v2_test_metrics)
    print_metrics(v3_test_metrics)

    # Hard-negative comparison
    print("\n" + "=" * 70)
    print("  Hard-Negative Set Comparison")
    print("=" * 70)
    hn_df = pd.read_parquet(os.path.join(V3_DATA_DIR, "hard_neg_eval_features.parquet"))
    print(f"Hard-negative set: {len(hn_df):,} samples")

    y_hn = hn_df['label'].values.astype(int)
    X_hn_struct = hn_df[STRUCTURAL_FEATURES].fillna(0).values.astype(np.float32)
    X_hn_sem_v2 = hn_df[SEMANTIC_FEATURES_V2].fillna(0).values.astype(np.float32)
    X_hn_sem_v3 = hn_df[SEMANTIC_FEATURES_V3].fillna(0).values.astype(np.float32)

    # V2 predictions on hard-negatives
    X_hn_struct_scaled = v2_struct_scaler.transform(X_hn_struct)
    p_hn_struct = v2_struct_model.predict_proba(X_hn_struct_scaled)[:, 1]

    X_hn_sem_v2_scaled = v2_sem_scaler.transform(X_hn_sem_v2)
    p_hn_sem_v2 = v2_sem_model.predict_proba(X_hn_sem_v2_scaled)[:, 1]

    X_fusion_hn_v2 = np.column_stack([p_hn_struct, p_hn_sem_v2])
    p_fusion_hn_v2 = v2_fusion_model.predict_proba(X_fusion_hn_v2)[:, 1]
    y_pred_hn_v2 = (p_fusion_hn_v2 >= v2_phishing_min).astype(int)

    # V3 predictions on hard-negatives
    X_hn_sem_v3_scaled = v3_sem_scaler.transform(X_hn_sem_v3)
    p_hn_sem_v3 = v3_sem_model.predict_proba(X_hn_sem_v3_scaled)[:, 1]

    X_fusion_hn_v3 = np.column_stack([p_hn_struct, p_hn_sem_v3])
    p_fusion_hn_v3 = v3_fusion_model.predict_proba(X_fusion_hn_v3)[:, 1]
    y_pred_hn_v3 = (p_fusion_hn_v3 >= v3_phishing_min).astype(int)

    # Evaluate hard-negatives
    v2_hn_metrics = evaluate_model(y_hn, y_pred_hn_v2, p_fusion_hn_v2, "V2 Fusion (Hard-Negative)")
    v3_hn_metrics = evaluate_model(y_hn, y_pred_hn_v3, p_fusion_hn_v3, "V3 Fusion (Hard-Negative)")
    
    print_metrics(v2_hn_metrics)
    print_metrics(v3_hn_metrics)

    # Summary comparison
    print("\n" + "=" * 70)
    print("  Summary Comparison")
    print("=" * 70)
    
    print("\nTest Set:")
    print(f"  Accuracy:  V2={v2_test_metrics['accuracy']:.4f}, V3={v3_test_metrics['accuracy']:.4f}, Δ={v3_test_metrics['accuracy']-v2_test_metrics['accuracy']:+.4f}")
    print(f"  Precision: V2={v2_test_metrics['precision']:.4f}, V3={v3_test_metrics['precision']:.4f}, Δ={v3_test_metrics['precision']-v2_test_metrics['precision']:+.4f}")
    print(f"  Recall:    V2={v2_test_metrics['recall']:.4f}, V3={v3_test_metrics['recall']:.4f}, Δ={v3_test_metrics['recall']-v2_test_metrics['recall']:+.4f}")
    print(f"  F1:        V2={v2_test_metrics['f1']:.4f}, V3={v3_test_metrics['f1']:.4f}, Δ={v3_test_metrics['f1']-v2_test_metrics['f1']:+.4f}")
    print(f"  FPR:       V2={v2_test_metrics['false_positive_rate']:.4f}, V3={v3_test_metrics['false_positive_rate']:.4f}, Δ={v3_test_metrics['false_positive_rate']-v2_test_metrics['false_positive_rate']:+.4f}")
    print(f"  FNR:       V2={v2_test_metrics['false_negative_rate']:.4f}, V3={v3_test_metrics['false_negative_rate']:.4f}, Δ={v3_test_metrics['false_negative_rate']-v2_test_metrics['false_negative_rate']:+.4f}")

    print("\nHard-Negative Set:")
    print(f"  False Positives: V2={v2_hn_metrics['confusion_matrix']['fp']}, V3={v3_hn_metrics['confusion_matrix']['fp']}, Δ={v3_hn_metrics['confusion_matrix']['fp']-v2_hn_metrics['confusion_matrix']['fp']:+d}")
    print(f"  FPR:            V2={v2_hn_metrics['false_positive_rate']:.4f}, V3={v3_hn_metrics['false_positive_rate']:.4f}, Δ={v3_hn_metrics['false_positive_rate']-v2_hn_metrics['false_positive_rate']:+.4f}")

    # Save comparison results
    comparison_results = {
        "test_set": {
            "v2": v2_test_metrics,
            "v3": v3_test_metrics,
            "delta": {
                "accuracy": round(v3_test_metrics['accuracy'] - v2_test_metrics['accuracy'], 4),
                "precision": round(v3_test_metrics['precision'] - v2_test_metrics['precision'], 4),
                "recall": round(v3_test_metrics['recall'] - v2_test_metrics['recall'], 4),
                "f1": round(v3_test_metrics['f1'] - v2_test_metrics['f1'], 4),
                "fpr": round(v3_test_metrics['false_positive_rate'] - v2_test_metrics['false_positive_rate'], 4),
                "fnr": round(v3_test_metrics['false_negative_rate'] - v2_test_metrics['false_negative_rate'], 4),
            }
        },
        "hard_negative_set": {
            "v2": v2_hn_metrics,
            "v3": v3_hn_metrics,
            "delta": {
                "false_positives": v3_hn_metrics['confusion_matrix']['fp'] - v2_hn_metrics['confusion_matrix']['fp'],
                "fpr": round(v3_hn_metrics['false_positive_rate'] - v2_hn_metrics['false_positive_rate'], 4),
            }
        },
        "v3_improves_over_v2": bool(
            v3_test_metrics['f1'] >= v2_test_metrics['f1'] and
            v3_hn_metrics['false_positive_rate'] <= v2_hn_metrics['false_positive_rate'] and
            v3_test_metrics['recall'] >= v2_test_metrics['recall']
        ),
        "v3_phishing_recall_improvement": round(v3_test_metrics['recall'] - v2_test_metrics['recall'], 4),
        "v3_phishing_f1_improvement": round(v3_test_metrics['f1'] - v2_test_metrics['f1'], 4),
        "v3_hard_negative_fp_change": v3_hn_metrics['confusion_matrix']['fp'] - v2_hn_metrics['confusion_matrix']['fp']
    }

    results_path = os.path.join(V3_MODELS_DIR, "v2_v3_comparison.json")
    with open(results_path, "w") as f:
        json.dump(comparison_results, f, indent=2)
    print(f"\n[+] Comparison results saved: {results_path}")

    print("\n" + "=" * 70)
    print("  V2 vs V3 comparison complete.")
    print("=" * 70)


if __name__ == "__main__":
    main()
