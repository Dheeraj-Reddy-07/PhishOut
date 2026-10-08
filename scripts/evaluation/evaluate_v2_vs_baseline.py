"""
PhishOut V2 vs Baseline Evaluation
==================================
Comprehensive evaluation comparing V2 models against baseline (V1) models.

Evaluates on the untouched test set to measure:
- Overall performance metrics
- False positive reduction
- Phishing recall impact
- Feature importance changes

Usage:
    python evaluate_v2_vs_baseline.py
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
V1_MODELS_DIR = os.path.join(os.path.dirname(__file__), "models", "phish360")
V2_MODELS_DIR = os.path.join(os.path.dirname(__file__), "models", "phish360_v2")
V1_DATA_DIR = os.path.join(os.path.dirname(__file__), "dataset", "phish360", "processed")
V2_DATA_DIR = os.path.join(os.path.dirname(__file__), "dataset", "phish360", "v2", "processed")

# Feature definitions
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

V1_SEMANTIC_FEATURES = [
    'password_fields', 'text_email_fields', 'forms', 'external_links',
    'iframes', 'scripts', 'login_indicators', 'credential_indicators',
    'payment_indicators', 'urgency_indicators', 'brand_indicators', 'text_length'
]

V2_SEMANTIC_FEATURES = [
    'password_fields', 'text_email_fields', 'forms', 'external_links',
    'iframes', 'scripts', 'login_indicators', 'credential_indicators',
    'payment_indicators', 'urgency_indicators', 'brand_indicators', 'text_length',
    # V2 context features
    'domain_brand_consistency', 'form_action_same_origin', 'trusted_domain'
]


def evaluate_model_predictions(y_true, y_pred, y_prob, model_name):
    """Evaluate model predictions and return metrics."""
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
        "false_positive_rate": round(fp / (fp + tn), 4),
        "false_negative_rate": round(fn / (fn + tp), 4),
    }


def print_metrics(metrics):
    """Print evaluation metrics."""
    print(f"\n  {metrics['model']}:")
    print(f"    Accuracy:  {metrics['accuracy']:.4f}")
    print(f"    Precision: {metrics['precision']:.4f}")
    print(f"    Recall:    {metrics['recall']:.4f}")
    print(f"    F1:        {metrics['f1']:.4f}")
    print(f"    ROC-AUC:   {metrics['roc_auc']:.4f}")
    print(f"    FP Rate:   {metrics['false_positive_rate']:.4f}")
    print(f"    FN Rate:   {metrics['false_negative_rate']:.4f}")
    cm = metrics['confusion_matrix']
    print(f"    Confusion: TN={cm['tn']}, FP={cm['fp']}, FN={cm['fn']}, TP={cm['tp']}")


def main():
    print("=" * 70)
    print("  PhishOut V2 vs Baseline Evaluation")
    print("=" * 70)

    # Load test sets (both V1 and V2 use same underlying data, different features)
    v1_test_path = os.path.join(V1_DATA_DIR, "test_features.parquet")
    v2_test_path = os.path.join(V2_DATA_DIR, "test_features.parquet")

    if not os.path.exists(v1_test_path) or not os.path.exists(v2_test_path):
        print("[ERROR] Test feature files not found.")
        print(f"Expected: {v1_test_path}, {v2_test_path}")
        return

    v1_test_df = pd.read_parquet(v1_test_path)
    v2_test_df = pd.read_parquet(v2_test_path)

    print(f"\nTest set sizes:")
    print(f"  V1: {len(v1_test_df):,} samples")
    print(f"  V2: {len(v2_test_df):,} samples")

    # Load V1 models
    print("\n" + "=" * 70)
    print("  Loading V1 (Baseline) Models")
    print("=" * 70)
    
    v1_struct_model_path = os.path.join(V1_MODELS_DIR, "structural_model.pkl")
    v1_struct_scaler_path = os.path.join(V1_MODELS_DIR, "structural_scaler.pkl")
    v1_sem_model_path = os.path.join(V1_MODELS_DIR, "semantic_model.pkl")
    v1_sem_scaler_path = os.path.join(V1_MODELS_DIR, "semantic_scaler.pkl")
    v1_fusion_model_path = os.path.join(V1_MODELS_DIR, "fusion_model.pkl")
    v1_threshold_config_path = os.path.join(V1_MODELS_DIR, "threshold_config.json")

    if all(os.path.exists(p) for p in [v1_struct_model_path, v1_struct_scaler_path, 
                                       v1_sem_model_path, v1_sem_scaler_path,
                                       v1_fusion_model_path, v1_threshold_config_path]):
        print("[*] Loading V1 models...")
        v1_struct_model = joblib.load(v1_struct_model_path)
        v1_struct_scaler = joblib.load(v1_struct_scaler_path)
        v1_sem_model = joblib.load(v1_sem_model_path)
        v1_sem_scaler = joblib.load(v1_sem_scaler_path)
        v1_fusion_model = joblib.load(v1_fusion_model_path)
        
        with open(v1_threshold_config_path) as f:
            v1_threshold_cfg = json.load(f)
        
        v1_phishing_min = v1_threshold_cfg.get("phishing_min_risk_score", 57)
        print(f"[+] V1 phishing threshold: {v1_phishing_min}")
    else:
        print("[!] V1 models not fully available, skipping V1 evaluation")
        v1_struct_model = None

    # Load V2 models
    print("\n" + "=" * 70)
    print("  Loading V2 Models")
    print("=" * 70)
    
    v2_struct_model_path = os.path.join(V2_MODELS_DIR, "structural_model.pkl")
    v2_struct_scaler_path = os.path.join(V2_MODELS_DIR, "structural_scaler.pkl")
    v2_sem_model_path = os.path.join(V2_MODELS_DIR, "semantic_model.pkl")
    v2_sem_scaler_path = os.path.join(V2_MODELS_DIR, "semantic_scaler.pkl")
    v2_fusion_model_path = os.path.join(V2_MODELS_DIR, "fusion_model.pkl")
    v2_threshold_config_path = os.path.join(V2_MODELS_DIR, "threshold_config.json")

    if all(os.path.exists(p) for p in [v2_struct_model_path, v2_struct_scaler_path,
                                       v2_sem_model_path, v2_sem_scaler_path,
                                       v2_fusion_model_path, v2_threshold_config_path]):
        print("[*] Loading V2 models...")
        v2_struct_model = joblib.load(v2_struct_model_path)
        v2_struct_scaler = joblib.load(v2_struct_scaler_path)
        v2_sem_model = joblib.load(v2_sem_model_path)
        v2_sem_scaler = joblib.load(v2_sem_scaler_path)
        v2_fusion_model = joblib.load(v2_fusion_model_path)
        
        with open(v2_threshold_config_path) as f:
            v2_threshold_cfg = json.load(f)
        
        v2_phishing_min = v2_threshold_cfg.get("phishing_min_risk_score", 45)
        print(f"[+] V2 phishing threshold: {v2_phishing_min}")
    else:
        print("[!] V2 models not fully available")
        return

    # Evaluate V1
    v1_results = {}
    if v1_struct_model:
        print("\n" + "=" * 70)
        print("  V1 (Baseline) Evaluation")
        print("=" * 70)
        
        y_test = v1_test_df['label'].values.astype(int)
        
        # Structural
        X_test_struct = v1_test_df[STRUCTURAL_FEATURES].fillna(0).values.astype(np.float32)
        X_test_struct_scaled = v1_struct_scaler.transform(X_test_struct)
        p_struct = v1_struct_model.predict_proba(X_test_struct_scaled)[:, 1]
        y_pred_struct = (p_struct >= 0.5).astype(int)
        v1_results["structural"] = evaluate_model_predictions(y_test, y_pred_struct, p_struct, "V1 Structural")
        print_metrics(v1_results["structural"])
        
        # Semantic
        X_test_sem = v1_test_df[V1_SEMANTIC_FEATURES].fillna(0).values.astype(np.float32)
        X_test_sem_scaled = v1_sem_scaler.transform(X_test_sem)
        p_sem = v1_sem_model.predict_proba(X_test_sem_scaled)[:, 1]
        y_pred_sem = (p_sem >= 0.5).astype(int)
        v1_results["semantic"] = evaluate_model_predictions(y_test, y_pred_sem, p_sem, "V1 Semantic")
        print_metrics(v1_results["semantic"])
        
        # Fusion
        X_fusion = np.column_stack([p_struct, p_sem])
        p_fusion = v1_fusion_model.predict_proba(X_fusion)[:, 1]
        risk_scores = (p_fusion * 100).astype(int)
        y_pred_fusion = (risk_scores >= v1_phishing_min).astype(int)
        v1_results["fusion"] = evaluate_model_predictions(y_test, y_pred_fusion, p_fusion, "V1 Fusion")
        print_metrics(v1_results["fusion"])

    # Evaluate V2
    v2_results = {}
    print("\n" + "=" * 70)
    print("  V2 Evaluation")
    print("=" * 70)
    
    y_test = v2_test_df['label'].values.astype(int)
    
    # Structural
    X_test_struct = v2_test_df[STRUCTURAL_FEATURES].fillna(0).values.astype(np.float32)
    X_test_struct_scaled = v2_struct_scaler.transform(X_test_struct)
    p_struct = v2_struct_model.predict_proba(X_test_struct_scaled)[:, 1]
    y_pred_struct = (p_struct >= 0.5).astype(int)
    v2_results["structural"] = evaluate_model_predictions(y_test, y_pred_struct, p_struct, "V2 Structural")
    print_metrics(v2_results["structural"])
    
    # Semantic
    X_test_sem = v2_test_df[V2_SEMANTIC_FEATURES].fillna(0).values.astype(np.float32)
    X_test_sem_scaled = v2_sem_scaler.transform(X_test_sem)
    p_sem = v2_sem_model.predict_proba(X_test_sem_scaled)[:, 1]
    y_pred_sem = (p_sem >= 0.5).astype(int)
    v2_results["semantic"] = evaluate_model_predictions(y_test, y_pred_sem, p_sem, "V2 Semantic")
    print_metrics(v2_results["semantic"])
    
    # Fusion
    X_fusion = np.column_stack([p_struct, p_sem])
    p_fusion = v2_fusion_model.predict_proba(X_fusion)[:, 1]
    risk_scores = (p_fusion * 100).astype(int)
    y_pred_fusion = (risk_scores >= v2_phishing_min).astype(int)
    v2_results["fusion"] = evaluate_model_predictions(y_test, y_pred_fusion, p_fusion, "V2 Fusion")
    print_metrics(v2_results["fusion"])

    # Comparison
    print("\n" + "=" * 70)
    print("  V2 vs V1 Comparison (Fusion)")
    print("=" * 70)
    
    if v1_struct_model:
        v1_fusion = v1_results["fusion"]
        v2_fusion = v2_results["fusion"]
        
        print(f"\n  Metric          V1 (Baseline)    V2 (Improved)    Change")
        print(f"  {'-'*60}")
        print(f"  Accuracy        {v1_fusion['accuracy']:.4f}          {v2_fusion['accuracy']:.4f}          {v2_fusion['accuracy'] - v1_fusion['accuracy']:+.4f}")
        print(f"  Precision       {v1_fusion['precision']:.4f}          {v2_fusion['precision']:.4f}          {v2_fusion['precision'] - v1_fusion['precision']:+.4f}")
        print(f"  Recall          {v1_fusion['recall']:.4f}          {v2_fusion['recall']:.4f}          {v2_fusion['recall'] - v1_fusion['recall']:+.4f}")
        print(f"  F1              {v1_fusion['f1']:.4f}          {v2_fusion['f1']:.4f}          {v2_fusion['f1'] - v1_fusion['f1']:+.4f}")
        print(f"  ROC-AUC         {v1_fusion['roc_auc']:.4f}          {v2_fusion['roc_auc']:.4f}          {v2_fusion['roc_auc'] - v1_fusion['roc_auc']:+.4f}")
        print(f"  FP Rate         {v1_fusion['false_positive_rate']:.4f}          {v2_fusion['false_positive_rate']:.4f}          {v2_fusion['false_positive_rate'] - v1_fusion['false_positive_rate']:+.4f}")
        print(f"  FN Rate         {v1_fusion['false_negative_rate']:.4f}          {v2_fusion['false_negative_rate']:.4f}          {v2_fusion['false_negative_rate'] - v1_fusion['false_negative_rate']:+.4f}")
        
        v1_fp = v1_fusion['confusion_matrix']['fp']
        v2_fp = v2_fusion['confusion_matrix']['fp']
        fp_reduction = (v1_fp - v2_fp) / v1_fp * 100 if v1_fp > 0 else 0
        
        print(f"\n  False Positives:")
        print(f"    V1: {v1_fp}")
        print(f"    V2: {v2_fp}")
        print(f"    Reduction: {fp_reduction:.1f}%")
        
        v1_fn = v1_fusion['confusion_matrix']['fn']
        v2_fn = v2_fusion['confusion_matrix']['fn']
        fn_change = (v2_fn - v1_fn) / v1_fn * 100 if v1_fn > 0 else 0
        
        print(f"\n  False Negatives:")
        print(f"    V1: {v1_fn}")
        print(f"    V2: {v2_fn}")
        print(f"    Change: {fn_change:+.1f}%")

    # Save comparison results
    comparison_results = {
        "v1_results": v1_results if v1_struct_model else None,
        "v2_results": v2_results,
        "v1_threshold": v1_phishing_min if v1_struct_model else None,
        "v2_threshold": v2_phishing_min,
        "v2_context_features": ["domain_brand_consistency", "form_action_same_origin", "trusted_domain"],
    }

    results_path = os.path.join(V2_MODELS_DIR, "v2_vs_baseline_comparison.json")
    with open(results_path, "w") as f:
        json.dump(comparison_results, f, indent=2)
    print(f"\n[+] Comparison results saved: {results_path}")

    print("\n" + "=" * 70)
    print("  Evaluation complete.")
    print("=" * 70)


if __name__ == "__main__":
    main()
