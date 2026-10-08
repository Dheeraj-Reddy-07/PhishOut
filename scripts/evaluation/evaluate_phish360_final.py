"""
Phish360 Final Test Evaluation
==============================
Comprehensive evaluation of all 4 models on the untouched test set.

This script evaluates:
1. Structural-only model (32 features)
2. Semantic-only model (12 features)  
3. Hybrid model (44 features)
4. Learned-fusion PhishOut model

This implements E1 (normal detection evaluation) and E2 (model comparison)
from the research plan.

The test set is NEVER used for training or calibration decisions.

Usage:
    python evaluate_phish360_final.py
"""
import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix, auc,
    precision_recall_curve
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

HYBRID_FEATURES = STRUCTURAL_FEATURES + SEMANTIC_FEATURES


def evaluate_model(model, scaler, X_test, y_test, model_name, feature_name):
    """Evaluate model and return comprehensive metrics dict."""
    if scaler is not None:
        X_scaled = scaler.transform(X_test)
    else:
        X_scaled = X_test
        
    y_pred = model.predict(X_scaled)
    y_prob = model.predict_proba(X_scaled)[:, 1]

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    # Calculate PR-AUC
    precision, recall, _ = precision_recall_curve(y_test, y_prob)
    pr_auc = auc(recall, precision)

    return {
        "model": model_name,
        "features": feature_name,
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred), 4),
        "recall": round(recall_score(y_test, y_pred), 4),
        "f1": round(f1_score(y_test, y_pred), 4),
        "roc_auc": round(roc_auc_score(y_test, y_prob), 4),
        "pr_auc": round(pr_auc, 4),
        "fpr": round(fp / (fp + tn) if (fp + tn) > 0 else 0, 4),
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
    print(f"    PR-AUC:    {metrics['pr_auc']:.4f}")
    print(f"    FPR:       {metrics['fpr']:.4f}")
    cm = metrics['confusion_matrix']
    print(f"    Confusion: TN={cm['tn']}, FP={cm['fp']}, FN={cm['fn']}, TP={cm['tp']}")


def print_comparison_table(metrics_list):
    """Print side-by-side comparison table."""
    print("\n" + "=" * 90)
    print(f"  FINAL TEST EVALUATION COMPARISON (E1/E2)")
    print("=" * 90)
    print(f"  {'Model':<28} {'Acc':>6} {'Prec':>6} {'Rec':>6} {'F1':>6} {'ROC':>6} {'PR':>6} {'FPR':>6}")
    print("  " + "-" * 82)
    for m in metrics_list:
        print(f"  {m['model']:<28} {m['accuracy']:>6.4f} {m['precision']:>6.4f} "
              f"{m['recall']:>6.4f} {m['f1']:>6.4f} {m['roc_auc']:>6.4f} "
              f"{m['pr_auc']:>6.4f} {m['fpr']:>6.4f}")
    print("=" * 90)


def main():
    print("=" * 90)
    print("  Phish360 Final Test Evaluation (E1/E2)")
    print("=" * 90)
    
    # Load test dataset
    test_path = os.path.join(DATA_DIR, "test_features.parquet")
    
    if not os.path.exists(test_path):
        print("[ERROR] Test features not found.")
        print(f"Expected: {test_path}")
        return
    
    test_df = pd.read_parquet(test_path)
    y_test = test_df['label'].values.astype(int)
    
    print(f"\nTest set: {len(test_df):,} samples")
    print(f"  Label distribution: Legit={sum(y_test==0):,}, Phish={sum(y_test==1):,}")
    
    # Load models
    print("\n[*] Loading trained models...")
    
    all_metrics = []
    
    # 1. Structural-only model
    struct_model_path = os.path.join(MODELS_DIR, "structural_model.pkl")
    struct_scaler_path = os.path.join(MODELS_DIR, "structural_scaler.pkl")
    
    if os.path.exists(struct_model_path) and os.path.exists(struct_scaler_path):
        print("  Loading structural model...")
        struct_model = joblib.load(struct_model_path)
        struct_scaler = joblib.load(struct_scaler_path)
        
        X_test_struct = test_df[STRUCTURAL_FEATURES].fillna(0).values.astype(np.float32)
        struct_metrics = evaluate_model(
            struct_model, struct_scaler, X_test_struct, y_test,
            "Structural-Only", f"{len(STRUCTURAL_FEATURES)} features"
        )
        all_metrics.append(struct_metrics)
        print_metrics(struct_metrics)
    else:
        print("  [SKIP] Structural model not found")
    
    # 2. Semantic-only model
    sem_model_path = os.path.join(MODELS_DIR, "semantic_model.pkl")
    sem_scaler_path = os.path.join(MODELS_DIR, "semantic_scaler.pkl")
    
    if os.path.exists(sem_model_path) and os.path.exists(sem_scaler_path):
        print("  Loading semantic model...")
        sem_model = joblib.load(sem_model_path)
        sem_scaler = joblib.load(sem_scaler_path)
        
        X_test_sem = test_df[SEMANTIC_FEATURES].fillna(0).values.astype(np.float32)
        sem_metrics = evaluate_model(
            sem_model, sem_scaler, X_test_sem, y_test,
            "Semantic-Only", f"{len(SEMANTIC_FEATURES)} features"
        )
        all_metrics.append(sem_metrics)
        print_metrics(sem_metrics)
    else:
        print("  [SKIP] Semantic model not found")
    
    # 3. Hybrid model
    hybrid_model_path = os.path.join(MODELS_DIR, "hybrid_model.pkl")
    hybrid_scaler_path = os.path.join(MODELS_DIR, "hybrid_scaler.pkl")
    
    if os.path.exists(hybrid_model_path) and os.path.exists(hybrid_scaler_path):
        print("  Loading hybrid model...")
        hybrid_model = joblib.load(hybrid_model_path)
        hybrid_scaler = joblib.load(hybrid_scaler_path)
        
        X_test_hybrid = test_df[HYBRID_FEATURES].fillna(0).values.astype(np.float32)
        hybrid_metrics = evaluate_model(
            hybrid_model, hybrid_scaler, X_test_hybrid, y_test,
            "Hybrid (44 features)", f"{len(HYBRID_FEATURES)} features"
        )
        all_metrics.append(hybrid_metrics)
        print_metrics(hybrid_metrics)
    else:
        print("  [SKIP] Hybrid model not found")
    
    # 4. Learned fusion model
    fusion_model_path = os.path.join(MODELS_DIR, "fusion_model.pkl")
    fusion_config_path = os.path.join(MODELS_DIR, "fusion_config.json")
    
    if os.path.exists(fusion_model_path) and os.path.exists(fusion_config_path):
        print("  Loading learned fusion model...")
        fusion_model = joblib.load(fusion_model_path)
        
        with open(fusion_config_path) as f:
            fusion_config = json.load(f)
        
        # Need structural and semantic models for fusion input
        if os.path.exists(struct_model_path) and os.path.exists(sem_model_path):
            X_test_struct = test_df[STRUCTURAL_FEATURES].fillna(0).values.astype(np.float32)
            X_test_sem = test_df[SEMANTIC_FEATURES].fillna(0).values.astype(np.float32)
            
            # Generate probabilities
            X_test_struct_scaled = struct_scaler.transform(X_test_struct)
            struct_prob = struct_model.predict_proba(X_test_struct_scaled)[:, 1]
            
            X_test_sem_scaled = sem_scaler.transform(X_test_sem)
            sem_prob = sem_model.predict_proba(X_test_sem_scaled)[:, 1]
            
            # Apply fusion
            X_fusion = np.column_stack([struct_prob, sem_prob])
            fusion_metrics = evaluate_model(
                fusion_model, None, X_fusion, y_test,
                "Learned-Fusion PhishOut", "score-level fusion"
            )
            all_metrics.append(fusion_metrics)
            print_metrics(fusion_metrics)
            
            print(f"\n  Fusion formula: {fusion_config['formula']}")
        else:
            print("  [SKIP] Cannot evaluate fusion without base models")
    else:
        print("  [SKIP] Fusion model not found")
    
    if not all_metrics:
        print("\n[ERROR] No models evaluated.")
        return
    
    # Print comparison table
    print_comparison_table(all_metrics)
    
    # Find best model by F1
    best_model = max(all_metrics, key=lambda m: m['f1'])
    print(f"\n  Best model by F1: {best_model['model']} (F1={best_model['f1']:.4f})")
    
    # Load threshold config
    threshold_config_path = os.path.join(MODELS_DIR, "threshold_config.json")
    threshold_config = {}
    if os.path.exists(threshold_config_path):
        with open(threshold_config_path) as f:
            threshold_config = json.load(f)
        print(f"\n  Calibrated thresholds:")
        print(f"    SAFE: risk score < {threshold_config.get('safe_max_risk_score', 'N/A')}")
        print(f"    SUSPICIOUS: {threshold_config.get('safe_max_risk_score', 'N/A')} <= score < {threshold_config.get('phishing_min_risk_score', 'N/A')}")
        print(f"    PHISHING: risk score >= {threshold_config.get('phishing_min_risk_score', 'N/A')}")
    
    # Save comprehensive results
    final_results = {
        "evaluation_type": "E1_E2_final_test",
        "test_set_size": len(test_df),
        "test_legitimate": int(sum(y_test == 0)),
        "test_phishing": int(sum(y_test == 1)),
        "test_set_usage": "NOT used for training or calibration - final evaluation only",
        "all_models": all_metrics,
        "best_model_by_f1": best_model['model'],
        "threshold_config": threshold_config,
        "fusion_config": fusion_config if os.path.exists(fusion_config_path) else None,
    }
    
    results_path = os.path.join(MODELS_DIR, "final_evaluation_results.json")
    with open(results_path, "w") as f:
        json.dump(final_results, f, indent=2)
    
    print(f"\n[+] Final results saved: {results_path}")
    
    print("\n" + "=" * 90)
    print("  FINAL TEST EVALUATION COMPLETE")
    print("=" * 90)
    print("\n  This concludes E1 (normal detection) and E2 (model comparison).")
    print("  The test set was NOT used for any training or calibration decisions.")


if __name__ == "__main__":
    main()