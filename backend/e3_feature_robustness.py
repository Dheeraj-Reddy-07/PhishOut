"""
PhishOut E3 — Feature-Level Robustness Evaluation
==================================================
Implements IEEE-style feature-level robustness testing using ±5% perturbation.

This is Phase E3 of the PhishOut research project, following the methodology
from the official base paper: "An Optimized Machine Learning Framework for
Phishing Website Detection Integrating Feature Robustness and Adversarial
Resilience Ranking" (IEEE ICPCSN 2025).

Usage:
    python e3_feature_robustness.py
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
ROBUSTNESS_DIR = os.path.join(MODELS_DIR, "robustness")
os.makedirs(ROBUSTNESS_DIR, exist_ok=True)

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

ALL_FEATURES = STRUCTURAL_FEATURES + SEMANTIC_FEATURES


def evaluate_model(model, scaler, X_test, y_test):
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
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred), 4),
        "recall": round(recall_score(y_test, y_pred), 4),
        "f1": round(f1_score(y_test, y_pred), 4),
        "roc_auc": round(roc_auc_score(y_test, y_prob), 4),
        "pr_auc": round(pr_auc, 4),
        "fpr": round(fp / (fp + tn) if (fp + tn) > 0 else 0, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def perturb_feature(X, feature_idx, perturbation_pct):
    """
    Apply ±5% perturbation to a single feature.
    
    Args:
        X: Feature matrix (n_samples, n_features)
        feature_idx: Index of feature to perturb
        perturbation_pct: Perturbation percentage (e.g., 0.05 for +5%, -0.05 for -5%)
    
    Returns:
        Perturbed feature matrix
    """
    X_perturbed = X.copy()
    X_perturbed[:, feature_idx] = X[:, feature_idx] * (1 + perturbation_pct)
    return X_perturbed


def safe_perturb_feature(X, feature_idx, perturbation_pct, feature_name):
    """
    Apply perturbation with safety checks for feature types.
    
    Handles:
    - Binary features (0/1) - clamp to [0,1]
    - Count features - ensure non-negative
    - Probability/ratio features - clamp to reasonable bounds
    """
    X_perturbed = X.copy()
    original_values = X[:, feature_idx].copy()
    
    # Apply perturbation
    perturbed_values = original_values * (1 + perturbation_pct)
    
    # Feature-specific safety checks
    # Binary indicators (has_ip, has_at, etc.)
    if feature_name.startswith('has_') or feature_name in ['https_token', 'is_shortening', 
                                                          'double_slash', 'prefix_suffix',
                                                          'punycode_present', 'has_redirect_param',
                                                          'double_extension', 'hex_encoded']:
        # Clamp to [0, 1] range for binary-like features
        perturbed_values = np.clip(perturbed_values, 0, 1)
    
    # Count features (should remain non-negative)
    elif feature_name in ['password_fields', 'text_email_fields', 'forms', 'external_links',
                         'iframes', 'scripts', 'sub_domain_count', 'num_params']:
        perturbed_values = np.maximum(perturbed_values, 0)
    
    # Probability/ratio features (clamp to [0, 1] or reasonable range)
    elif 'ratio' in feature_name or 'score' in feature_name or feature_name in ['tld_risk_score']:
        perturbed_values = np.clip(perturbed_values, 0, 1)
    
    # Length/count features (ensure non-negative)
    elif 'length' in feature_name or 'count' in feature_name or feature_name in ['url_depth']:
        perturbed_values = np.maximum(perturbed_values, 0)
    
    # Distance features (ensure non-negative)
    elif feature_name in ['levenshtein_min', 'levenshtein_ratio']:
        perturbed_values = np.maximum(perturbed_values, 0)
    
    X_perturbed[:, feature_idx] = perturbed_values
    return X_perturbed


def main():
    print("=" * 80)
    print("  PhishOut E3 — Feature-Level Robustness Evaluation")
    print("=" * 80)
    
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
    
    # Load frozen models
    print("\n[*] Loading frozen Phase 2 models...")
    
    # Load structural model
    struct_model_path = os.path.join(MODELS_DIR, "structural_model.pkl")
    struct_scaler_path = os.path.join(MODELS_DIR, "structural_scaler.pkl")
    
    if not os.path.exists(struct_model_path) or not os.path.exists(struct_scaler_path):
        print("[ERROR] Structural model not found.")
        return
    
    struct_model = joblib.load(struct_model_path)
    struct_scaler = joblib.load(struct_scaler_path)
    print("  [OK] Loaded structural model")
    
    # Load semantic model
    sem_model_path = os.path.join(MODELS_DIR, "semantic_model.pkl")
    sem_scaler_path = os.path.join(MODELS_DIR, "semantic_scaler.pkl")
    
    if not os.path.exists(sem_model_path) or not os.path.exists(sem_scaler_path):
        print("[ERROR] Semantic model not found.")
        return
    
    sem_model = joblib.load(sem_model_path)
    sem_scaler = joblib.load(sem_scaler_path)
    print("  [OK] Loaded semantic model")
    
    # Load fusion model
    fusion_model_path = os.path.join(MODELS_DIR, "fusion_model.pkl")
    
    if not os.path.exists(fusion_model_path):
        print("[ERROR] Fusion model not found.")
        return
    
    fusion_model = joblib.load(fusion_model_path)
    print("  [OK] Loaded fusion model")
    
    # Load hybrid model
    hybrid_model_path = os.path.join(MODELS_DIR, "hybrid_model.pkl")
    hybrid_scaler_path = os.path.join(MODELS_DIR, "hybrid_scaler.pkl")
    
    if not os.path.exists(hybrid_model_path) or not os.path.exists(hybrid_scaler_path):
        print("[WARNING] Hybrid model not found, skipping hybrid evaluation")
        hybrid_model = None
        hybrid_scaler = None
    else:
        hybrid_model = joblib.load(hybrid_model_path)
        hybrid_scaler = joblib.load(hybrid_scaler_path)
        print("  Loaded hybrid model")
    
    # Extract features
    X_test_struct = test_df[STRUCTURAL_FEATURES].fillna(0).values.astype(np.float32)
    X_test_sem = test_df[SEMANTIC_FEATURES].fillna(0).values.astype(np.float32)
    X_test_hybrid = test_df[ALL_FEATURES].fillna(0).values.astype(np.float32)
    
    # Generate fusion inputs
    X_test_struct_scaled = struct_scaler.transform(X_test_struct)
    struct_prob = struct_model.predict_proba(X_test_struct_scaled)[:, 1]
    
    X_test_sem_scaled = sem_scaler.transform(X_test_sem)
    sem_prob = sem_model.predict_proba(X_test_sem_scaled)[:, 1]
    
    X_fusion = np.column_stack([struct_prob, sem_prob])
    
    print("\n[*] Evaluating clean baseline performance...")
    
    # Evaluate clean baseline for all models
    clean_struct_metrics = evaluate_model(struct_model, struct_scaler, X_test_struct, y_test)
    clean_sem_metrics = evaluate_model(sem_model, sem_scaler, X_test_sem, y_test)
    clean_fusion_metrics = evaluate_model(fusion_model, None, X_fusion, y_test)
    
    if hybrid_model is not None:
        clean_hybrid_metrics = evaluate_model(hybrid_model, hybrid_scaler, X_test_hybrid, y_test)
    else:
        clean_hybrid_metrics = None
    
    print("\n  Clean Baseline Performance:")
    print(f"    Structural:  F1={clean_struct_metrics['f1']:.4f}, ROC-AUC={clean_struct_metrics['roc_auc']:.4f}")
    print(f"    Semantic:    F1={clean_sem_metrics['f1']:.4f}, ROC-AUC={clean_sem_metrics['roc_auc']:.4f}")
    print(f"    Fusion:      F1={clean_fusion_metrics['f1']:.4f}, ROC-AUC={clean_fusion_metrics['roc_auc']:.4f}")
    if hybrid_model is not None:
        print(f"    Hybrid:      F1={clean_hybrid_metrics['f1']:.4f}, ROC-AUC={clean_hybrid_metrics['roc_auc']:.4f}")
    
    # Feature-by-feature robustness evaluation
    print("\n[*] Starting feature-by-feature robustness evaluation...")
    print(f"    Evaluating {len(ALL_FEATURES)} features × 2 perturbations = {len(ALL_FEATURES) * 2} experiments")
    
    feature_results = []
    
    for idx, feature_name in enumerate(ALL_FEATURES):
        feature_group = "structural" if feature_name in STRUCTURAL_FEATURES else "semantic"
        
        # Determine which feature matrix to use
        if feature_name in STRUCTURAL_FEATURES:
            local_idx = STRUCTURAL_FEATURES.index(feature_name)
            X_base = X_test_struct
            scaler = struct_scaler
            model = struct_model
            clean_metrics = clean_struct_metrics
        else:
            local_idx = SEMANTIC_FEATURES.index(feature_name)
            X_base = X_test_sem
            scaler = sem_scaler
            model = sem_model
            clean_metrics = clean_sem_metrics
        
        # Evaluate -5% perturbation
        X_minus5 = safe_perturb_feature(X_base, local_idx, -0.05, feature_name)
        metrics_minus5 = evaluate_model(model, scaler, X_minus5, y_test)
        
        # Evaluate +5% perturbation
        X_plus5 = safe_perturb_feature(X_base, local_idx, 0.05, feature_name)
        metrics_plus5 = evaluate_model(model, scaler, X_plus5, y_test)
        
        # Calculate degradation
        f1_drop_minus5 = clean_metrics['f1'] - metrics_minus5['f1']
        f1_drop_plus5 = clean_metrics['f1'] - metrics_plus5['f1']
        worst_f1_drop = max(f1_drop_minus5, f1_drop_plus5)
        mean_f1_drop = (f1_drop_minus5 + f1_drop_plus5) / 2
        
        acc_drop_minus5 = clean_metrics['accuracy'] - metrics_minus5['accuracy']
        acc_drop_plus5 = clean_metrics['accuracy'] - metrics_plus5['accuracy']
        worst_acc_drop = max(acc_drop_minus5, acc_drop_plus5)
        
        roc_drop_minus5 = clean_metrics['roc_auc'] - metrics_minus5['roc_auc']
        roc_drop_plus5 = clean_metrics['roc_auc'] - metrics_plus5['roc_auc']
        worst_roc_drop = max(roc_drop_minus5, roc_drop_plus5)
        
        feature_results.append({
            "feature": feature_name,
            "feature_group": feature_group,
            "feature_index": idx,
            "clean_f1": clean_metrics['f1'],
            "clean_accuracy": clean_metrics['accuracy'],
            "clean_roc_auc": clean_metrics['roc_auc'],
            "f1_minus5": metrics_minus5['f1'],
            "f1_plus5": metrics_plus5['f1'],
            "worst_f1": min(metrics_minus5['f1'], metrics_plus5['f1']),
            "f1_drop_minus5": round(f1_drop_minus5, 4),
            "f1_drop_plus5": round(f1_drop_plus5, 4),
            "worst_f1_drop": round(worst_f1_drop, 4),
            "mean_f1_drop": round(mean_f1_drop, 4),
            "accuracy_drop_minus5": round(acc_drop_minus5, 4),
            "accuracy_drop_plus5": round(acc_drop_plus5, 4),
            "worst_accuracy_drop": round(worst_acc_drop, 4),
            "roc_auc_drop_minus5": round(roc_drop_minus5, 4),
            "roc_auc_drop_plus5": round(roc_drop_plus5, 4),
            "worst_roc_auc_drop": round(worst_roc_drop, 4),
        })
        
        if (idx + 1) % 10 == 0:
            print(f"    Progress: {idx + 1}/{len(ALL_FEATURES)} features evaluated")
    
    print(f"\n[*] Completed {len(ALL_FEATURES)} feature robustness evaluations")
    
    # Create ranking
    print("\n[*] Creating feature robustness ranking...")
    
    # Sort by worst F1 drop (most fragile first)
    ranked_features = sorted(feature_results, key=lambda x: x['worst_f1_drop'], reverse=True)
    
    # Separate by feature group
    structural_results = [r for r in feature_results if r['feature_group'] == 'structural']
    semantic_results = [r for r in feature_results if r['feature_group'] == 'semantic']
    
    # Calculate group averages
    avg_struct_f1_drop = np.mean([r['worst_f1_drop'] for r in structural_results])
    avg_sem_f1_drop = np.mean([r['worst_f1_drop'] for r in semantic_results])
    
    # Find most fragile and most robust features
    most_fragile_5 = ranked_features[:5]
    most_robust_5 = ranked_features[-5:][::-1]  # Reverse to show highest robustness first
    
    most_fragile_struct = sorted(structural_results, key=lambda x: x['worst_f1_drop'], reverse=True)[:3]
    most_fragile_sem = sorted(semantic_results, key=lambda x: x['worst_f1_drop'], reverse=True)[:3]
    
    most_robust_struct = sorted(structural_results, key=lambda x: x['worst_f1_drop'])[:3]
    most_robust_sem = sorted(semantic_results, key=lambda x: x['worst_f1_drop'])[:3]
    
    # Print summary
    print("\n" + "=" * 80)
    print("  E3 ROBUSTNESS EVALUATION SUMMARY")
    print("=" * 80)
    
    print(f"\n  Clean Baseline (Fusion Model):")
    print(f"    F1:        {clean_fusion_metrics['f1']:.4f}")
    print(f"    Accuracy:  {clean_fusion_metrics['accuracy']:.4f}")
    print(f"    ROC-AUC:   {clean_fusion_metrics['roc_auc']:.4f}")
    
    print(f"\n  Most Fragile 5 Features (by worst F1 drop):")
    for i, r in enumerate(most_fragile_5, 1):
        print(f"    {i}. {r['feature']:30s} - Worst F1 drop: {r['worst_f1_drop']:.4f}")
    
    print(f"\n  Most Robust 5 Features (by worst F1 drop):")
    for i, r in enumerate(most_robust_5, 1):
        print(f"    {i}. {r['feature']:30s} - Worst F1 drop: {r['worst_f1_drop']:.4f}")
    
    print(f"\n  Structural vs Semantic Robustness:")
    print(f"    Average structural F1 drop:  {avg_struct_f1_drop:.4f}")
    print(f"    Average semantic F1 drop:    {avg_sem_f1_drop:.4f}")
    
    print(f"\n  Most Fragile Structural Features:")
    for i, r in enumerate(most_fragile_struct, 1):
        print(f"    {i}. {r['feature']:30s} - Worst F1 drop: {r['worst_f1_drop']:.4f}")
    
    print(f"\n  Most Fragile Semantic Features:")
    for i, r in enumerate(most_fragile_sem, 1):
        print(f"    {i}. {r['feature']:30s} - Worst F1 drop: {r['worst_f1_drop']:.4f}")
    
    print(f"\n  Most Robust Structural Features:")
    for i, r in enumerate(most_robust_struct, 1):
        print(f"    {i}. {r['feature']:30s} - Worst F1 drop: {r['worst_f1_drop']:.4f}")
    
    print(f"\n  Most Robust Semantic Features:")
    for i, r in enumerate(most_robust_sem, 1):
        print(f"    {i}. {r['feature']:30s} - Worst F1 drop: {r['worst_f1_drop']:.4f}")
    
    # Save results
    print("\n[*] Saving results...")
    
    # Save detailed results as CSV
    results_df = pd.DataFrame(feature_results)
    csv_path = os.path.join(ROBUSTNESS_DIR, "e3_feature_robustness_results.csv")
    results_df.to_csv(csv_path, index=False)
    print(f"  [OK] Saved: {csv_path}")
    
    # Save detailed results as JSON
    json_path = os.path.join(ROBUSTNESS_DIR, "e3_feature_robustness_results.json")
    with open(json_path, "w") as f:
        json.dump(feature_results, f, indent=2)
    print(f"  [OK] Saved: {json_path}")
    
    # Save summary
    summary = {
        "experiment_type": "E3_feature_level_robustness",
        "base_paper": "IEEE ICPCSN 2025 - Feature Robustness and Adversarial Resilience Ranking",
        "methodology_adaptation": "±5% feature perturbation adapted to PhishOut 44-feature architecture",
        "dataset": "Phish360 test set",
        "test_set_size": len(test_df),
        "n_features_evaluated": len(ALL_FEATURES),
        "n_perturbation_experiments": len(ALL_FEATURES) * 2,
        "perturbation_level": "±5%",
        "clean_baseline": {
            "structural": clean_struct_metrics,
            "semantic": clean_sem_metrics,
            "fusion": clean_fusion_metrics,
            "hybrid": clean_hybrid_metrics
        },
        "most_fragile_5": [{"feature": r['feature'], "worst_f1_drop": r['worst_f1_drop']} for r in most_fragile_5],
        "most_robust_5": [{"feature": r['feature'], "worst_f1_drop": r['worst_f1_drop']} for r in most_robust_5],
        "structural_vs_semantic": {
            "avg_structural_f1_drop": round(float(avg_struct_f1_drop), 4),
            "avg_semantic_f1_drop": round(float(avg_sem_f1_drop), 4),
            "most_fragile_structural": [{"feature": r['feature'], "worst_f1_drop": r['worst_f1_drop']} for r in most_fragile_struct],
            "most_fragile_semantic": [{"feature": r['feature'], "worst_f1_drop": r['worst_f1_drop']} for r in most_fragile_sem],
            "most_robust_structural": [{"feature": r['feature'], "worst_f1_drop": r['worst_f1_drop']} for r in most_robust_struct],
            "most_robust_semantic": [{"feature": r['feature'], "worst_f1_drop": r['worst_f1_drop']} for r in most_robust_sem],
        },
        "ranking_definition": "Features ranked by worst-case F1 degradation under ±5% perturbation",
        "higher_loss_more_fragile": True,
    }
    
    summary_path = os.path.join(ROBUSTNESS_DIR, "e3_summary.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"  [OK] Saved: {summary_path}")
    
    # Save ranking as CSV
    ranking_df = pd.DataFrame(ranked_features)
    ranking_path = os.path.join(ROBUSTNESS_DIR, "e3_feature_ranking.csv")
    ranking_df.to_csv(ranking_path, index=False)
    print(f"  [OK] Saved: {ranking_path}")
    
    print("\n" + "=" * 80)
    print("  E3 FEATURE-LEVEL ROBUSTNESS EVALUATION COMPLETE")
    print("=" * 80)
    print("\n  This evaluation tested the sensitivity of individual features to ±5% perturbation.")
    print("  Results demonstrate which features are most fragile vs most robust.")
    print("  Next step: Create comprehensive E3 documentation report.")


if __name__ == "__main__":
    main()