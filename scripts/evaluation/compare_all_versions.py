"""
Compare V2 vs Old V3 vs Fixed V3
================================
Comprehensive comparison of all three model versions.
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
V2_MODELS_DIR = "models/phish360_v2"
V3_MODELS_DIR = "models/phish360_v3"
V3_DATA_DIR = "dataset/phish360/v3/processed"
OLD_V3_RESULTS_DIR = "models/phish360_v3_old"  # We'll save old V3 results first

# Structural features (32)
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

# V2 Semantic features (15)
SEMANTIC_FEATURES_V2 = [
    'password_fields', 'text_email_fields', 'forms', 'external_links',
    'iframes', 'scripts', 'login_indicators', 'credential_indicators',
    'payment_indicators', 'urgency_indicators', 'brand_indicators', 'text_length',
    'domain_brand_consistency', 'form_action_same_origin', 'trusted_domain'
]

# V3 Semantic features (19)
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

def main():
    print("=" * 80)
    print("V2 vs Old V3 vs Fixed V3 Comparison")
    print("=" * 80)
    
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
    
    # Load Fixed V3 models
    print("[*] Loading Fixed V3 models...")
    v3_sem_model = joblib.load(os.path.join(V3_MODELS_DIR, "semantic_model.pkl"))
    v3_sem_scaler = joblib.load(os.path.join(V3_MODELS_DIR, "semantic_scaler.pkl"))
    v3_fusion_model = joblib.load(os.path.join(V3_MODELS_DIR, "fusion_model.pkl"))
    
    with open(os.path.join(V3_MODELS_DIR, "threshold_config.json")) as f:
        v3_threshold_config = json.load(f)
    v3_phishing_min = v3_threshold_config['phishing_min_probability']
    
    # Load Old V3 results from audit
    print("[*] Loading Old V3 results from audit...")
    with open(os.path.join(V3_MODELS_DIR, "audit_results.json")) as f:
        old_v3_audit = json.load(f)
    
    # Load test set
    print("\n[*] Loading test set...")
    test_df = pd.read_parquet(os.path.join(V3_DATA_DIR, "test_features.parquet"))
    print(f"Test set: {len(test_df)} samples")
    
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
    
    # Fixed V3 predictions
    X_test_sem_v3_scaled = v3_sem_scaler.transform(X_test_sem_v3)
    p_test_sem_v3 = v3_sem_model.predict_proba(X_test_sem_v3_scaled)[:, 1]
    
    X_fusion_test_v3 = np.column_stack([p_test_struct, p_test_sem_v3])
    p_fusion_test_v3 = v3_fusion_model.predict_proba(X_fusion_test_v3)[:, 1]
    y_pred_test_v3 = (p_fusion_test_v3 >= v3_phishing_min).astype(int)
    
    # Evaluate V2 and Fixed V3
    v2_test_metrics = evaluate_model(y_test, y_pred_test_v2, p_fusion_test_v2, "V2")
    v3_fixed_test_metrics = evaluate_model(y_test, y_pred_test_v3, p_fusion_test_v3, "Fixed V3")
    
    # Old V3 metrics from audit (reconstructed)
    v3_old_test_metrics = {
        "model": "Old V3 (Pre-Fix)",
        "accuracy": 0.9618,
        "precision": 0.9411,
        "recall": 0.9748,
        "f1": 0.9577,
        "roc_auc": 0.9917,
        "confusion_matrix": {"tn": 901, "fp": 46, "fn": 19, "tp": 735},
        "false_positive_rate": 0.0486,
        "false_negative_rate": 0.0252,
    }
    
    # Hard-negative evaluation
    print("\n[*] Loading hard-negative eval set...")
    hn_df = pd.read_parquet(os.path.join(V3_DATA_DIR, "hard_neg_eval_features.parquet"))
    print(f"Hard-negative eval set: {len(hn_df)} samples")
    
    y_hn = hn_df['label'].values.astype(int)
    X_hn_struct = hn_df[STRUCTURAL_FEATURES].fillna(0).values.astype(np.float32)
    X_hn_sem_v2 = hn_df[SEMANTIC_FEATURES_V2].fillna(0).values.astype(np.float32)
    X_hn_sem_v3 = hn_df[SEMANTIC_FEATURES_V3].fillna(0).values.astype(np.float32)
    
    # V2 on hard-negatives
    X_hn_struct_scaled = v2_struct_scaler.transform(X_hn_struct)
    p_hn_struct = v2_struct_model.predict_proba(X_hn_struct_scaled)[:, 1]
    
    X_hn_sem_v2_scaled = v2_sem_scaler.transform(X_hn_sem_v2)
    p_hn_sem_v2 = v2_sem_model.predict_proba(X_hn_sem_v2_scaled)[:, 1]
    
    X_fusion_hn_v2 = np.column_stack([p_hn_struct, p_hn_sem_v2])
    p_fusion_hn_v2 = v2_fusion_model.predict_proba(X_fusion_hn_v2)[:, 1]
    y_pred_hn_v2 = (p_fusion_hn_v2 >= v2_phishing_min).astype(int)
    
    # Fixed V3 on hard-negatives
    X_hn_sem_v3_scaled = v3_sem_scaler.transform(X_hn_sem_v3)
    p_hn_sem_v3 = v3_sem_model.predict_proba(X_hn_sem_v3_scaled)[:, 1]
    
    X_fusion_hn_v3 = np.column_stack([p_hn_struct, p_hn_sem_v3])
    p_fusion_hn_v3 = v3_fusion_model.predict_proba(X_fusion_hn_v3)[:, 1]
    y_pred_hn_v3 = (p_fusion_hn_v3 >= v3_phishing_min).astype(int)
    
    v2_hn_metrics = evaluate_model(y_hn, y_pred_hn_v2, p_fusion_hn_v2, "V2")
    v3_fixed_hn_metrics = evaluate_model(y_hn, y_pred_hn_v3, p_fusion_hn_v3, "Fixed V3")
    
    # Old V3 hard-negative metrics from audit
    v3_old_hn_metrics = {
        "model": "Old V3 (Pre-Fix)",
        "accuracy": 0.9450,
        "precision": 0.0,
        "recall": 0.0,
        "f1": 0.0,
        "roc_auc": float('nan'),
        "confusion_matrix": {"tn": 189, "fp": 11, "fn": 0, "tp": 0},
        "false_positive_rate": 0.0550,
        "false_negative_rate": 0.0,
    }
    
    # Load real-world sanity check results
    print("[*] Loading real-world sanity check results...")
    with open(os.path.join(V3_MODELS_DIR, "real_world_sanity_check.json")) as f:
        sanity_check = json.load(f)
    
    v2_safe = sum(1 for r in sanity_check if r['v2_verdict'] == "SAFE")
    v3_safe = sum(1 for r in sanity_check if r['v3_verdict'] == "SAFE")
    
    # Print comparison
    print("\n" + "=" * 80)
    print("Test Set Comparison")
    print("=" * 80)
    print(f"{'Metric':<15} {'V2':<12} {'Old V3':<12} {'Fixed V3':<12}")
    print("-" * 80)
    print(f"{'Accuracy':<15} {v2_test_metrics['accuracy']:<12.4f} {v3_old_test_metrics['accuracy']:<12.4f} {v3_fixed_test_metrics['accuracy']:<12.4f}")
    print(f"{'Precision':<15} {v2_test_metrics['precision']:<12.4f} {v3_old_test_metrics['precision']:<12.4f} {v3_fixed_test_metrics['precision']:<12.4f}")
    print(f"{'Recall':<15} {v2_test_metrics['recall']:<12.4f} {v3_old_test_metrics['recall']:<12.4f} {v3_fixed_test_metrics['recall']:<12.4f}")
    print(f"{'F1':<15} {v2_test_metrics['f1']:<12.4f} {v3_old_test_metrics['f1']:<12.4f} {v3_fixed_test_metrics['f1']:<12.4f}")
    print(f"{'ROC-AUC':<15} {v2_test_metrics['roc_auc']:<12.4f} {v3_old_test_metrics['roc_auc']:<12.4f} {v3_fixed_test_metrics['roc_auc']:<12.4f}")
    print(f"{'FPR':<15} {v2_test_metrics['false_positive_rate']:<12.4f} {v3_old_test_metrics['false_positive_rate']:<12.4f} {v3_fixed_test_metrics['false_positive_rate']:<12.4f}")
    print(f"{'FNR':<15} {v2_test_metrics['false_negative_rate']:<12.4f} {v3_old_test_metrics['false_negative_rate']:<12.4f} {v3_fixed_test_metrics['false_negative_rate']:<12.4f}")
    
    print("\n" + "=" * 80)
    print("Hard-Negative Set Comparison")
    print("=" * 80)
    print(f"{'Metric':<20} {'V2':<12} {'Old V3':<12} {'Fixed V3':<12}")
    print("-" * 80)
    print(f"{'False Positives':<20} {v2_hn_metrics['confusion_matrix']['fp']:<12} {v3_old_hn_metrics['confusion_matrix']['fp']:<12} {v3_fixed_hn_metrics['confusion_matrix']['fp']:<12}")
    print(f"{'FPR':<20} {v2_hn_metrics['false_positive_rate']:<12.4f} {v3_old_hn_metrics['false_positive_rate']:<12.4f} {v3_fixed_hn_metrics['false_positive_rate']:<12.4f}")
    
    print("\n" + "=" * 80)
    print("Real-World Sanity Check (5 URLs)")
    print("=" * 80)
    print(f"V2 SAFE: {v2_safe}/5 ({v2_safe/5*100:.0f}%)")
    print(f"Fixed V3 SAFE: {v3_safe}/5 ({v3_safe/5*100:.0f}%)")
    
    # Save comparison results
    comparison_results = {
        "test_set": {
            "v2": v2_test_metrics,
            "old_v3": v3_old_test_metrics,
            "fixed_v3": v3_fixed_test_metrics,
            "deltas": {
                "v2_to_fixed_v3": {
                    "accuracy": round(v3_fixed_test_metrics['accuracy'] - v2_test_metrics['accuracy'], 4),
                    "precision": round(v3_fixed_test_metrics['precision'] - v2_test_metrics['precision'], 4),
                    "recall": round(v3_fixed_test_metrics['recall'] - v2_test_metrics['recall'], 4),
                    "f1": round(v3_fixed_test_metrics['f1'] - v2_test_metrics['f1'], 4),
                    "fpr": round(v3_fixed_test_metrics['false_positive_rate'] - v2_test_metrics['false_positive_rate'], 4),
                }
            }
        },
        "hard_negative_set": {
            "v2": v2_hn_metrics,
            "old_v3": v3_old_hn_metrics,
            "fixed_v3": v3_fixed_hn_metrics,
            "deltas": {
                "v2_to_fixed_v3": {
                    "false_positives": v3_fixed_hn_metrics['confusion_matrix']['fp'] - v2_hn_metrics['confusion_matrix']['fp'],
                    "fpr": round(v3_fixed_hn_metrics['false_positive_rate'] - v2_hn_metrics['false_positive_rate'], 4),
                }
            }
        },
        "real_world_sanity": {
            "v2_safe": v2_safe,
            "fixed_v3_safe": v3_safe,
            "total_urls": 5
        },
        "fix_summary": {
            "root_cause": "Script extraction failed on 99.5% of Phish360 HTML (used html2text_text instead of full_html)",
            "fix": "Changed html_column from 'html2text_text' to 'full_html' in phish360_v3_feature_extractor.py",
            "impact": "Scripts now correctly detected (0.5% zero vs 99.5% zero), text_to_script_ratio normalized (mean 913 vs 48,974)"
        }
    }
    
    results_path = os.path.join(V3_MODELS_DIR, "v2_old_v3_fixed_v3_comparison.json")
    with open(results_path, "w") as f:
        json.dump(comparison_results, f, indent=2)
    print(f"\n[+] Comparison results saved: {results_path}")
    
    print("\n" + "=" * 80)
    print("Comparison Complete")
    print("=" * 80)


if __name__ == "__main__":
    main()
