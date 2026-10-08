import os
import sys
import pandas as pd
import numpy as np
import joblib
from pathlib import Path
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from ml_model import extract_features
from semantic_v4.model import SemanticModelV4

def main():
    # Load raw data
    phish_path = r"D:\Downloads\phish360_parquet\Phish360_phish.parquet"
    legit_path = r"D:\Downloads\phish360_parquet\Phish360_legit.parquet"
    
    df_phish = pd.read_parquet(phish_path).sample(1500, random_state=123)
    df_legit = pd.read_parquet(legit_path).sample(1500, random_state=123)
    
    df_phish["label"] = 1
    df_legit["label"] = 0
    df = pd.concat([df_phish, df_legit]).reset_index(drop=True)
    df = df[df["full_html"].notna()]
    df = df[df["full_html"].str.len() > 100]
    df = df.sample(2400, random_state=123).reset_index(drop=True)
    
    print(f"Test set size: {len(df)}")
    y_test = df["label"].values
    
    # Evaluate V2 Structural
    struct_model = joblib.load("models/phish360_v2/structural_model.pkl")
    struct_scaler = joblib.load("models/phish360_v2/structural_scaler.pkl")
    
    urls = df["URL"].tolist()
    struct_features = []
    for u in urls:
        try:
            feats = extract_features(u)
            struct_features.append([feats.get(k, 0) for k in [
                "url_length", "hostname_length", "path_length", "query_length", "url_depth", 
                "num_params", "has_ip", "has_at", "has_port", "double_slash", "prefix_suffix", 
                "sub_domain_count", "excessive_dots", "numeric_subdomain", "punycode_present", 
                "https_token", "is_shortening", "tld_risk_score", "has_redirect_param", 
                "double_extension", "hex_encoded", "domain_entropy", "digit_ratio", 
                "special_char_count", "consonant_ratio", "longest_word_length", 
                "brand_impersonation_score", "subdomain_brand_match", "suspicious_keywords", 
                "login_path_score", "levenshtein_min", "levenshtein_ratio"
            ]])
        except:
            struct_features.append([0]*32)
            
    struct_features_scaled = struct_scaler.transform(struct_features)
    p_struct = struct_model.predict_proba(struct_features_scaled)[:, 1]
    y_pred_struct = (p_struct >= 0.5).astype(int)
    
    cm = confusion_matrix(y_test, y_pred_struct)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp+tn) > 0 else 0
    
    print(f"--- V2 Structural ---")
    print(f"Accuracy: {accuracy_score(y_test, y_pred_struct):.4f}")
    print(f"FPR: {fpr:.4f}")
    print(f"Confusion Matrix: TN={tn}, FP={fp}, FN={fn}, TP={tp}")
    
    # Evaluate V4 Semantic
    print("\nExtracting V4 Semantic embeddings...")
    htmls = df["full_html"].tolist()
    semantic_model = SemanticModelV4("models/phish360_v4")
    X_sem = semantic_model.extract_features_batch(htmls)
    
    p_sem = semantic_model.classifier.predict_proba(X_sem)[:, 1]
    y_pred_sem = (p_sem >= 0.5).astype(int)
    
    cm_sem = confusion_matrix(y_test, y_pred_sem)
    tn_s, fp_s, fn_s, tp_s = cm_sem.ravel()
    fpr_s = fp_s / (fp_s + tn_s) if (fp_s+tn_s) > 0 else 0
    
    print(f"--- V4 Semantic ---")
    print(f"Accuracy: {accuracy_score(y_test, y_pred_sem):.4f}")
    print(f"Precision: {precision_score(y_test, y_pred_sem):.4f}")
    print(f"Recall: {recall_score(y_test, y_pred_sem):.4f}")
    print(f"F1: {f1_score(y_test, y_pred_sem):.4f}")
    print(f"FPR: {fpr_s:.4f}")
    print(f"Confusion Matrix: TN={tn_s}, FP={fp_s}, FN={fn_s}, TP={tp_s}")
    
    # Evaluate V4 Hybrid
    fusion_model = joblib.load("models/phish360_v4/fusion_model.pkl")
    X_fusion = np.column_stack((p_struct, p_sem))
    
    p_fusion = fusion_model.predict_proba(X_fusion)[:, 1]
    y_pred_fusion = (p_fusion >= 0.5).astype(int)
    
    cm_f = confusion_matrix(y_test, y_pred_fusion)
    tn_f, fp_f, fn_f, tp_f = cm_f.ravel()
    fpr_f = fp_f / (fp_f + tn_f) if (fp_f+tn_f) > 0 else 0
    
    print(f"\n--- V4 Hybrid ---")
    print(f"Accuracy: {accuracy_score(y_test, y_pred_fusion):.4f}")
    print(f"Precision: {precision_score(y_test, y_pred_fusion):.4f}")
    print(f"Recall: {recall_score(y_test, y_pred_fusion):.4f}")
    print(f"F1: {f1_score(y_test, y_pred_fusion):.4f}")
    print(f"FPR: {fpr_f:.4f}")
    print(f"Confusion Matrix: TN={tn_f}, FP={fp_f}, FN={fn_f}, TP={tp_f}")

if __name__ == "__main__":
    main()
