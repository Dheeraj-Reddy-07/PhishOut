import sys
import os
import pandas as pd
import numpy as np
import joblib
from pathlib import Path
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

from semantic_v4.model import SemanticModelV4

def main():
    print("PHISH OUT - Part 4: Training Semantic V4 & Fusion Layer")
    
    # Load dataset
    phish_path = r"D:\Downloads\phish360_parquet\Phish360_phish.parquet"
    legit_path = r"D:\Downloads\phish360_parquet\Phish360_legit.parquet"
    
    # Load limited subset to keep it fast
    print("Loading raw HTML datasets...")
    df_phish = pd.read_parquet(phish_path, columns=["URL", "full_html"]).sample(1500, random_state=42)
    df_legit = pd.read_parquet(legit_path, columns=["URL", "full_html"]).sample(1500, random_state=42)
    
    df_phish["label"] = 1
    df_legit["label"] = 0
    
    df = pd.concat([df_phish, df_legit]).reset_index(drop=True)
    df = df[df["full_html"].notna()]
    df = df[df["full_html"].str.len() > 100]
    
    print(f"Total samples: {len(df)}")
    
    # Init V4 Semantic
    semantic_model = SemanticModelV4()
    
    print("Extracting semantic embeddings (this may take a minute)...")
    X_embeddings = semantic_model.extract_features_batch(df["full_html"].tolist())
    y = df["label"].values
    
    # Split for semantic training
    X_s_train, X_s_test, y_s_train, y_s_test, html_train, html_test, url_train, url_test = train_test_split(
        X_embeddings, y, df["full_html"].tolist(), df["URL"].tolist(), test_size=0.2, random_state=42
    )
    
    # Train semantic
    semantic_model.train(X_s_train, y_s_train)
    out_dir = Path("models/phish360_v4")
    semantic_model.save(str(out_dir))
    
    # Evaluate semantic independently
    print("\n--- Semantic V4 Independent Performance ---")
    preds_s = semantic_model.classifier.predict(X_s_test)
    print(f"Accuracy:  {accuracy_score(y_s_test, preds_s):.4f}")
    print(f"Precision: {precision_score(y_s_test, preds_s):.4f}")
    print(f"Recall:    {recall_score(y_s_test, preds_s):.4f}")
    print(f"F1 Score:  {f1_score(y_s_test, preds_s):.4f}")
    
    # Now, Train the Fusion Model
    print("\nPreparing Fusion Training...")
    print("Loading Frozen Structural Pipeline...")
    struct_model = joblib.load("models/phish360_v2/structural_model.pkl")
    struct_scaler = joblib.load("models/phish360_v2/structural_scaler.pkl")
    
    if hasattr(struct_model, 'n_jobs'):
        struct_model.n_jobs = 1
    if hasattr(struct_model, 'estimators_'):
        for est in struct_model.estimators_:
            if hasattr(est, 'n_jobs'):
                est.n_jobs = 1
    
    from ml_model import extract_features
    
    # We will generate structural features for the train set
    def get_struct_probs(urls, htmls):
        probs = []
        for u, h in zip(urls, htmls):
            try:
                feats = extract_features(u, h)
                f_array = []
                for k in ["url_length", "hostname_length", "path_length", "query_length", "url_depth", "num_params", "has_ip", "has_at", "has_port", "double_slash", "prefix_suffix", "sub_domain_count", "excessive_dots", "numeric_subdomain", "punycode_present", "https_token", "is_shortening", "tld_risk_score", "has_redirect_param", "double_extension", "hex_encoded", "domain_entropy", "digit_ratio", "special_char_count", "consonant_ratio", "longest_word_length", "brand_impersonation_score", "subdomain_brand_match", "suspicious_keywords", "login_path_score", "levenshtein_min", "levenshtein_ratio"]:
                    f_array.append(feats.get(k, 0))
                # Scale
                f_scaled = struct_scaler.transform([f_array])
                p = struct_model.predict_proba(f_scaled)[0][1]
            except:
                p = 0.5
            probs.append(p)
        return np.array(probs)
    
    print("Extracting Structural probabilities for Fusion (using V2 Baseline)...")
    struct_train_probs = get_struct_probs(url_train, html_train)
    semantic_train_probs = semantic_model.classifier.predict_proba(X_s_train)[:, 1]
    
    X_fusion_train = np.column_stack((struct_train_probs, semantic_train_probs))
    
    fusion_model = LogisticRegression(random_state=42)
    fusion_model.fit(X_fusion_train, y_s_train)
    joblib.dump(fusion_model, out_dir / "fusion_model.pkl")
    print("Saved Fusion Model (Logistic Regression).")
    
    # Evaluate Fusion
    print("\n--- Fusion V4 Performance ---")
    struct_test_probs = get_struct_probs(url_test, html_test)
    semantic_test_probs = semantic_model.classifier.predict_proba(X_s_test)[:, 1]
    
    X_fusion_test = np.column_stack((struct_test_probs, semantic_test_probs))
    fusion_preds = fusion_model.predict(X_fusion_test)
    
    print(f"Accuracy:  {accuracy_score(y_s_test, fusion_preds):.4f}")
    print(f"Precision: {precision_score(y_s_test, fusion_preds):.4f}")
    print(f"Recall:    {recall_score(y_s_test, fusion_preds):.4f}")
    print(f"F1 Score:  {f1_score(y_s_test, fusion_preds):.4f}")
    
    cm = confusion_matrix(y_s_test, fusion_preds)
    fp = cm[0][1]
    tn = cm[0][0]
    print(f"False Positive Rate: {fp / (fp + tn):.4f}")

if __name__ == "__main__":
    main()
