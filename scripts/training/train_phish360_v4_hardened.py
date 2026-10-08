import sys
import os
import pandas as pd
import numpy as np
import joblib
from pathlib import Path
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from bs4 import BeautifulSoup

from semantic_v4.model import SemanticModelV4
from attacker.webpage_state import WebPageState
from attacker.mutations import (
    HtmlAddMassiveBenignTextMutation,
    HtmlSwapPasswordInputMutation,
    HtmlObfuscateTextMutation,
    HtmlAddCosmeticDivMutation,
    UrlRemoveSuspiciousKeywordsMutation
)
from ml_model import extract_features

def augment_with_mutations(df):
    """
    Apply adversarial mutations to phishing samples in the dataframe
    to generate adversarial training examples.
    """
    print("Generating adversarial samples for training...")
    mutations = [
        HtmlAddMassiveBenignTextMutation(),
        HtmlSwapPasswordInputMutation(),
        HtmlObfuscateTextMutation(),
        HtmlAddCosmeticDivMutation()
    ]
    
    adv_rows = []
    phish_df = df[df['label'] == 1]
    
    # We will just take 500 samples to mutate to save time
    sample_to_mutate = phish_df.sample(min(500, len(phish_df)), random_state=42)
    
    for _, row in sample_to_mutate.iterrows():
        state = WebPageState(row['URL'], row['URL'], row['full_html'], row['full_html'])
        for mut in mutations:
            try:
                if mut.is_applicable(state):
                    new_state = mut.apply(state)
                    adv_rows.append({
                        'URL': new_state.current_url,
                        'full_html': new_state.current_html,
                        'label': 1,
                        'is_adv': True
                    })
            except Exception:
                pass
                
    adv_df = pd.DataFrame(adv_rows)
    print(f"Generated {len(adv_df)} adversarial examples.")
    df['is_adv'] = False
    return pd.concat([df, adv_df]).reset_index(drop=True)

def main():
    print("PHISH OUT - Hardened V4 Training (Adversarial + Preprocessing)")
    
    phish_path = r"D:\Downloads\phish360_parquet\Phish360_phish.parquet"
    legit_path = r"D:\Downloads\phish360_parquet\Phish360_legit.parquet"
    
    df_phish = pd.read_parquet(phish_path, columns=["URL", "full_html"]).sample(1500, random_state=42)
    df_legit = pd.read_parquet(legit_path, columns=["URL", "full_html"]).sample(1500, random_state=42)
    
    df_phish["label"] = 1
    df_legit["label"] = 0
    
    df = pd.concat([df_phish, df_legit]).reset_index(drop=True)
    df = df[df["full_html"].notna()]
    df = df[df["full_html"].str.len() > 100]
    
    # Split BEFORE augmentation to prevent leakage
    train_df, test_df = train_test_split(df, test_size=0.2, random_state=42)
    
    # Augment Training Set
    train_df = augment_with_mutations(train_df)
    
    print(f"Total training samples (incl. adv): {len(train_df)}")
    
    # Init V4 Semantic
    semantic_model = SemanticModelV4()
    
    print("Extracting semantic embeddings for train set...")
    X_s_train = semantic_model.extract_features_batch(train_df["full_html"].tolist())
    y_s_train = train_df["label"].values
    
    print("Extracting semantic embeddings for test set...")
    X_s_test = semantic_model.extract_features_batch(test_df["full_html"].tolist())
    y_s_test = test_df["label"].values
    
    # Train semantic
    semantic_model.train(X_s_train, y_s_train)
    out_dir = Path("models/phish360_v4_hardened")
    semantic_model.save(str(out_dir))
    
    # Now, Train the Fusion Model
    print("\nPreparing Fusion Training...")
    struct_model = joblib.load("models/phish360_v2/structural_model.pkl")
    struct_scaler = joblib.load("models/phish360_v2/structural_scaler.pkl")
    
    if hasattr(struct_model, 'n_jobs'): struct_model.n_jobs = 1
    if hasattr(struct_model, 'estimators_'):
        for est in struct_model.estimators_:
            if hasattr(est, 'n_jobs'): est.n_jobs = 1
    
    def get_struct_probs(urls, htmls):
        probs = []
        for u, h in zip(urls, htmls):
            try:
                feats = extract_features(u, h)
                f_array = [feats.get(k, 0) for k in [
                    "url_length", "hostname_length", "path_length", "query_length", "url_depth", "num_params", "has_ip", "has_at", "has_port", "double_slash", "prefix_suffix", "sub_domain_count", "excessive_dots", "numeric_subdomain", "punycode_present", "https_token", "is_shortening", "tld_risk_score", "has_redirect_param", "double_extension", "hex_encoded", "domain_entropy", "digit_ratio", "special_char_count", "consonant_ratio", "longest_word_length", "brand_impersonation_score", "subdomain_brand_match", "suspicious_keywords", "login_path_score", "levenshtein_min", "levenshtein_ratio"
                ]]
                f_scaled = struct_scaler.transform([f_array])
                p = struct_model.predict_proba(f_scaled)[0][1]
            except:
                p = 0.5
            probs.append(p)
        return np.array(probs)
    
    print("Extracting Structural probabilities for Train...")
    struct_train_probs = get_struct_probs(train_df["URL"].tolist(), train_df["full_html"].tolist())
    semantic_train_probs = semantic_model.classifier.predict_proba(X_s_train)[:, 1]
    
    X_fusion_train = np.column_stack((struct_train_probs, semantic_train_probs))
    
    fusion_model = LogisticRegression(random_state=42)
    fusion_model.fit(X_fusion_train, y_s_train)
    joblib.dump(fusion_model, out_dir / "fusion_model.pkl")
    print("Saved Hardened Fusion Model.")
    
    # Evaluate Fusion
    print("\n--- Hardened Fusion V4 Performance on Normal Test Set ---")
    struct_test_probs = get_struct_probs(test_df["URL"].tolist(), test_df["full_html"].tolist())
    semantic_test_probs = semantic_model.classifier.predict_proba(X_s_test)[:, 1]
    
    X_fusion_test = np.column_stack((struct_test_probs, semantic_test_probs))
    fusion_preds = fusion_model.predict(X_fusion_test)
    
    print(f"Accuracy:  {accuracy_score(y_s_test, fusion_preds):.4f}")
    print(f"FPR:       {confusion_matrix(y_s_test, fusion_preds)[0][1] / (confusion_matrix(y_s_test, fusion_preds)[0][1] + confusion_matrix(y_s_test, fusion_preds)[0][0]):.4f}")

if __name__ == "__main__":
    main()
