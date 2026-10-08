import os
os.environ["LOKY_MAX_CPU_COUNT"] = "1"
os.environ["OMP_NUM_THREADS"] = "1"
import sys
import pandas as pd
import numpy as np
import json
import joblib
from urllib.parse import urlparse
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from sklearn.linear_model import LogisticRegression
from pathlib import Path
from tqdm import tqdm
import warnings

warnings.filterwarnings('ignore')
import logging
logging.getLogger("sklearn").setLevel(logging.ERROR)

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from semantic_v4.model import SemanticModelV4
from ml_model import extract_features
from attacker.webpage_state import WebPageState
from attacker.mutations import (
    HtmlAddMassiveBenignTextMutation,
    HtmlSwapPasswordInputMutation,
    HtmlObfuscateTextMutation,
    HtmlAddCosmeticDivMutation,
    HtmlAddBenignTextMutation,
    HtmlAddDummyScriptMutation,
    HtmlAddExternalLinkMutation,
    HtmlInsertBenignMetaMutation,
    UrlRemoveSuspiciousKeywordsMutation,
    HtmlObfuscateFormActionMutation,
    HtmlConvertLinksToButtonsMutation
)
from attacker.semantic_mutations import (
    HtmlParaphraseCredentialTextMutation,
    HtmlTextToImageMutation,
    HtmlAddIframeMutation,
    HtmlPrependMassivePaddingMutation
)
from attacker.beam_search import BeamSearchAttacker
from attacker.simulated_annealing import SimulatedAnnealingAttacker
from attacker.mcts import MCTSAttacker
from attacker.mutation_engine import MutationEngine
from phishout_predictor import get_predictor

# --- 1. DATA PREP (No Leakage) ---
def get_domain(url):
    try:
        return urlparse(url).netloc.lower()
    except:
        return url

def load_and_split_data():
    print("Loading datasets...")
    phish_path = r"D:\Downloads\phish360_parquet\Phish360_phish.parquet"
    legit_path = r"D:\Downloads\phish360_parquet\Phish360_legit.parquet"
    
    df_phish = pd.read_parquet(phish_path, columns=["URL", "full_html"]).sample(2000, random_state=42)
    df_legit = pd.read_parquet(legit_path, columns=["URL", "full_html"]).sample(2000, random_state=42)
    
    df_phish["label"] = 1
    df_legit["label"] = 0
    df = pd.concat([df_phish, df_legit]).reset_index(drop=True)
    df = df[df["full_html"].notna()]
    df = df[df["full_html"].str.len() > 100]
    df["domain"] = df["URL"].apply(get_domain)
    
    # 60% Train, 15% Val, 25% Test
    gss1 = GroupShuffleSplit(n_splits=1, test_size=0.4, random_state=42)
    train_idx, temp_idx = next(gss1.split(df, groups=df['domain']))
    train_df = df.iloc[train_idx]
    temp_df = df.iloc[temp_idx]
    
    gss2 = GroupShuffleSplit(n_splits=1, test_size=0.625, random_state=42) # 0.625 of 0.4 = 0.25 (Test)
    val_idx, test_idx = next(gss2.split(temp_df, groups=temp_df['domain']))
    val_df = temp_df.iloc[val_idx]
    test_df = temp_df.iloc[test_idx]
    
    # Assert no overlap
    train_domains = set(train_df['domain'])
    test_domains = set(test_df['domain'])
    assert len(train_domains.intersection(test_domains)) == 0, "Leakage detected!"
    
    return train_df, val_df, test_df

# --- 2. TRAIN HARDENED V4 ---
def augment_train_set(train_df):
    mutations = [
        HtmlAddMassiveBenignTextMutation(),
        HtmlSwapPasswordInputMutation(),
        HtmlObfuscateTextMutation(),
        HtmlAddCosmeticDivMutation()
    ] # Only structural evasions
    
    adv_rows = []
    phish_df = train_df[train_df['label'] == 1]
    for _, row in phish_df.iterrows():
        state = WebPageState(row['URL'], row['URL'], row['full_html'], row['full_html'])
        for mut in mutations:
            try:
                if mut.is_applicable(state):
                    new_state = mut.apply(state)
                    adv_rows.append({
                        'URL': new_state.current_url,
                        'full_html': new_state.current_html,
                        'label': 1,
                        'domain': row['domain']
                    })
            except:
                pass
                
    adv_df = pd.DataFrame(adv_rows)
    return pd.concat([train_df, adv_df]).reset_index(drop=True)

def train_and_eval():
    train_df, val_df, test_df = load_and_split_data()
    train_df = augment_train_set(train_df)
    
    print("Training Semantic V4...")
    semantic_model = SemanticModelV4()
    X_s_train = semantic_model.extract_features_batch(train_df["full_html"].tolist())
    semantic_model.train(X_s_train, train_df["label"].values)
    out_dir = Path("models/phish360_v4_final")
    out_dir.mkdir(parents=True, exist_ok=True)
    semantic_model.save(str(out_dir))
    
    print("Extracting struct probs for Fusion...")
    struct_model = joblib.load("models/phish360_v2/structural_model.pkl")
    struct_scaler = joblib.load("models/phish360_v2/structural_scaler.pkl")
    
    def get_struct_probs(df):
        probs = []
        for _, row in df.iterrows():
            try:
                feats = extract_features(row['URL'])
                f_array = [feats.get(k, 0) for k in [
                    "url_length", "hostname_length", "path_length", "query_length", "url_depth", "num_params", "has_ip", "has_at", "has_port", "double_slash", "prefix_suffix", "sub_domain_count", "excessive_dots", "numeric_subdomain", "punycode_present", "https_token", "is_shortening", "tld_risk_score", "has_redirect_param", "double_extension", "hex_encoded", "domain_entropy", "digit_ratio", "special_char_count", "consonant_ratio", "longest_word_length", "brand_impersonation_score", "subdomain_brand_match", "suspicious_keywords", "login_path_score", "levenshtein_min", "levenshtein_ratio"
                ]]
                p = struct_model.predict_proba(struct_scaler.transform([f_array]))[0][1]
            except: p = 0.5
            probs.append(p)
        return np.array(probs)
    
    struct_train = get_struct_probs(train_df)
    sem_train = semantic_model.classifier.predict_proba(X_s_train)[:, 1]
    
    fusion_model = LogisticRegression(random_state=42)
    fusion_model.fit(np.column_stack((struct_train, sem_train)), train_df["label"].values)
    joblib.dump(fusion_model, out_dir / "fusion_model.pkl")
    
    # Evaluate Clean Test
    print("Evaluating Clean Test Set...")
    X_s_test = semantic_model.extract_features_batch(test_df["full_html"].tolist())
    sem_test = semantic_model.classifier.predict_proba(X_s_test)[:, 1]
    struct_test = get_struct_probs(test_df)
    
    fusion_test_probs = fusion_model.predict_proba(np.column_stack((struct_test, sem_test)))[:, 1]
    preds = (fusion_test_probs >= 0.5).astype(int)
    y_test = test_df["label"].values
    
    metrics = {
        "precision": precision_score(y_test, preds),
        "recall": recall_score(y_test, preds),
        "f1": f1_score(y_test, preds),
        "auc": roc_auc_score(y_test, fusion_test_probs),
        "fpr": confusion_matrix(y_test, preds)[0][1] / (confusion_matrix(y_test, preds)[0][1] + confusion_matrix(y_test, preds)[0][0])
    }
    
    with open("clean_test_metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)
        
    return test_df

# --- 3. ATTACK EVALUATORS ---
class ModelEvaluator:
    def __init__(self, mode="Baseline_V3"):
        self.mode = mode
        if mode == "Baseline_V3":
            self.predictor = get_predictor()
            self.thresholds = self.predictor._threshold_cfg
        elif mode in ["Hardened_V4", "Semantic_V4", "Structural_V2"]:
            self.semantic_model = SemanticModelV4("models/phish360_v4_final")
            self.struct_model = joblib.load("models/phish360_v2/structural_model.pkl")
            self.struct_scaler = joblib.load("models/phish360_v2/structural_scaler.pkl")
            self.fusion_model = joblib.load("models/phish360_v4_final/fusion_model.pkl")

    def evaluate(self, state: WebPageState):
        if self.mode == "Baseline_V3":
            from e5_webpage_perturbations import score_offline
            result = score_offline(self.predictor, state.current_url, state.current_html, self.thresholds)
            return {"fusion_probability": result["fusion_probability"], "verdict": result["verdict"]}
            
        # Get Struct
        try:
            feats = extract_features(state.current_url)
            f_array = [feats.get(k, 0) for k in ["url_length", "hostname_length", "path_length", "query_length", "url_depth", "num_params", "has_ip", "has_at", "has_port", "double_slash", "prefix_suffix", "sub_domain_count", "excessive_dots", "numeric_subdomain", "punycode_present", "https_token", "is_shortening", "tld_risk_score", "has_redirect_param", "double_extension", "hex_encoded", "domain_entropy", "digit_ratio", "special_char_count", "consonant_ratio", "longest_word_length", "brand_impersonation_score", "subdomain_brand_match", "suspicious_keywords", "login_path_score", "levenshtein_min", "levenshtein_ratio"]]
            struct_prob = self.struct_model.predict_proba(self.struct_scaler.transform([f_array]))[0][1]
        except: struct_prob = 0.5
        
        # Get Semantic
        try:
            sem_arr = self.semantic_model.extract_features_batch([state.current_html])
            sem_prob = self.semantic_model.classifier.predict_proba(sem_arr)[0][1]
        except: sem_prob = 0.5
        
        if self.mode == "Structural_V2":
            return {"fusion_probability": struct_prob, "verdict": "PHISHING" if struct_prob >= 0.5 else "SAFE"}
        elif self.mode == "Semantic_V4":
            return {"fusion_probability": sem_prob, "verdict": "PHISHING" if sem_prob >= 0.5 else "SAFE"}
        else: # Hardened_V4
            X_f = np.column_stack(([struct_prob], [sem_prob]))
            f_prob = self.fusion_model.predict_proba(X_f)[0][1]
            return {"fusion_probability": f_prob, "verdict": "PHISHING" if f_prob >= 0.5 else "SAFE"}

    def populate_scores(self, state: WebPageState):
        scores = self.evaluate(state)
        state.original_scores = scores
        state.current_scores = scores

# --- 4. RUN MASSIVE ATTACK ---
def run_attacks(test_df):
    mutations = [
        HtmlAddMassiveBenignTextMutation(), HtmlSwapPasswordInputMutation(), HtmlObfuscateTextMutation(),
        HtmlAddCosmeticDivMutation(), HtmlAddBenignTextMutation(), HtmlAddDummyScriptMutation(),
        HtmlAddExternalLinkMutation(), HtmlInsertBenignMetaMutation(), UrlRemoveSuspiciousKeywordsMutation(),
        HtmlObfuscateFormActionMutation(), HtmlConvertLinksToButtonsMutation(),
        HtmlParaphraseCredentialTextMutation(), HtmlTextToImageMutation(), HtmlAddIframeMutation(),
        HtmlPrependMassivePaddingMutation()
    ]
    mutation_engine = MutationEngine(mutations)
    
    # Filter true phishing samples, pick 100
    phish_test = test_df[test_df['label'] == 1]
    attack_df = phish_test.sample(100, random_state=42)
    
    seeds = [42, 100, 999, 1234, 5555]
    models = ["Structural_V2", "Semantic_V4", "Baseline_V3", "Hardened_V4"]
    
    results = []
    
    for seed in seeds:
        np.random.seed(seed)
        for model_name in models:
            evaluator = ModelEvaluator(mode=model_name)
            for _, row in tqdm(attack_df.iterrows(), total=len(attack_df), desc=f"{model_name} Seed {seed}"):
                initial_state = WebPageState(row['URL'], row['URL'], row['full_html'], row['full_html'])
                evaluator.populate_scores(initial_state)
                
                if initial_state.original_scores["verdict"] == "PHISHING":
                    attacker = MCTSAttacker(evaluator=evaluator, mutation_engine=mutation_engine, max_queries=150, rollout_depth=5)
                    res = attacker.run(initial_state)
                    results.append({
                        "seed": seed, "model": model_name, "url": row['URL'],
                        "orig_prob": float(res.original_fusion_probability),
                        "new_prob": float(res.final_fusion_probability),
                        "success": bool(res.success), "queries": int(res.queries_used)
                    })
                    
                with open("massive_attack_results.json", "w") as f:
                    json.dump(results, f, indent=2)

if __name__ == "__main__":
    print("Starting Final Evaluation Pipeline")
    test_df = train_and_eval()
    run_attacks(test_df)
    print("Pipeline Complete")
