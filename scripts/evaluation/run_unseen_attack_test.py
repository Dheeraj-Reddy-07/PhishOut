import os
os.environ["LOKY_MAX_CPU_COUNT"] = "1"
os.environ["OMP_NUM_THREADS"] = "1"
import sys
import pandas as pd
import json
import joblib
import numpy as np
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
    HtmlAddBenignTextMutation,
    HtmlAddDummyScriptMutation,
    HtmlAddExternalLinkMutation,
    HtmlInsertBenignMetaMutation,
    UrlRemoveSuspiciousKeywordsMutation,
    HtmlObfuscateFormActionMutation,
    HtmlConvertLinksToButtonsMutation
)
from attacker.beam_search import BeamSearchAttacker
from attacker.simulated_annealing import SimulatedAnnealingAttacker
from attacker.mcts import MCTSAttacker

# ── 1. Load Hardened Model ──
print("Loading Hardened V4 Model...")
semantic_model = SemanticModelV4("models/phish360_v4_hardened")
struct_model = joblib.load("models/phish360_v2/structural_model.pkl")
struct_scaler = joblib.load("models/phish360_v2/structural_scaler.pkl")
fusion_model = joblib.load("models/phish360_v4_hardened/fusion_model.pkl")

if hasattr(struct_model, 'n_jobs'): struct_model.n_jobs = 1
for est in getattr(struct_model, 'estimators_', []):
    if hasattr(est, 'n_jobs'): est.n_jobs = 1

def evaluate_hardened(state: WebPageState):
    # Structural
    try:
        feats = extract_features(state.current_url, state.current_html)
        f_array = [feats.get(k, 0) for k in [
            "url_length", "hostname_length", "path_length", "query_length", "url_depth", "num_params", "has_ip", "has_at", "has_port", "double_slash", "prefix_suffix", "sub_domain_count", "excessive_dots", "numeric_subdomain", "punycode_present", "https_token", "is_shortening", "tld_risk_score", "has_redirect_param", "double_extension", "hex_encoded", "domain_entropy", "digit_ratio", "special_char_count", "consonant_ratio", "longest_word_length", "brand_impersonation_score", "subdomain_brand_match", "suspicious_keywords", "login_path_score", "levenshtein_min", "levenshtein_ratio"
        ]]
        f_scaled = struct_scaler.transform([f_array])
        struct_prob = struct_model.predict_proba(f_scaled)[0][1]
    except:
        struct_prob = 0.5
        
    # Semantic
    try:
        sem_arr = semantic_model.extract_features_batch([state.current_html])
        sem_prob = semantic_model.classifier.predict_proba(sem_arr)[0][1]
    except:
        sem_prob = 0.5
        
    # Fusion
    X_fusion = np.column_stack(([struct_prob], [sem_prob]))
    fusion_prob = fusion_model.predict_proba(X_fusion)[0][1]
    
    return {
        "structural_probability": struct_prob,
        "fusion_probability": fusion_prob,
        "verdict": "PHISHING" if fusion_prob >= 0.5 else "SAFE",
        "risk_score": int(fusion_prob * 100)
    }

class HardenedEvaluator:
    def evaluate(self, state: WebPageState):
        return evaluate_hardened(state)
        
    def populate_scores(self, state: WebPageState):
        scores = self.evaluate(state)
        state.original_scores = scores
        state.current_scores = scores

# ── 2. Run Attack on Unseen Mutations ──
def main():
    print("Evaluating Hardened V4 on UNSEEN Attacks...")
    
    # Define Unseen mutations
    mutations = [
        HtmlAddBenignTextMutation(),
        HtmlAddDummyScriptMutation(),
        HtmlAddExternalLinkMutation(),
        HtmlInsertBenignMetaMutation(),
        UrlRemoveSuspiciousKeywordsMutation(),
        HtmlObfuscateFormActionMutation(),
        HtmlConvertLinksToButtonsMutation()
    ]
    
    evaluator = HardenedEvaluator()
    
    attackers = {
        "MCTS": MCTSAttacker(mutations=mutations, max_queries=150, rollout_depth=5),
        "BeamSearch": BeamSearchAttacker(mutations=mutations, max_queries=150, beam_width=3, max_depth=10)
    }
    
    phish_path = r"D:\Downloads\phish360_parquet\Phish360_phish.parquet"
    raw_df = pd.read_parquet(phish_path, columns=["folder_name", "URL", "full_html"])
    # Filter to valid HTMLs
    valid_df = raw_df[raw_df["full_html"].str.len() > 1000]
    # Sample 20
    df = valid_df.sample(n=20, random_state=42)
    
    results = []
    
    for i, row in tqdm(df.iterrows(), total=len(df)):
        sample_id = row['folder_name']
        original_url = row['URL']
        original_html = row['full_html']
        
        initial_state = WebPageState(original_url, original_url, original_html, original_html)
        evaluator.populate_scores(initial_state)
        
        # Skip if model couldn't even detect it before attack
        if initial_state.original_scores["verdict"] != "PHISHING":
            continue
            
        for name, attacker in attackers.items():
            try:
                best_state, queries = attacker.attack(initial_state, evaluator)
                
                success = best_state.current_scores["verdict"] == "SAFE"
                
                results.append({
                    "sample_id": sample_id,
                    "attacker": name,
                    "success": success,
                    "queries_used": queries,
                    "orig_fusion": initial_state.original_scores["fusion_probability"],
                    "new_fusion": best_state.current_scores["fusion_probability"]
                })
            except Exception as e:
                print(f"Error on {sample_id} with {name}: {e}")
                
        # Incremental save
        with open("unseen_attack_results.json", "w") as f:
            json.dump(results, f, indent=2)
            
    print("Done! Saved to unseen_attack_results.json")

if __name__ == "__main__":
    main()
