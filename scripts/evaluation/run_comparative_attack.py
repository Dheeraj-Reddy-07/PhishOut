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
    HtmlConvertLinksToButtonsMutation,
    HtmlAddMassiveBenignTextMutation,
    HtmlSwapPasswordInputMutation,
    HtmlObfuscateTextMutation,
    HtmlAddCosmeticDivMutation
)
from attacker.beam_search import BeamSearchAttacker
from attacker.simulated_annealing import SimulatedAnnealingAttacker
from attacker.mcts import MCTSAttacker
from phishout_predictor import get_predictor

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

# ── 2. Baseline Evaluator ──
from e5_webpage_perturbations import score_offline
class BaselineEvaluator:
    def __init__(self):
        self.predictor = get_predictor()
        self.thresholds = self.predictor._threshold_cfg

    def evaluate(self, state: WebPageState):
        result = score_offline(
            predictor=self.predictor,
            url=state.current_url,
            html=state.current_html,
            thresholds=self.thresholds
        )
        return {
            "structural_probability": result["structural_probability"],
            "fusion_probability": result["fusion_probability"],
            "verdict": result["verdict"],
            "risk_score": result["risk_score"]
        }
        
    def populate_scores(self, state: WebPageState):
        scores = self.evaluate(state)
        state.original_scores = scores
        state.current_scores = scores

from attacker.mutation_engine import MutationEngine

# ── 3. Run Attack ──
def main():
    print("Evaluating Baseline vs Hardened Models...")
    
    all_mutations = [
        HtmlAddMassiveBenignTextMutation(),
        HtmlSwapPasswordInputMutation(),
        HtmlObfuscateTextMutation(),
        HtmlAddCosmeticDivMutation(),
        HtmlAddBenignTextMutation(),
        HtmlAddDummyScriptMutation(),
        HtmlAddExternalLinkMutation(),
        HtmlInsertBenignMetaMutation(),
        UrlRemoveSuspiciousKeywordsMutation(),
        HtmlObfuscateFormActionMutation(),
        HtmlConvertLinksToButtonsMutation()
    ]
    mutation_engine = MutationEngine(all_mutations)
    
    baseline_eval = BaselineEvaluator()
    hardened_eval = HardenedEvaluator()
    
    phish_path = r"D:\Downloads\phish360_parquet\Phish360_phish.parquet"
    raw_df = pd.read_parquet(phish_path, columns=["folder_name", "URL", "full_html"])
    valid_df = raw_df[raw_df["full_html"].str.len() > 1000]
    df = valid_df.sample(n=25, random_state=42) # 25 samples for quick robust evaluation
    
    results = []
    
    for i, row in tqdm(df.iterrows(), total=len(df)):
        sample_id = row['folder_name']
        original_url = row['URL']
        original_html = row['full_html']
        
        initial_state = WebPageState(original_url, original_url, original_html, original_html)
        
        # Test Baseline
        baseline_eval.populate_scores(initial_state)
        if initial_state.original_scores["verdict"] == "PHISHING":
            attacker = MCTSAttacker(evaluator=baseline_eval, mutation_engine=mutation_engine, max_queries=150, rollout_depth=5)
            attack_result = attacker.run(initial_state)
            queries = attack_result.queries_used
            success = bool(attack_result.success)
            results.append({
                "sample_id": str(sample_id),
                "model": "Baseline_V3",
                "success": success,
                "queries_used": int(queries),
                "orig_fusion": float(attack_result.original_fusion_probability),
                "new_fusion": float(attack_result.final_fusion_probability)
            })
            
        # Test Hardened
        hardened_eval.populate_scores(initial_state)
        if initial_state.original_scores["verdict"] == "PHISHING":
            attacker = MCTSAttacker(evaluator=hardened_eval, mutation_engine=mutation_engine, max_queries=150, rollout_depth=5)
            attack_result = attacker.run(initial_state)
            queries = attack_result.queries_used
            success = bool(attack_result.success)
            results.append({
                "sample_id": str(sample_id),
                "model": "Hardened_V4",
                "success": success,
                "queries_used": int(queries),
                "orig_fusion": float(attack_result.original_fusion_probability),
                "new_fusion": float(attack_result.final_fusion_probability)
            })
            
        with open("comparative_attack_results.json", "w") as f:
            json.dump(results, f, indent=2)
            
    print("Done! Saved to comparative_attack_results.json")

if __name__ == "__main__":
    main()
