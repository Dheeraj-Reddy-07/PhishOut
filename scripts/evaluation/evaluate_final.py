import sys
import os
import json
import warnings
warnings.filterwarnings('ignore')
import os
os.environ["PYTHONWARNINGS"] = "ignore"
os.environ["LOKY_MAX_CPU_COUNT"] = "1"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"

import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

# Set up paths
sys.path.insert(0, os.path.abspath('.'))

from attacker.webpage_state import WebPageState
from attacker.evaluator import Evaluator
from attacker.mutation_engine import MutationEngine
from attacker.beam_search import BeamSearchAttacker
from attacker.simulated_annealing import SimulatedAnnealingAttacker
from attacker.mcts import MCTSAttacker
from ml_model import extract_features
from semantic_v4.model import SemanticModelV4

# Load Models
print("[+] Loading Models...")
struct_model = joblib.load("models/phish360_v2/structural_model.pkl")
struct_scaler = joblib.load("models/phish360_v2/structural_scaler.pkl")

# Patch n_jobs to prevent joblib stalling
if hasattr(struct_model, 'n_jobs'):
    struct_model.n_jobs = 1
if hasattr(struct_model, 'estimators_'):
    for est in struct_model.estimators_:
        if hasattr(est, 'n_jobs'):
            est.n_jobs = 1

semantic_model = SemanticModelV4(model_dir="models/phish360_v4")
fusion_model = joblib.load("models/phish360_v4/fusion_model.pkl")

# Helper functions
def get_v2_prob(url, html):
    try:
        feats = extract_features(url, html)
        f_array = []
        for k in ["url_length", "hostname_length", "path_length", "query_length", "url_depth", "num_params", "has_ip", "has_at", "has_port", "double_slash", "prefix_suffix", "sub_domain_count", "excessive_dots", "numeric_subdomain", "punycode_present", "https_token", "is_shortening", "tld_risk_score", "has_redirect_param", "double_extension", "hex_encoded", "domain_entropy", "digit_ratio", "special_char_count", "consonant_ratio", "longest_word_length", "brand_impersonation_score", "subdomain_brand_match", "suspicious_keywords", "login_path_score", "levenshtein_min", "levenshtein_ratio"]:
            f_array.append(feats.get(k, 0))
        f_scaled = struct_scaler.transform([f_array])
        return struct_model.predict_proba(f_scaled)[0][1]
    except Exception as e:
        return 0.5

def get_v4_prob(url, html):
    try:
        p_struct = get_v2_prob(url, html)
        p_sem, findings = semantic_model.predict_proba(html)
        X_f = np.array([[p_struct, p_sem]])
        return fusion_model.predict_proba(X_f)[0][1]
    except Exception as e:
        return 0.5

def evaluate_metrics(y_true, y_pred, y_prob):
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred)
    rec = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0,0,0,0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    dr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    return acc, prec, rec, f1, fpr, dr

def main():
    os.makedirs("results/plots", exist_ok=True)
    
    # -------------------------------------------------------------------------
    # STEP 1 - NORMAL PERFORMANCE
    # -------------------------------------------------------------------------
    print("\n[+] STEP 1: Evaluating Normal Performance...")
    phish_path = r"D:\Downloads\phish360_parquet\Phish360_phish.parquet"
    legit_path = r"D:\Downloads\phish360_parquet\Phish360_legit.parquet"
    
    df_phish = pd.read_parquet(phish_path, columns=["folder_name", "URL", "full_html"]).tail(500)
    df_legit = pd.read_parquet(legit_path, columns=["folder_name", "URL", "full_html"]).tail(500)
    
    df_phish["label"] = 1
    df_legit["label"] = 0
    df_test = pd.concat([df_phish, df_legit]).reset_index(drop=True)
    df_test = df_test[df_test["full_html"].notna()]
    df_test = df_test[df_test["full_html"].str.len() > 100]
    
    # Sample 100 for normal evaluation to keep it fast
    df_normal = df_test.sample(200, random_state=1)
    
    v2_probs = []
    v4_probs = []
    for _, row in df_normal.iterrows():
        v2_probs.append(get_v2_prob(row["URL"], row["full_html"]))
        v4_probs.append(get_v4_prob(row["URL"], row["full_html"]))
        
    y_true = df_normal["label"].values
    v2_preds = [1 if p >= 0.5 else 0 for p in v2_probs]
    v4_preds = [1 if p >= 0.5 else 0 for p in v4_probs]
    
    v2_metrics = evaluate_metrics(y_true, v2_preds, v2_probs)
    v4_metrics = evaluate_metrics(y_true, v4_preds, v4_probs)
    
    df_normal_res = pd.DataFrame([
        {"Model": "Baseline V2", "Accuracy": v2_metrics[0], "Precision": v2_metrics[1], "Recall": v2_metrics[2], "F1": v2_metrics[3], "FPR": v2_metrics[4], "Detection Rate": v2_metrics[5]},
        {"Model": "Phish Out V4", "Accuracy": v4_metrics[0], "Precision": v4_metrics[1], "Recall": v4_metrics[2], "F1": v4_metrics[3], "FPR": v4_metrics[4], "Detection Rate": v4_metrics[5]}
    ])
    df_normal_res.to_csv("results/normal_performance.csv", index=False)
    print(df_normal_res.to_string(index=False))
    
    # -------------------------------------------------------------------------
    # STEP 2 - GENERATE ADVERSARIAL DATA
    # -------------------------------------------------------------------------
    print("\n[+] STEP 2: Generating Adversarial Data...")
    
    # Take 10 distinct phishing samples that Baseline V2 detects successfully
    adv_pool = df_phish[df_phish["full_html"].str.len() > 1000].sample(30, random_state=42)
    valid_samples = []
    for _, row in adv_pool.iterrows():
        if get_v2_prob(row["URL"], row["full_html"]) >= 0.5:
            valid_samples.append(row)
        if len(valid_samples) == 10:
            break
            
    print(f"Selected {len(valid_samples)} true positive phishing samples for attack.")
    
    evaluator = Evaluator()
    if hasattr(evaluator.predictor._struct_model, 'n_jobs'):
        evaluator.predictor._struct_model.n_jobs = 1
    if hasattr(evaluator.predictor._struct_model, 'estimators_'):
        for est in evaluator.predictor._struct_model.estimators_:
            if hasattr(est, 'n_jobs'):
                est.n_jobs = 1
                
    mutation_engine = MutationEngine()
    
    # We will use Beam Search and SA to save time, MCTS might take too long for a live run
    attackers = [
        BeamSearchAttacker(evaluator, mutation_engine, beam_width=3, max_queries=15, target_probability=0.49),
        SimulatedAnnealingAttacker(evaluator, mutation_engine, initial_temp=1.0, cooling_rate=0.8, max_queries=20, target_probability=0.49),
        MCTSAttacker(evaluator, mutation_engine, rollout_depth=2, max_queries=15, target_probability=0.49)
    ]
    
    adv_results = []
    
    for row in valid_samples:
        sid = row["folder_name"]
        url = row["URL"]
        html = row["full_html"]
        orig_v2 = get_v2_prob(url, html)
        orig_v4 = get_v4_prob(url, html)
        
        initial_state = WebPageState(url, url, html, html)
        evaluator.populate_scores(initial_state)
        
        for attacker in attackers:
            res = attacker.run(initial_state)
            adv_html = res.final_state.current_html if hasattr(res, 'final_state') else res.final_html
            
            adv_v2 = get_v2_prob(url, adv_html)
            adv_v4 = get_v4_prob(url, adv_html)
            
            history = getattr(res, 'mutation_history', []) if not hasattr(res, 'final_state') else getattr(res.final_state, 'mutation_history', [])
            if isinstance(history, list):
                history = ",".join(history)
                
            adv_filename = f"adv_{sid}_{attacker.__class__.__name__}.html"
            adv_filepath = os.path.join("results", adv_filename)
            with open(adv_filepath, "w", encoding="utf-8") as f:
                f.write(adv_html)
                
            adv_results.append({
                "sample_id": sid,
                "algorithm": attacker.__class__.__name__,
                "original_v2_prob": orig_v2,
                "original_v4_prob": orig_v4,
                "adv_v2_prob": adv_v2,
                "adv_v4_prob": adv_v4,
                "success": res.success,
                "queries": getattr(res, 'queries_used', getattr(res, 'queries', 0)),
                "mutations": res.mutation_count,
                "mutation_path": history,
                "url": url,
                "orig_html": html,
                "adv_html": adv_html,
                "file_path": adv_filepath
            })
            
    df_adv = pd.DataFrame(adv_results)
    
    # Save manifest
    df_manifest = df_adv[["sample_id", "algorithm", "success", "queries", "mutations", "original_v2_prob", "adv_v2_prob", "file_path"]]
    df_manifest.rename(columns={"queries": "query_count", "mutations": "mutation_count", "original_v2_prob": "original_score", "adv_v2_prob": "final_score"}, inplace=True)
    df_manifest.to_csv("results/adversarial_manifest.csv", index=False)
    
    # -------------------------------------------------------------------------
    # STEP 3 & 4 - EVALUATE & ROBUSTNESS METRICS
    # -------------------------------------------------------------------------
    print("\n[+] STEP 3 & 4: Evaluating Adversarial Samples & Robustness...")
    
    df_adv["v2_detected_orig"] = df_adv["original_v2_prob"] >= 0.5
    df_adv["v4_detected_orig"] = df_adv["original_v4_prob"] >= 0.5
    df_adv["v2_detected_adv"] = df_adv["adv_v2_prob"] >= 0.5
    df_adv["v4_detected_adv"] = df_adv["adv_v4_prob"] >= 0.5
    
    v2_orig_dr = df_adv["v2_detected_orig"].mean()
    v2_adv_dr = df_adv["v2_detected_adv"].mean()
    v4_orig_dr = df_adv["v4_detected_orig"].mean()
    v4_adv_dr = df_adv["v4_detected_adv"].mean()
    
    df_rob = pd.DataFrame([
        {"Model": "Baseline V2", "Normal Detection": v2_orig_dr, "Adversarial Detection": v2_adv_dr, "Degradation": v2_orig_dr - v2_adv_dr},
        {"Model": "Phish Out V4", "Normal Detection": v4_orig_dr, "Adversarial Detection": v4_adv_dr, "Degradation": v4_orig_dr - v4_adv_dr}
    ])
    df_rob.to_csv("results/robustness_metrics.csv", index=False)
    print("\nTABLE 3 — DETECTION DEGRADATION")
    print(df_rob.to_string(index=False))
    
    # -------------------------------------------------------------------------
    # STEP 5 - ALGORITHM COMPARISON
    # -------------------------------------------------------------------------
    print("\n[+] STEP 5: Algorithm Comparison...")
    alg_stats = []
    for alg in df_adv["algorithm"].unique():
        sub = df_adv[df_adv["algorithm"] == alg]
        alg_stats.append({
            "Attack": alg,
            "Samples": len(sub),
            "Avg Queries": sub["queries"].mean(),
            "Avg Mutations": sub["mutations"].mean(),
            "V2 Success Rate": 1 - sub["v2_detected_adv"].mean(),
            "V4 Success Rate": 1 - sub["v4_detected_adv"].mean()
        })
        
    df_attack = pd.DataFrame(alg_stats)
    df_attack.to_csv("results/attack_metrics.csv", index=False)
    print("\nTABLE 2/4 — ADVERSARIAL PERFORMANCE / ATTACK DIFFICULTY")
    print(df_attack.to_string(index=False))
    
    # -------------------------------------------------------------------------
    # STEP 8 - VISUALIZATIONS
    # -------------------------------------------------------------------------
    print("\n[+] STEP 8: Generating Plots...")
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    
    # Plot 1: Detection Degradation
    labels = ['Baseline V2', 'Phish Out V4']
    norm_dr = [v2_orig_dr, v4_orig_dr]
    adv_dr = [v2_adv_dr, v4_adv_dr]
    
    x = np.arange(len(labels))
    width = 0.35
    fig, ax = plt.subplots()
    rects1 = ax.bar(x - width/2, norm_dr, width, label='Normal DR')
    rects2 = ax.bar(x + width/2, adv_dr, width, label='Adversarial DR')
    ax.set_ylabel('Detection Rate')
    ax.set_title('Detection Degradation under Attack')
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend()
    fig.tight_layout()
    plt.savefig("results/plots/detection_degradation.png")
    
    # Plot 2: Probabilities Distribution
    plt.figure()
    sns.kdeplot(df_adv["adv_v2_prob"], label="Baseline V2", shade=True)
    sns.kdeplot(df_adv["adv_v4_prob"], label="Phish Out V4", shade=True)
    plt.axvline(0.5, color='red', linestyle='--')
    plt.title("Adversarial Final Probabilities")
    plt.legend()
    plt.savefig("results/plots/adv_probabilities.png")
    
    # Cleanup df_adv and save to csv without massive HTML payload
    df_adv_clean = df_adv.drop(columns=["orig_html", "adv_html"])
    df_adv_clean.to_csv("results/adversarial_performance.csv", index=False)
    
    print("\n[+] Final Experiment Complete.")

if __name__ == "__main__":
    main()
