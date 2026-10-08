import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path

OUT_DIR = Path("results/fast_track")

def generate_report():
    print("Loading data...")
    adv_df = pd.read_csv(OUT_DIR / "adversarial_performance.csv")
    norm_df = pd.read_csv(OUT_DIR / "normal_performance.csv")
    
    models = ["Structural_V2", "Semantic_V4", "Baseline_V3", "Hardened_V4"]
    algorithms = ["BeamSearch", "SimulatedAnnealing", "MCTS"]
    
    # Attack metrics
    metrics = []
    for tm in models:
        for algo in algorithms:
            sub = adv_df[(adv_df['target_model'] == tm) & (adv_df['attack_algorithm'] == algo)]
            if len(sub) == 0: continue
            
            success_count = len(sub[sub['success'] == 'SUCCESS'])
            metrics.append({
                "target_model": tm,
                "attack_algorithm": algo,
                "attacks_attempted": len(sub),
                "successful_evasions": success_count,
                "attack_success_rate": success_count / len(sub),
                "average_queries": sub['query_count'].mean(),
                "average_mutations": sub['mutation_count'].mean(),
                "average_probability_reduction": (sub['original_probability'] - sub['final_target_probability']).mean()
            })
    met_df = pd.DataFrame(metrics)
    met_df.to_csv(OUT_DIR / "attack_metrics.csv", index=False)
    
    # Transfer metrics
    transfers = []
    
    col_mapping = {
        "Structural_V2": "V2_probability",
        "Semantic_V4": "Semantic_V4_probability",
        "Baseline_V3": "Baseline_V3_probability",
        "Hardened_V4": "Hardened_V4_probability"
    }
    
    for tm in models: # Model that generated the attack
        for eval_m in models: # Model evaluating the attack
            col = col_mapping[eval_m]
            sub = adv_df[adv_df['target_model'] == tm]
            if len(sub) == 0: continue
            detected = sum(sub[col] >= 0.5)
            transfers.append({
                "source_target": tm,
                "evaluating_model": eval_m,
                "detection_rate": detected / len(sub)
            })
    trans_df = pd.DataFrame(transfers)
    trans_df.to_csv(OUT_DIR / "transfer_metrics.csv", index=False)
    
    # Plots
    plt.figure(figsize=(10,6))
    sns.barplot(data=met_df, x="target_model", y="attack_success_rate", hue="attack_algorithm")
    plt.title("Attack Success Rate by Model and Algorithm")
    plt.savefig(OUT_DIR / "plot_attack_success.png")
    plt.close()
    
    plt.figure(figsize=(10,6))
    sns.barplot(data=met_df, x="target_model", y="average_probability_reduction", hue="attack_algorithm")
    plt.title("Average Probability Reduction")
    plt.savefig(OUT_DIR / "plot_prob_reduction.png")
    plt.close()
    
    report = [
        "# FAST-TRACK RESEARCH REPORT",
        "",
        "## 1. Objective",
        "To perform a focused, scientifically valid Fast-Track evaluation determining if adding semantic intent analysis to structural phishing detection improves resilience to adversarial webpage modifications.",
        "",
        "## 2. Models Compared",
        "- **Structural_V2:** URL-only legacy features.",
        "- **Semantic_V4:** Text-embedding only features.",
        "- **Baseline_V3:** Unhardened hybrid model.",
        "- **Hardened_V4:** Adversarially trained hybrid model.",
        "",
        "## 3. Dataset",
        "Exactly 25 genuine phishing and 25 genuine legitimate samples held out from training, selected deterministically using seed 42.",
        "",
        "## 4. Feature Compatibility Audit",
        "Please refer to `compatibility_audit.md`. Mutations were strictly matched to the features the models can actually parse.",
        "",
        "## 5. Experimental Protocol",
        "Each phishing page was targeted individually using Beam Search, Simulated Annealing, and MCTS against all four models.",
        "",
        "## 6. Normal Performance",
        norm_df.to_markdown(index=False),
        "",
        "## 7. Adversarial Attack Results",
        met_df.to_markdown(index=False),
        "",
        "## 8. Transfer Results (Adversarial Detection Rate)",
        trans_df.to_markdown(index=False),
        "",
        "## 9. Limitations & Threats to Validity",
        "- **Sample Size:** 25 pages is a small sample; findings indicate trends but are not definitive proof of absolute immunity.",
        "- **Mutation Scope:** The attacks are limited to the implemented classes; novel out-of-distribution attacks may still succeed.",
        "",
        "## 10. Findings & Final Conclusion",
        "The empirical evidence demonstrates the measured differences in adversarial robustness between purely structural and semantic-hybrid approaches."
    ]
    with open(OUT_DIR / "FAST_TRACK_RESEARCH_REPORT.md", "w") as f:
        f.write("\n".join(report))
        
    print("FAST-TRACK POST-PROCESSING COMPLETE.")

if __name__ == "__main__":
    generate_report()
