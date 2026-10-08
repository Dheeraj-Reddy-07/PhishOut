import os
os.environ["LOKY_MAX_CPU_COUNT"] = "1"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["VECLIB_MAXIMUM_THREADS"] = "1"
os.environ["NUMEXPR_NUM_THREADS"] = "1"

import sys
import pandas as pd
import json
import warnings
from pathlib import Path

# Suppress sklearn parallel warnings that flood the console and slow down execution
warnings.filterwarnings('ignore')
import logging
logging.getLogger("sklearn").setLevel(logging.ERROR)

# Setup paths
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from attacker.webpage_state import WebPageState
from attacker.evaluator import Evaluator
from attacker.mutation_engine import MutationEngine
from attacker.beam_search import BeamSearchAttacker
from attacker.simulated_annealing import SimulatedAnnealingAttacker
from attacker.mcts import MCTSAttacker

def get_samples(n=3):
    """Load real phishing samples directly from the raw dataset."""
    raw_dir = Path(r"D:\Downloads\phish360_parquet")
    raw_source = raw_dir / "Phish360_phish.parquet"
    
    samples = []
    if raw_source.exists():
        try:
            # Read first N rows, we shuffle with random state for reproducibility
            raw_df = pd.read_parquet(raw_source, columns=["folder_name", "URL", "full_html"])
            # Sample 10 random pages that are long enough to be meaningful
            raw_df = raw_df[raw_df['full_html'].str.len() > 1000]
            sampled_df = raw_df.sample(n=n, random_state=42)
            
            for _, row in sampled_df.iterrows():
                sample_id = row['folder_name']
                url = row['URL']
                html = row['full_html']
                if url and html:
                    samples.append((sample_id, url, html))
            return samples
        except Exception as e:
            print(f"Error loading samples: {e}")
            
    print("Warning: Could not load real samples, falling back to dummy data.")
    return []

def print_result_row(sample_id, result):
    # Truncate strings for display
    alg = result.algorithm[:3]
    prob_orig = f"{result.original_fusion_probability:.4f}"
    prob_final = f"{result.final_fusion_probability:.4f}"
    reduction = f"{result.probability_reduction:.4f}"
    muts = result.mutation_count
    queries = result.queries_used
    success = "YES" if result.success else "NO"
    
    print(f"{sample_id:<12} | {alg:<3} | {prob_orig:<14} | {prob_final:<11} | {reduction:<9} | {muts:<9} | {queries:<7} | {success:<7}")

def main():
    print("="*80)
    print("PHISH OUT - Heuristic Adversarial Attack Engine")
    print("="*80)
    
    print("[+] Initializing Evaluator & Mutation Engine...")
    evaluator = Evaluator()
    mutation_engine = MutationEngine()
    
    print("[+] Loading samples...")
    samples = get_samples(n=100)
    print(f"Loaded {len(samples)} samples.")
    
    attackers = [
        BeamSearchAttacker(evaluator, mutation_engine, beam_width=5, max_depth=20, max_queries=500, target_probability=0.49),
        SimulatedAnnealingAttacker(evaluator, mutation_engine, initial_temp=1.0, cooling_rate=0.8, max_iterations=500, max_queries=500, target_probability=0.49),
        MCTSAttacker(evaluator, mutation_engine, rollout_depth=5, max_queries=500, target_probability=0.49)
    ]
    
    print("\n{:<12} | {:<3} | {:<14} | {:<11} | {:<9} | {:<9} | {:<7} | {:<7}".format(
        "Sample", "Alg", "Original Score", "Final Score", "Reduction", "Mutations", "Queries", "Success"))
    print("-" * 80)
    
    results = []
    
    for sample_id, url, html in samples:
        initial_state = WebPageState(
            original_url=url,
            current_url=url,
            original_html=html,
            current_html=html
        )
        evaluator.populate_scores(initial_state)
        
        # Skip if already safe
        if initial_state.original_scores['fusion_probability'] < 0.50:
            print(f"{sample_id:<12} | SKIP| Original score already safe ({initial_state.original_scores['fusion_probability']:.4f})")
            continue
            
        for attacker in attackers:
            # Clone initial state for fresh attack
            res = attacker.run(initial_state.clone())
            results.append((sample_id, res))
            print_result_row(sample_id, res)
            
        # Save details incrementally
        with open("heuristic_search_results.json", "w") as f:
            # Convert objects to dicts for json
            out = []
            for s, r in results:
                d = r.__dict__.copy()
                d['sample_id'] = s
                # Remove full WebPageState objects from trace if present to make it serializable
                out.append(d)
            json.dump(out, f, indent=2)
            
    print("-" * 80)
    
    # Calculate Summary Stats
    if not results:
        print("No valid results collected.")
        return
        
    print("\n[+] Summary Statistics:")
    
    summary = {}
    for alg in ["Beam Search", "Simulated Annealing", "MCTS"]:
        alg_results = [r for s, r in results if r.algorithm == alg]
        if not alg_results:
            continue
            
        success_rate = sum(1 for r in alg_results if r.success) / len(alg_results)
        avg_reduction = sum(r.probability_reduction for r in alg_results) / len(alg_results)
        avg_mutations = sum(r.mutation_count for r in alg_results) / len(alg_results)
        avg_queries = sum(r.queries_used for r in alg_results) / len(alg_results)
        avg_final = sum(r.final_fusion_probability for r in alg_results) / len(alg_results)
        
        summary[alg] = {
            "success_rate": f"{success_rate:.2%}",
            "avg_reduction": f"{avg_reduction:.4f}",
            "avg_mutations": f"{avg_mutations:.1f}",
            "avg_queries": f"{avg_queries:.1f}",
            "avg_final": f"{avg_final:.4f}"
        }
        print(f"\nAlgorithm: {alg}")
        print(f"  Success Rate:      {success_rate:.2%}")
        print(f"  Avg Reduction:     {avg_reduction:.4f}")
        print(f"  Avg Final Prob:    {avg_final:.4f}")
        print(f"  Avg Mutations:     {avg_mutations:.1f}")
        print(f"  Avg Queries:       {avg_queries:.1f}")

    # Save details
    with open("heuristic_search_results.json", "w") as f:
        # Convert objects to dicts for json
        out = []
        for s, r in results:
            d = r.__dict__.copy()
            d['sample_id'] = s
            # Remove full WebPageState objects from trace if present to make it serializable
            out.append(d)
        json.dump(out, f, indent=2)
        
    # Save successful adversarial HTMLs
    successes = [r for s, r in results if r.success]
    if successes:
        print(f"\n[+] Saved {len(successes)} successful adversarial examples to disk.")
        for r in successes:
            safe_name = f"adv_{r.algorithm}_{r.final_fusion_probability:.2f}.html"
            with open(safe_name, "w", encoding="utf-8") as f:
                f.write(r.final_state.current_html)

if __name__ == "__main__":
    main()
