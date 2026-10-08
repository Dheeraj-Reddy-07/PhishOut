from typing import List, Dict, Set
from .webpage_state import WebPageState
from .mutation_engine import MutationEngine
from .evaluator import Evaluator
from .objective import calculate_objective_score
from .attack_result import AttackResult

class BeamSearchAttacker:
    def __init__(self, evaluator: Evaluator, mutation_engine: MutationEngine, 
                 beam_width: int = 3, max_depth: int = 5, max_queries: int = 100,
                 target_probability: float = 0.49):
        self.evaluator = evaluator
        self.mutation_engine = mutation_engine
        self.beam_width = beam_width
        self.max_depth = max_depth
        self.max_queries = max_queries
        self.target_probability = target_probability
        
    def run(self, initial_state: WebPageState) -> AttackResult:
        if not initial_state.original_scores:
            self.evaluator.populate_scores(initial_state)
            
        queries_used = 1
        trace = []
        visited_hashes: Set[str] = set()
        
        beam = [initial_state]
        best_state = initial_state
        best_prob = initial_state.original_scores.get('fusion_probability', 1.0)
        
        # Initial check
        if best_prob < self.target_probability:
            return AttackResult.from_state("Beam Search", initial_state, best_state, queries_used, 0, trace)
            
        visited_hashes.add(hash(initial_state.current_html + initial_state.current_url))
        
        for depth in range(1, self.max_depth + 1):
            if queries_used >= self.max_queries:
                break
                
            next_candidates = []
            
            for state in beam:
                candidates = self.mutation_engine.generate_candidates(state)
                
                for cand in candidates:
                    state_hash = hash(cand.current_html + cand.current_url)
                    if state_hash in visited_hashes:
                        continue
                    visited_hashes.add(state_hash)
                    
                    if queries_used >= self.max_queries:
                        break
                        
                    cand.current_scores = self.evaluator.evaluate(cand)
                    queries_used += 1
                    
                    cand_prob = cand.current_scores.get('fusion_probability', 1.0)
                    
                    trace.append({
                        "depth": depth,
                        "mutation": cand.mutation_history[-1],
                        "prob": cand_prob
                    })
                    
                    if cand_prob < best_prob:
                        best_prob = cand_prob
                        best_state = cand
                        
                    next_candidates.append(cand)
                    
                    # Early stopping if target reached
                    if best_prob < self.target_probability:
                        break
                        
                if queries_used >= self.max_queries or best_prob < self.target_probability:
                    break
                    
            if not next_candidates or best_prob < self.target_probability:
                break
                
            # Sort candidates by objective score (lower is better) and keep top B
            next_candidates.sort(key=lambda x: calculate_objective_score(x))
            beam = next_candidates[:self.beam_width]
            
        return AttackResult.from_state("Beam Search", initial_state, best_state, queries_used, depth, trace)
