import math
import random
from typing import List, Dict
from .webpage_state import WebPageState
from .mutation_engine import MutationEngine
from .evaluator import Evaluator
from .objective import calculate_objective_score
from .attack_result import AttackResult

class SimulatedAnnealingAttacker:
    def __init__(self, evaluator: Evaluator, mutation_engine: MutationEngine,
                 initial_temp: float = 1.0, cooling_rate: float = 0.95,
                 max_iterations: int = 50, max_queries: int = 100,
                 target_probability: float = 0.49):
        self.evaluator = evaluator
        self.mutation_engine = mutation_engine
        self.initial_temp = initial_temp
        self.cooling_rate = cooling_rate
        self.max_iterations = max_iterations
        self.max_queries = max_queries
        self.target_probability = target_probability

    def run(self, initial_state: WebPageState) -> AttackResult:
        if not initial_state.original_scores:
            self.evaluator.populate_scores(initial_state)

        queries_used = 1
        trace = []
        
        current_state = initial_state
        current_obj = calculate_objective_score(current_state)
        
        best_state = current_state
        best_prob = current_state.original_scores.get('fusion_probability', 1.0)
        
        if best_prob < self.target_probability:
            return AttackResult.from_state("Simulated Annealing", initial_state, best_state, queries_used, 0, trace)

        temp = self.initial_temp
        
        for iteration in range(1, self.max_iterations + 1):
            if queries_used >= self.max_queries:
                break

            # Generate neighbors (candidates)
            candidates = self.mutation_engine.generate_candidates(current_state)
            if not candidates:
                break
                
            # Randomly pick a neighbor
            neighbor = random.choice(candidates)
            neighbor.current_scores = self.evaluator.evaluate(neighbor)
            queries_used += 1
            
            neighbor_prob = neighbor.current_scores.get('fusion_probability', 1.0)
            neighbor_obj = calculate_objective_score(neighbor)
            
            trace.append({
                "iteration": iteration,
                "temp": temp,
                "mutation": neighbor.mutation_history[-1],
                "prob": neighbor_prob,
                "accepted": False
            })

            # Calculate acceptance probability
            if neighbor_obj < current_obj:
                accept = True
            else:
                # Accept worse moves occasionally
                delta = neighbor_obj - current_obj
                try:
                    p_accept = math.exp(-delta / temp)
                except OverflowError:
                    p_accept = 0
                accept = random.random() < p_accept

            if accept:
                current_state = neighbor
                current_obj = neighbor_obj
                trace[-1]["accepted"] = True

                if neighbor_prob < best_prob:
                    best_prob = neighbor_prob
                    best_state = neighbor

            # Early stopping
            if best_prob < self.target_probability:
                break

            temp *= self.cooling_rate

        return AttackResult.from_state("Simulated Annealing", initial_state, best_state, queries_used, iteration, trace)
