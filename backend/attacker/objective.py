from .webpage_state import WebPageState

def calculate_objective_score(state: WebPageState, mutation_penalty: float = 0.005) -> float:
    """
    Calculates the objective/loss score for a state.
    Lower is better (we want to minimize probability of being phishing).
    
    Objective = fusion_probability + (mutation_count * penalty)
    
    This penalizes excessively long mutation chains if they don't significantly
    reduce the detector's probability.
    """
    if not state.current_scores:
        return 1.0 # Maximum penalty if not scored
        
    prob = state.current_scores.get('fusion_probability', 1.0)
    penalty = state.mutation_count * mutation_penalty
    
    return prob + penalty
