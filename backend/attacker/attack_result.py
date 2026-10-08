from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from .webpage_state import WebPageState

@dataclass
class AttackResult:
    algorithm: str
    success: bool
    
    original_structural_probability: float
    final_structural_probability: float
    
    original_fusion_probability: float
    final_fusion_probability: float
    
    probability_reduction: float
    relative_reduction: float
    
    mutation_count: int
    mutation_history: List[str]
    
    queries_used: int
    search_depth_or_iterations: int
    
    final_html: str
    final_url: str
    
    search_trace: List[Dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_state(cls, algorithm: str, original_state: WebPageState, final_state: WebPageState, 
                   queries_used: int, iterations: int, trace: List[Dict], threshold: float = 0.5):
        orig_p = original_state.original_scores.get('fusion_probability', 1.0)
        final_p = final_state.current_scores.get('fusion_probability', 1.0)
        
        orig_sp = original_state.original_scores.get('structural_probability', 1.0)
        final_sp = final_state.current_scores.get('structural_probability', 1.0)
        
        abs_reduction = orig_p - final_p
        rel_reduction = abs_reduction / orig_p if orig_p > 0 else 0.0
        
        success = final_p < threshold
        
        return cls(
            algorithm=algorithm,
            success=success,
            original_structural_probability=orig_sp,
            final_structural_probability=final_sp,
            original_fusion_probability=orig_p,
            final_fusion_probability=final_p,
            probability_reduction=abs_reduction,
            relative_reduction=rel_reduction,
            mutation_count=final_state.mutation_count,
            mutation_history=final_state.mutation_history,
            queries_used=queries_used,
            search_depth_or_iterations=iterations,
            final_html=final_state.current_html,
            final_url=final_state.current_url,
            search_trace=trace
        )
