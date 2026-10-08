from dataclasses import dataclass, field
from typing import List, Dict, Optional

@dataclass
class WebPageState:
    original_url: str
    current_url: str
    original_html: str
    current_html: str
    
    mutation_history: List[str] = field(default_factory=list)
    
    # Track the scores for comparison
    original_scores: Dict = field(default_factory=dict)
    current_scores: Dict = field(default_factory=dict)
    
    # Store distance metrics if needed
    distance_metrics: Dict = field(default_factory=dict)
    
    @property
    def mutation_count(self) -> int:
        return len(self.mutation_history)
    
    def clone(self) -> 'WebPageState':
        """Create a deep copy of this state for further mutation."""
        return WebPageState(
            original_url=self.original_url,
            current_url=self.current_url,
            original_html=self.original_html,
            current_html=self.current_html,
            mutation_history=list(self.mutation_history),
            original_scores=dict(self.original_scores),
            current_scores=dict(self.current_scores),
            distance_metrics=dict(self.distance_metrics)
        )
