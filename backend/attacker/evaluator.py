import sys
import os
from typing import Dict, Any
from .webpage_state import WebPageState

# Add parent to path to import backend modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from phishout_predictor import get_predictor
from e5_webpage_perturbations import score_offline

class Evaluator:
    def __init__(self):
        # Load predictor once
        self.predictor = get_predictor()
        self.thresholds = self.predictor._threshold_cfg

    def evaluate(self, state: WebPageState) -> Dict[str, Any]:
        """
        Evaluate the state using the frozen PhishOut pipeline in-memory.
        Returns the scores without modifying the state.
        """
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
        """Helper to populate both original and current scores for a new state."""
        scores = self.evaluate(state)
        state.original_scores = scores
        state.current_scores = scores
