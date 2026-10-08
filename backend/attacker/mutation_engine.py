from typing import List
from .webpage_state import WebPageState
from .mutations import ALL_MUTATIONS
from .constraints import is_valid_candidate
from .distance import calculate_distance

class MutationEngine:
    def __init__(self, mutations=None):
        self.mutations = mutations if mutations is not None else ALL_MUTATIONS

    def generate_candidates(self, state: WebPageState) -> List[WebPageState]:
        """
        Applies all applicable mutations to the current state, returning valid candidate states.
        """
        candidates = []
        for mutation in self.mutations:
            if mutation.is_applicable(state):
                try:
                    new_state = mutation.apply(state)
                    if is_valid_candidate(new_state):
                        new_state.distance_metrics = calculate_distance(state, new_state)
                        candidates.append(new_state)
                except Exception as e:
                    # Ignore mutations that fail to apply
                    pass
        return candidates
