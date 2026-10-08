import math
import random
from typing import List, Dict, Optional
from .webpage_state import WebPageState
from .mutation_engine import MutationEngine
from .evaluator import Evaluator
from .attack_result import AttackResult

class MCTSNode:
    def __init__(self, state: WebPageState, parent: Optional['MCTSNode'] = None, action: str = None):
        self.state = state
        self.parent = parent
        self.action = action
        self.children: List['MCTSNode'] = []
        self.visits = 0
        self.value = 0.0 # Using inverted objective (higher is better for MCTS)
        self.untried_actions = None # Will be populated upon expansion

class MCTSAttacker:
    def __init__(self, evaluator: Evaluator, mutation_engine: MutationEngine,
                 exploration_weight: float = 1.414, max_queries: int = 100,
                 rollout_depth: int = 3, target_probability: float = 0.49):
        self.evaluator = evaluator
        self.mutation_engine = mutation_engine
        self.exploration_weight = exploration_weight
        self.max_queries = max_queries
        self.rollout_depth = rollout_depth
        self.target_probability = target_probability
        self.queries_used = 0
        self.best_state = None
        self.best_prob = 1.0
        self.trace = []
        
    def run(self, initial_state: WebPageState) -> AttackResult:
        if not initial_state.original_scores:
            self.evaluator.populate_scores(initial_state)
            
        self.queries_used = 1
        self.best_state = initial_state
        self.best_prob = initial_state.original_scores.get('fusion_probability', 1.0)
        self.trace = []
        
        if self.best_prob < self.target_probability:
            return AttackResult.from_state("MCTS", initial_state, self.best_state, self.queries_used, 0, self.trace)
            
        root = MCTSNode(initial_state)
        
        iteration = 0
        while self.queries_used < self.max_queries:
            iteration += 1
            node = self._tree_policy(root)
            if not node:
                break
                
            reward = self._default_policy(node.state)
            self._backpropagate(node, reward)
            
            if self.best_prob < self.target_probability:
                break
                
        return AttackResult.from_state("MCTS", initial_state, self.best_state, self.queries_used, iteration, self.trace)
        
    def _tree_policy(self, node: MCTSNode) -> Optional[MCTSNode]:
        while not self._is_terminal(node.state) and self.queries_used < self.max_queries:
            if node.untried_actions is None:
                # Expand
                candidates = self.mutation_engine.generate_candidates(node.state)
                node.untried_actions = candidates
                
            if len(node.untried_actions) > 0:
                # Expand one
                cand = node.untried_actions.pop()
                cand.current_scores = self.evaluator.evaluate(cand)
                self.queries_used += 1
                
                prob = cand.current_scores.get('fusion_probability', 1.0)
                self._update_best(cand, prob, "MCTS Expand")
                
                child = MCTSNode(cand, parent=node, action=cand.mutation_history[-1] if cand.mutation_history else "")
                node.children.append(child)
                return child
            else:
                if not node.children:
                    return None
                # Select best child via UCB
                node = self._best_child(node)
        return node
        
    def _best_child(self, node: MCTSNode) -> MCTSNode:
        best_score = -float('inf')
        best_c = None
        for c in node.children:
            if c.visits == 0:
                return c
            # UCB formula
            exploit = c.value / c.visits
            explore = self.exploration_weight * math.sqrt(2 * math.log(node.visits) / c.visits)
            score = exploit + explore
            if score > best_score:
                best_score = score
                best_c = c
        return best_c if best_c else node.children[0]
        
    def _default_policy(self, state: WebPageState) -> float:
        current = state
        for d in range(self.rollout_depth):
            if self._is_terminal(current) or self.queries_used >= self.max_queries:
                break
            candidates = self.mutation_engine.generate_candidates(current)
            if not candidates:
                break
            current = random.choice(candidates)
            current.current_scores = self.evaluator.evaluate(current)
            self.queries_used += 1
            
            prob = current.current_scores.get('fusion_probability', 1.0)
            self._update_best(current, prob, "MCTS Rollout")
            
        prob = current.current_scores.get('fusion_probability', 1.0) if current.current_scores else 1.0
        # Reward function: 1.0 - prob (higher is better for MCTS)
        return 1.0 - prob
        
    def _backpropagate(self, node: MCTSNode, reward: float):
        while node is not None:
            node.visits += 1
            node.value += reward
            node = node.parent
            
    def _is_terminal(self, state: WebPageState) -> bool:
        prob = state.current_scores.get('fusion_probability', 1.0) if state.current_scores else 1.0
        return prob < self.target_probability

    def _update_best(self, state: WebPageState, prob: float, phase: str):
        self.trace.append({
            "phase": phase,
            "mutation": state.mutation_history[-1] if state.mutation_history else "",
            "prob": prob
        })
        if prob < self.best_prob:
            self.best_prob = prob
            self.best_state = state
