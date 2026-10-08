import os
import joblib
import numpy as np
from pathlib import Path
from sklearn.linear_model import LogisticRegression
from sklearn.metrics.pairwise import cosine_similarity
from sentence_transformers import SentenceTransformer
from typing import List, Tuple

from .extractor import extract_semantic_text

class SemanticModelV4:
    def __init__(self, model_dir=None):
        print("Loading local SentenceTransformer (all-MiniLM-L6-v2)...")
        # Lightweight local model
        self.encoder = SentenceTransformer("all-MiniLM-L6-v2")
        self.classifier = None
        self.model_dir = Path(model_dir) if model_dir else None
        
        # Interpretability concepts
        self.concepts = {
            "Credential collection intent detected": "Enter your password to continue. Provide your login credentials to proceed.",
            "Account verification request detected": "Verify your identity or account immediately.",
            "Financial information request detected": "Enter your credit card, banking, or payment details.",
            "Urgency detected": "Urgent action required, your account will be suspended."
        }
        self.concept_embeddings = self.encoder.encode(list(self.concepts.values()))
        self.concept_names = list(self.concepts.keys())
        
        if self.model_dir and (self.model_dir / "semantic_classifier.pkl").exists():
            self.classifier = joblib.load(self.model_dir / "semantic_classifier.pkl")

    def predict_proba(self, html: str) -> Tuple[float, List[str]]:
        """
        Takes raw HTML, extracts semantic text, produces an embedding,
        runs the classifier, and returns the phishing probability and
        interpretable findings.
        """
        text = extract_semantic_text(html)
        if not text:
            return 0.0, []
            
        embedding = self.encoder.encode([text])[0]
        
        # Classifier probability
        if self.classifier:
            # logistic regression expects 2D array
            prob = self.classifier.predict_proba([embedding])[0][1]
        else:
            prob = 0.5 # Untrained fallback
            
        # Explanations / Interpretability
        # Check cosine similarity to predefined concepts
        findings = []
        sims = cosine_similarity([embedding], self.concept_embeddings)[0]
        for i, sim in enumerate(sims):
            if sim > 0.4: # Threshold for semantic similarity
                findings.append(self.concept_names[i])
                
        return prob, findings

    def extract_features_batch(self, html_list: List[str]) -> np.ndarray:
        texts = [extract_semantic_text(h) for h in html_list]
        return self.encoder.encode(texts)

    def train(self, X_embeddings: np.ndarray, y: np.ndarray):
        print(f"Training Semantic Classifier on {len(y)} samples...")
        self.classifier = LogisticRegression(max_iter=1000, random_state=42)
        self.classifier.fit(X_embeddings, y)
        
    def save(self, model_dir: str):
        Path(model_dir).mkdir(parents=True, exist_ok=True)
        joblib.dump(self.classifier, Path(model_dir) / "semantic_classifier.pkl")
        print(f"Saved Semantic Classifier to {model_dir}")
