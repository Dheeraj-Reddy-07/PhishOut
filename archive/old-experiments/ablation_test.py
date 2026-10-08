import sys
import os
import joblib
import numpy as np

sys.path.append(os.path.join(os.getcwd(), "backend"))
from ml_model import extract_features, features_to_array, FEATURE_KEYS

# Load the V2 structural model
MODEL_DIR = "backend/models/phish360_v2"
model = joblib.load(os.path.join(MODEL_DIR, "structural_model.pkl"))
scaler = joblib.load(os.path.join(MODEL_DIR, "structural_scaler.pkl"))

def evaluate_url(url):
    feats = extract_features(url)
    X = features_to_array(feats)
    X_s = scaler.transform(X)
    prob = model.predict_proba(X_s)[0, 1]
    
    print(f"\n--- {url} ---")
    print(f"Base Probability: {prob:.4f}")
    
    # Feature ablation: zero out one feature at a time to see its impact
    impacts = []
    for i, key in enumerate(FEATURE_KEYS):
        orig_val = feats[key]
        if orig_val != 0:
            feats_copy = dict(feats)
            feats_copy[key] = 0
            X_abl = features_to_array(feats_copy)
            X_abl_s = scaler.transform(X_abl)
            prob_abl = model.predict_proba(X_abl_s)[0, 1]
            diff = prob - prob_abl
            if abs(diff) > 0.01:
                impacts.append((key, orig_val, diff))
    
    impacts.sort(key=lambda x: abs(x[2]), reverse=True)
    for k, v, diff in impacts:
        print(f"Feature '{k}' (val={v}): Contributed {diff:+.4f} to probability")

urls = [
    "https://github.com",
    "https://github.com/login",
    "https://www.facebook.com/login",
    "https://stackoverflow.com/questions/tagged/python",
    "https://github.com/Dheeraj-Reddy-07/PhishOut"
]

for u in urls:
    evaluate_url(u)
