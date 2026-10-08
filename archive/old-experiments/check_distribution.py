import os
import pandas as pd
import numpy as np
import sys
sys.path.append(os.path.join(os.getcwd(), "backend"))

train_path = "backend/dataset/phish360/v2/processed/train_features.parquet"
df = pd.read_parquet(train_path)

legit = df[df['label'] == 0]
phish = df[df['label'] == 1]

print("Legitimate vs Phishing means:")
for col in ['url_depth', 'path_length', 'url_length', 'suspicious_keywords', 'login_path_score']:
    l_mean, l_std = legit[col].mean(), legit[col].std()
    p_mean, p_std = phish[col].mean(), phish[col].std()
    print(f"{col:20s} | Legit: {l_mean:5.2f} (±{l_std:5.2f}) | Phish: {p_mean:5.2f} (±{p_std:5.2f})")
    
# Also check max
print("\nMax values in Legit:")
for col in ['url_depth', 'path_length', 'url_length', 'suspicious_keywords']:
    print(f"{col}: {legit[col].max()}")
