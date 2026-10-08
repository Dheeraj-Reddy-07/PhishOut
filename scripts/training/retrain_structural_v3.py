import os
import sys
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier, VotingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.calibration import CalibratedClassifierCV

sys.path.append(os.path.join(os.getcwd(), "backend"))
from ml_model import extract_features, FEATURE_KEYS as STRUCTURAL_FEATURES

DATA_DIR = "backend/dataset/phish360/v2/processed"
V3_MODELS_DIR = "backend/models/phish360_v3"
os.makedirs(V3_MODELS_DIR, exist_ok=True)

# 1. Define Legitimate Hard-Negative URLs
hard_negatives = [
    # Login / Auth
    "https://github.com/login", "https://www.facebook.com/login", "https://www.reddit.com/login",
    "https://www.linkedin.com/login", "https://accounts.google.com/signin",
    "https://login.live.com/login.srf", "https://login.yahoo.com/config/login",
    "https://www.amazon.com/ap/signin", "https://account.microsoft.com/account",
    "https://appleid.apple.com/account", "https://secure.bankofamerica.com/login/sign-in/signOnV2Screen.go",
    "https://www.paypal.com/signin", "https://auth.services.adobe.com",
    # Search / Query Params
    "https://www.google.com/search?q=machine+learning+phishing+detection&hl=en",
    "https://www.youtube.com/results?search_query=machine+learning",
    "https://www.amazon.in/s?k=laptop&crid=12345",
    "https://github.com/search?q=phishing+detection&type=repositories",
    "https://twitter.com/search?q=phishing",
    # Long URLs / Paths
    "https://stackoverflow.com/questions/tagged/python",
    "https://stackoverflow.com/questions/123456/how-to-fix-this-error-in-python-django",
    "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/map",
    "https://en.wikipedia.org/wiki/Machine_learning",
    "https://github.com/Dheeraj-Reddy-07/PhishOut",
    "https://docs.python.org/3/library/os.html#os.environ",
    "https://www.reddit.com/r/technology/comments/12345/interesting_news_article/"
]

# We will oversample these slightly to ensure the model learns them.
# Let's add them 50 times each to give them enough weight (~1,250 samples in a ~7k training set).
OVERSAMPLE_FACTOR = 50

print(f"[*] Extracting features for {len(hard_negatives)} hard negatives...")
hn_features = []
for url in hard_negatives:
    feats = extract_features(url)
    # Ensure they match the expected order
    row = [feats.get(k, 0) for k in STRUCTURAL_FEATURES]
    hn_features.append(row)

# Create DataFrame and oversample
df_hn = pd.DataFrame(hn_features, columns=STRUCTURAL_FEATURES)
df_hn['label'] = 0  # Legitimate
df_hn = pd.concat([df_hn] * OVERSAMPLE_FACTOR, ignore_index=True)

# 2. Load existing V2 training data
train_df = pd.read_parquet(os.path.join(DATA_DIR, "train_features.parquet"))
val_df = pd.read_parquet(os.path.join(DATA_DIR, "validation_features.parquet"))

# 3. Append Hard Negatives to Training
train_df = pd.concat([train_df, df_hn], ignore_index=True)
print(f"[*] Augmented training set size: {len(train_df)}")

# 4. Prepare data
X_train = train_df[STRUCTURAL_FEATURES].fillna(0).values.astype(np.float32)
y_train = train_df['label'].values.astype(int)
X_val = val_df[STRUCTURAL_FEATURES].fillna(0).values.astype(np.float32)
y_val = val_df['label'].values.astype(int)

# 5. Scale features
print("[*] Scaling features...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_val_scaled = scaler.transform(X_val)

# 6. Train model
print("[*] Training GradientBoostingClassifier...")
gb = GradientBoostingClassifier(
    n_estimators=300, learning_rate=0.08, max_depth=5,
    min_samples_leaf=3, subsample=0.85, max_features="sqrt", random_state=42
)

print("[*] Training RandomForestClassifier...")
rf = RandomForestClassifier(
    n_estimators=200, max_depth=14, min_samples_leaf=2,
    max_features="sqrt", class_weight="balanced", random_state=42, n_jobs=-1
)

ensemble = VotingClassifier(estimators=[("gb", gb), ("rf", rf)], voting="soft", weights=[0.6, 0.4])

print("[*] Fitting ensemble...")
ensemble.fit(X_train_scaled, y_train)

print("[*] Calibrating...")
try:
    calibrated = CalibratedClassifierCV(ensemble, method="sigmoid", cv="prefit")
    calibrated.fit(X_val_scaled, y_val)
except:
    calibrated = CalibratedClassifierCV(ensemble, method="sigmoid", cv=3)
    calibrated.fit(X_train_scaled, y_train)

# 7. Save to V3
model_path = os.path.join(V3_MODELS_DIR, "structural_model.pkl")
scaler_path = os.path.join(V3_MODELS_DIR, "structural_scaler.pkl")

joblib.dump(calibrated, model_path)
joblib.dump(scaler, scaler_path)

print(f"[+] Saved V3 Structural Model to {model_path}")
print(f"[+] Saved V3 Structural Scaler to {scaler_path}")
