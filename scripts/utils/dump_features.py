import sys
import os
sys.path.append(os.path.join(os.getcwd(), "backend"))
import ml_model

url = "https://github.com/login"
features = ml_model.extract_features(url)
print("Features for", url)
for k, v in features.items():
    print(f"{k}: {v}")
