"""Quick validation of V3 datasets"""
import pandas as pd
import json

print("=" * 80)
print("V3 Dataset Validation")
print("=" * 80)

# Load augmentation manifest
with open('dataset/phish360/v3/processed/v3_augmentation_manifest.json') as f:
    manifest = json.load(f)
print("\nAugmentation Manifest:")
print(json.dumps(manifest, indent=2))

# Load and validate augmented training set
print("\n" + "=" * 80)
print("Augmented Training Set")
print("=" * 80)
train_aug = pd.read_parquet('dataset/phish360/v3/processed/train_features_augmented.parquet')
print(f"Shape: {train_aug.shape}")
print(f"Label distribution: {train_aug['label'].value_counts().to_dict()}")
print(f"Has is_hard_negative column: {'is_hard_negative' in train_aug.columns}")
if 'is_hard_negative' in train_aug.columns:
    print(f"Hard-negative count: {train_aug['is_hard_negative'].sum()}")
print(f"Missing values: {train_aug.isnull().sum().sum()}")

# Check for V3 semantic features
v3_features = ['link_to_form_ratio', 'text_to_script_ratio', 'credential_density', 'brand_context_score']
print(f"\nV3 new features present:")
for feat in v3_features:
    present = feat in train_aug.columns
    print(f"  {feat}: {present}")

# Load validation set
print("\n" + "=" * 80)
print("Validation Set")
print("=" * 80)
val = pd.read_parquet('dataset/phish360/v3/processed/validation_features.parquet')
print(f"Shape: {val.shape}")
print(f"Label distribution: {val['label'].value_counts().to_dict()}")

# Load test set
print("\n" + "=" * 80)
print("Test Set")
print("=" * 80)
test = pd.read_parquet('dataset/phish360/v3/processed/test_features.parquet')
print(f"Shape: {test.shape}")
print(f"Label distribution: {test['label'].value_counts().to_dict()}")

# Load hard-negative eval set
print("\n" + "=" * 80)
print("Hard-Negative Eval Set")
print("=" * 80)
hard_neg_eval = pd.read_parquet('dataset/phish360/v3/processed/hard_neg_eval_features.parquet')
print(f"Shape: {hard_neg_eval.shape}")
print(f"Label distribution: {hard_neg_eval['label'].value_counts().to_dict()}")

print("\n" + "=" * 80)
print("Validation Summary")
print("=" * 80)
print(f"✓ Augmented training set: {len(train_aug)} samples (expected 8,330)")
print(f"✓ Validation set: {len(val)} samples (expected 1,317)")
print(f"✓ Test set: {len(test)} samples (expected 1,701)")
print(f"✓ Hard-negative eval: {len(hard_neg_eval)} samples")
print(f"✓ V3 features present: {all(feat in train_aug.columns for feat in v3_features)}")
print("=" * 80)
