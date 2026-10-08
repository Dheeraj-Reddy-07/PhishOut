"""Diagnose V3 label corruption"""
import pandas as pd

print("=" * 80)
print("Diagnosing V3 Label Corruption")
print("=" * 80)

# Check original train_features.parquet (before augmentation)
print("\nOriginal train_features.parquet:")
train_orig = pd.read_parquet('dataset/phish360/v3/processed/train_features.parquet')
print(f"Shape: {train_orig.shape}")
print(f"Label column dtype: {train_orig['label'].dtype}")
print(f"Label distribution: {train_orig['label'].value_counts(dropna=False).to_dict()}")
print(f"Missing labels: {train_orig['label'].isnull().sum()}")

# Check hard_neg_train_features.parquet
print("\nHard-negative train features:")
hard_neg_train = pd.read_parquet('dataset/phish360/v3/processed/hard_neg_train_features.parquet')
print(f"Shape: {hard_neg_train.shape}")
print(f"Label column dtype: {hard_neg_train['label'].dtype}")
print(f"Label distribution: {hard_neg_train['label'].value_counts(dropna=False).to_dict()}")
print(f"Missing labels: {hard_neg_train['label'].isnull().sum()}")

# Check augmented training set
print("\nAugmented train_features_augmented.parquet:")
train_aug = pd.read_parquet('dataset/phish360/v3/processed/train_features_augmented.parquet')
print(f"Shape: {train_aug.shape}")
print(f"Label column dtype: {train_aug['label'].dtype}")
print(f"Label distribution: {train_aug['label'].value_counts(dropna=False).to_dict()}")
print(f"Missing labels: {train_aug['label'].isnull().sum()}")

# Check validation set
print("\nValidation features:")
val = pd.read_parquet('dataset/phish360/v3/processed/validation_features.parquet')
print(f"Shape: {val.shape}")
print(f"Label column dtype: {val['label'].dtype}")
print(f"Label distribution: {val['label'].value_counts(dropna=False).to_dict()}")
print(f"Missing labels: {val['label'].isnull().sum()}")

# Check test set
print("\nTest features:")
test = pd.read_parquet('dataset/phish360/v3/processed/test_features.parquet')
print(f"Shape: {test.shape}")
print(f"Label column dtype: {test['label'].dtype}")
print(f"Label distribution: {test['label'].value_counts(dropna=False).to_dict()}")
print(f"Missing labels: {test['label'].isnull().sum()}")
