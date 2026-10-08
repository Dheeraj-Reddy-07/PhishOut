"""
V3 Augmented Training Set Builder

This script builds the augmented V3 training set by combining:
- Original V2 training set (7,730 samples)
- Hard-negative training samples (600 samples)

Following the V3 implementation plan:
- Keep V2 structural model frozen (not retrained)
- Augment training set with hard negatives for semantic model training
- Total V3 training set: 8,330 samples
"""

import pandas as pd
import numpy as np
from pathlib import Path
import json
from datetime import datetime

# Configuration
V3_PROCESSED_DIR = Path("dataset/phish360/v3/processed")
V3_OUTPUT_DIR = Path("dataset/phish360/v3/processed")

def build_augmented_training_set():
    """Build augmented V3 training set by combining original train + hard negatives."""
    
    print("=" * 80)
    print("V3 Step 3: Building Augmented V3 Training Set")
    print("=" * 80)
    
    # Load original V3 training set
    print("\nLoading original V3 training set...")
    original_train = pd.read_parquet(V3_PROCESSED_DIR / "train_features.parquet")
    print(f"Original training samples: {len(original_train):,}")
    print(f"Original label distribution: {original_train['label'].value_counts().to_dict()}")
    
    # Load hard-negative training set
    print("Loading hard-negative training set...")
    hard_neg_train = pd.read_parquet(V3_PROCESSED_DIR / "hard_neg_train_features.parquet")
    print(f"Hard-negative training samples: {len(hard_neg_train):,}")
    print(f"Hard-negative label distribution: {hard_neg_train['label'].value_counts().to_dict()}")
    
    # Combine datasets
    print("\nCombining original training + hard negatives...")
    augmented_train = pd.concat([original_train, hard_neg_train], ignore_index=True)
    
    # Add is_hard_negative flag (0 for original, 1 for hard negatives)
    if 'is_hard_negative' not in augmented_train.columns:
        augmented_train['is_hard_negative'] = 0
    # Set flag for hard negatives
    augmented_train.loc[augmented_train.index >= len(original_train), 'is_hard_negative'] = 1
    
    print(f"Augmented training samples: {len(augmented_train):,}")
    print(f"  - Original samples: {len(original_train):,}")
    print(f"  - Hard-negative samples: {len(hard_neg_train):,}")
    
    # Verify feature consistency
    print("\nVerifying feature consistency...")
    print(f"Original features: {len(original_train.columns)}")
    print(f"Hard-negative features: {len(hard_neg_train.columns)}")
    print(f"Augmented features: {len(augmented_train.columns)}")
    
    # Check for missing values and handle non-numeric columns
    print("\nChecking for missing values and non-numeric columns...")
    missing_counts = augmented_train.isnull().sum()
    if missing_counts.sum() > 0:
        print("Missing values found:")
        print(missing_counts[missing_counts > 0])
    
    # Remove non-numeric columns that can't be used for ML training
    non_numeric_cols = ['sample_id', 'url', 'domain', 'page_title', 'form_actions']
    cols_to_drop = [col for col in non_numeric_cols if col in augmented_train.columns and col != 'label']
    if cols_to_drop:
        print(f"Dropping non-numeric columns: {cols_to_drop}")
        augmented_train = augmented_train.drop(columns=cols_to_drop)
    
    # Fill missing values with 0, but preserve labels (and handle NaN labels)
    label_values = augmented_train['label'].copy()
    # Fix NaN labels - they should be 0 (legitimate) from the original data
    label_values = label_values.fillna(0)
    augmented_train = augmented_train.fillna(0)
    augmented_train['label'] = label_values
    print("Filled missing values with 0 (preserving and fixing labels)")
    
    # Save augmented training set
    print("\nSaving augmented V3 training set...")
    augmented_train.to_parquet(V3_OUTPUT_DIR / "train_features_augmented.parquet", index=False)
    print(f"Saved: {V3_OUTPUT_DIR / 'train_features_augmented.parquet'}")
    
    # Create augmentation manifest
    augmentation_manifest = {
        "augmentation_date": datetime.now().isoformat(),
        "original_train_samples": len(original_train),
        "hard_negative_train_samples": len(hard_neg_train),
        "augmented_train_samples": len(augmented_train),
        "augmentation_ratio": len(hard_neg_train) / len(original_train),
        "feature_count": len(augmented_train.columns),
        "hard_negative_percentage": len(hard_neg_train) / len(augmented_train) * 100,
        "split_provenance": {
            "original_train_source": "V2 train split (same domain stratification)",
            "hard_negative_source": "Phish360 legit HTML with auth keywords (Step 1)",
            "validation_source": "V2 validation split (unchanged)",
            "test_source": "V2 test split (unchanged, frozen)"
        }
    }
    
    manifest_path = V3_OUTPUT_DIR / "v3_augmentation_manifest.json"
    with open(manifest_path, 'w') as f:
        json.dump(augmentation_manifest, f, indent=2)
    
    print(f"Saved augmentation manifest: {manifest_path}")
    
    print("\n" + "=" * 80)
    print("V3 Augmented Training Set Summary")
    print("=" * 80)
    print(f"Original training samples: {len(original_train):,}")
    print(f"Hard-negative augmentation: {len(hard_neg_train):,}")
    print(f"Final augmented training set: {len(augmented_train):,}")
    print(f"Augmentation increase: {len(hard_neg_train)/len(original_train)*100:.1f}%")
    print(f"Hard-negative percentage: {len(hard_neg_train)/len(augmented_train)*100:.1f}%")
    print(f"Features per sample: {len(augmented_train.columns)}")
    print("=" * 80)
    
    return augmented_train

if __name__ == "__main__":
    build_augmented_training_set()
