"""
V3 Feature Extractor for Phish360 Dataset

This script extracts features for V3 training:
- 32 structural features (unchanged from V2)
- 19 semantic features (15 V2 + 4 new V3 features)
- Total: 51 features per sample

It processes:
1. Original Phish360 train/val/test splits (re-extracted with 19 semantic features)
2. Hard-negative train/val/eval sets (extract all features)
3. Outputs to backend/dataset/phish360/v3/processed/
"""

import pandas as pd
import numpy as np
from pathlib import Path
import sys
import json
from datetime import datetime

# Add backend to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from ml_model import extract_features as extract_structural_features
from webpage_analyzer import extract_semantic_features

# Configuration
PHISH360_LEGIT_PATH = r"D:\Downloads\phish360_parquet\Phish360_legit.parquet"
PHISH360_PHISH_PATH = r"D:\Downloads\phish360_parquet\Phish360_phish.parquet"

V3_OUTPUT_DIR = Path("dataset/phish360/v3")
V3_PROCESSED_DIR = V3_OUTPUT_DIR / "processed"
V3_PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

HARD_NEG_DIR = Path("backend/dataset/phish360/v3/hard_negatives")

# V2 processed data (to get split information)
V2_PROCESSED_DIR = Path("dataset/phish360/v2/processed")

# Semantic feature keys (V3: 19 features)
SEMANTIC_KEYS_V3 = [
    'password_fields', 'text_email_fields', 'forms', 'external_links',
    'iframes', 'scripts', 'login_indicators', 'credential_indicators',
    'payment_indicators', 'urgency_indicators', 'brand_indicators', 'text_length',
    # V2 context features
    'domain_brand_consistency', 'form_action_same_origin', 'trusted_domain',
    # V3 new features
    'link_to_form_ratio', 'text_to_script_ratio', 'credential_density', 'brand_context_score',
]

def extract_all_features_from_sample(url: str, html: str) -> dict:
    """Extract all V3 features (structural + semantic) from a single sample."""
    
    # Extract structural features
    try:
        struct_feats = extract_structural_features(url)
    except Exception as e:
        print(f"Warning: Structural extraction failed for URL {url}: {e}")
        struct_feats = {f"struct_{i}": 0.0 for i in range(32)}
    
    # Extract semantic features (V3: 19 features)
    try:
        sem_feats = extract_semantic_features(html, url)
    except Exception as e:
        print(f"Warning: Semantic extraction failed for URL {url}: {e}")
        sem_feats = {key: 0.0 for key in SEMANTIC_KEYS_V3}
    
    # Combine features
    all_feats = {**struct_feats, **sem_feats}
    return all_feats

def process_dataframe_with_v3_features(
    df: pd.DataFrame,
    split_name: str,
    html_column: str = "full_html"  # FIXED: Use full_html instead of html2text_text for script extraction
) -> pd.DataFrame:
    """Process a DataFrame and extract V3 features."""
    
    print(f"\nProcessing {split_name}: {len(df)} samples")
    
    # Extract features
    all_features = []
    
    total_samples = len(df)
    for idx, row in df.iterrows():
        if idx % 100 == 0:
            print(f"  Processing {idx}/{total_samples} ({idx/total_samples*100:.1f}%)...")
        
        url = row.get('URL', '')
        html = row.get(html_column, '')
        
        # Extract all features
        feats = extract_all_features_from_sample(url, html)
        all_features.append(feats)
    
    # Convert to DataFrame
    feature_df = pd.DataFrame(all_features)
    
    # Add metadata
    feature_df['sample_id'] = df['sample_id'] if 'sample_id' in df.columns else [f"{split_name}_{i}" for i in range(len(df))]
    feature_df['url'] = df['URL']
    # Handle label mapping - ensure Class column exists and is properly mapped
    if 'Class' in df.columns:
        feature_df['label'] = df['Class'].map({'legit': 0, 'legitimate': 0, 'phish': 1, 'phishing': 1}).fillna(df.get('label', 0))
    else:
        feature_df['label'] = df.get('label', 0)
    # Ensure labels are integers (0 or 1)
    feature_df['label'] = feature_df['label'].astype(int)
    feature_df['domain'] = df.get('Domain', '')
    feature_df['html_available'] = df[html_column].notna().astype(int)
    
    print(f"Extracted features shape: {feature_df.shape}")
    print(f"Total features: {len(feature_df.columns) - 4}")  # Exclude metadata columns
    
    return feature_df

def main():
    """Main execution: extract V3 features for all datasets."""
    
    print("=" * 80)
    print("V3 Step 2: Extracting V3 Features (19 semantic) for All Datasets")
    print("=" * 80)
    
    # Load V2 splits to identify which samples go where
    print("\nLoading V2 splits to identify train/val/test structure...")
    
    v2_train = pd.read_parquet(V2_PROCESSED_DIR / "train_features.parquet")
    v2_val = pd.read_parquet(V2_PROCESSED_DIR / "validation_features.parquet")
    v2_test = pd.read_parquet(V2_PROCESSED_DIR / "test_features.parquet")
    
    print(f"V2 Train: {len(v2_train)} samples")
    print(f"V2 Val: {len(v2_val)} samples")
    print(f"V2 Test: {len(v2_test)} samples")
    
    # The V2 processed data doesn't have URLs, so we need to reconstruct from original data
    # We'll use the V2 split counts to guide our sampling from the full Phish360 data
    
    # Load full Phish360 data
    print("\nLoading full Phish360 datasets...")
    legit_df = pd.read_parquet(PHISH360_LEGIT_PATH)
    phish_df = pd.read_parquet(PHISH360_PHISH_PATH)
    
    print(f"Phish360 Legit: {len(legit_df)} samples")
    print(f"Phish360 Phish: {len(phish_df)} samples")
    
    # Add sample_id if not present
    if 'sample_id' not in legit_df.columns:
        legit_df['sample_id'] = [f"LEGIT_{i:06d}" for i in range(len(legit_df))]
    if 'sample_id' not in phish_df.columns:
        phish_df['sample_id'] = [f"PHISH_{i:06d}" for i in range(len(phish_df))]
    
    # Use the same random seed as V2 to recreate the splits
    RANDOM_SEED = 42
    
    # Shuffle with same seed
    legit_shuffled = legit_df.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)
    phish_shuffled = phish_df.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)
    
    # Calculate split sizes based on V2 counts
    # V2 train: 7,730 (4,660 legit + 3,070 phish)
    # V2 val: 1,317 (809 legit + 508 phish)
    # V2 test: 1,701 (947 legit + 754 phish)
    
    legit_train_size = 4660
    legit_val_size = 809
    legit_test_size = 947
    
    phish_train_size = 3070
    phish_val_size = 508
    phish_test_size = 754
    
    # Split legitimate data
    legit_train = legit_shuffled.iloc[:legit_train_size].copy()
    legit_val = legit_shuffled.iloc[legit_train_size:legit_train_size + legit_val_size].copy()
    legit_test = legit_shuffled.iloc[legit_train_size + legit_val_size:legit_train_size + legit_val_size + legit_test_size].copy()
    
    # Split phishing data
    phish_train = phish_shuffled.iloc[:phish_train_size].copy()
    phish_val = phish_shuffled.iloc[phish_train_size:phish_train_size + phish_val_size].copy()
    phish_test = phish_shuffled.iloc[phish_train_size + phish_val_size:phish_train_size + phish_val_size + phish_test_size].copy()
    
    print(f"\nRecreated V2 splits:")
    print(f"Legit Train: {len(legit_train)}, Val: {len(legit_val)}, Test: {len(legit_test)}")
    print(f"Phish Train: {len(phish_train)}, Val: {len(phish_val)}, Test: {len(phish_test)}")
    
    # Combine legit and phish for each split
    train_df = pd.concat([legit_train, phish_train], ignore_index=True)
    val_df = pd.concat([legit_val, phish_val], ignore_index=True)
    test_df = pd.concat([legit_test, phish_test], ignore_index=True)
    
    # Process each split with V3 features
    print("\n" + "=" * 80)
    print("Extracting V3 features for each split...")
    print("=" * 80)
    
    train_features = process_dataframe_with_v3_features(train_df, "Train")
    val_features = process_dataframe_with_v3_features(val_df, "Validation")
    test_features = process_dataframe_with_v3_features(test_df, "Test")
    
    # Process hard negatives
    print("\n" + "=" * 80)
    print("Processing hard-negative sets...")
    print("=" * 80)
    
    hard_neg_train_path = HARD_NEG_DIR / "hard_neg_train.parquet"
    hard_neg_val_path = HARD_NEG_DIR / "hard_neg_val.parquet"
    hard_neg_eval_path = HARD_NEG_DIR / "hard_neg_eval.parquet"
    
    hard_neg_train_df = pd.read_parquet(hard_neg_train_path)
    hard_neg_val_df = pd.read_parquet(hard_neg_val_path)
    hard_neg_eval_df = pd.read_parquet(hard_neg_eval_path)
    
    # Add Class column for processing
    hard_neg_train_df['Class'] = 'legitimate'
    hard_neg_val_df['Class'] = 'legitimate'
    hard_neg_eval_df['Class'] = 'legitimate'
    
    hard_neg_train_features = process_dataframe_with_v3_features(hard_neg_train_df, "Hard Neg Train")
    hard_neg_val_features = process_dataframe_with_v3_features(hard_neg_val_df, "Hard Neg Val")
    hard_neg_eval_features = process_dataframe_with_v3_features(hard_neg_eval_df, "Hard Neg Eval")
    
    # Add hard-negative flag
    hard_neg_train_features['is_hard_negative'] = 1
    hard_neg_val_features['is_hard_negative'] = 1
    hard_neg_eval_features['is_hard_negative'] = 1
    
    # Save V3 processed datasets
    print("\n" + "=" * 80)
    print("Saving V3 processed datasets...")
    print("=" * 80)
    
    train_features.to_parquet(V3_PROCESSED_DIR / "train_features.parquet", index=False)
    val_features.to_parquet(V3_PROCESSED_DIR / "validation_features.parquet", index=False)
    test_features.to_parquet(V3_PROCESSED_DIR / "test_features.parquet", index=False)
    
    hard_neg_train_features.to_parquet(V3_PROCESSED_DIR / "hard_neg_train_features.parquet", index=False)
    hard_neg_val_features.to_parquet(V3_PROCESSED_DIR / "hard_neg_val_features.parquet", index=False)
    hard_neg_eval_features.to_parquet(V3_PROCESSED_DIR / "hard_neg_eval_features.parquet", index=False)
    
    print(f"\nSaved V3 datasets:")
    print(f"  {V3_PROCESSED_DIR / 'train_features.parquet'}")
    print(f"  {V3_PROCESSED_DIR / 'validation_features.parquet'}")
    print(f"  {V3_PROCESSED_DIR / 'test_features.parquet'}")
    print(f"  {V3_PROCESSED_DIR / 'hard_neg_train_features.parquet'}")
    print(f"  {V3_PROCESSED_DIR / 'hard_neg_val_features.parquet'}")
    print(f"  {V3_PROCESSED_DIR / 'hard_neg_eval_features.parquet'}")
    
    # Create feature manifest
    feature_manifest = {
        "extraction_date": datetime.now().isoformat(),
        "total_features": 51,  # 32 structural + 19 semantic
        "structural_features": 32,
        "semantic_features": 19,
        "semantic_feature_keys": SEMANTIC_KEYS_V3,
        "v2_context_features": ["domain_brand_consistency", "form_action_same_origin", "trusted_domain"],
        "v3_new_features": ["link_to_form_ratio", "text_to_script_ratio", "credential_density", "brand_context_score"],
        "dataset_statistics": {
            "train_samples": len(train_features),
            "validation_samples": len(val_features),
            "test_samples": len(test_features),
            "hard_neg_train_samples": len(hard_neg_train_features),
            "hard_neg_val_samples": len(hard_neg_val_features),
            "hard_neg_eval_samples": len(hard_neg_eval_features),
        }
    }
    
    manifest_path = V3_PROCESSED_DIR / "v3_feature_manifest.json"
    with open(manifest_path, 'w') as f:
        json.dump(feature_manifest, f, indent=2)
    
    print(f"\nSaved feature manifest: {manifest_path}")
    
    print("\n" + "=" * 80)
    print("V3 Feature Extraction Summary")
    print("=" * 80)
    print(f"Total features per sample: 51 (32 structural + 19 semantic)")
    print(f"Train samples: {len(train_features):,}")
    print(f"Validation samples: {len(val_features):,}")
    print(f"Test samples: {len(test_features):,}")
    print(f"Hard-negative train: {len(hard_neg_train_features):,}")
    print(f"Hard-negative val: {len(hard_neg_val_features):,}")
    print(f"Hard-negative eval: {len(hard_neg_eval_features):,}")
    print("=" * 80)

if __name__ == "__main__":
    main()
