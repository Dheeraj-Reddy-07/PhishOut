"""
V3 Hard-Negative Extraction from Phish360 Legitimate HTML

This script extracts legitimate pages that naturally contain phishing-like characteristics
(authentication content, password fields, credential language, etc.) to serve as hard negatives
for V3 training.

According to the V3 implementation plan:
- Filter Phish360 legit HTML by auth keywords: password, login, signin, authenticate, oauth
- Sample to create hard-negative pool of ~800-1,200 samples
- Split hard-negative pool: 60% train, 20% val, 20% eval (held out)
- Record provenance manifest
"""

import pandas as pd
import numpy as np
from pathlib import Path
import json
from datetime import datetime
import re

# Configuration
PHISH360_LEGIT_PATH = r"D:\Downloads\phish360_parquet\Phish360_legit.parquet"
V3_OUTPUT_DIR = Path("backend/dataset/phish360/v3")
V3_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

HARD_NEG_OUTPUT_DIR = V3_OUTPUT_DIR / "hard_negatives"
HARD_NEG_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Auth keywords for filtering (from implementation plan)
AUTH_KEYWORDS = ["password", "login", "signin", "authenticate", "oauth"]

# Target hard-negative pool size (plan suggests ~800-1,200)
TARGET_HARD_NEGATIVE_POOL = 1000

# Hard-negative split ratios
HARD_NEG_TRAIN_RATIO = 0.60
HARD_NEG_VAL_RATIO = 0.20
HARD_NEG_EVAL_RATIO = 0.20

def extract_hard_negatives():
    """Extract hard-negative samples from Phish360 legitimate HTML."""
    
    print("=" * 80)
    print("V3 Step 1: Extracting Hard-Negative Samples from Phish360 Legitimate HTML")
    print("=" * 80)
    
    # Load Phish360 legitimate parquet
    print(f"\nLoading Phish360 legitimate parquet from: {PHISH360_LEGIT_PATH}")
    legit_df = pd.read_parquet(PHISH360_LEGIT_PATH)
    print(f"Loaded {len(legit_df)} legitimate samples")
    
    # Inspect columns
    print(f"\nAvailable columns: {list(legit_df.columns)}")
    
    # Check for HTML column
    html_column = None
    for col in legit_df.columns:
        if 'html' in col.lower():
            html_column = col
            break
    
    if html_column is None:
        raise ValueError("No HTML column found in Phish360_legit.parquet")
    
    print(f"Using HTML column: {html_column}")
    
    # Filter samples with auth keywords in HTML
    print(f"\nFiltering for auth keywords: {AUTH_KEYWORDS}")
    
    def contains_auth_keywords(html_text):
        """Check if HTML contains any auth keywords (case-insensitive)."""
        if pd.isna(html_text) or html_text is None:
            return False
        html_lower = str(html_text).lower()
        return any(keyword in html_lower for keyword in AUTH_KEYWORDS)
    
    # Apply filter
    auth_mask = legit_df[html_column].apply(contains_auth_keywords)
    hard_neg_candidates = legit_df[auth_mask].copy()
    
    print(f"Found {len(hard_neg_candidates)} samples with auth keywords ({len(hard_neg_candidates)/len(legit_df)*100:.1f}% of legit)")
    
    # If we have more candidates than target, sample to target size
    if len(hard_neg_candidates) > TARGET_HARD_NEGATIVE_POOL:
        print(f"\nSampling {TARGET_HARD_NEGATIVE_POOL} from {len(hard_neg_candidates)} candidates")
        hard_negatives = hard_neg_candidates.sample(n=TARGET_HARD_NEGATIVE_POOL, random_state=42)
    else:
        print(f"\nUsing all {len(hard_neg_candidates)} candidates (below target {TARGET_HARD_NEGATIVE_POOL})")
        hard_negatives = hard_neg_candidates
    
    # Add provenance metadata
    hard_negatives['extraction_date'] = datetime.now().isoformat()
    hard_negatives['filter_criteria'] = 'auth_keywords:' + ','.join(AUTH_KEYWORDS)
    hard_negatives['label'] = 0  # All legitimate
    hard_negatives['hard_negative_type'] = 'legitimate_auth_page'
    
    # Generate sample_id if not present
    if 'sample_id' not in hard_negatives.columns:
        hard_negatives['sample_id'] = [f"HN_{i:06d}" for i in range(len(hard_negatives))]
    
    # Split hard-negative pool into train/val/eval
    print(f"\nSplitting hard-negative pool: {HARD_NEG_TRAIN_RATIO:.0%} train, {HARD_NEG_VAL_RATIO:.0%} val, {HARD_NEG_EVAL_RATIO:.0%} eval")
    
    # Shuffle before split
    hard_negatives = hard_negatives.sample(frac=1, random_state=42).reset_index(drop=True)
    
    n_total = len(hard_negatives)
    n_train = int(n_total * HARD_NEG_TRAIN_RATIO)
    n_val = int(n_total * HARD_NEG_VAL_RATIO)
    n_eval = n_total - n_train - n_val
    
    hard_neg_train = hard_negatives.iloc[:n_train].copy()
    hard_neg_val = hard_negatives.iloc[n_train:n_train + n_val].copy()
    hard_neg_eval = hard_negatives.iloc[n_train + n_val:].copy()
    
    print(f"  Train: {len(hard_neg_train)} samples")
    print(f"  Val:   {len(hard_neg_val)} samples")
    print(f"  Eval:  {len(hard_neg_eval)} samples")
    
    # Save hard-negative datasets
    train_path = HARD_NEG_OUTPUT_DIR / "hard_neg_train.parquet"
    val_path = HARD_NEG_OUTPUT_DIR / "hard_neg_val.parquet"
    eval_path = HARD_NEG_OUTPUT_DIR / "hard_neg_eval.parquet"
    
    hard_neg_train.to_parquet(train_path, index=False)
    hard_neg_val.to_parquet(val_path, index=False)
    hard_neg_eval.to_parquet(eval_path, index=False)
    
    print(f"\nSaved hard-negative datasets:")
    print(f"  {train_path}")
    print(f"  {val_path}")
    print(f"  {eval_path}")
    
    # Create provenance manifest
    manifest = {
        "extraction_date": datetime.now().isoformat(),
        "source_file": str(PHISH360_LEGIT_PATH),
        "filter_criteria": {
            "keywords": AUTH_KEYWORDS,
            "html_column": html_column
        },
        "pool_statistics": {
            "total_legit_samples": len(legit_df),
            "auth_keyword_matches": len(hard_neg_candidates),
            "final_pool_size": len(hard_negatives),
            "target_pool_size": TARGET_HARD_NEGATIVE_POOL
        },
        "split_statistics": {
            "train": len(hard_neg_train),
            "validation": len(hard_neg_val),
            "evaluation": len(hard_neg_eval),
            "train_ratio": HARD_NEG_TRAIN_RATIO,
            "val_ratio": HARD_NEG_VAL_RATIO,
            "eval_ratio": HARD_NEG_EVAL_RATIO
        },
        "sample_provenance": {
            "train_sample_ids": hard_neg_train['sample_id'].tolist() if 'sample_id' in hard_neg_train.columns else list(range(len(hard_neg_train))),
            "val_sample_ids": hard_neg_val['sample_id'].tolist() if 'sample_id' in hard_neg_val.columns else list(range(len(hard_neg_val))),
            "eval_sample_ids": hard_neg_eval['sample_id'].tolist() if 'sample_id' in hard_neg_eval.columns else list(range(len(hard_neg_eval)))
        }
    }
    
    manifest_path = HARD_NEG_OUTPUT_DIR / "hard_neg_manifest.json"
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)
    
    print(f"\nSaved provenance manifest: {manifest_path}")
    
    # Display sample statistics
    print(f"\n{'=' * 80}")
    print("Hard-Negative Extraction Summary")
    print(f"{'=' * 80}")
    print(f"Total legitimate samples in Phish360: {len(legit_df):,}")
    print(f"Samples with auth keywords: {len(hard_neg_candidates):,} ({len(hard_neg_candidates)/len(legit_df)*100:.1f}%)")
    print(f"Final hard-negative pool: {len(hard_negatives):,}")
    print(f"  - Train augmentation: {len(hard_neg_train):,}")
    print(f"  - Validation fusion: {len(hard_neg_val):,}")
    print(f"  - Held-out evaluation: {len(hard_neg_eval):,}")
    print(f"{'=' * 80}")
    
    return hard_neg_train, hard_neg_val, hard_neg_eval, manifest

if __name__ == "__main__":
    extract_hard_negatives()
