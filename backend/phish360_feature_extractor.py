"""
Phish360 Feature Extraction Pipeline
Extracts 32 structural + 12 semantic features from Phish360 dataset.
"""
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple
import sys
import os

# Add parent directory to path to import existing modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml_model import extract_features, FEATURE_KEYS
from webpage_analyzer import extract_semantic_features_from_html
from leakage_validator import create_leakage_free_split, LeakageValidator
import tldextract


class Phish360FeatureExtractor:
    """
    Extracts structural and semantic features from Phish360 dataset.
    """
    
    def __init__(self, output_dir: str = "backend/dataset/phish360"):
        """
        Initialize feature extractor.
        
        Args:
            output_dir: Directory to save processed features
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Structural feature keys (32 features)
        self.structural_keys = FEATURE_KEYS
        
        # Semantic feature keys (select 12 out of 14 available)
        self.semantic_keys = [
            'password_fields',
            'text_email_fields', 
            'forms',
            'external_links',
            'iframes',
            'scripts',
            'login_indicators',
            'credential_indicators',
            'payment_indicators',
            'urgency_indicators',
            'brand_indicators',
            'text_length'
        ]
        
        print(f"[*] Feature extractor initialized")
        print(f"    Output directory: {self.output_dir}")
        print(f"    Structural features: {len(self.structural_keys)}")
        print(f"    Semantic features: {len(self.semantic_keys)}")
        print(f"    Total features: {len(self.structural_keys) + len(self.semantic_keys)}")
    
    def extract_structural_features(self, url: str) -> Dict:
        """
        Extract 32 structural features from URL.
        
        Args:
            url: URL string
            
        Returns:
            Dictionary of structural features
        """
        try:
            features = extract_features(url)
            return features
        except Exception as e:
            print(f"    [ERROR] Failed to extract structural features from {url[:50]}: {e}")
            # Return zero features on failure
            return {key: 0 for key in self.structural_keys}
    
    def extract_semantic_features(self, html: str, url: str = "") -> Dict:
        """
        Extract 12 semantic features from HTML.
        
        Args:
            html: HTML content
            url: Original URL (optional, for external link detection)
            
        Returns:
            Dictionary of semantic features
        """
        try:
            features = extract_semantic_features_from_html(html, url)
            # Select only the 12 features we need
            selected_features = {key: features.get(key, 0) for key in self.semantic_keys}
            return selected_features
        except Exception as e:
            print(f"    [ERROR] Failed to extract semantic features: {e}")
            # Return zero features on failure
            return {key: 0 for key in self.semantic_keys}
    
    def process_sample(self, sample_data: Dict) -> Dict:
        """
        Process a single sample to extract all features.
        
        Args:
            sample_data: Dictionary containing url, html, label, sample_id
            
        Returns:
            Dictionary with all features and metadata
        """
        url = sample_data.get('url', '')
        html = sample_data.get('html', '')
        label = sample_data.get('label', 0)
        sample_id = sample_data.get('sample_id', '')
        
        # Extract structural features
        structural_features = self.extract_structural_features(url)
        
        # Extract semantic features (if HTML available)
        if html:
            semantic_features = self.extract_semantic_features(html, url)
        else:
            semantic_features = {key: 0 for key in self.semantic_keys}
        
        # Combine all features
        combined_features = {
            'sample_id': sample_id,
            'url': url,
            'label': label,
            'html_available': 1 if html else 0,
            **structural_features,
            **semantic_features
        }
        
        return combined_features
    
    def process_dataframe(
        self,
        df: pd.DataFrame,
        batch_size: int = 100
    ) -> pd.DataFrame:
        """
        Process a DataFrame of samples to extract features.
        
        Args:
            df: DataFrame with columns: sample_id, url, html, label
            batch_size: Number of samples to process at once (for progress reporting)
            
        Returns:
            DataFrame with extracted features
        """
        print(f"[*] Processing {len(df)} samples...")
        
        all_features = []
        failed_samples = []
        
        for idx, row in df.iterrows():
            sample_data = {
                'sample_id': row.get('sample_id', f"sample_{idx}"),
                'url': row.get('url', ''),
                'html': row.get('html', ''),
                'label': row.get('label', 0)
            }
            
            try:
                features = self.process_sample(sample_data)
                all_features.append(features)
                
                # Progress reporting
                if (idx + 1) % batch_size == 0:
                    print(f"    Processed {idx + 1}/{len(df)} samples...")
                    
            except Exception as e:
                print(f"    [ERROR] Failed to process sample {idx}: {e}")
                failed_samples.append(idx)
                continue
        
        result_df = pd.DataFrame(all_features)
        
        print(f"[+] Successfully processed {len(result_df)} samples")
        if failed_samples:
            print(f"[-] Failed to process {len(failed_samples)} samples")
        
        return result_df
    
    def create_splits(
        self,
        df: pd.DataFrame,
        train_ratio: float = 0.85,
        val_ratio: float = 0.15,
        random_state: int = 42
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Create leakage-free train/validation/test splits.
        
        Args:
            df: Input DataFrame with URLs and labels
            train_ratio: Ratio for training set (from non-test data)
            val_ratio: Ratio for validation set (from non-test data)
            random_state: Random seed for reproducibility
            
        Returns:
            Tuple of (train_df, val_df, test_df) DataFrames
        """
        print("[*] Creating leakage-free splits...")
        
        # Check if we already have a test split (from Phish360 ZIP structure)
        if 'split' in df.columns:
            # Use existing test split
            test_df = df[df['split'] == 'test'].copy()
            trainval_df = df[df['split'] == 'trainval'].copy()
            
            print(f"    Using existing test split: {len(test_df)} samples")
            print(f"    Trainval samples: {len(trainval_df)}")
            
            # Create train/val split from trainval
            train_df, val_df = create_leakage_free_split(
                trainval_df,
                train_ratio=train_ratio,
                val_ratio=val_ratio,
                random_state=random_state
            )
            
        else:
            # Create all splits from single dataset
            # First split off test set (15%)
            trainval_df, test_df = create_leakage_free_split(
                df,
                train_ratio=0.85,
                val_ratio=0.15,
                random_state=random_state
            )
            
            # Then split trainval into train/val
            train_df, val_df = create_leakage_free_split(
                trainval_df,
                train_ratio=train_ratio,
                val_ratio=val_ratio,
                random_state=random_state
            )
        
        print(f"[+] Train samples: {len(train_df)}")
        print(f"[+] Validation samples: {len(val_df)}")
        print(f"[+] Test samples: {len(test_df)}")
        
        return train_df, val_df, test_df
    
    def validate_splits(
        self,
        train_df: pd.DataFrame,
        val_df: pd.DataFrame,
        test_df: pd.DataFrame
    ) -> Dict:
        """
        Validate that splits are leakage-free.
        
        Args:
            train_df: Training set DataFrame
            val_df: Validation set DataFrame
            test_df: Test set DataFrame
            
        Returns:
            Validation results dictionary
        """
        print("[*] Validating splits for leakage...")
        
        validator = LeakageValidator()
        results = validator.validate_split(train_df, val_df, test_df)
        validator.print_report()
        
        return results
    
    def save_features(
        self,
        train_df: pd.DataFrame,
        val_df: pd.DataFrame,
        test_df: pd.DataFrame
    ) -> Tuple[str, str, str]:
        """
        Save processed feature datasets to disk.
        
        Args:
            train_df: Training set DataFrame
            val_df: Validation set DataFrame
            test_df: Test set DataFrame
            
        Returns:
            Tuple of (train_path, val_path, test_path) file paths
        """
        print("[*] Saving processed features...")
        
        # Create processed directory
        processed_dir = self.output_dir / "processed"
        processed_dir.mkdir(parents=True, exist_ok=True)
        
        # Save as Parquet files
        train_path = processed_dir / "train_features.parquet"
        val_path = processed_dir / "validation_features.parquet"
        test_path = processed_dir / "test_features.parquet"
        
        train_df.to_parquet(train_path, index=False)
        val_df.to_parquet(val_path, index=False)
        test_df.to_parquet(test_path, index=False)
        
        print(f"[+] Saved train features to {train_path}")
        print(f"[+] Saved validation features to {val_path}")
        print(f"[+] Saved test features to {test_path}")
        
        return str(train_path), str(val_path), str(test_path)
    
    def generate_report(
        self,
        train_df: pd.DataFrame,
        val_df: pd.DataFrame,
        test_df: pd.DataFrame,
        validation_results: Dict
    ) -> str:
        """
        Generate a comprehensive processing report.
        
        Args:
            train_df: Training set DataFrame
            val_df: Validation set DataFrame
            test_df: Test set DataFrame
            validation_results: Leakage validation results
            
        Returns:
            Report file path
        """
        print("[*] Generating processing report...")
        
        reports_dir = self.output_dir / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        
        report_path = reports_dir / "dataset_report.md"
        
        # Calculate statistics
        total_samples = len(train_df) + len(val_df) + len(test_df)
        
        train_phishing = int(train_df['label'].sum())
        train_legit = len(train_df) - train_phishing
        val_phishing = int(val_df['label'].sum())
        val_legit = len(val_df) - val_phishing
        test_phishing = int(test_df['label'].sum())
        test_legit = len(test_df) - test_phishing
        
        # Generate report
        report = f"""# Phish360 Dataset Processing Report

**Generated:** {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## Dataset Statistics

### Overall
- **Total Samples:** {total_samples}
- **Training Samples:** {len(train_df)} ({100*len(train_df)/total_samples:.1f}%)
- **Validation Samples:** {len(val_df)} ({100*len(val_df)/total_samples:.1f}%)
- **Test Samples:** {len(test_df)} ({100*len(test_df)/total_samples:.1f}%)

### Class Distribution

#### Training Set
- **Phishing:** {train_phishing} ({100*train_phishing/len(train_df):.1f}%)
- **Legitimate:** {train_legit} ({100*train_legit/len(train_df):.1f}%)

#### Validation Set
- **Phishing:** {val_phishing} ({100*val_phishing/len(val_df):.1f}%)
- **Legitimate:** {val_legit} ({100*val_legit/len(val_df):.1f}%)

#### Test Set
- **Phishing:** {test_phishing} ({100*test_phishing/len(test_df):.1f}%)
- **Legitimate:** {test_legit} ({100*test_legit/len(test_df):.1f}%)

---

## Feature Statistics

### Structural Features (32)
- **Source:** URL analysis
- **Feature Count:** {len(self.structural_keys)}
- **Features:** {', '.join(self.structural_keys[:5])}...

### Semantic Features (12)
- **Source:** HTML content analysis
- **Feature Count:** {len(self.semantic_keys)}
- **Features:** {', '.join(self.semantic_keys[:5])}...

### HTML Availability
- **Training Set:** {int(train_df['html_available'].sum())}/{len(train_df)} samples ({100*train_df['html_available'].sum()/len(train_df):.1f}%)
- **Validation Set:** {int(val_df['html_available'].sum())}/{len(val_df)} samples ({100*val_df['html_available'].sum()/len(val_df):.1f}%)
- **Test Set:** {int(test_df['html_available'].sum())}/{len(test_df)} samples ({100*test_df['html_available'].sum()/len(test_df):.1f}%)

---

## Leakage Validation Results

### URL Overlap
- **Train-Val:** {validation_results['url_overlap']['train_val']} URLs
- **Train-Test:** {validation_results['url_overlap']['train_test']} URLs
- **Val-Test:** {validation_results['url_overlap']['val_test']} URLs
- **Status:** {'✅ PASS' if validation_results['url_overlap']['total'] == 0 else '❌ FAIL'}

### Domain Overlap
- **Train-Val:** {validation_results['registered_domain_overlap']['train_val']} domains
- **Train-Test:** {validation_results['registered_domain_overlap']['train_test']} domains
- **Val-Test:** {validation_results['registered_domain_overlap']['val_test']} domains
- **Status:** {'✅ PASS' if validation_results['registered_domain_overlap']['total'] == 0 else '❌ FAIL'}

### Test Contamination
- **Is Contaminated:** {'❌ YES' if validation_results['test_contamination']['is_contaminated'] else '✅ NO'}
- **URL Leakage:** {'❌ YES' if validation_results['test_contamination']['url_leakage'] else '✅ NO'}
- **Domain Leakage:** {'❌ YES' if validation_results['test_contamination']['domain_leakage'] else '✅ NO'}

### Overall Validation
- **Result:** {'✅ PASS - Leakage-free splits' if validation_results['overall_pass'] else '❌ FAIL - Leakage detected'}

---

## Processing Information

### Feature Extraction
- **Structural Features:** Extracted from URLs using existing `ml_model.py`
- **Semantic Features:** Extracted from HTML using existing `webpage_analyzer.py`
- **Total Features:** {len(self.structural_keys) + len(self.semantic_keys)} (32 structural + 12 semantic)

### Splitting Methodology
- **Domain-Aware Splitting:** Used to prevent domain leakage
- **Random Seed:** 42 (for reproducibility)
- **Test Set:** Preserved as final evaluation set (from original Phish360 split if available)

### Output Files
- **Train Features:** `processed/train_features.parquet`
- **Validation Features:** `processed/validation_features.parquet`
- **Test Features:** `processed/test_features.parquet`

---

## Notes

- This dataset is ready for model training and evaluation
- All splits have been validated for leakage
- Feature extraction follows the PhishOut architecture (32 structural + 12 semantic)
- HTML content was used directly from the dataset (no network requests made)

---

**END OF REPORT**
"""
        
        with open(report_path, 'w') as f:
            f.write(report)
        
        print(f"[+] Saved processing report to {report_path}")
        return str(report_path)


def process_phish360_dataset(
    data_path: str,
    output_dir: str = "backend/dataset/phish360",
    password: str = None
) -> Tuple[str, str, str]:
    """
    Complete pipeline to process Phish360 dataset.
    
    Args:
        data_path: Path to Phish360 data (Parquet files or ZIP archive)
        output_dir: Directory to save processed features
        password: ZIP password if required
        
    Returns:
        Tuple of (train_path, val_path, test_path) file paths
    """
    from data_loader_phish360 import Phish360Loader
    
    print("="*60)
    print("  PHISH360 DATASET PROCESSING PIPELINE")
    print("="*60)
    
    # Load dataset
    loader = Phish360Loader(data_path)
    trainval_df, test_df = loader.load(password)
    
    # If Parquet format (no pre-split), create splits
    if test_df is None:
        print("[*] Creating train/validation/test splits from Parquet data...")
        extractor = Phish360FeatureExtractor(output_dir)
        train_df, val_df, test_df = extractor.create_splits(trainval_df)
    else:
        # ZIP format - use existing test split
        print("[*] Using existing trainval/test split from ZIP...")
        extractor = Phish360FeatureExtractor(output_dir)
        train_df, val_df, test_df = extractor.create_splits(
            pd.concat([trainval_df.assign(split='trainval'), test_df.assign(split='test')])
        )
    
    # Extract features
    print("[*] Extracting structural features from URLs...")
    train_df = extractor.process_dataframe(train_df)
    val_df = extractor.process_dataframe(val_df)
    test_df = extractor.process_dataframe(test_df)
    
    # Validate splits
    validation_results = extractor.validate_splits(train_df, val_df, test_df)
    
    # Save features
    train_path, val_path, test_path = extractor.save_features(train_df, val_df, test_df)
    
    # Generate report
    report_path = extractor.generate_report(train_df, val_df, test_df, validation_results)
    
    print("\n" + "="*60)
    print("  PROCESSING COMPLETE")
    print("="*60)
    print(f"  Train features: {train_path}")
    print(f"  Validation features: {val_path}")
    print(f"  Test features: {test_path}")
    print(f"  Report: {report_path}")
    print("="*60 + "\n")
    
    return train_path, val_path, test_path


if __name__ == "__main__":
    print("Phish360 Feature Extraction Pipeline")
    print("Import this module to use feature extraction functions.")