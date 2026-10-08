"""
Phish360 Parquet Processing Pipeline
Processes the actual Phish360 Parquet dataset for PhishOut research.
"""
import pandas as pd
import numpy as np
from pathlib import Path
import sys
import os
import json
from datetime import datetime

# Add backend directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml_model import extract_features, FEATURE_KEYS
from webpage_analyzer import extract_semantic_features_from_html
from leakage_validator import LeakageValidator, create_leakage_free_split
import tldextract


class Phish360ParquetProcessor:
    """
    Process Phish360 Parquet dataset for PhishOut research.
    """
    
    def __init__(self, data_path: str, output_dir: str = "backend/dataset/phish360"):
        """
        Initialize processor.
        
        Args:
            data_path: Path to Phish360 Parquet directory
            output_dir: Directory to save processed features
        """
        self.data_path = Path(data_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Feature keys
        self.structural_keys = FEATURE_KEYS
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
        
        print(f"[*] Phish360 Parquet Processor initialized")
        print(f"    Data path: {self.data_path}")
        print(f"    Output directory: {self.output_dir}")
        print(f"    Structural features: {len(self.structural_keys)}")
        print(f"    Semantic features: {len(self.semantic_keys)}")
    
    def load_parquet_data(self) -> pd.DataFrame:
        """
        Load and combine Phish360 Parquet files.
        
        Returns:
            Combined DataFrame with all samples
        """
        print("[*] Loading Phish360 Parquet files...")
        
        phish_file = self.data_path / 'Phish360_phish.parquet'
        legit_file = self.data_path / 'Phish360_legit.parquet'
        
        if not phish_file.exists() or not legit_file.exists():
            raise FileNotFoundError(
                f"Expected Phish360_phish.parquet and Phish360_legit.parquet in {self.data_path}"
            )
        
        # Load files
        print(f"    Loading phishing data: {len(pd.read_parquet(phish_file))} rows")
        phish_df = pd.read_parquet(phish_file)
        print(f"    Loading legitimate data: {len(pd.read_parquet(legit_file))} rows")
        legit_df = pd.read_parquet(legit_file)
        
        # Add labels
        phish_df['label'] = 1
        legit_df['label'] = 0
        
        # Add sample_id from folder_name
        phish_df['sample_id'] = phish_df['folder_name']
        legit_df['sample_id'] = legit_df['folder_name']
        
        # Clean URLs
        phish_df['url'] = phish_df['URL'].str.strip()
        legit_df['url'] = legit_df['URL'].str.strip()
        
        # Rename full_html to html for consistency
        phish_df['html'] = phish_df['full_html']
        legit_df['html'] = legit_df['full_html']
        
        # Combine
        combined_df = pd.concat([phish_df, legit_df], ignore_index=True)
        
        print(f"[+] Combined {len(combined_df)} total samples")
        print(f"    Phishing: {len(phish_df)}, Legitimate: {len(legit_df)}")
        
        return combined_df
    
    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Clean and deduplicate data.
        
        Args:
            df: Input DataFrame
            
        Returns:
            Cleaned DataFrame
        """
        print("[*] Cleaning and deduplicating data...")
        
        # Remove exact duplicate URLs
        initial_count = len(df)
        df = df.drop_duplicates(subset=['url'], keep='first')
        duplicates_removed = initial_count - len(df)
        
        print(f"    Removed {duplicates_removed} duplicate URLs")
        print(f"    Remaining: {len(df)} samples")
        
        # Validate URLs
        invalid_urls = df['url'].isnull().sum()
        if invalid_urls > 0:
            print(f"    [WARNING] Found {invalid_urls} null URLs, removing...")
            df = df.dropna(subset=['url'])
        
        # Validate labels
        invalid_labels = df[~df['label'].isin([0, 1])]
        if len(invalid_labels) > 0:
            print(f"    [WARNING] Found {len(invalid_labels)} invalid labels, removing...")
            df = df[df['label'].isin([0, 1])]
        
        # Validate HTML
        html_null_rate = df['html'].isnull().sum() / len(df)
        print(f"    HTML null rate: {html_null_rate:.3%}")
        
        return df
    
    def extract_domain_info(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract domain information from URLs.
        
        Args:
            df: Input DataFrame
            
        Returns:
            DataFrame with domain columns added
        """
        print("[*] Extracting domain information...")
        
        def extract_registered_domain(url):
            try:
                extracted = tldextract.extract(url)
                if extracted.domain and extracted.suffix:
                    return f"{extracted.domain}.{extracted.suffix}".lower()
                return url.lower()
            except:
                return url.lower()
        
        def extract_root_domain(url):
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                if domain.startswith('www.'):
                    domain = domain[4:]
                return domain
            except:
                return url.lower()
        
        df['registered_domain'] = df['url'].apply(extract_registered_domain)
        df['root_domain'] = df['url'].apply(extract_root_domain)
        
        unique_registered = df['registered_domain'].nunique()
        unique_root = df['root_domain'].nunique()
        
        print(f"    Unique registered domains: {unique_registered}")
        print(f"    Unique root domains: {unique_root}")
        
        return df
    
    def create_splits(self, df: pd.DataFrame, random_state: int = 42) -> tuple:
        """
        Create leakage-free train/validation/test splits.
        
        Args:
            df: Input DataFrame
            random_state: Random seed
            
        Returns:
            Tuple of (train_df, val_df, test_df)
        """
        print("[*] Creating leakage-free splits...")
        
        # Since Parquet doesn't preserve original trainval/test structure,
        # create domain-aware splits
        train_df, test_df = create_leakage_free_split(
            df,
            train_ratio=0.85,
            val_ratio=0.15,
            random_state=random_state
        )
        
        # Split train into train/val
        train_df, val_df = create_leakage_free_split(
            train_df,
            train_ratio=0.85,
            val_ratio=0.15,
            random_state=random_state
        )
        
        print(f"[+] Train samples: {len(train_df)}")
        print(f"[+] Validation samples: {len(val_df)}")
        print(f"[+] Test samples: {len(test_df)}")
        
        return train_df, val_df, test_df
    
    def extract_structural_features(self, url: str) -> dict:
        """Extract 32 structural features from URL."""
        try:
            return extract_features(url)
        except Exception as e:
            return {key: 0 for key in self.structural_keys}
    
    def extract_semantic_features(self, html: str, url: str = "") -> dict:
        """Extract 12 semantic features from HTML."""
        try:
            features = extract_semantic_features_from_html(html, url)
            return {key: features.get(key, 0) for key in self.semantic_keys}
        except Exception as e:
            return {key: 0 for key in self.semantic_keys}
    
    def process_features_batch(self, df: pd.DataFrame, batch_size: int = 100) -> pd.DataFrame:
        """
        Process features for a DataFrame in batches.
        
        Args:
            df: Input DataFrame
            batch_size: Batch size for processing
            
        Returns:
            DataFrame with extracted features
        """
        print(f"[*] Processing features for {len(df)} samples...")
        
        all_features = []
        failed_samples = []
        
        for idx, row in df.iterrows():
            url = row['url']
            html = row['html'] if pd.notna(row.get('html', '')) else ""
            label = row['label']
            sample_id = row['sample_id']
            registered_domain = row.get('registered_domain', '')
            root_domain = row.get('root_domain', '')
            
            try:
                # Extract structural features
                structural = self.extract_structural_features(url)
                
                # Extract semantic features
                semantic = self.extract_semantic_features(html, url)
                
                # Combine
                features = {
                    'sample_id': sample_id,
                    'url': url,
                    'label': label,
                    'registered_domain': registered_domain,
                    'root_domain': root_domain,
                    'html_available': 1 if html else 0,
                    **structural,
                    **semantic
                }
                
                all_features.append(features)
                
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
    
    def validate_leakage(self, train_df: pd.DataFrame, val_df: pd.DataFrame, test_df: pd.DataFrame) -> dict:
        """
        Validate leakage-free splits.
        
        Args:
            train_df: Training DataFrame
            val_df: Validation DataFrame
            test_df: Test DataFrame
            
        Returns:
            Validation results
        """
        print("[*] Validating leakage-free splits...")
        
        validator = LeakageValidator()
        results = validator.validate_split(train_df, val_df, test_df)
        validator.print_report()
        
        return results
    
    def save_results(self, train_df: pd.DataFrame, val_df: pd.DataFrame, test_df: pd.DataFrame, 
                    leakage_results: dict) -> dict:
        """
        Save processed datasets and reports.
        
        Args:
            train_df: Training DataFrame
            val_df: Validation DataFrame
            test_df: Test DataFrame
            leakage_results: Leakage validation results
            
        Returns:
            Dictionary of saved file paths
        """
        print("[*] Saving processed data...")
        
        # Create directories
        processed_dir = self.output_dir / "processed"
        reports_dir = self.output_dir / "reports"
        processed_dir.mkdir(parents=True, exist_ok=True)
        reports_dir.mkdir(parents=True, exist_ok=True)
        
        # Save feature datasets
        train_path = processed_dir / "train_features.parquet"
        val_path = processed_dir / "validation_features.parquet"
        test_path = processed_dir / "test_features.parquet"
        
        train_df.to_parquet(train_path, index=False)
        val_df.to_parquet(val_path, index=False)
        test_df.to_parquet(test_path, index=False)
        
        print(f"[+] Saved train features: {train_path}")
        print(f"[+] Saved validation features: {val_path}")
        print(f"[+] Saved test features: {test_path}")
        
        # Save leakage report
        leakage_path = reports_dir / "leakage_report.json"
        with open(leakage_path, 'w') as f:
            json.dump(leakage_results, f, indent=2)
        print(f"[+] Saved leakage report: {leakage_path}")
        
        # Generate dataset report
        report_path = reports_dir / "dataset_report.md"
        self.generate_report(train_df, val_df, test_df, leakage_results, report_path)
        print(f"[+] Saved dataset report: {report_path}")
        
        return {
            'train_features': str(train_path),
            'validation_features': str(val_path),
            'test_features': str(test_path),
            'leakage_report': str(leakage_path),
            'dataset_report': str(report_path)
        }
    
    def generate_report(self, train_df: pd.DataFrame, val_df: pd.DataFrame, test_df: pd.DataFrame,
                       leakage_results: dict, report_path: Path):
        """Generate comprehensive dataset report."""
        
        total_samples = len(train_df) + len(val_df) + len(test_df)
        
        # Calculate class distributions
        train_phish = int(train_df['label'].sum())
        train_legit = len(train_df) - train_phish
        val_phish = int(val_df['label'].sum())
        val_legit = len(val_df) - val_phish
        test_phish = int(test_df['label'].sum())
        test_legit = len(test_df) - test_phish
        
        report = f"""# Phish360 Dataset Processing Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## Dataset Statistics

### Overall
- **Total Samples:** {total_samples}
- **Training Samples:** {len(train_df)} ({100*len(train_df)/total_samples:.1f}%)
- **Validation Samples:** {len(val_df)} ({100*len(val_df)/total_samples:.1f}%)
- **Test Samples:** {len(test_df)} ({100*len(test_df)/total_samples:.1f}%)

### Class Distribution

#### Training Set
- **Phishing:** {train_phish} ({100*train_phish/len(train_df):.1f}%)
- **Legitimate:** {train_legit} ({100*train_legit/len(train_df):.1f}%)

#### Validation Set
- **Phishing:** {val_phish} ({100*val_phish/len(val_df):.1f}%)
- **Legitimate:** {val_legit} ({100*val_legit/len(val_df):.1f}%)

#### Test Set
- **Phishing:** {test_phish} ({100*test_phish/len(test_df):.1f}%)
- **Legitimate:** {test_legit} ({100*test_legit/len(test_df):.1f}%)

---

## Feature Statistics

### Structural Features (32)
- **Source:** URL analysis using existing `ml_model.py`
- **Feature Count:** {len(self.structural_keys)}

### Semantic Features (12)
- **Source:** HTML content analysis using existing `webpage_analyzer.py`
- **Feature Count:** {len(self.semantic_keys)}

### HTML Availability
- **Training Set:** {int(train_df['html_available'].sum())}/{len(train_df)} samples ({100*train_df['html_available'].sum()/len(train_df):.1f}%)
- **Validation Set:** {int(val_df['html_available'].sum())}/{len(val_df)} samples ({100*val_df['html_available'].sum()/len(val_df):.1f}%)
- **Test Set:** {int(test_df['html_available'].sum())}/{len(test_df)} samples ({100*test_df['html_available'].sum()/len(test_df):.1f}%)

---

## Leakage Validation Results

### URL Overlap
- **Train-Val:** {leakage_results['url_overlap']['train_val']} URLs
- **Train-Test:** {leakage_results['url_overlap']['train_test']} URLs
- **Val-Test:** {leakage_results['url_overlap']['val_test']} URLs
- **Status:** {'PASS' if leakage_results['url_overlap']['total'] == 0 else 'FAIL'}

### Domain Overlap
- **Train-Val:** {leakage_results['registered_domain_overlap']['train_val']} domains
- **Train-Test:** {leakage_results['registered_domain_overlap']['train_test']} domains
- **Val-Test:** {leakage_results['registered_domain_overlap']['val_test']} domains
- **Status:** {'PASS' if leakage_results['registered_domain_overlap']['total'] == 0 else 'FAIL'}

### Test Contamination
- **Is Contaminated:** {'YES' if leakage_results['test_contamination']['is_contaminated'] else 'NO'}
- **URL Leakage:** {'YES' if leakage_results['test_contamination']['url_leakage'] else 'NO'}
- **Domain Leakage:** {'YES' if leakage_results['test_contamination']['domain_leakage'] else 'NO'}

### Overall Validation
- **Result:** {'PASS - Leakage-free splits' if leakage_results['overall_pass'] else 'FAIL - Leakage detected'}

---

## Processing Information

### Data Source
- **Format:** Parquet files
- **Source Directory:** {self.data_path}
- **Files:** Phish360_phish.parquet, Phish360_legit.parquet

### Feature Extraction
- **Structural Features:** 32 features from URLs using existing `ml_model.py`
- **Semantic Features:** 12 features from HTML using existing `webpage_analyzer.py`
- **Total Features:** {len(self.structural_keys) + len(self.semantic_keys)} (32 structural + 12 semantic)

### Splitting Methodology
- **Domain-Aware Splitting:** Used to prevent domain leakage
- **Random Seed:** 42 (for reproducibility)
- **Split Ratios:** ~70% train, ~15% validation, ~15% test

### Output Files
- **Train Features:** `processed/train_features.parquet`
- **Validation Features:** `processed/validation_features.parquet`
- **Test Features:** `processed/test_features.parquet`
- **Leakage Report:** `reports/leakage_report.json`

---

## Notes

- This dataset is ready for model training and evaluation
- All splits have been validated for leakage
- Feature extraction follows the PhishOut architecture (32 structural + 12 semantic)
- Full HTML content was used directly from the dataset (no network requests)
- Original Parquet files remain in source directory (not copied)

---

**END OF REPORT**
"""
        
        with open(report_path, 'w') as f:
            f.write(report)


def main():
    """Main processing function."""
    print("="*70)
    print("  PHISH360 PARQUET PROCESSING PIPELINE")
    print("="*70)
    
    # Configuration
    data_path = "D:/Downloads/phish360_parquet"
    output_dir = "backend/dataset/phish360"
    random_seed = 42
    
    try:
        # Initialize processor
        processor = Phish360ParquetProcessor(data_path, output_dir)
        
        # Load data
        df = processor.load_parquet_data()
        
        # Clean data
        df = processor.clean_data(df)
        
        # Extract domain info
        df = processor.extract_domain_info(df)
        
        # Create splits
        train_df, val_df, test_df = processor.create_splits(df, random_seed)
        
        # Process features
        print("[*] Extracting features...")
        train_features = processor.process_features_batch(train_df)
        val_features = processor.process_features_batch(val_df)
        test_features = processor.process_features_batch(test_df)
        
        # Validate leakage
        leakage_results = processor.validate_leakage(train_features, val_features, test_features)
        
        # Save results
        saved_files = processor.save_results(train_features, val_features, test_features, leakage_results)
        
        print("\n" + "="*70)
        print("  PROCESSING COMPLETE")
        print("="*70)
        for name, path in saved_files.items():
            print(f"  {name}: {path}")
        print("="*70 + "\n")
        
        # Final validation
        if not leakage_results['overall_pass']:
            print("LEAKAGE VALIDATION FAILED - Please review before proceeding")
            return False
        
        print("ALL VALIDATIONS PASSED - Dataset ready for model training")
        return True
        
    except Exception as e:
        print(f"\nPROCESSING FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)