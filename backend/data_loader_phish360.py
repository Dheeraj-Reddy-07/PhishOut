"""
Phish360 Data Loader
Loads Phish360 dataset from either Parquet format or ZIP archive.
"""
import pandas as pd
import numpy as np
import zipfile
from pathlib import Path
from typing import Tuple, Dict, List, Optional
from urllib.parse import urlparse
import tldextract
import json
import os


class Phish360Loader:
    """
    Phish360 dataset loader supporting multiple formats.
    """
    
    def __init__(self, data_path: str):
        """
        Initialize Phish360 loader.
        
        Args:
            data_path: Path to Phish360 data (directory with Parquet files or ZIP archive)
        """
        self.data_path = Path(data_path)
        self.format = None
        self.train_data = None
        self.test_data = None
        self.metadata = {}
        
    def detect_format(self) -> str:
        """
        Detect the format of Phish360 data.
        
        Returns:
            'parquet', 'zip', or 'unknown'
        """
        if self.data_path.is_file() and self.data_path.suffix == '.zip':
            return 'zip'
        elif self.data_path.is_dir():
            # Check for Parquet files
            parquet_files = list(self.data_path.glob('*.parquet'))
            if parquet_files:
                return 'parquet'
            # Check for extracted directory structure
            if (self.data_path / 'trainval').exists() and (self.data_path / 'test').exists():
                return 'extracted'
        return 'unknown'
    
    def load_parquet_format(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Load Phish360 from Parquet format.
        
        Returns:
            Tuple of (trainval_data, test_data) DataFrames
        """
        print("[*] Loading Phish360 from Parquet format...")
        
        # Find Parquet files
        phish_file = self.data_path / 'Phish360_phish.parquet'
        legit_file = self.data_path / 'Phish360_legit.parquet'
        
        if not phish_file.exists() or not legit_file.exists():
            raise FileNotFoundError(
                f"Expected Phish360_phish.parquet and Phish360_legit.parquet in {self.data_path}"
            )
        
        # Load Parquet files
        print(f"    Loading phishing data from {phish_file}...")
        phish_df = pd.read_parquet(phish_file)
        print(f"    Loading legitimate data from {legit_file}...")
        legit_df = pd.read_parquet(legit_file)
        
        print(f"[+] Loaded {len(phish_df)} phishing samples")
        print(f"[+] Loaded {len(legit_df)} legitimate samples")
        
        # Standardize column names based on actual schema
        phish_df = self._standardize_columns(phish_df, label='phishing')
        legit_df = self._standardize_columns(legit_df, label='legitimate')
        
        # Add sample_id from folder_name
        phish_df['sample_id'] = phish_df['folder_name']
        legit_df['sample_id'] = legit_df['folder_name']
        
        # Clean URLs (remove newlines)
        phish_df['url'] = phish_df['url'].str.strip()
        legit_df['url'] = legit_df['url'].str.strip()
        
        # Combine
        combined_df = pd.concat([phish_df, legit_df], ignore_index=True)
        
        print(f"[+] Combined {len(combined_df)} total samples")
        
        # Store metadata
        self.metadata = {
            'format': 'parquet',
            'total_samples': len(combined_df),
            'phishing_samples': len(phish_df),
            'legitimate_samples': len(legit_df),
            'columns': list(combined_df.columns),
            'has_full_html': 'full_html' in combined_df.columns,
            'html_null_rate': combined_df['full_html'].isnull().sum() / len(combined_df) if 'full_html' in combined_df.columns else None
        }
        
        # For Parquet format, we need to create our own train/val/test split
        # since the data doesn't come pre-split
        return combined_df, None
    
    def load_zip_format(self, password: Optional[str] = None) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Load Phish360 from ZIP archive.
        
        Args:
            password: ZIP password if required
            
        Returns:
            Tuple of (trainval_data, test_data) DataFrames
        """
        print("[*] Loading Phish360 from ZIP archive...")
        
        if not self.data_path.exists():
            raise FileNotFoundError(f"ZIP file not found: {self.data_path}")
        
        try:
            with zipfile.ZipFile(self.data_path, 'r') as zip_ref:
                if password:
                    zip_ref.setpassword(password.encode('utf-8'))
                
                # List all files
                all_files = zip_ref.namelist()
                print(f"    Archive contains {len(all_files)} entries")
                
                # Parse structure
                trainval_samples = self._parse_zip_structure(zip_ref, all_files, 'trainval')
                test_samples = self._parse_zip_structure(zip_ref, all_files, 'test')
                
                print(f"    Found {len(trainval_samples)} trainval samples")
                print(f"    Found {len(test_samples)} test samples")
                
                # Extract sample data
                trainval_data = self._extract_samples_from_zip(zip_ref, trainval_samples, password)
                test_data = self._extract_samples_from_zip(zip_ref, test_samples, password)
                
                print(f"[+] Loaded {len(trainval_data)} trainval samples")
                print(f"[+] Loaded {len(test_data)} test samples")
                
                # Store metadata
                self.metadata = {
                    'format': 'zip',
                    'trainval_samples': len(trainval_data),
                    'test_samples': len(test_data),
                    'total_samples': len(trainval_data) + len(test_data)
                }
                
                return trainval_data, test_data
                
        except RuntimeError as e:
            if "password" in str(e).lower():
                raise ValueError("ZIP archive is password-protected. Please provide the correct password.")
            raise
    
    def load_extracted_format(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Load Phish360 from extracted directory structure.
        
        Returns:
            Tuple of (trainval_data, test_data) DataFrames
        """
        print("[*] Loading Phish360 from extracted directory...")
        
        trainval_path = self.data_path / 'trainval'
        test_path = self.data_path / 'test'
        
        if not trainval_path.exists() or not test_path.exists():
            raise FileNotFoundError(
                f"Expected trainval/ and test/ directories in {self.data_path}"
            )
        
        # Parse directory structure
        trainval_samples = self._parse_directory_structure(trainval_path)
        test_samples = self._parse_directory_structure(test_path)
        
        print(f"    Found {len(trainval_samples)} trainval samples")
        print(f"    Found {len(test_samples)} test samples")
        
        # Extract sample data
        trainval_data = self._extract_samples_from_directory(trainval_samples)
        test_data = self._extract_samples_from_directory(test_samples)
        
        print(f"[+] Loaded {len(trainval_data)} trainval samples")
        print(f"[+] Loaded {len(test_data)} test samples")
        
        # Store metadata
        self.metadata = {
            'format': 'extracted',
            'trainval_samples': len(trainval_data),
            'test_samples': len(test_data),
            'total_samples': len(trainval_data) + len(test_data)
        }
        
        return trainval_data, test_data
    
    def _standardize_columns(self, df: pd.DataFrame, label: str) -> pd.DataFrame:
        """Standardize column names across different Phish360 formats."""
        df = df.copy()
        
        # Map common column name variations based on actual schema
        column_mapping = {
            'URL': 'url',
            'url': 'url',
            'Class': 'original_label',
            'class': 'original_label',
            'full_html': 'html',
            'full_html': 'html',
            'image_path': 'screenshot_path',
            'Domain': 'domain',
            'domain': 'domain',
            'TLD': 'tld',
            'tld': 'tld',
            'Subdomain': 'subdomain',
            'subdomain': 'subdomain',
            'brand': 'brand',
            'brand': 'brand',
            'folder_name': 'folder_name',
            'folder_name': 'folder_name'
        }
        
        df.rename(columns={k: v for k, v in column_mapping.items() if k in df.columns}, inplace=True)
        
        # Convert label to numeric
        if label == 'phishing':
            df['label'] = 1
        elif label == 'legitimate':
            df['label'] = 0
        
        return df
    
    def _parse_zip_structure(self, zip_ref: zipfile.ZipFile, all_files: List[str], split: str) -> List[Dict]:
        """Parse ZIP structure to identify samples."""
        samples = {}
        split_prefix = f"Phish360/{split}/"
        
        for file_path in all_files:
            if not file_path.startswith(split_prefix):
                continue
            
            parts = file_path.split('/')
            if len(parts) < 4:
                continue
            
            sample_id = parts[2]
            component = parts[3]
            filename = parts[4] if len(parts) > 4 else None
            
            if sample_id not in samples:
                samples[sample_id] = {'sample_id': sample_id, 'split': split}
            
            if component == 'Label' and filename == 'label.txt':
                samples[sample_id]['label_path'] = file_path
            elif component == 'URL' and filename == 'url.txt':
                samples[sample_id]['url_path'] = file_path
            elif component == 'RAW-HTML' and filename == 'index.html':
                samples[sample_id]['html_path'] = file_path
            elif component == 'SCREEN-SHOT' and filename == 'screen_shoot.png':
                samples[sample_id]['screenshot_path'] = file_path
        
        return list(samples.values())
    
    def _parse_directory_structure(self, base_path: Path) -> List[Dict]:
        """Parse directory structure to identify samples."""
        samples = {}
        
        for sample_dir in base_path.iterdir():
            if not sample_dir.is_dir():
                continue
            
            sample_id = sample_dir.name
            samples[sample_id] = {'sample_id': sample_id, 'base_path': sample_dir}
            
            # Check for components
            label_file = sample_dir / 'Label' / 'label.txt'
            url_file = sample_dir / 'URL' / 'url.txt'
            html_file = sample_dir / 'RAW-HTML' / 'index.html'
            screenshot_file = sample_dir / 'SCREEN-SHOT' / 'screen_shoot.png'
            
            if label_file.exists():
                samples[sample_id]['label_path'] = label_file
            if url_file.exists():
                samples[sample_id]['url_path'] = url_file
            if html_file.exists():
                samples[sample_id]['html_path'] = html_file
            if screenshot_file.exists():
                samples[sample_id]['screenshot_path'] = screenshot_file
        
        return list(samples.values())
    
    def _extract_samples_from_zip(
        self,
        zip_ref: zipfile.ZipFile,
        samples: List[Dict],
        password: Optional[str]
    ) -> pd.DataFrame:
        """Extract sample data from ZIP archive."""
        data = []
        
        for sample in samples:
            try:
                # Extract label
                label = None
                if 'label_path' in sample:
                    label_content = zip_ref.read(sample['label_path']).decode('utf-8')
                    label = self._parse_label(label_content)
                
                # Extract URL
                url = None
                if 'url_path' in sample:
                    url = zip_ref.read(sample['url_path']).decode('utf-8').strip()
                
                # Extract HTML
                html = None
                if 'html_path' in sample:
                    html = zip_ref.read(sample['html_path']).decode('utf-8')
                
                # Create record
                record = {
                    'sample_id': sample['sample_id'],
                    'url': url,
                    'label': label,
                    'html': html,
                    'screenshot_available': 'screenshot_path' in sample
                }
                
                data.append(record)
                
            except Exception as e:
                print(f"    [WARNING] Failed to extract sample {sample['sample_id']}: {e}")
                continue
        
        return pd.DataFrame(data)
    
    def _extract_samples_from_directory(self, samples: List[Dict]) -> pd.DataFrame:
        """Extract sample data from directory structure."""
        data = []
        
        for sample in samples:
            try:
                # Extract label
                label = None
                if 'label_path' in sample:
                    with open(sample['label_path'], 'r', encoding='utf-8') as f:
                        label_content = f.read()
                    label = self._parse_label(label_content)
                
                # Extract URL
                url = None
                if 'url_path' in sample:
                    with open(sample['url_path'], 'r', encoding='utf-8') as f:
                        url = f.read().strip()
                
                # Extract HTML
                html = None
                if 'html_path' in sample:
                    with open(sample['html_path'], 'r', encoding='utf-8') as f:
                        html = f.read()
                
                # Create record
                record = {
                    'sample_id': sample['sample_id'],
                    'url': url,
                    'label': label,
                    'html': html,
                    'screenshot_available': 'screenshot_path' in sample
                }
                
                data.append(record)
                
            except Exception as e:
                print(f"    [WARNING] Failed to extract sample {sample['sample_id']}: {e}")
                continue
        
        return pd.DataFrame(data)
    
    def _parse_label(self, label_content: str) -> int:
        """Parse label from various formats."""
        label_content = label_content.strip().lower()
        
        # Numeric labels
        if label_content in ['0', '1']:
            return int(label_content)
        
        # Text labels
        if label_content in ['legitimate', 'legit', 'benign', 'safe']:
            return 0
        if label_content in ['phishing', 'phish', 'malicious']:
            return 1
        
        # Try to convert to int
        try:
            return int(label_content)
        except ValueError:
            raise ValueError(f"Unknown label format: {label_content}")
    
    def load(self, password: Optional[str] = None) -> Tuple[pd.DataFrame, Optional[pd.DataFrame]]:
        """
        Load Phish360 dataset (auto-detect format).
        
        Args:
            password: ZIP password if required
            
        Returns:
            Tuple of (trainval_data, test_data) DataFrames
            test_data is None for Parquet format (needs splitting)
        """
        self.format = self.detect_format()
        print(f"[*] Detected format: {self.format}")
        
        if self.format == 'parquet':
            return self.load_parquet_format()
        elif self.format == 'zip':
            return self.load_zip_format(password)
        elif self.format == 'extracted':
            return self.load_extracted_format()
        else:
            raise ValueError(f"Unknown Phish360 format at {self.data_path}")
    
    def get_metadata(self) -> Dict:
        """Get dataset metadata."""
        return self.metadata


def load_phish360(
    data_path: str,
    password: Optional[str] = None
) -> Tuple[pd.DataFrame, Optional[pd.DataFrame]]:
    """
    Convenience function to load Phish360 dataset.
    
    Args:
        data_path: Path to Phish360 data
        password: ZIP password if required
        
    Returns:
        Tuple of (trainval_data, test_data) DataFrames
    """
    loader = Phish360Loader(data_path)
    return loader.load(password)


if __name__ == "__main__":
    # Example usage
    print("Phish360 Data Loader Module")
    print("Import this module to use Phish360 loading functions.")