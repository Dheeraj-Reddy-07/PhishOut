"""
Leakage Validation Utility for Phish360 Dataset
Ensures train/validation/test splits are leakage-free according to research standards.
"""
import pandas as pd
import numpy as np
from urllib.parse import urlparse
from typing import List, Dict, Tuple, Set
import tldextract
from collections import defaultdict


def extract_registered_domain(url: str) -> str:
    """
    Extract the registered domain (e.g., "google.com") from a URL.
    
    Args:
        url: URL string
        
    Returns:
        Registered domain string
    """
    try:
        extracted = tldextract.extract(url)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}".lower()
        return url.lower()
    except:
        return url.lower()


def extract_root_domain(url: str) -> str:
    """
    Extract the root domain (including subdomains) from a URL.
    
    Args:
        url: URL string
        
    Returns:
        Root domain string
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain
    except:
        return url.lower()


class LeakageValidator:
    """
    Comprehensive leakage validation for dataset splits.
    """
    
    def __init__(self):
        self.results = {}
        
    def validate_split(
        self,
        train_data: pd.DataFrame,
        val_data: pd.DataFrame,
        test_data: pd.DataFrame,
        url_col: str = 'url',
        label_col: str = 'label',
        sample_id_col: str = 'sample_id'
    ) -> Dict:
        """
        Validate that train/validation/test splits are leakage-free.
        
        Args:
            train_data: Training set DataFrame
            val_data: Validation set DataFrame  
            test_data: Test set DataFrame
            url_col: Name of URL column
            label_col: Name of label column
            sample_id_col: Name of sample ID column
            
        Returns:
            Dictionary of validation results
        """
        print("[*] Performing comprehensive leakage validation...")
        
        # Extract URLs from each split
        train_urls = set(train_data[url_col].tolist())
        val_urls = set(val_data[url_col].tolist())
        test_urls = set(test_data[url_col].tolist())
        
        # Extract domains
        train_registered = set(extract_registered_domain(url) for url in train_urls)
        val_registered = set(extract_registered_domain(url) for url in val_urls)
        test_registered = set(extract_registered_domain(url) for url in test_urls)
        
        train_root = set(extract_root_domain(url) for url in train_urls)
        val_root = set(extract_root_domain(url) for url in val_urls)
        test_root = set(extract_root_domain(url) for url in test_urls)
        
        # Check 1: Exact URL overlap
        url_train_val = train_urls & val_urls
        url_train_test = train_urls & test_urls
        url_val_test = val_urls & test_urls
        
        self.results['url_overlap'] = {
            'train_val': len(url_train_val),
            'train_test': len(url_train_test),
            'val_test': len(url_val_test),
            'total': len(url_train_val) + len(url_train_test) + len(url_val_test)
        }
        
        # Check 2: Registered domain overlap
        reg_train_val = train_registered & val_registered
        reg_train_test = train_registered & test_registered
        reg_val_test = val_registered & test_registered
        
        self.results['registered_domain_overlap'] = {
            'train_val': len(reg_train_val),
            'train_test': len(reg_train_test),
            'val_test': len(reg_val_test),
            'total': len(reg_train_val) + len(reg_train_test) + len(reg_val_test)
        }
        
        # Check 3: Root domain overlap
        root_train_val = train_root & val_root
        root_train_test = train_root & test_root
        root_val_test = val_root & test_root
        
        self.results['root_domain_overlap'] = {
            'train_val': len(root_train_val),
            'train_test': len(root_train_test),
            'val_test': len(root_val_test),
            'total': len(root_train_val) + len(root_train_test) + len(root_val_test)
        }
        
        # Check 4: Sample ID overlap (if available)
        if sample_id_col in train_data.columns:
            train_ids = set(train_data[sample_id_col].tolist())
            val_ids = set(val_data[sample_id_col].tolist())
            test_ids = set(test_data[sample_id_col].tolist())
            
            id_train_val = train_ids & val_ids
            id_train_test = train_ids & test_ids
            id_val_test = val_ids & test_ids
            
            self.results['sample_id_overlap'] = {
                'train_val': len(id_train_val),
                'train_test': len(id_train_test),
                'val_test': len(id_val_test),
                'total': len(id_train_val) + len(id_train_test) + len(id_val_test)
            }
        
        # Check 5: Label validation
        self.results['label_validation'] = self._validate_labels(
            train_data, val_data, test_data, label_col
        )
        
        # Check 6: Test contamination check
        self.results['test_contamination'] = {
            'url_leakage': len(url_train_test) + len(url_val_test) > 0,
            'domain_leakage': len(reg_train_test) + len(reg_val_test) > 0,
            'is_contaminated': (len(url_train_test) + len(url_val_test) + 
                               len(reg_train_test) + len(reg_val_test)) > 0
        }
        
        # Overall pass/fail
        self.results['overall_pass'] = self._determine_pass_fail()
        
        return self.results
    
    def _validate_labels(
        self,
        train_data: pd.DataFrame,
        val_data: pd.DataFrame,
        test_data: pd.DataFrame,
        label_col: str
    ) -> Dict:
        """Validate label integrity across splits."""
        results = {}
        
        for split_name, data in [('train', train_data), ('val', val_data), ('test', test_data)]:
            labels = data[label_col].tolist()
            unique_labels = set(labels)
            invalid_labels = [l for l in unique_labels if l not in [0, 1, 'legitimate', 'phishing', 'legit', 'phish']]
            
            results[split_name] = {
                'total_samples': len(data),
                'unique_labels': len(unique_labels),
                'label_values': list(unique_labels),
                'invalid_labels': invalid_labels,
                'has_invalid': len(invalid_labels) > 0
            }
        
        return results
    
    def _determine_pass_fail(self) -> bool:
        """Determine overall validation pass/fail status."""
        # Critical failures that must be zero
        critical_failures = [
            self.results['url_overlap']['total'] > 0,
            self.results['registered_domain_overlap']['total'] > 0,
            self.results['test_contamination']['is_contaminated']
        ]
        
        # Label validation
        label_failures = []
        if 'label_validation' in self.results:
            for split in ['train', 'val', 'test']:
                if self.results['label_validation'][split]['has_invalid']:
                    label_failures.append(True)
        
        return not any(critical_failures + label_failures)
    
    def print_report(self):
        """Print a comprehensive leakage validation report."""
        print("\n" + "="*60)
        print("  LEAKAGE VALIDATION REPORT")
        print("="*60)
        
        # URL Overlap
        print("\n[1] EXACT URL OVERLAP:")
        url_overlap = self.results['url_overlap']
        print(f"    Train-Val:   {url_overlap['train_val']} URLs")
        print(f"    Train-Test:  {url_overlap['train_test']} URLs")
        print(f"    Val-Test:    {url_overlap['val_test']} URLs")
        print(f"    Total:       {url_overlap['total']} URLs")
        print(f"    Status:      {'FAIL' if url_overlap['total'] > 0 else 'PASS'}")
        
        # Registered Domain Overlap
        print("\n[2] REGISTERED DOMAIN OVERLAP:")
        reg_overlap = self.results['registered_domain_overlap']
        print(f"    Train-Val:   {reg_overlap['train_val']} domains")
        print(f"    Train-Test:  {reg_overlap['train_test']} domains")
        print(f"    Val-Test:    {reg_overlap['val_test']} domains")
        print(f"    Total:       {reg_overlap['total']} domains")
        print(f"    Status:      {'FAIL' if reg_overlap['total'] > 0 else 'PASS'}")
        
        # Root Domain Overlap
        print("\n[3] ROOT DOMAIN OVERLAP:")
        root_overlap = self.results['root_domain_overlap']
        print(f"    Train-Val:   {root_overlap['train_val']} domains")
        print(f"    Train-Test:  {root_overlap['train_test']} domains")
        print(f"    Val-Test:    {root_overlap['val_test']} domains")
        print(f"    Total:       {root_overlap['total']} domains")
        print(f"    Status:      {'FAIL' if root_overlap['total'] > 0 else 'PASS'}")
        
        # Sample ID Overlap (if available)
        if 'sample_id_overlap' in self.results:
            print("\n[4] SAMPLE ID OVERLAP:")
            id_overlap = self.results['sample_id_overlap']
            print(f"    Train-Val:   {id_overlap['train_val']} IDs")
            print(f"    Train-Test:  {id_overlap['train_test']} IDs")
            print(f"    Val-Test:    {id_overlap['val_test']} IDs")
            print(f"    Total:       {id_overlap['total']} IDs")
            print(f"    Status:      {'FAIL' if id_overlap['total'] > 0 else 'PASS'}")
        
        # Label Validation
        print("\n[5] LABEL VALIDATION:")
        for split in ['train', 'val', 'test']:
            label_info = self.results['label_validation'][split]
            print(f"    {split.upper()}:")
            print(f"      Samples:      {label_info['total_samples']}")
            print(f"      Unique labels: {label_info['unique_labels']}")
            print(f"      Label values:  {label_info['label_values']}")
            print(f"      Status:        {'FAIL' if label_info['has_invalid'] else 'PASS'}")
        
        # Test Contamination
        print("\n[6] TEST CONTAMINATION CHECK:")
        test_contam = self.results['test_contamination']
        print(f"    URL leakage:     {'YES' if test_contam['url_leakage'] else 'NO'}")
        print(f"    Domain leakage:  {'YES' if test_contam['domain_leakage'] else 'NO'}")
        print(f"    Is contaminated: {'YES' if test_contam['is_contaminated'] else 'NO'}")
        
        # Overall Result
        print("\n" + "="*60)
        overall = self.results['overall_pass']
        print(f"  OVERALL RESULT: {'PASS - Leakage-free splits' if overall else 'FAIL - Leakage detected'}")
        print("="*60 + "\n")
        
        return overall


def create_leakage_free_split(
    data: pd.DataFrame,
    train_ratio: float = 0.85,
    val_ratio: float = 0.15,
    random_state: int = 42,
    url_col: str = 'url',
    label_col: str = 'label'
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Create a leakage-free train/validation split from a dataset.
    
    Args:
        data: Input DataFrame with URLs and labels
        train_ratio: Ratio for training set (rest goes to validation)
        val_ratio: Ratio for validation set
        random_state: Random seed for reproducibility
        url_col: Name of URL column
        label_col: Name of label column
        
    Returns:
        Tuple of (train_data, val_data) DataFrames
    """
    from sklearn.model_selection import train_test_split
    
    print("[*] Creating leakage-free train/validation split...")
    
    # Extract registered domains if not already present
    data = data.copy()
    if 'registered_domain' not in data.columns:
        data['registered_domain'] = data[url_col].apply(extract_registered_domain)
    
    # Group by domain
    domain_groups = data.groupby('registered_domain')
    
    # Get unique domains with their majority label
    domain_info = []
    for domain, group in domain_groups:
        labels = group[label_col].tolist()
        majority_label = 1 if sum(labels) > len(labels)/2 else 0
        domain_info.append({
            'domain': domain,
            'majority_label': majority_label,
            'sample_count': len(group)
        })
    
    domain_df = pd.DataFrame(domain_info)
    
    # Stratified split on domains
    np.random.seed(random_state)
    train_domains, val_domains = train_test_split(
        domain_df['domain'].tolist(),
        test_size=val_ratio,
        stratify=domain_df['majority_label'].tolist(),
        random_state=random_state
    )
    
    # Assign samples based on domain split
    train_mask = data['registered_domain'].isin(train_domains)
    val_mask = data['registered_domain'].isin(val_domains)
    
    train_data = data[train_mask].copy()
    val_data = data[val_mask].copy()
    
    print(f"[+] Train samples: {len(train_data)} ({len(train_domains)} domains)")
    print(f"[+] Val samples: {len(val_data)} ({len(val_domains)} domains)")
    
    return train_data, val_data


if __name__ == "__main__":
    # Example usage
    print("Leakage Validator Module")
    print("Import this module to use leakage validation functions.")