"""
Data Loader for PhishGuard Baseline V2
Loads clean dataset from CSV, validates, and returns structured data.
"""
import pandas as pd
import numpy as np
from urllib.parse import urlparse
from typing import Tuple, List


def load_clean_dataset(csv_path: str = "dataset/clean_urls.csv") -> Tuple[List[str], np.ndarray]:
    """
    Load and validate the clean dataset from CSV.
    
    Args:
        csv_path: Path to the clean_urls.csv file
        
    Returns:
        Tuple of (urls, labels) where:
        - urls: List of URL strings
        - labels: numpy array of 0/1 labels (0=legitimate, 1=phishing)
    """
    # Load CSV
    print(f"[*] Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path)
    
    # Validate columns
    required_columns = ['url', 'label', 'source']
    for col in required_columns:
        if col not in df.columns:
            raise ValueError(f"Missing required column: {col}")
    
    print(f"[+] Loaded {len(df)} rows from CSV")
    
    # Validate URLs
    print("[*] Validating URLs...")
    valid_urls = []
    valid_labels = []
    invalid_count = 0
    
    for idx, row in df.iterrows():
        url = row['url'].strip()
        label = row['label']
        
        # Check URL format
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                print(f"    [SKIP] Invalid URL format: {url[:60]}")
                invalid_count += 1
                continue
        except Exception as e:
            print(f"    [SKIP] Parse error: {url[:60]}: {e}")
            invalid_count += 1
            continue
        
        # Validate label
        if label not in [0, 1]:
            print(f"    [SKIP] Invalid label {label} for: {url[:60]}")
            invalid_count += 1
            continue
        
        valid_urls.append(url)
        valid_labels.append(int(label))
    
    print(f"[+] Valid URLs: {len(valid_urls)}")
    print(f"[-] Invalid URLs: {invalid_count}")
    
    # Remove exact duplicate URLs
    print("[*] Removing exact duplicate URLs...")
    url_set = set()
    dedup_urls = []
    dedup_labels = []
    duplicate_count = 0
    
    for url, label in zip(valid_urls, valid_labels):
        if url in url_set:
            duplicate_count += 1
            continue
        url_set.add(url)
        dedup_urls.append(url)
        dedup_labels.append(label)
    
    print(f"[+] After deduplication: {len(dedup_urls)} URLs")
    print(f"[-] Duplicates removed: {duplicate_count}")
    
    # Report class counts
    labels_array = np.array(dedup_labels)
    phishing_count = int(np.sum(labels_array))
    legit_count = len(labels_array) - phishing_count
    
    print("\n" + "="*50)
    print("  Dataset Statistics")
    print("="*50)
    print(f"  Total samples:      {len(dedup_urls)}")
    print(f"  Phishing samples:   {phishing_count} ({100*phishing_count/len(dedup_urls):.1f}%)")
    print(f"  Legitimate samples: {legit_count} ({100*legit_count/len(dedup_urls):.1f}%)")
    print("="*50 + "\n")
    
    return dedup_urls, labels_array


def extract_domain(url: str) -> str:
    """
    Extract the base domain from a URL for domain-level splitting.
    
    Args:
        url: URL string
        
    Returns:
        Base domain (e.g., "google.com" from "https://mail.google.com/mail")
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        # Remove www. prefix if present
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain
    except:
        return url


def get_domain_split(urls: List[str], labels: np.ndarray, test_size: float = 0.15, random_state: int = 42) -> Tuple[List[str], np.ndarray, List[str], np.ndarray]:
    """
    Perform domain-level split to ensure no domain appears in both train and test.
    
    Args:
        urls: List of URL strings
        labels: numpy array of labels
        test_size: Fraction of domains to reserve for test set
        random_state: Random seed for reproducibility
        
    Returns:
        Tuple of (train_urls, train_labels, test_urls, test_labels)
    """
    print("[*] Performing domain-level split...")
    
    # Extract domains
    domains = [extract_domain(url) for url in urls]
    
    # Get unique domains with their labels
    domain_data = {}
    for url, label, domain in zip(urls, labels, domains):
        if domain not in domain_data:
            domain_data[domain] = {'urls': [], 'labels': []}
        domain_data[domain]['urls'].append(url)
        domain_data[domain]['labels'].append(label)
    
    unique_domains = list(domain_data.keys())
    print(f"[+] Unique domains: {len(unique_domains)}")
    
    # Split domains (stratified by majority label in domain)
    np.random.seed(random_state)
    
    # Determine majority label for each domain
    domain_labels = []
    for domain in unique_domains:
        labels_in_domain = domain_data[domain]['labels']
        majority_label = 1 if sum(labels_in_domain) > len(labels_in_domain)/2 else 0
        domain_labels.append(majority_label)
    
    # Stratified split on domains
    from sklearn.model_selection import train_test_split
    train_domains, test_domains = train_test_split(
        unique_domains, 
        test_size=test_size, 
        stratify=domain_labels,
        random_state=random_state
    )
    
    print(f"[+] Train domains: {len(train_domains)}")
    print(f"[+] Test domains: {len(test_domains)}")
    
    # Assign URLs based on domain split
    train_urls = []
    train_labels = []
    test_urls = []
    test_labels = []
    
    for domain in train_domains:
        train_urls.extend(domain_data[domain]['urls'])
        train_labels.extend(domain_data[domain]['labels'])
    
    for domain in test_domains:
        test_urls.extend(domain_data[domain]['urls'])
        test_labels.extend(domain_data[domain]['labels'])
    
    print(f"[+] Train samples: {len(train_urls)}")
    print(f"[+] Test samples: {len(test_urls)}")
    
    return train_urls, np.array(train_labels), test_urls, np.array(test_labels)


if __name__ == "__main__":
    # Test the data loader
    urls, labels = load_clean_dataset()
    print("\n[*] Testing domain-level split...")
    train_urls, train_labels, test_urls, test_labels = get_domain_split(urls, labels)
