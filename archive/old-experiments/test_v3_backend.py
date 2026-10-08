"""
Test V3 Backend End-to-End
===========================
Test the backend API with V3 models loaded.
"""
import requests
import json

API_URL = "http://localhost:8000"

# Test URLs
LEGITIMATE_URLS = [
    "https://www.google.com",
    "https://www.microsoft.com",
    "https://www.wikipedia.org",
    "https://www.paypal.com",
    "https://github.com",
]

SYNTHETIC_PHISHING_URLS = [
    "https://paypal-login-verify.example.com/account/login",
    "https://secure-bank-update.example.com/login",
    "https://example.com/account/verify",
]

def test_health():
    """Test health endpoint."""
    print("=" * 80)
    print("Testing /health endpoint")
    print("=" * 80)
    response = requests.get(f"{API_URL}/health")
    print(f"Status: {response.status_code}")
    print(json.dumps(response.json(), indent=2))
    print()

def test_scan(url):
    """Test /phishout/scan endpoint."""
    print(f"Testing: {url}")
    try:
        response = requests.post(
            f"{API_URL}/phishout/scan",
            json={"url": url},
            timeout=30
        )
        if response.status_code == 200:
            result = response.json()
            print(f"  Verdict: {result['verdict']}")
            print(f"  Risk Score: {result['risk_score']}")
            print(f"  Structural Score: {result['structural_score']}")
            print(f"  Semantic Score: {result['semantic_score']}")
            print(f"  Model Type: {result['model_type']}")
            print(f"  Webpage Available: {result['webpage_analysis_available']}")
            print(f"  Fusion Mode: {result['fusion_mode']}")
            print(f"  Scripts: {result['semantic_analysis'].get('scripts', 'N/A')}")
            print(f"  text_to_script_ratio: {result['semantic_analysis'].get('text_to_script_ratio', 'N/A')}")
            return result
        else:
            print(f"  ERROR: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"  ERROR: {e}")
        return None

def main():
    print("=" * 80)
    print("V3 Backend End-to-End Test")
    print("=" * 80)
    print()
    
    # Test health
    test_health()
    
    # Test legitimate URLs
    print("=" * 80)
    print("Testing Legitimate URLs")
    print("=" * 80)
    for url in LEGITIMATE_URLS:
        test_scan(url)
        print()
    
    # Test synthetic phishing URLs
    print("=" * 80)
    print("Testing Synthetic Phishing URLs")
    print("=" * 80)
    for url in SYNTHETIC_PHISHING_URLS:
        test_scan(url)
        print()
    
    print("=" * 80)
    print("Backend Test Complete")
    print("=" * 80)

if __name__ == "__main__":
    main()
