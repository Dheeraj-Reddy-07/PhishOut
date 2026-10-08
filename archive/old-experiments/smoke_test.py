import requests
import json

API = "http://localhost:8000/phishout/scan"

# Test URLs
test_urls = [
    "https://www.google.com",
    "https://www.microsoft.com",
    "https://www.wikipedia.org",
    "https://www.github.com",
    "https://www.paypal.com",
    "http://paypal-login-verify.example.com/account/login",  # Synthetic phishing
]

print("=" * 80)
print("SMOKE TESTS")
print("=" * 80)
print()

for url in test_urls:
    print(f"Testing: {url}")
    try:
        response = requests.post(API, json={"url": url}, timeout=30)
        result = response.json()
        print(f"  Verdict: {result['verdict']}")
        print(f"  Risk Score: {result['risk_score']}")
        print(f"  Structural: {result['structural_score']}")
        print(f"  Semantic: {result['semantic_score']}")
        print(f"  Model: {result['model_type']}")
        print(f"  Status: OK")
    except Exception as e:
        print(f"  Status: ERROR - {e}")
    print()

print("=" * 80)
print("SMOKE TESTS COMPLETE")
print("=" * 80)
