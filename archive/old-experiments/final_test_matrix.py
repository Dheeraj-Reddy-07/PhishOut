"""
Final Test Matrix - End-to-End Validation
==========================================
Comprehensive test of legitimate and synthetic phishing URLs.
"""
import requests
import json
from datetime import datetime

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
    "https://apple-id-confirm.example.com/signin",
    "https://netflix-account-update.example.com/login",
]

def test_url(url, category):
    """Test a single URL and return results."""
    try:
        response = requests.post(
            f"{API_URL}/phishout/scan",
            json={"url": url},
            timeout=30
        )
        if response.status_code == 200:
            result = response.json()
            return {
                "url": url,
                "category": category,
                "expected": "SAFE" if category == "legitimate" else "PHISHING",
                "actual_verdict": result['verdict'],
                "risk_score": result['risk_score'],
                "structural_score": result['structural_score'],
                "semantic_score": result['semantic_score'],
                "model_type": result['model_type'],
                "webpage_available": result['webpage_analysis_available'],
                "fusion_mode": result['fusion_mode'],
                "scripts": result['semantic_analysis'].get('scripts', 'N/A'),
                "text_to_script_ratio": result['semantic_analysis'].get('text_to_script_ratio', 'N/A'),
                "match": result['verdict'] == ("SAFE" if category == "legitimate" else "PHISHING"),
                "status": "success"
            }
        else:
            return {
                "url": url,
                "category": category,
                "expected": "SAFE" if category == "legitimate" else "PHISHING",
                "actual_verdict": "ERROR",
                "error": f"HTTP {response.status_code}",
                "match": False,
                "status": "error"
            }
    except Exception as e:
        return {
            "url": url,
            "category": category,
            "expected": "SAFE" if category == "legitimate" else "PHISHING",
            "actual_verdict": "ERROR",
            "error": str(e),
            "match": False,
            "status": "error"
        }

def main():
    print("=" * 80)
    print("FINAL TEST MATRIX - End-to-End Validation")
    print("=" * 80)
    print(f"Timestamp: {datetime.now().isoformat()}")
    print()
    
    results = []
    
    # Test legitimate URLs
    print("Testing Legitimate URLs...")
    for url in LEGITIMATE_URLS:
        result = test_url(url, "legitimate")
        results.append(result)
        status = "✓" if result['match'] else "✗"
        print(f"  {status} {url}: {result['actual_verdict']} (expected {result['expected']})")
    
    print()
    print("Testing Synthetic Phishing URLs...")
    for url in SYNTHETIC_PHISHING_URLS:
        result = test_url(url, "phishing")
        results.append(result)
        status = "✓" if result['match'] else "✗"
        print(f"  {status} {url}: {result['actual_verdict']} (expected {result['expected']})")
    
    print()
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    total = len(results)
    matches = sum(1 for r in results if r['match'])
    legitimate_correct = sum(1 for r in results if r['category'] == 'legitimate' and r['match'])
    phishing_correct = sum(1 for r in results if r['category'] == 'phishing' and r['match'])
    
    print(f"Total Tests: {total}")
    print(f"Correct: {matches}/{total} ({matches/total*100:.1f}%)")
    print(f"Legitimate Correct: {legitimate_correct}/{len(LEGITIMATE_URLS)}")
    print(f"Phishing Correct: {phishing_correct}/{len(SYNTHETIC_PHISHING_URLS)}")
    
    # Detailed results
    print()
    print("=" * 80)
    print("DETAILED RESULTS")
    print("=" * 80)
    for result in results:
        print(f"\nURL: {result['url']}")
        print(f"  Category: {result['category']}")
        print(f"  Expected: {result['expected']}")
        print(f"  Actual: {result['actual_verdict']}")
        print(f"  Risk Score: {result.get('risk_score', 'N/A')}")
        print(f"  Structural: {result.get('structural_score', 'N/A')}")
        print(f"  Semantic: {result.get('semantic_score', 'N/A')}")
        print(f"  Model: {result.get('model_type', 'N/A')}")
        print(f"  Webpage: {result.get('webpage_available', 'N/A')}")
        print(f"  Scripts: {result.get('scripts', 'N/A')}")
        print(f"  text_to_script_ratio: {result.get('text_to_script_ratio', 'N/A')}")
        print(f"  Match: {result['match']}")
    
    # Save results
    output = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_tests": total,
            "correct": matches,
            "accuracy": matches/total,
            "legitimate_correct": legitimate_correct,
            "phishing_correct": phishing_correct
        },
        "results": results
    }
    
    with open("models/phish360_v3/final_test_matrix.json", "w") as f:
        json.dump(output, f, indent=2)
    
    print()
    print(f"[+] Results saved to models/phish360_v3/final_test_matrix.json")
    print()
    print("=" * 80)
    print("TEST MATRIX COMPLETE")
    print("=" * 80)

if __name__ == "__main__":
    main()
