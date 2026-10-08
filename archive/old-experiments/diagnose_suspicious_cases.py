"""
Diagnostic Investigation: SUSPICIOUS Verdicts on Legitimate Sites
================================================================
READ-ONLY investigation - NO model changes, NO threshold tuning
"""
import requests
import json
from datetime import datetime

API_URL = "http://localhost:8000"

LEGITIMATE_SITES = [
    "https://www.google.com",
    "https://www.microsoft.com",
    "https://github.com",
    "https://www.paypal.com",
    "https://www.wikipedia.org",
    "https://gemini.google.com",
]

def diagnose_site(url):
    """Run detailed diagnostic scan on a single site."""
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
                "risk_score": result['risk_score'],
                "verdict": result['verdict'],
                "structural_score": result['structural_score'],
                "semantic_score": result['semantic_score'],
                "structural_analysis": result['structural_analysis'],
                "semantic_analysis": result['semantic_analysis'],
                "reasons": result.get('reasons', []),
                "webpage_available": result['webpage_analysis_available'],
                "model_type": result['model_type'],
                "fusion_mode": result.get('fusion_mode'),
                "status": "success"
            }
        else:
            return {
                "url": url,
                "error": f"HTTP {response.status_code}",
                "status": "error"
            }
    except Exception as e:
        return {
            "url": url,
            "error": str(e),
            "status": "error"
        }

def main():
    print("=" * 80)
    print("DIAGNOSTIC INVESTIGATION: SUSPICIOUS Verdicts on Legitimate Sites")
    print("=" * 80)
    print(f"Timestamp: {datetime.now().isoformat()}")
    print()
    
    results = []
    
    for url in LEGITIMATE_SITES:
        print(f"Scanning: {url}")
        result = diagnose_site(url)
        results.append(result)
        
        if result['status'] == 'success':
            print(f"  Verdict: {result['verdict']}")
            print(f"  Risk Score: {result['risk_score']}")
            print(f"  Structural: {result['structural_score']}")
            print(f"  Semantic: {result['semantic_score']}")
            print(f"  Webpage Available: {result['webpage_available']}")
            print(f"  Reasons: {result['reasons']}")
        else:
            print(f"  Error: {result.get('error', 'Unknown')}")
        print()
    
    # Detailed analysis
    print("=" * 80)
    print("DETAILED FEATURE ANALYSIS")
    print("=" * 80)
    print()
    
    for result in results:
        if result['status'] != 'success':
            continue
            
        print(f"URL: {result['url']}")
        print(f"Verdict: {result['verdict']}")
        print(f"Risk Score: {result['risk_score']}")
        print()
        
        # Structural features
        print("STRUCTURAL FEATURES (32):")
        struct = result['structural_analysis']
        for key, value in struct.items():
            print(f"  {key}: {value}")
        print()
        
        # Semantic features
        print("SEMANTIC FEATURES (19):")
        sem = result['semantic_analysis']
        for key, value in sem.items():
            print(f"  {key}: {value}")
        print()
        
        # Reasons
        print("DETECTED INDICATORS:")
        for reason in result['reasons']:
            print(f"  - {reason}")
        print()
        
        print("-" * 80)
        print()
    
    # Summary
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    total = len(results)
    safe = sum(1 for r in results if r['status'] == 'success' and r['verdict'] == 'SAFE')
    suspicious = sum(1 for r in results if r['status'] == 'success' and r['verdict'] == 'SUSPICIOUS')
    phishing = sum(1 for r in results if r['status'] == 'success' and r['verdict'] == 'PHISHING')
    errors = sum(1 for r in results if r['status'] == 'error')
    
    print(f"Total Sites: {total}")
    print(f"SAFE: {safe}")
    print(f"SUSPICIOUS: {suspicious}")
    print(f"PHISHING: {phishing}")
    print(f"ERRORS: {errors}")
    print()
    
    # Save results
    output = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total": total,
            "safe": safe,
            "suspicious": suspicious,
            "phishing": phishing,
            "errors": errors
        },
        "results": results
    }
    
    with open("suspicious_case_diagnosis.json", "w") as f:
        json.dump(output, f, indent=2)
    
    print(f"[+] Results saved to suspicious_case_diagnosis.json")
    print()
    print("=" * 80)
    print("DIAGNOSTIC COMPLETE")
    print("=" * 80)

if __name__ == "__main__":
    main()
