import requests
import json
import time
import sys

first_10_urls = [
    "https://www.google.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://github.com",
    "https://github.com/login",
    "https://www.youtube.com",
    "https://www.reddit.com",
    "https://accounts.google.com",
    "https://www.amazon.com",
    "https://www.irctc.co.in"
]

all_other_urls = [
    # Simple legitimate sites
    "https://www.wikipedia.org", "https://www.netflix.com", 
    "https://www.adobe.com", "https://www.ibm.com", "https://www.oracle.com", "https://www.intel.com",
    # Login / authentication pages
    "https://account.microsoft.com", 
    "https://www.reddit.com/login", "https://www.linkedin.com/login", "https://www.facebook.com/login", 
    "https://www.amazon.com/ap/signin", "https://login.live.com", "https://login.yahoo.com",
    # Developer / technical
    "https://stackoverflow.com", "https://www.npmjs.com", "https://www.python.org", 
    "https://developer.mozilla.org", "https://pypi.org", "https://gitlab.com", "https://www.docker.com", 
    "https://kubernetes.io", "https://nodejs.org",
    # Social / content
    "https://www.instagram.com", "https://www.facebook.com", "https://www.linkedin.com", "https://www.tiktok.com", 
    "https://www.pinterest.com", "https://medium.com", "https://www.quora.com",
    # Indian websites
    "https://www.sbi.co.in", "https://www.hdfcbank.com", 
    "https://www.icicibank.com", "https://www.axisbank.com", "https://www.flipkart.com", 
    "https://www.phonepe.com", "https://paytm.com", "https://www.airtel.in", "https://www.jio.com",
    # Complex legitimate URLs
    "https://www.google.com/search?q=machine+learning+phishing+detection", 
    "https://www.youtube.com/results?search_query=machine+learning", 
    "https://github.com/Dheeraj-Reddy-07/PhishOut", 
    "https://github.com/search?q=phishing+detection&type=repositories", 
    "https://stackoverflow.com/questions/tagged/python", 
    "https://www.reddit.com/r/technology/", 
    "https://www.amazon.in/s?k=laptop", 
    "https://www.google.com/maps/search/restaurants+near+tirupati", 
    "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference", 
    "https://en.wikipedia.org/wiki/Machine_learning"
]

def scan_url(url):
    try:
        resp = requests.post("http://localhost:8000/phishout/scan", json={"url": url}, timeout=20)
        if resp.status_code == 200:
            return resp.json()
        return {"url": url, "verdict": f"HTTP {resp.status_code}", "risk_score": -1}
    except Exception as e:
        return {"url": url, "verdict": f"ERROR: {str(e)}", "risk_score": -1}

print("=== FIRST 10 URLS (DETAILED) ===")
with open("test_results.md", "w", encoding="utf-8") as f:
    f.write("# PhishOut Scan Results\n\n## First 10 URLs\n\n")
    
    for url in first_10_urls:
        print(f"Scanning {url}...")
        res = scan_url(url)
        
        # Write to file
        f.write(f"### `{url}`\n")
        f.write(f"**Verdict:** {res.get('verdict')}\n")
        f.write(f"**Risk Score:** {res.get('risk_score')}\n")
        f.write(f"**Structural Score:** {res.get('structural_score')}\n")
        f.write(f"**Semantic Score:** {res.get('semantic_score')}\n\n")
        f.write("**Reasons:**\n")
        for reason in res.get('reasons', []):
            f.write(f"- {reason}\n")
        f.write("\n---\n\n")

    print("\n=== SCANNING REMAINING 49 URLS (SUMMARY) ===")
    f.write("## Remaining URLs (Summary)\n\n")
    f.write("| URL | Verdict | Risk Score | Structural | Semantic |\n")
    f.write("|-----|---------|------------|------------|----------|\n")
    
    for i, url in enumerate(all_other_urls, 1):
        print(f"[{i}/{len(all_other_urls)}] Scanning {url}...")
        res = scan_url(url)
        verdict = res.get('verdict', 'N/A')
        score = res.get('risk_score', 'N/A')
        struct = res.get('structural_score', 'N/A')
        sem = res.get('semantic_score', 'N/A')
        
        # Color code verdict in markdown
        if verdict == "SAFE":
            verdict_md = "🟢 SAFE"
        elif verdict == "SUSPICIOUS":
            verdict_md = "🟠 SUSPICIOUS"
        elif verdict == "PHISHING":
            verdict_md = "🔴 PHISHING"
        else:
            verdict_md = verdict
            
        f.write(f"| {url} | {verdict_md} | {score} | {struct} | {sem} |\n")

print("Finished scanning all URLs. Results saved to test_results.md")
