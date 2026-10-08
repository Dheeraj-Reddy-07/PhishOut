import json
import sys
import os
import time

sys.path.append(os.path.join(os.getcwd(), "backend"))
from phishout_predictor import predict

urls = [
    # root domains
    "https://www.google.com", "https://www.microsoft.com", "https://www.apple.com", 
    "https://www.amazon.com", "https://www.wikipedia.org", "https://www.netflix.com", 
    "https://www.adobe.com", "https://www.ibm.com", "https://www.oracle.com", "https://www.intel.com",
    # login/authentication URLs
    "https://accounts.google.com", "https://account.microsoft.com", "https://github.com/login", 
    "https://www.reddit.com/login", "https://www.linkedin.com/login", "https://www.facebook.com/login", 
    "https://www.amazon.com/ap/signin", "https://login.live.com", "https://login.yahoo.com",
    # developer/documentation URLs
    "https://stackoverflow.com", "https://www.npmjs.com", "https://www.python.org", 
    "https://developer.mozilla.org", "https://pypi.org", "https://gitlab.com", "https://www.docker.com", 
    "https://kubernetes.io", "https://nodejs.org",
    # social media
    "https://www.instagram.com", "https://www.facebook.com", "https://www.linkedin.com", 
    "https://www.tiktok.com", "https://www.pinterest.com", "https://medium.com", "https://www.quora.com",
    # Indian financial/e-commerce sites
    "https://www.sbi.co.in", "https://www.hdfcbank.com", "https://www.icicibank.com", 
    "https://www.axisbank.com", "https://www.flipkart.com", "https://www.phonepe.com", 
    "https://paytm.com", "https://www.airtel.in", "https://www.jio.com",
    # query/search URLs
    "https://www.google.com/search?q=machine+learning+phishing+detection", 
    "https://www.youtube.com/results?search_query=machine+learning", 
    "https://github.com/search?q=phishing+detection&type=repositories", 
    "https://www.amazon.in/s?k=laptop", 
    "https://www.google.com/maps/search/restaurants+near+tirupati", 
    # long/deep URLs
    "https://github.com/Dheeraj-Reddy-07/PhishOut", 
    "https://stackoverflow.com/questions/tagged/python", 
    "https://www.reddit.com/r/technology/", 
    "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference", 
    "https://en.wikipedia.org/wiki/Machine_learning"
]

results = []
for i, url in enumerate(urls, 1):
    print(f"Testing {i}/{len(urls)}: {url}")
    try:
        res = predict(url)
        fetch_status = "Success" if res.get("webpage_analysis_available") else "Failed (Structure only)"
        results.append({
            "url": url,
            "risk_score": res.get("risk_score", -1),
            "structural_score": res.get("structural_score", -1),
            "semantic_score": res.get("semantic_score", -1),
            "verdict": res.get("verdict", "ERROR"),
            "reasons": res.get("reasons", []),
            "fetch_status": fetch_status
        })
    except Exception as e:
        results.append({
            "url": url, "risk_score": -1, "structural_score": -1, 
            "semantic_score": -1, "verdict": f"ERROR: {str(e)}", 
            "reasons": [], "fetch_status": "Failed"
        })

with open("final_validation_results.json", "w") as f:
    json.dump(results, f, indent=2)

print("Done writing final_validation_results.json")
