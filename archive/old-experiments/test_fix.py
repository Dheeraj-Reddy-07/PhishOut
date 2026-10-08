import sys
import os
sys.path.append(os.path.join(os.getcwd(), "backend"))
from phishout_predictor import predict

urls = [
    "https://github.com/login",
    "https://www.facebook.com/login",
    "https://www.stackoverflow.com/questions/tagged/python",
    "https://github.com/Dheeraj-Reddy-07/PhishOut",
    "https://www.youtube.com/results?search_query=machine+learning",
    "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference",
    "https://www.reddit.com/r/technology/",
    "https://www.python.org",
    "https://www.icicibank.com",
    "https://www.axisbank.com",
    "https://www.phonepe.com"
]

print("BEFORE SCORES (from prompt):")
print("- https://github.com/login -> 67% PHISHING")
print("- https://www.facebook.com/login -> 67% PHISHING")
print("- https://www.stackoverflow.com/questions/tagged/python -> 90% PHISHING")
print("- https://github.com/Dheeraj-Reddy-07/PhishOut -> 63% PHISHING")
print("- https://www.youtube.com/results?search_query=machine+learning -> 40% SUSPICIOUS")
print("- https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference -> 37% SUSPICIOUS")
print("- https://www.reddit.com/r/technology/ -> 21% SUSPICIOUS")
print("- https://www.python.org -> 15% SUSPICIOUS")
print("- https://www.icicibank.com -> 15% SUSPICIOUS")
print("- https://www.axisbank.com -> 15% SUSPICIOUS")
print("- https://www.phonepe.com -> 15% SUSPICIOUS")

print("\nAFTER SCORES (Testing now):")
for url in urls:
    res = predict(url)
    print(f"- {url} -> {res['risk_score']}% {res['verdict']} (Struct: {res['structural_score']}, Sem: {res['semantic_score']})")
    print(f"  Reasons: {res['reasons']}")
