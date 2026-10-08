import requests
import json

# Test /phishout/scan endpoint
url = "http://localhost:8000/phishout/scan"
test_url = "https://www.google.com"

payload = {"url": test_url}

try:
    response = requests.post(url, json=payload)
    print(f"Status: {response.status_code}")
    result = response.json()
    print(json.dumps(result, indent=2))
except Exception as e:
    print(f"Error: {e}")
