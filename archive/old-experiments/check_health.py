import requests
try:
    response = requests.get('http://localhost:8000/health')
    print(response.json())
except Exception as e:
    print(f"Error: {e}")
