"""
Debug is_shortening logic
"""
from ml_model import SHORTENING_SERVICES

print("SHORTENING_SERVICES:")
for s in SHORTENING_SERVICES:
    print(f"  '{s}'")

print()

test_hostnames = [
    "www.microsoft.com",
    "t.co",
    "bit.ly",
    "tinyurl.com",
]

for hostname in test_hostnames:
    is_shortening = 1 if any(hostname == s or hostname.endswith('.' + s) for s in SHORTENING_SERVICES) else 0
    print(f"Hostname: '{hostname}'")
    print(f"  is_shortening: {is_shortening}")
    print(f"  Exact matches: {[s for s in SHORTENING_SERVICES if hostname == s]}")
    print(f"  Ends with matches: {[s for s in SHORTENING_SERVICES if hostname.endswith('.' + s)]}")
    print()
