"""
Bug Fix Validation
=================
Validate the 3 bug fixes implemented
"""
import importlib
import sys
# Force reload of ml_model to get latest changes
if 'ml_model' in sys.modules:
    del sys.modules['ml_model']
from ml_model import analyze_structural
from urllib.parse import urlparse

print("=" * 80)
print("BUG FIX VALIDATION")
print("=" * 80)
print()

# Test 1: microsoft.com should NOT be detected as URL shortener
print("TEST 1: microsoft.com should NOT be detected as URL shortener")
print("-" * 80)
url1 = "https://www.microsoft.com"
parsed1 = urlparse(url1)
hostname1 = parsed1.hostname
features1 = analyze_structural(url1)
is_shortening1 = features1.get('is_shortening', 0)
print(f"URL: {url1}")
print(f"Hostname: {hostname1}")
print(f"is_shortening: {is_shortening1}")
if is_shortening1 == 0:
    print("✓ PASS: microsoft.com is NOT detected as URL shortener")
else:
    print("✗ FAIL: microsoft.com is STILL detected as URL shortener")
print()

# Test 2: t.co should still be detected as URL shortener
print("TEST 2: t.co should still be detected as URL shortener")
print("-" * 80)
url2 = "https://t.co/abc123"
parsed2 = urlparse(url2)
hostname2 = parsed2.hostname
features2 = analyze_structural(url2)
is_shortening2 = features2.get('is_shortening', 0)
print(f"URL: {url2}")
print(f"Hostname: {hostname2}")
print(f"is_shortening: {is_shortening2}")
if is_shortening2 == 1:
    print("✓ PASS: t.co is STILL detected as URL shortener")
else:
    print("✗ FAIL: t.co is NOT detected as URL shortener")
print()

# Test 3: bit.ly should still be detected as URL shortener
print("TEST 3: bit.ly should still be detected as URL shortener")
print("-" * 80)
url3 = "https://bit.ly/xyz"
parsed3 = urlparse(url3)
hostname3 = parsed3.hostname
features3 = analyze_structural(url3)
is_shortening3 = features3.get('is_shortening', 0)
print(f"URL: {url3}")
print(f"Hostname: {hostname3}")
print(f"is_shortening: {is_shortening3}")
if is_shortening3 == 1:
    print("✓ PASS: bit.ly is STILL detected as URL shortener")
else:
    print("✗ FAIL: bit.ly is NOT detected as URL shortener")
print()

# Test 4: Unrelated domains should not match shortening services
print("TEST 4: Unrelated domains should NOT match shortening services")
print("-" * 80)
test_domains = [
    "example.com",
    "github.com",
    "paypal.com",
    "google.com",
]
all_pass = True
for domain in test_domains:
    url = f"https://{domain}"
    features = analyze_structural(url)
    is_shortening = features.get('is_shortening', 0)
    if is_shortening == 0:
        print(f"  ✓ {domain}: is_shortening=0")
    else:
        print(f"  ✗ {domain}: is_shortening=1 (FAIL)")
        all_pass = False

if all_pass:
    print("✓ PASS: All unrelated domains correctly not detected as shorteners")
else:
    print("✗ FAIL: Some unrelated domains incorrectly detected as shorteners")
print()

print("=" * 80)
print("STRUCTURAL FEATURE VALIDATION COMPLETE")
print("=" * 80)
print()

# Test 5: Wikipedia should receive trusted-domain and brand signals
print("TEST 5: Wikipedia should receive trusted-domain and brand signals")
print("-" * 80)
print("This requires a full scan via the API to test semantic features")
print("Will be tested in the full scan validation")
print()

print("=" * 80)
print("VALIDATION COMPLETE")
print("=" * 80)
