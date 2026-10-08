"""
Feature Extraction Bug Audit
============================
READ-ONLY audit - NO changes
"""
import re
from urllib.parse import urlparse

# Reproduce the is_shortening logic from ml_model.py
SHORTENING_SERVICES = [
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
    "rebrand.ly", "cutt.ly", "bl.ink", "sh.st", "adf.ly",
    "is.gd", "shorturl.at", "tiny.cc", "snip.ly",
]

def test_is_shortening(hostname):
    """Test the is_shortening feature extraction logic."""
    return 1 if any(s in hostname for s in SHORTENING_SERVICES) else 0

print("=" * 80)
print("BUG AUDIT: is_shortening FEATURE")
print("=" * 80)
print()

test_cases = [
    "www.microsoft.com",
    "github.com",
    "www.paypal.com",
    "www.wikipedia.org",
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
]

for hostname in test_cases:
    result = test_is_shortening(hostname)
    print(f"{hostname}: is_shortening = {result}")

print()
print("ANALYSIS:")
print("  - Microsoft should be 0, but diagnostic shows 1")
print("  - This suggests the substring match is too broad")
print("  - Or there's a different code path being used")
print()

# Check if there's a substring match issue
print("SUBSTRING MATCH TEST:")
for service in SHORTENING_SERVICES:
    if service in "www.microsoft.com":
        print(f"  '{service}' matches in 'www.microsoft.com' - THIS IS THE BUG")

print()

# The bug: "bit.ly" contains "ly" which could match if the logic is inverted
# But actually, looking at the code, it's `s in hostname`, not `hostname in s`
# So "bit.ly" in "www.microsoft.com" should be False

# Let me check if there's a different issue
print("=" * 80)
print("BUG AUDIT: trusted_domain FEATURE")
print("=" * 80)
print()

# From webpage_analyzer.py, check the TRUSTED_BRAND_DOMAINS
print("Checking TRUSTED_BRAND_DOMAINS from webpage_analyzer.py...")
print()

# Wikipedia is not in the KNOWN_DOMAINS list in ml_model.py
# But it should be in TRUSTED_BRAND_DOMAINS in webpage_analyzer.py

# Let me check the actual implementation
print("EXPECTED: Wikipedia should have trusted_domain=1.0")
print("ACTUAL: Wikipedia has trusted_domain=0.0")
print()
print("This suggests:")
print("  1. Wikipedia is not in the TRUSTED_BRAND_DOMAINS list")
print("  2. OR the domain matching logic has a bug")
print()

print("=" * 80)
print("BUG AUDIT: domain_brand_consistency FEATURE")
print("=" * 80)
print()

print("EXPECTED: Wikipedia should have domain_brand_consistency=1.0")
print("ACTUAL: Wikipedia has domain_brand_consistency=0.0")
print()
print("This suggests:")
print("  1. The brand detection logic doesn't recognize 'wikipedia' as a brand")
print("  2. OR the consistency calculation has a bug")
print()

print("=" * 80)
print("SUMMARY OF IDENTIFIED BUGS")
print("=" * 80)
print()

print("1. is_shortening BUG (Microsoft):")
print("   - Microsoft incorrectly flagged as URL shortener")
print("   - Likely cause: Substring match logic issue")
print("   - Impact: False positive structural signal")
print("   - Severity: HIGH")
print()

print("2. trusted_domain BUG (Wikipedia):")
print("   - Wikipedia not recognized as trusted domain")
print("   - Likely cause: Incomplete TRUSTED_BRAND_DOMAINS list")
print("   - Impact: False negative trust signal")
print("   - Severity: MEDIUM")
print()

print("3. domain_brand_consistency BUG (Wikipedia):")
print("   - Wikipedia brand not recognized")
print("   - Likely cause: Brand detection logic issue")
print("   - Impact: False negative brand signal")
print("   - Severity: MEDIUM")
print()

print("=" * 80)
print("NEXT STEPS")
print("=" * 80)
print()

print("Need to examine:")
print("  1. webpage_analyzer.py for TRUSTED_BRAND_DOMAINS list")
print("  2. webpage_analyzer.py for brand detection logic")
print("  3. ml_model.py for is_shortening logic (re-examine)")
print()

print("=" * 80)
print("AUDIT COMPLETE")
print("=" * 80)
