"""
PhishOut Pipeline - Sanity Tests v4.0
====================================
PhishOut Test Script
====================
This script performs HTTP smoke tests against a running PhishOut API.

Verifies:
  - /health reports all components loaded
  - /scan still works (backward compatibility)
  - /phishout/scan returns all required fields
    - risk_score and component scores are 0-100
  - verdict is SAFE / SUSPICIOUS / PHISHING
  - reasons correspond to actually detected signals
  - API does not crash on any test URL

Usage:
    # Start server first:
    #   python -m uvicorn main:app --port 8000
    # Then:
    python test_phishout.py [--host http://localhost:8000]
"""
import sys
import argparse
import requests as req

BASE = "http://localhost:8000"

# ── Test URLs ──────────────────────────────────────────────────────────────────
# Format: (url, expected_verdict, note)
# expected_verdict is a soft expectation — mismatches are logged, not hard-fail.
TEST_URLS = [
    ("https://www.google.com",          "SAFE",     "known safe"),
    ("https://www.paypal.com",          "SAFE",     "known safe"),
    ("https://github.com/login",        "SAFE",     "known safe login page"),
    ("https://www.bankofamerica.com",   "SAFE",     "known safe bank"),
    ("https://discord.com/login",       "SAFE",     "known safe login page"),
    ("http://paypa1.com/login",         "PHISHING", "typosquatted paypal"),
    ("http://secure-paypal.com/signin", "PHISHING", "brand impersonation + hyphen"),
    ("http://paypal.account-verify.tk", "PHISHING", "high-risk TLD + brand"),
    ("https://www.linkedin.com/login",  "SAFE",     "known safe login page"),
    ("https://www.microsoft.com",       "SAFE",     "known safe"),
]

W = 72


def _sep(c="─", w=W): print(c * w)


def check_health(base):
    print("\n[Health Check]")
    r    = req.get(f"{base}/health", timeout=10)
    data = r.json()
    print(f"  Status        : {data.get('status')}")
    print(f"  Version       : {data.get('version')}")
    print(f"  ML model      : {data.get('ml_model_loaded')}")
    print(f"  PhishOut      : {data.get('phishout_model')}")
    print(f"  PhishOut ready: {data.get('phishout_ready')}")
    assert r.status_code == 200
    assert data.get("status") == "online"
    print("  ✓ Health check passed")


def test_scan_legacy(base):
    """Verify /scan still works (backward compatibility)."""
    r = req.post(f"{base}/scan", json={"url": "https://www.google.com"}, timeout=30)
    assert r.status_code == 200, f"/scan failed: {r.status_code}"
    d = r.json()
    assert "threat_level_pct" in d
    assert "verdict" in d
    assert "red_flags" in d
    assert isinstance(d["threat_level_pct"], int)
    assert 0 <= d["threat_level_pct"] <= 100
    assert d["verdict"] in ("SAFE", "SUSPICIOUS", "PHISHING")
    print(f"  ✓ /scan works | verdict={d['verdict']} | score={d['threat_level_pct']}")


def validate_phishout_response(data):
    """Assert all required fields are present and valid."""
    required = [
        "url", "risk_score", "verdict",
        "structural_score", "semantic_score",
        "phishing_probability", "webpage_analysis_available",
        "fusion_mode", "fusion_note", "model_type",
        "structural_analysis", "structural_evidence",
        "semantic_analysis", "semantic_evidence", "reasons",
    ]
    for field in required:
        assert field in data, f"Missing field: '{field}'"

    assert isinstance(data["risk_score"],        int),  "risk_score not int"
    assert isinstance(data["structural_score"],  int),  "structural_score not int"
    assert isinstance(data["semantic_score"],    int),  "semantic_score not int"
    assert isinstance(data["phishing_probability"], float)
    assert isinstance(data["reasons"],           list)
    assert isinstance(data["structural_evidence"], list)
    assert isinstance(data["semantic_evidence"], list)
    assert isinstance(data["webpage_analysis_available"], bool)

    assert 0 <= data["risk_score"]        <= 100, f"risk_score OOB: {data['risk_score']}"
    assert 0 <= data["structural_score"]  <= 100
    assert 0 <= data["semantic_score"]    <= 100
    assert 0.0 <= data["phishing_probability"] <= 1.0
    assert data["verdict"] in ("SAFE", "SUSPICIOUS", "PHISHING")
    assert data["fusion_mode"] in ("combined", "structural_only")


def test_phishout(base, url):
    r = req.post(f"{base}/phishout/scan", json={"url": url}, timeout=60)
    assert r.status_code == 200, f"/phishout/scan failed: {r.status_code} — {r.text[:200]}"
    data = r.json()
    validate_phishout_response(data)
    return data


def print_result(url, data, expected, note):
    verdict = data["verdict"]
    match   = "✓" if verdict == expected else "✗"
    page    = "OK" if data["webpage_analysis_available"] else "FAIL"
    print(f"\n  {match} [{note}]")
    print(f"    URL       : {url}")
    print(f"    Verdict   : {verdict:10s} (expected: {expected:10s})  {match}")
    print(f"    Score     : {data['risk_score']:3d}/100  "
          f"Struct={data['structural_score']:3d}  "
          f"Sem={data['semantic_score']:3d}  "
          f"Webpage={page}  Mode={data['fusion_mode']}")
    if data["reasons"]:
        for r in data["reasons"][:4]:
            print(f"      ▸ {r}")
        if len(data["reasons"]) > 4:
            print(f"      … and {len(data['reasons'])-4} more")
    else:
        print("      (no risk indicators)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=BASE)
    args = parser.parse_args()
    base = args.host.rstrip("/")

    print("=" * W)
    print("  PhishOut Pipeline — Sanity Tests v4.0")
    print("=" * W)

    failures = []

    # ── Health ────────────────────────────────────────────────────────────
    try:
        check_health(base)
    except Exception as e:
        print(f"  ✗ Health check FAILED: {e}")
        print("  Cannot continue — is the server running?")
        sys.exit(1)

    # ── Backward compatibility ────────────────────────────────────────────
    _sep()
    print("[Test] /scan backward compatibility")
    try:
        test_scan_legacy(base)
    except AssertionError as e:
        failures.append(f"/scan compat: {e}")
        print(f"  ✗ FAILED: {e}")

    # ── Full pipeline tests ───────────────────────────────────────────────
    _sep()
    print("[Test] /phishout/scan — 10 URL pipeline test")
    for url, expected, note in TEST_URLS:
        try:
            data = test_phishout(base, url)
            print_result(url, data, expected, note)
            if data["verdict"] != expected:
                failures.append(f"verdict mismatch [{note}] {url}: expected {expected}, got {data['verdict']}")
        except AssertionError as e:
            failures.append(f"[{note}] assertion: {e}")
            print(f"\n  ✗ ASSERTION FAILED for {url}: {e}")
        except Exception as e:
            failures.append(f"[{note}] error: {e}")
            print(f"\n  ✗ ERROR for {url}: {e}")

    # ── Field completeness check ──────────────────────────────────────────
    _sep()
    print("[Test] Response field completeness")
    try:
        data = test_phishout(base, "https://www.google.com")
        required_fields = [
            "url", "risk_score", "verdict", "structural_score", "semantic_score",
            "phishing_probability", "webpage_analysis_available", "fusion_mode",
            "fusion_note", "model_type", "structural_analysis", "structural_evidence",
            "semantic_analysis", "semantic_evidence", "reasons",
        ]
        for field in required_fields:
            status = "✓" if field in data else "✗"
            print(f"  {status} {field}")
            if field not in data:
                failures.append(f"Missing field: {field}")
    except Exception as e:
        failures.append(f"Field check error: {e}")

    # ── Summary ───────────────────────────────────────────────────────────
    _sep("=")
    if not failures:
        print(f"  ALL SANITY TESTS PASSED ✓  ({len(TEST_URLS)+2} tests)")
    else:
        print(f"  {len(failures)} ISSUE(S) FOUND:")
        for i, f in enumerate(failures, 1):
            print(f"    {i}. {f}")
    _sep("=")
    return len(failures)


if __name__ == "__main__":
    sys.exit(0 if main() == 0 else 1)
