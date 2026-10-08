"""
Regression Test for Script Extraction Fix
========================================
Ensures that script extraction works correctly after the fix.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from webpage_analyzer import extract_semantic_features

def test_script_extraction():
    """Test that script extraction works correctly."""
    print("=" * 80)
    print("Regression Test: Script Extraction")
    print("=" * 80)
    
    # Test 1: Synthetic HTML with 2 scripts
    html_2_scripts = """
    <html>
    <head>
        <script>console.log("test1")</script>
        <script src="test.js"></script>
    </head>
    <body>
        <p>Test content</p>
    </body>
    </html>
    """
    feats = extract_semantic_features(html_2_scripts, "http://test.com")
    assert feats['scripts'] == 2, f"Expected 2 scripts, got {feats['scripts']}"
    print("✓ Test 1 PASSED: 2 scripts detected correctly")
    
    # Test 2: HTML with 0 scripts
    html_0_scripts = """
    <html>
    <body>
        <p>No scripts here</p>
    </body>
    </html>
    """
    feats = extract_semantic_features(html_0_scripts, "http://test.com")
    assert feats['scripts'] == 0, f"Expected 0 scripts, got {feats['scripts']}"
    print("✓ Test 2 PASSED: 0 scripts detected correctly")
    
    # Test 3: HTML with 5 scripts
    html_5_scripts = """
    <html>
    <head>
        <script>var x = 1;</script>
        <script src="a.js"></script>
        <script src="b.js"></script>
    </head>
    <body>
        <script>var y = 2;</script>
        <script src="c.js"></script>
    </body>
    </html>
    """
    feats = extract_semantic_features(html_5_scripts, "http://test.com")
    assert feats['scripts'] == 5, f"Expected 5 scripts, got {feats['scripts']}"
    print("✓ Test 3 PASSED: 5 scripts detected correctly")
    
    # Test 4: text_to_script_ratio calculation
    html_with_text = """
    <html>
    <head>
        <script>var x = 1;</script>
    </head>
    <body>
        <p>This is some text content on the page</p>
    </body>
    </html>
    """
    feats = extract_semantic_features(html_with_text, "http://test.com")
    expected_ratio = len("This is some text content on the page") / (1 + 1)  # text_length / (scripts + 1)
    assert abs(feats['text_to_script_ratio'] - expected_ratio) < 1.0, f"text_to_script_ratio calculation incorrect"
    print("✓ Test 4 PASSED: text_to_script_ratio calculated correctly")
    
    print("\n" + "=" * 80)
    print("All regression tests PASSED")
    print("=" * 80)
    return True

if __name__ == "__main__":
    try:
        test_script_extraction()
        print("\nREGRESSION TEST SUCCESSFUL")
    except AssertionError as e:
        print(f"\nREGRESSION TEST FAILED: {e}")
        sys.exit(1)
