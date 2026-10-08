"""
Test Script Extraction Fix
===========================
Test that using full_html instead of html2text_text fixes script extraction.
"""
import pandas as pd
from bs4 import BeautifulSoup
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from webpage_analyzer import extract_semantic_features

PHISH360_LEGIT_PATH = r"D:\Downloads\phish360_parquet\Phish360_legit.parquet"

def main():
    print("=" * 80)
    print("Test Script Extraction Fix")
    print("=" * 80)
    
    # Load legit parquet
    print("\nLoading Phish360_legit.parquet...")
    legit_df = pd.read_parquet(PHISH360_LEGIT_PATH)
    
    # Test on a sample with full_html
    sample = legit_df[legit_df['full_html'].notna()].iloc[0]
    
    print(f"\nSample URL: {sample['URL']}")
    
    # Test with html2text_text (current - broken)
    print("\n" + "=" * 80)
    print("Test 1: Using html2text_text (CURRENT - BROKEN)")
    print("=" * 80)
    html2text = sample['html2text_text']
    print(f"HTML length: {len(html2text)}")
    print(f"Contains <script>: {'<script' in html2text.lower()}")
    
    feats1 = extract_semantic_features(html2text, sample['URL'])
    print(f"Scripts count: {feats1['scripts']}")
    print(f"text_to_script_ratio: {feats1['text_to_script_ratio']:.2f}")
    
    # Test with full_html (fixed)
    print("\n" + "=" * 80)
    print("Test 2: Using full_html (FIXED)")
    print("=" * 80)
    full_html = sample['full_html']
    print(f"HTML length: {len(full_html)}")
    print(f"Contains <script>: {'<script' in full_html.lower()}")
    
    import re
    script_count = len(re.findall(r'<script', full_html, re.IGNORECASE))
    print(f"Manual script count: {script_count}")
    
    feats2 = extract_semantic_features(full_html, sample['URL'])
    print(f"Scripts count: {feats2['scripts']}")
    print(f"text_to_script_ratio: {feats2['text_to_script_ratio']:.2f}")
    
    # Test synthetic HTML
    print("\n" + "=" * 80)
    print("Test 3: Synthetic HTML with 2 scripts")
    print("=" * 80)
    synthetic_html = """
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
    feats3 = extract_semantic_features(synthetic_html, "http://test.com")
    print(f"Scripts count: {feats3['scripts']}")
    print(f"Expected: 2")
    print(f"PASS: {feats3['scripts'] == 2}")
    
    print("\n" + "=" * 80)
    print("Summary")
    print("=" * 80)
    print(f"html2text_text scripts: {feats1['scripts']} (broken)")
    print(f"full_html scripts: {feats2['scripts']} (fixed)")
    print(f"Synthetic HTML scripts: {feats3['scripts']} (expected 2)")
    print(f"\nFIX: Change html_column from 'html2text_text' to 'full_html'")


if __name__ == "__main__":
    main()
