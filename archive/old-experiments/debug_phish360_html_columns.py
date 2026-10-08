"""
Debug Phish360 HTML Columns
===========================
Check what HTML columns are available in Phish360 parquet files
and determine which one contains raw HTML vs processed text.
"""
import pandas as pd

PHISH360_LEGIT_PATH = r"D:\Downloads\phish360_parquet\Phish360_legit.parquet"
PHISH360_PHISH_PATH = r"D:\Downloads\phish360_parquet\Phish360_phish.parquet"

def main():
    print("=" * 80)
    print("Debug Phish360 HTML Columns")
    print("=" * 80)
    
    # Load legit parquet
    print("\nLoading Phish360_legit.parquet...")
    legit_df = pd.read_parquet(PHISH360_LEGIT_PATH)
    print(f"Columns: {list(legit_df.columns)}")
    print(f"Shape: {legit_df.shape}")
    
    # Check for HTML-related columns
    html_columns = [col for col in legit_df.columns if 'html' in col.lower() or 'text' in col.lower()]
    print(f"\nHTML/Text columns: {html_columns}")
    
    # Sample data from each HTML column
    for col in html_columns:
        print(f"\n{'=' * 80}")
        print(f"Column: {col}")
        print('=' * 80)
        
        # Get first non-null sample
        sample = legit_df[col].dropna().iloc[0]
        print(f"Type: {type(sample)}")
        print(f"Length: {len(str(sample))}")
        print(f"First 500 chars:\n{str(sample)[:500]}")
        
        # Check if it contains HTML tags
        sample_str = str(sample)
        has_script = '<script' in sample_str.lower()
        has_form = '<form' in sample_str.lower()
        has_div = '<div' in sample_str.lower()
        
        print(f"\nContains <script>: {has_script}")
        print(f"Contains <form>: {has_form}")
        print(f"Contains <div>: {has_div}")
        
        if has_script:
            # Count script tags
            import re
            script_count = len(re.findall(r'<script', sample_str, re.IGNORECASE))
            print(f"Script tag count: {script_count}")
    
    # Check what column V3 is currently using
    print("\n" + "=" * 80)
    print("V3 Feature Extractor Configuration")
    print("=" * 80)
    print("Current html_column parameter: 'html2text_text'")
    print("\nThis is likely already-processed plain text, not raw HTML.")
    print("That's why script extraction fails - no <script> tags in plain text.")


if __name__ == "__main__":
    main()
