"""
Phish360 Dataset Processing - Quick Start Script
Run this script to process the Phish360 dataset once the data access issue is resolved.
"""
import sys
import os

# Add backend directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from phish360_feature_extractor import process_phish360_dataset


def main():
    """
    Main processing function.
    """
    print("="*70)
    print("  PHISH360 DATASET PROCESSING - QUICK START")
    print("="*70)
    print()
    print("IMPORTANT: This script requires Phish360 data access.")
    print()
    print("OPTION 1: Parquet Format (Recommended)")
    print("  1. Download Parquet files from:")
    print("     https://drive.google.com/drive/u/1/folders/1ulQYtb63pZlhgcKMuTeiDze1onsY1yKT")
    print("  2. Extract to: D:/Downloads/phish360_parquet/")
    print("  3. Run: python run_phish360_processing.py parquet")
    print()
    print("OPTION 2: ZIP Format (Requires Password)")
    print("  1. Obtain ZIP password for: D:/Downloads/phish360.zip")
    print("  2. Run: python run_phish360_processing.py zip <password>")
    print()
    print("="*70)
    print()
    
    # Check command line arguments
    if len(sys.argv) < 2:
        print("ERROR: Please specify format")
        print("Usage: python run_phish360_processing.py <format> [password]")
        print("  format: 'parquet' or 'zip'")
        print("  password: required only for ZIP format")
        return
    
    format_type = sys.argv[1].lower()
    
    if format_type == 'parquet':
        # Parquet format
        data_path = "D:/Downloads/phish360_parquet"
        password = None
        
        if not os.path.exists(data_path):
            print(f"ERROR: Parquet directory not found: {data_path}")
            print("Please download and extract the Parquet files first.")
            return
        
        print(f"[*] Using Parquet format from: {data_path}")
        
    elif format_type == 'zip':
        # ZIP format
        data_path = "D:/Downloads/phish360.zip"
        
        if len(sys.argv) < 3:
            print("ERROR: ZIP format requires password")
            print("Usage: python run_phish360_processing.py zip <password>")
            return
        
        password = sys.argv[2]
        
        if not os.path.exists(data_path):
            print(f"ERROR: ZIP file not found: {data_path}")
            return
        
        print(f"[*] Using ZIP format from: {data_path}")
        
    else:
        print(f"ERROR: Unknown format: {format_type}")
        print("Supported formats: 'parquet', 'zip'")
        return
    
    # Output directory
    output_dir = "backend/dataset/phish360"
    
    try:
        # Process the dataset
        train_path, val_path, test_path = process_phish360_dataset(
            data_path=data_path,
            output_dir=output_dir,
            password=password
        )
        
        print()
        print("="*70)
        print("  SUCCESS!")
        print("="*70)
        print()
        print("Processed feature datasets are ready for model training:")
        print(f"  - Train:      {train_path}")
        print(f"  - Validation: {val_path}")
        print(f"  - Test:       {test_path}")
        print()
        print("Next steps:")
        print("  1. Review the processing report in: backend/dataset/phish360/reports/")
        print("  2. Use the processed features for model training")
        print("  3. Follow the research roadmap in docs/PROJECT_PLAN.md")
        print()
        
    except Exception as e:
        print()
        print("="*70)
        print("  PROCESSING FAILED")
        print("="*70)
        print(f"ERROR: {e}")
        print()
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()