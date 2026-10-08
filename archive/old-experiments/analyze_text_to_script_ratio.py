"""
Analyze text_to_script_ratio feature in hard-negative dataset
==============================================================
Investigates why this feature has abnormally high values (24,000-108,000)
and whether it's causing false positives.
"""
import pandas as pd
import numpy as np

V3_DATA_DIR = "dataset/phish360/v3/processed"

def main():
    print("=" * 80)
    print("Analyze text_to_script_ratio Feature")
    print("=" * 80)
    
    # Load hard-negative eval set
    hn_eval_df = pd.read_parquet(f"{V3_DATA_DIR}/hard_neg_eval_features.parquet")
    
    print(f"\nHard-negative eval set: {len(hn_eval_df)} samples")
    
    # Analyze text_to_script_ratio distribution
    print("\n" + "=" * 80)
    print("text_to_script_ratio Distribution")
    print("=" * 80)
    
    ttr = hn_eval_df['text_to_script_ratio']
    print(f"Mean: {ttr.mean():.2f}")
    print(f"Median: {ttr.median():.2f}")
    print(f"Std: {ttr.std():.2f}")
    print(f"Min: {ttr.min():.2f}")
    print(f"Max: {ttr.max():.2f}")
    print(f"Percentiles:")
    print(f"  25%: {ttr.quantile(0.25):.2f}")
    print(f"  50%: {ttr.quantile(0.50):.2f}")
    print(f"  75%: {ttr.quantile(0.75):.2f}")
    print(f"  90%: {ttr.quantile(0.90):.2f}")
    print(f"  95%: {ttr.quantile(0.95):.2f}")
    print(f"  99%: {ttr.quantile(0.99):.2f}")
    
    # Count samples with abnormally high values
    high_ttr = ttr > 10000
    print(f"\nSamples with text_to_script_ratio > 10,000: {high_ttr.sum()} ({high_ttr.mean()*100:.1f}%)")
    
    # Analyze the relationship between text_to_script_ratio and other features
    print("\n" + "=" * 80)
    print("Correlation with Other Features")
    print("=" * 80)
    
    features_to_check = ['text_length', 'scripts', 'forms', 'password_fields', 'credential_density']
    for feat in features_to_check:
        if feat in hn_eval_df.columns:
            corr = hn_eval_df['text_to_script_ratio'].corr(hn_eval_df[feat])
            print(f"  {feat}: {corr:.4f}")
    
    # Show samples with highest text_to_script_ratio
    print("\n" + "=" * 80)
    print("Top 20 Samples by text_to_script_ratio")
    print("=" * 80)
    
    top_ttr = hn_eval_df.nlargest(20, 'text_to_script_ratio')[['url', 'text_to_script_ratio', 'text_length', 'scripts', 'forms', 'password_fields', 'credential_density']]
    for idx, row in top_ttr.iterrows():
        print(f"\n{row['url'][:80]}")
        print(f"  text_to_script_ratio: {row['text_to_script_ratio']:.2f}")
        print(f"  text_length: {row['text_length']}")
        print(f"  scripts: {row['scripts']}")
        print(f"  forms: {row['forms']}")
        print(f"  password_fields: {row['password_fields']}")
        print(f"  credential_density: {row['credential_density']:.4f}")
    
    # Check if high text_to_script_ratio correlates with zero scripts
    print("\n" + "=" * 80)
    print("Script Count Analysis")
    print("=" * 80)
    
    zero_scripts = hn_eval_df['scripts'] == 0
    print(f"Samples with zero scripts: {zero_scripts.sum()} ({zero_scripts.mean()*100:.1f}%)")
    print(f"Mean text_to_script_ratio for zero scripts: {ttr[zero_scripts].mean():.2f}")
    print(f"Mean text_to_script_ratio for non-zero scripts: {ttr[~zero_scripts].mean():.2f}")
    
    # Check the 11 false positives specifically
    print("\n" + "=" * 80)
    print("Analysis of 11 V3 False Positives")
    print("=" * 80)
    
    fp_urls = [
        'https://www.volgistics.com/ex/portal.dll/?from=256484',
        'https://www.dolbycustomer.com/login.aspx',
        'http://slideplayer.com/slide/4759150/',
        'https://www.christianbook.com/hello-name-discover-your-true-identity/matthew-wes',
        'https://v6.upperbooking.com//en/booking/details/wrap/panoramicmountainresidence1',
        'https://www.bridgecrest.com/Account/Login',
        'https://fondationdefrance.evision.ca/eAwards_applicant/faces/jsp/login/login.xht',
        'http://e-coka.cepac.cz/inf-portal/Login.aspx',
        'http://tureng.com/en/german-english/bascule%20bridge',
        'https://gerardnico.com/wiki/database/transaction',
        'https://investorjunkie.com/8995/optionshouse-review/'
    ]
    
    for url in fp_urls:
        mask = hn_eval_df['url'].str.startswith(url[:50])  # Partial match due to truncation
        if mask.any():
            row = hn_eval_df[mask].iloc[0]
            print(f"\n{url[:80]}")
            print(f"  text_to_script_ratio: {row['text_to_script_ratio']:.2f}")
            print(f"  text_length: {row['text_length']}")
            print(f"  scripts: {row['scripts']}")
            print(f"  forms: {row['forms']}")
            print(f"  password_fields: {row['password_fields']}")
            print(f"  credential_density: {row['credential_density']:.4f}")
            print(f"  brand_context_score: {row['brand_context_score']:.4f}")


if __name__ == "__main__":
    main()
