"""
PhishOut Hybrid Feature Extractor
==================================
*** OBSOLETE - Keep for reference only ***
This script extracted hybrid features for the old 250-URL dataset.
See docs/PROJECT_PLAN.md for current direction.

Original purpose:
Extracts combined structural and semantic features for the hybrid model.
Combines 32 structural URL features with 12 numeric semantic webpage features.

Missing-data strategy: "Zero-fill on fetch failure"
  - Every URL has its structural features extracted (URL parsing — always works).
  - We attempt to fetch and analyze the webpage with a short timeout (5s).
  - If the fetch fails (DNS error, timeout, non-HTML, HTTP error, etc.) all
    semantic features are set to 0 and fetch_success=False is recorded.
  - Zeros mean "no webpage evidence detected", NOT invented values.
  - This is intentional and documented: many simulated phishing URLs in the
    dataset do not resolve to real pages, so the semantic signal is absent for
    those samples. The hybrid model learns this asymmetry.
"""
import pandas as pd
import numpy as np
from ml_model import extract_features, FEATURE_KEYS
from webpage_analyzer import analyze_webpage
from data_loader import load_clean_dataset
import time

# Semantic feature names (12 numeric features from webpage_analyzer)
# page_title and form_actions are excluded — they are string/list,
# used only for explanation generation, not as model inputs.
SEMANTIC_FEATURE_KEYS = [
    "text_length",
    "password_fields",
    "text_email_fields",
    "forms",
    "external_links",
    "iframes",
    "scripts",
    "login_indicators",
    "credential_indicators",
    "payment_indicators",
    "urgency_indicators",
    "brand_indicators",
]

# Combined feature names (32 structural + 12 semantic = 44 total)
HYBRID_FEATURE_KEYS = FEATURE_KEYS + SEMANTIC_FEATURE_KEYS


def extract_hybrid_features(urls, labels, timeout: int = 5):
    """
    Extract hybrid features for a list of URLs.

    Structural features are always extracted (URL-level, no network).
    Semantic features require fetching the webpage; on failure zeros are used.

    Args:
        urls:    List of URL strings
        labels:  List of labels (0=legitimate, 1=phishing)
        timeout: Seconds to wait for each webpage fetch

    Returns:
        List of dicts with keys: url, label, fetch_success, + all feature cols
    """
    results = []
    total = len(urls)
    fetch_ok = 0
    fetch_fail = 0

    for i, (url, label) in enumerate(zip(urls, labels)):
        safe_url = url.encode("ascii", errors="replace").decode("ascii")
        print(f"  [{i+1:03d}/{total}] {safe_url[:65]}", end="", flush=True)

        # ── Structural features (always available) ────────────────────────
        try:
            structural_feats = extract_features(url)
            structural_values = [structural_feats[k] for k in FEATURE_KEYS]
        except Exception as e:
            print(f"  [SKIP structural] {e}")
            continue

        # ── Semantic features (attempt real fetch) ────────────────────────
        semantic_values = [0] * len(SEMANTIC_FEATURE_KEYS)
        fetch_success = False

        try:
            webpage_result = analyze_webpage(url, timeout=timeout)
            if webpage_result.get("success", False):
                semantic_values = [
                    webpage_result.get(k, 0) for k in SEMANTIC_FEATURE_KEYS
                ]
                fetch_success = True
                fetch_ok += 1
                print(f"  [fetch OK]")
            else:
                fetch_fail += 1
                err = webpage_result.get("error", "unknown")
                print(f"  [fetch FAIL: {str(err)[:40]}]")
        except Exception as e:
            fetch_fail += 1
            print(f"  [fetch EXC: {str(e)[:40]}]")

        # ── Combine ───────────────────────────────────────────────────────
        combined_values = structural_values + semantic_values

        result = {
            "url": url,
            "label": int(label),
            "fetch_success": fetch_success,
            **{k: v for k, v in zip(HYBRID_FEATURE_KEYS, combined_values)},
        }
        results.append(result)

    print(f"\n[+] Fetch summary: {fetch_ok} succeeded, {fetch_fail} failed")
    return results


def save_hybrid_dataset(results, output_path):
    """
    Save hybrid dataset to CSV.

    Args:
        results:     List of feature dicts
        output_path: Path to save CSV
    """
    df = pd.DataFrame(results)
    cols = ["url", "label", "fetch_success"] + HYBRID_FEATURE_KEYS
    df = df[cols]
    df.to_csv(output_path, index=False)

    print(f"[+] Saved hybrid dataset to {output_path}")
    print(f"[+] Total samples:      {len(df)}")
    print(f"[+] Phishing samples:   {df['label'].sum()}")
    print(f"[+] Legitimate samples: {(df['label'] == 0).sum()}")
    print(f"[+] Fetch succeeded:    {df['fetch_success'].sum()}")
    print(f"[+] Fetch failed:       {(~df['fetch_success']).sum()}")
    print(f"[+] Semantic columns:   {len(SEMANTIC_FEATURE_KEYS)}")
    print(f"[+] Total features:     {len(HYBRID_FEATURE_KEYS)} (structural + semantic)")
    return df


if __name__ == "__main__":
    print("=" * 60)
    print("  PhishOut Hybrid Feature Extraction")
    print("=" * 60)
    print()
    print("Strategy: Zero-fill on fetch failure")
    print("  - Structural: always extracted from URL")
    print("  - Semantic:   fetched with 5s timeout; zeros if fetch fails")
    print()

    # Load clean dataset
    urls, labels = load_clean_dataset()

    # Extract
    print(f"[*] Extracting hybrid features for {len(urls)} URLs...\n")
    t0 = time.time()
    results = extract_hybrid_features(urls, labels, timeout=5)
    elapsed = time.time() - t0

    # Save
    output_path = "dataset/hybrid_features.csv"
    df = save_hybrid_dataset(results, output_path)
    print(f"\n[+] Extraction complete in {elapsed:.1f}s")
