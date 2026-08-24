"""
PhreshPhish Dataset Inspector
=============================
*** LEGACY - DO NOT USE ***
This script was for inspecting the abandoned PhreshPhish dataset.
The project has moved to Phish360 (local dataset).
See docs/PROJECT_PLAN.md for current direction.

Original purpose:
Streams a tiny sample (200 rows) from PhreshPhish to inspect schema,
label encoding, HTML presence, class distribution, and language distribution.

DOES NOT save any data. Read-only.

Usage:
    python inspect_phreshphish.py
"""
from datasets import load_dataset
import sys

N_SAMPLE = 200   # rows to inspect (very fast)

def inspect():
    print("=" * 60)
    print("  PhreshPhish Dataset Inspector")
    print("=" * 60)
    print(f"\nStreaming {N_SAMPLE} rows from train split...")

    try:
        ds = load_dataset(
            "phreshphish/phreshphish",
            split="train",
            streaming=True,
            trust_remote_code=False,
        )
    except Exception as e:
        print(f"\n[ERROR] Could not load dataset: {e}")
        sys.exit(1)

    rows = []
    for i, row in enumerate(ds):
        if i >= N_SAMPLE:
            break
        rows.append(row)

    if not rows:
        print("[ERROR] No rows returned from stream.")
        sys.exit(1)

    print(f"\n✓ Received {len(rows)} rows\n")

    # ── Column names ──────────────────────────────────────────────────────
    cols = list(rows[0].keys())
    print(f"Columns ({len(cols)}):")
    for c in cols:
        val = rows[0][c]
        typ = type(val).__name__
        preview = str(val)[:80] if val is not None else "None"
        print(f"  {c:20s} | {typ:10s} | {preview}")

    # ── Label values ──────────────────────────────────────────────────────
    labels = [r.get("label") for r in rows]
    label_types = set(type(l).__name__ for l in labels)
    label_values = set(str(l) for l in labels if l is not None)
    print(f"\nLabel column:")
    print(f"  Python type(s) : {label_types}")
    print(f"  Unique values  : {label_values}")

    # ── Class distribution ────────────────────────────────────────────────
    from collections import Counter
    dist = Counter(str(l) for l in labels)
    print(f"\nClass distribution (sample of {N_SAMPLE}):")
    for k, v in sorted(dist.items()):
        print(f"  {k:15s}: {v:4d}  ({v/N_SAMPLE*100:.1f}%)")

    # ── Null / empty checks ───────────────────────────────────────────────
    print("\nNull / empty checks:")
    for col in ["url", "html", "label", "sha256"]:
        if col not in cols:
            print(f"  {col:20s}: COLUMN MISSING")
            continue
        nulls = sum(1 for r in rows if r.get(col) is None or r.get(col) == "")
        print(f"  {col:20s}: {nulls} null/empty out of {N_SAMPLE}")

    # ── HTML size ─────────────────────────────────────────────────────────
    html_sizes = [len(r["html"]) for r in rows if r.get("html")]
    if html_sizes:
        print(f"\nHTML size (bytes):")
        print(f"  min  : {min(html_sizes):,}")
        print(f"  max  : {max(html_sizes):,}")
        print(f"  mean : {sum(html_sizes)//len(html_sizes):,}")
        tiny = sum(1 for s in html_sizes if s < 200)
        print(f"  tiny (<200 bytes): {tiny}")

    # ── Language distribution ─────────────────────────────────────────────
    langs = Counter(r.get("lang", "?") for r in rows)
    top_langs = langs.most_common(5)
    print(f"\nTop languages (sample):")
    for lang, cnt in top_langs:
        print(f"  {str(lang):10s}: {cnt}")

    # ── Sample URL + label pairs ──────────────────────────────────────────
    print(f"\nSample URL + label pairs:")
    for r in rows[:5]:
        url    = str(r.get("url",""))[:60]
        label  = r.get("label")
        target = r.get("target", "")
        print(f"  [{label}] {url}  (target={target})")

    print("\n" + "=" * 60)
    print("  Inspection complete.")
    print("=" * 60)

if __name__ == "__main__":
    inspect()
