"""
PhreshPhish Stream-and-Extract Pipeline  (with checkpoint/resume)
===================================================================
*** LEGACY - DO NOT USE ***
This script was part of the abandoned PhreshPhish streaming approach.
The project has moved to Phish360 (local dataset).
See docs/PROJECT_PLAN.md for current direction.

Original purpose:
Streams PhreshPhish from HuggingFace, extracts structural + semantic
features IN MEMORY, discards HTML immediately, and saves ONLY the
resulting feature dataset locally.

HOW STREAMING WORKS:
  - load_dataset(..., streaming=True) does NOT download the full 36.6 GB.
  - HuggingFace reads remote Parquet shards in chunks over HTTP.
  - HTML is processed per-row and immediately discarded.
  - Nothing is written to disk except feature rows (no HTML ever).

CHECKPOINT / RESUME:
  - Every CHECKPOINT_EVERY accepted rows, the script appends them to
    a checkpoint Parquet file:
        dataset/phreshphish/<split>_checkpoint.parquet
  - On startup, if a checkpoint file exists, it is loaded and already-
    seen URLs are skipped. Streaming resumes from scratch but skips
    rows already processed — reaching completion much faster.
  - Once a split is fully collected, the checkpoint is promoted to
    <split>_features.parquet and the checkpoint file is deleted.
  - If <split>_features.parquet already exists and is complete,
    that split is skipped entirely.

EXPECTED LOCAL DISK USAGE (features only, no HTML):
  20,000 rows × 44 numeric features → ~2–4 MB Parquet (compressed)
  Checkpoint files are the same size — they are promoted, not copied.

Target:
  Train: 8,000 benign + 8,000 phishing = 16,000
  Test:  2,000 benign + 2,000 phishing =  4,000

Usage:
    python stream_and_extract.py [--dry-run]
"""
import os
import sys
import time
import argparse
import numpy as np
import pandas as pd
from datasets import load_dataset

sys.path.insert(0, os.path.dirname(__file__))

from ml_model import extract_features
from webpage_analyzer import extract_semantic_features_from_html

# ── Configuration ──────────────────────────────────────────────────────────────
TARGET = {
    "train": {"benign": 8_000, "phishing": 8_000},
    "test":  {"benign": 2_000, "phishing": 2_000},
}
MIN_HTML_BYTES    = 200    # discard trivially empty pages
MIN_URL_LEN       = 8      # discard obviously malformed URLs
CHECKPOINT_EVERY  = 200    # flush accepted rows to disk every N rows

DATA_DIR = os.path.join(os.path.dirname(__file__), "dataset", "phreshphish")
os.makedirs(DATA_DIR, exist_ok=True)

REPORT_PATH = os.path.join(DATA_DIR, "stream_extract_report.txt")

SEMANTIC_KEYS = [
    "text_length", "password_fields", "text_email_fields", "forms",
    "external_links", "iframes", "scripts",
    "login_indicators", "credential_indicators",
    "payment_indicators", "urgency_indicators", "brand_indicators",
]


# ── Label normaliser ───────────────────────────────────────────────────────────
def normalise_label(raw) -> str | None:
    """PhreshPhish uses 'phish' as the positive label (not 'phishing')."""
    if raw is None:
        return None
    s = str(raw).strip().lower()
    if s in ("benign", "0", "legitimate", "legit", "safe"):
        return "benign"
    if s in ("phishing", "phish", "1", "malicious"):
        return "phishing"
    return None


# ── Feature extraction ─────────────────────────────────────────────────────────
def extract_row_features(url: str, html: str) -> tuple[dict, dict, bool, bool]:
    """Extract structural + semantic features. HTML is NOT stored after this."""
    struct_feats, struct_ok = {}, False
    try:
        raw = extract_features(url)
        struct_feats = {
            k: float(v) if isinstance(v, (int, float, bool, np.integer, np.floating))
            else 0.0
            for k, v in raw.items()
        }
        struct_ok = True
    except Exception:
        pass

    sem_feats, sem_ok = {}, False
    try:
        raw = extract_semantic_features_from_html(html, url)
        sem_feats = {k: float(raw.get(k, 0) or 0) for k in SEMANTIC_KEYS}
        sem_ok = True
    except Exception:
        pass

    return struct_feats, sem_feats, struct_ok, sem_ok


# ── Checkpoint helpers ─────────────────────────────────────────────────────────
def checkpoint_path(split: str) -> str:
    return os.path.join(DATA_DIR, f"{split}_checkpoint.parquet")


def features_path(split: str) -> str:
    return os.path.join(DATA_DIR, f"{split}_features.parquet")


def load_checkpoint(split: str) -> tuple[pd.DataFrame, set, dict]:
    """
    Load existing checkpoint for this split.
    Returns (df, seen_urls_set, counts_dict).
    seen_urls_set contains lowercased URLs already processed.
    counts_dict = {'benign': N, 'phishing': N}
    """
    cp = checkpoint_path(split)
    fp = features_path(split)

    # Prefer completed features file over checkpoint
    for path in (fp, cp):
        if os.path.exists(path):
            try:
                df = pd.read_parquet(path)
                seen = set(df["url"].str.strip().str.lower().tolist())
                counts = {
                    "benign":   int((df["label"] == 0).sum()),
                    "phishing": int((df["label"] == 1).sum()),
                }
                source = "features" if path == fp else "checkpoint"
                print(f"  [resume] Loaded {source}: "
                      f"{len(df):,} rows  "
                      f"(benign={counts['benign']:,}  "
                      f"phishing={counts['phishing']:,})")
                return df, seen, counts
            except Exception as e:
                print(f"  [resume] Could not read {path}: {e}")

    return pd.DataFrame(), set(), {"benign": 0, "phishing": 0}


def flush_checkpoint(split: str, rows: list, existing_df: pd.DataFrame) -> pd.DataFrame:
    """Append new rows to checkpoint Parquet and return combined DataFrame."""
    new_df = pd.DataFrame(rows)
    if not existing_df.empty:
        combined = pd.concat([existing_df, new_df], ignore_index=True)
    else:
        combined = new_df

    cp = checkpoint_path(split)
    combined.to_parquet(cp, index=False, compression="snappy")
    return combined


def promote_checkpoint(split: str):
    """Rename checkpoint → features file when collection is complete."""
    cp = checkpoint_path(split)
    fp = features_path(split)
    if os.path.exists(cp):
        os.replace(cp, fp)
        print(f"  ✓ Promoted checkpoint → {os.path.basename(fp)}")


# ── Split extraction ───────────────────────────────────────────────────────────
def stream_and_extract_split(
    split_name: str,
    targets: dict,
    dry_run: bool,
    report_lines: list,
) -> pd.DataFrame:

    print(f"\n{'─' * 64}")
    print(f"  Split: {split_name.upper()}  "
          f"| Target: {targets['benign']:,} benign + {targets['phishing']:,} phishing")
    print(f"{'─' * 64}")

    fp = features_path(split_name)

    # ── Check if already complete ──────────────────────────────────────────
    if os.path.exists(fp) and not dry_run:
        df = pd.read_parquet(fp)
        b = int((df["label"] == 0).sum())
        p = int((df["label"] == 1).sum())
        if b >= targets["benign"] and p >= targets["phishing"]:
            print(f"  ✓ Already complete: {len(df):,} rows "
                  f"(benign={b:,} phishing={p:,}) — skipping.")
            report_lines.append(f"\nSplit {split_name.upper()}: already complete, skipped.")
            return df
        else:
            print(f"  Partial features file found: {b:,}/{targets['benign']:,} benign, "
                  f"{p:,}/{targets['phishing']:,} phishing — will re-extract.")

    # ── Load checkpoint (resume state) ────────────────────────────────────
    existing_df, seen_urls, existing_counts = load_checkpoint(split_name)
    pending_rows = []   # buffer for rows not yet flushed

    # Reconstruct per-class counters from checkpoint
    accepted_counts = dict(existing_counts)
    skipped_resume  = 0

    stats = {
        "rows_streamed":       0,
        "null_url":            0,
        "tiny_html":           0,
        "bad_label":           0,
        "dup_url":             0,
        "struct_failures":     0,
        "sem_failures":        0,
        "skipped_quota_full":  0,
        "skipped_resume":      0,
    }

    t0 = time.time()
    last_progress_print = t0

    print(f"  Resuming from: benign={accepted_counts['benign']:,}  "
          f"phishing={accepted_counts['phishing']:,}  "
          f"(need {targets['benign']-accepted_counts['benign']:,} more benign, "
          f"{targets['phishing']-accepted_counts['phishing']:,} more phishing)")

    # ── Stream ─────────────────────────────────────────────────────────────
    ds = load_dataset(
        "phreshphish/phreshphish",
        split=split_name,
        streaming=True,
        trust_remote_code=False,
    )

    for row in ds:
        stats["rows_streamed"] += 1

        # Progress every 5k rows
        now = time.time()
        if now - last_progress_print >= 30:   # print at most every 30s
            b = accepted_counts["benign"]
            p = accepted_counts["phishing"]
            elapsed = now - t0
            rate = stats["rows_streamed"] / elapsed if elapsed > 0 else 0
            print(f"  [{split_name}] scanned={stats['rows_streamed']:,}  "
                  f"B={b:,}/{targets['benign']:,}  P={p:,}/{targets['phishing']:,}  "
                  f"rate={rate:.0f} rows/s  t={elapsed:.0f}s")
            sys.stdout.flush()
            last_progress_print = now

        # Completion check
        if (accepted_counts["benign"]    >= targets["benign"] and
                accepted_counts["phishing"] >= targets["phishing"]):
            break

        if dry_run and stats["rows_streamed"] > 15:
            break

        # ── Filter: URL ───────────────────────────────────────────────────
        url = row.get("url") or ""
        if len(url.strip()) < MIN_URL_LEN:
            stats["null_url"] += 1
            continue

        # ── Resume skip: already in checkpoint ────────────────────────────
        url_norm = url.strip().lower()
        if url_norm in seen_urls:
            stats["skipped_resume"] += 1
            continue
        seen_urls.add(url_norm)

        # ── Filter: HTML ──────────────────────────────────────────────────
        html = row.get("html") or ""
        if len(html) < MIN_HTML_BYTES:
            stats["tiny_html"] += 1
            continue

        # ── Filter: label ─────────────────────────────────────────────────
        label = normalise_label(row.get("label"))
        if label is None:
            stats["bad_label"] += 1
            continue

        # ── Quota check ───────────────────────────────────────────────────
        if accepted_counts[label] >= targets[label]:
            stats["skipped_quota_full"] += 1
            continue

        # ── Feature extraction (HTML consumed, not stored) ─────────────
        struct_feats, sem_feats, struct_ok, sem_ok = extract_row_features(
            url.strip(), html
        )
        # html goes out of scope here — GC reclaims memory, nothing written

        if not struct_ok:
            stats["struct_failures"] += 1
        if not sem_ok:
            stats["sem_failures"] += 1

        # ── Build feature row (no html field) ─────────────────────────────
        feat_row = {
            "url":       url.strip(),
            "label":     1 if label == "phishing" else 0,
            "label_str": label,
            "sha256":    row.get("sha256", ""),
            "lang":      row.get("lang", ""),
        }
        for k, v in struct_feats.items():
            feat_row[f"s_{k}"] = v
        for k, v in sem_feats.items():
            feat_row[f"e_{k}"] = v

        pending_rows.append(feat_row)
        accepted_counts[label] += 1

        # ── Checkpoint flush ───────────────────────────────────────────────
        if not dry_run and len(pending_rows) >= CHECKPOINT_EVERY:
            existing_df = flush_checkpoint(split_name, pending_rows, existing_df)
            pending_rows = []
            b = accepted_counts["benign"]
            p = accepted_counts["phishing"]
            print(f"  [checkpoint] Saved  B={b:,}/{targets['benign']:,}  "
                  f"P={p:,}/{targets['phishing']:,}  "
                  f"total={len(existing_df):,}", flush=True)

        # Dry-run sample
        if dry_run and (accepted_counts["benign"] + accepted_counts["phishing"]) <= 3:
            print(f"  Sample [{label}]: {url[:60]}  "
                  f"text={sem_feats.get('text_length',0):.0f}  "
                  f"forms={sem_feats.get('forms',0):.0f}  "
                  f"pw={sem_feats.get('password_fields',0):.0f}")

    # ── Final flush ────────────────────────────────────────────────────────
    if not dry_run and pending_rows:
        existing_df = flush_checkpoint(split_name, pending_rows, existing_df)
        pending_rows = []

    elapsed = time.time() - t0
    final_df = existing_df if not dry_run else pd.DataFrame(
        [{"url": "dry-run", "label": 0}]
    )

    # ── Promote checkpoint → features ──────────────────────────────────────
    if not dry_run:
        promote_checkpoint(split_name)

        # Verify final file
        final_df = pd.read_parquet(features_path(split_name))
        b = int((final_df["label"] == 0).sum())
        p = int((final_df["label"] == 1).sum())
        size_kb = os.path.getsize(features_path(split_name)) / 1024
        print(f"\n  ✓ {split_name}_features.parquet: "
              f"{len(final_df):,} rows  (benign={b:,}  phishing={p:,})  "
              f"{size_kb:.0f} KB")

    lines = [
        f"\nSplit: {split_name.upper()}",
        f"  Rows streamed         : {stats['rows_streamed']:,}",
        f"  Elapsed               : {elapsed:.1f}s",
        f"  Skipped (resume)      : {stats['skipped_resume']:,}",
        f"  Dropped null URL      : {stats['null_url']:,}",
        f"  Dropped tiny HTML     : {stats['tiny_html']:,}",
        f"  Dropped bad label     : {stats['bad_label']:,}",
        f"  Skipped quota full    : {stats['skipped_quota_full']:,}",
        f"  Struct failures       : {stats['struct_failures']:,}",
        f"  Semantic failures     : {stats['sem_failures']:,}",
        f"  Accepted benign       : {accepted_counts['benign']:,}",
        f"  Accepted phishing     : {accepted_counts['phishing']:,}",
    ]
    for line in lines:
        print(line)
    report_lines.extend(lines)

    return final_df


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview a few rows without saving")
    args = parser.parse_args()

    print("=" * 64)
    print("  PhreshPhish Stream-and-Extract  (checkpoint/resume enabled)")
    print("=" * 64)

    # Quick status summary
    for split_name, targets in TARGET.items():
        cp = checkpoint_path(split_name)
        fp = features_path(split_name)
        if os.path.exists(fp):
            df = pd.read_parquet(fp)
            b = int((df["label"] == 0).sum())
            p = int((df["label"] == 1).sum())
            status = "COMPLETE" if (b >= targets["benign"] and p >= targets["phishing"]) else "PARTIAL"
            print(f"  {split_name:6s}: features.parquet exists  "
                  f"[{status}]  benign={b:,}  phishing={p:,}")
        elif os.path.exists(cp):
            df = pd.read_parquet(cp)
            b = int((df["label"] == 0).sum())
            p = int((df["label"] == 1).sum())
            print(f"  {split_name:6s}: checkpoint exists  "
                  f"benign={b:,}/{targets['benign']:,}  "
                  f"phishing={p:,}/{targets['phishing']:,}  → will resume")
        else:
            print(f"  {split_name:6s}: no checkpoint — starting fresh")

    print()
    if args.dry_run:
        print("  *** DRY-RUN — nothing will be saved ***\n")

    report_lines = [
        "PhreshPhish Stream-and-Extract Report",
        "HF streaming=True — no full download, no HTML saved",
        f"Checkpoint every {CHECKPOINT_EVERY} accepted rows",
    ]

    for split_name, targets in TARGET.items():
        stream_and_extract_split(split_name, targets, args.dry_run, report_lines)

    if not args.dry_run:
        with open(REPORT_PATH, "w", encoding="utf-8") as f:
            f.write("\n".join(report_lines))
        print(f"\n✓ Report: {REPORT_PATH}")

    print("\n" + "=" * 64)
    if args.dry_run:
        print("  DRY-RUN complete.")
    else:
        print("  Extraction complete.")
        print("  Next: python train_semantic_model.py")
        print("        python train_hybrid_model.py")
        print("        python calibrate_fusion.py")
        print("        python evaluate_final.py")
    print("=" * 64)


if __name__ == "__main__":
    main()
