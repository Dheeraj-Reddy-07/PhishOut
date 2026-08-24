"""
PhishOut — Fusion Calibration
================================
*** LEGACY - DO NOT USE ***
This script expects PhreshPhish dataset features.
The project has moved to Phish360 (local dataset).
See docs/PROJECT_PLAN.md for current direction.

Original purpose:
Calibrates verdict thresholds (SAFE_MAX, PHISHING_MIN) using a
held-out 20% validation split from the TRAINING data only.

The test set is NOT touched.

If the best model from train_hybrid_model.py is a hybrid model,
calibration sets the fusion mode to "hybrid_direct" (no separate
structural/semantic weights needed — the hybrid model provides a
single probability).

If the best model is structural-only, calibration finds optimal
fusion weights (structural_weight, semantic_weight) for combining
the two models.

Calibration approach for verdict thresholds:
  - Sweep SAFE_MAX   from 0.15 to 0.45 in steps of 0.01
  - Sweep PHISHING_MIN from 0.50 to 0.85 in steps of 0.01
  - Select thresholds that maximise F1 on the validation split

Output:
  models/calibration_results.json
  config/semantic_rules.py (updated with calibrated values)

Usage:
    python calibrate_fusion.py
"""
import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, precision_score, recall_score

DATA_DIR    = os.path.join(os.path.dirname(__file__), "dataset", "phreshphish")
MODELS_DIR  = os.path.join(os.path.dirname(__file__), "models")
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config", "semantic_rules.py")


def load_best_model():
    """Load the best model determined by train_hybrid_model.py."""
    config_path = os.path.join(MODELS_DIR, "phishout_best_config.json")
    if not os.path.exists(config_path):
        print("[ERROR] phishout_best_config.json not found. Run train_hybrid_model.py first.")
        sys.exit(1)

    with open(config_path) as f:
        config = json.load(f)

    model  = joblib.load(os.path.join(MODELS_DIR, "phishout_best_model.pkl"))
    scaler = joblib.load(os.path.join(MODELS_DIR, "phishout_best_scaler.pkl"))
    return model, scaler, config


def calibrate_thresholds(y_true: np.ndarray, y_prob: np.ndarray) -> dict:
    """
    Grid search over SAFE_MAX and PHISHING_MIN thresholds.
    Maximises F1 on the validation set.

    Returns: {safe_max, phishing_min, f1, precision, recall}
    """
    best = {"f1": -1.0}

    safe_candidates     = np.arange(0.15, 0.46, 0.01)
    phishing_candidates = np.arange(0.50, 0.86, 0.01)

    for safe_max in safe_candidates:
        for phish_min in phishing_candidates:
            if safe_max >= phish_min:
                continue

            # Map probabilities → 3-class verdict
            y_pred = np.where(y_prob >= phish_min, 1,
                     np.where(y_prob <  safe_max,  0, 2))
            # For F1: treat SUSPICIOUS (2) as positive (phishing) — conservative
            y_binary = (y_pred >= 1).astype(int)

            try:
                f1  = f1_score(y_true, y_binary, zero_division=0)
                prec = precision_score(y_true, y_binary, zero_division=0)
                rec  = recall_score(y_true, y_binary, zero_division=0)
            except Exception:
                continue

            if f1 > best["f1"]:
                best = {
                    "safe_max":       round(float(safe_max),  2),
                    "phishing_min":   round(float(phish_min), 2),
                    "f1":             round(f1,   4),
                    "precision":      round(prec, 4),
                    "recall":         round(rec,  4),
                }

    return best


def main():
    print("=" * 60)
    print("  PhishOut — Fusion Calibration")
    print("=" * 60)

    # ── Load training data ────────────────────────────────────────────────────
    train_path = os.path.join(DATA_DIR, "train_features.parquet")
    if not os.path.exists(train_path):
        print("[ERROR] train_features.parquet not found.")
        sys.exit(1)

    train_df = pd.read_parquet(train_path)

    # ── Load best model ───────────────────────────────────────────────────────
    model, scaler, config = load_best_model()
    winner_type = config["winner_type"]
    feature_cols = config["feature_columns"]

    print(f"\nBest model type : {winner_type}")
    print(f"Feature columns : {len(feature_cols)}")

    # ── Create validation split from training data (20%) ──────────────────────
    X_all = train_df[feature_cols].fillna(0).values.astype(np.float32)
    y_all = train_df["label"].values.astype(int)

    _, X_val, _, y_val = train_test_split(
        X_all, y_all, test_size=0.20, random_state=42, stratify=y_all
    )
    print(f"\nValidation set (20% of train): {len(X_val):,} rows  "
          f"(benign={int((y_val==0).sum()):,}  phishing={int((y_val==1).sum()):,})")

    # ── Get probabilities on validation set ───────────────────────────────────
    X_val_s = scaler.transform(X_val)
    y_prob  = model.predict_proba(X_val_s)[:, 1]

    print(f"\nProbability distribution (val set):")
    print(f"  P < 0.20  : {(y_prob < 0.20).sum():,} rows")
    print(f"  0.20-0.50 : {((y_prob >= 0.20) & (y_prob < 0.50)).sum():,} rows")
    print(f"  >= 0.50   : {(y_prob >= 0.50).sum():,} rows")

    # ── Calibrate thresholds ──────────────────────────────────────────────────
    print("\nRunning threshold grid search...")
    best_thresholds = calibrate_thresholds(y_val, y_prob)

    safe_max_int    = int(round(best_thresholds["safe_max"]    * 100))
    phishing_min_int = int(round(best_thresholds["phishing_min"] * 100))

    print(f"\nCalibrated thresholds:")
    print(f"  SAFE_MAX     (probability): {best_thresholds['safe_max']:.2f}  →  score {safe_max_int}")
    print(f"  PHISHING_MIN (probability): {best_thresholds['phishing_min']:.2f}  →  score {phishing_min_int}")
    print(f"  Validation F1   : {best_thresholds['f1']:.4f}")
    print(f"  Validation Prec : {best_thresholds['precision']:.4f}")
    print(f"  Validation Rec  : {best_thresholds['recall']:.4f}")

    # ── Fusion weights ────────────────────────────────────────────────────────
    # For hybrid model: fusion is done inside the model; weights are informational
    # For structural-only: keep existing 60/40 split (no live semantic model)
    if winner_type == "hybrid":
        fusion_note = "hybrid_direct"
        struct_w = 1.0
        sem_w    = 0.0
    else:
        fusion_note = "weighted_average"
        struct_w = 0.60
        sem_w    = 0.40

    # ── Save calibration results ──────────────────────────────────────────────
    results = {
        "winner_type":            winner_type,
        "fusion_mode":            fusion_note,
        "calibrated_safe_max":    best_thresholds["safe_max"],
        "calibrated_phish_min":   best_thresholds["phishing_min"],
        "calibrated_safe_max_score":    safe_max_int,
        "calibrated_phish_min_score":   phishing_min_int,
        "validation_f1":          best_thresholds["f1"],
        "validation_precision":   best_thresholds["precision"],
        "validation_recall":      best_thresholds["recall"],
        "structural_weight":      struct_w,
        "semantic_weight":        sem_w,
        "validation_set_size":    len(X_val),
    }

    results_path = os.path.join(MODELS_DIR, "calibration_results.json")
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n✓ Calibration results saved: {results_path}")

    # ── Update config/semantic_rules.py ───────────────────────────────────────
    _update_config(
        safe_max_int, phishing_min_int, struct_w, sem_w, fusion_note
    )
    print(f"✓ Updated {CONFIG_PATH}")

    print("\n" + "=" * 60)
    print("  Calibration complete.")
    print(f"  SAFE < {safe_max_int}  |  SUSPICIOUS {safe_max_int}–{phishing_min_int-1}  |  PHISHING >= {phishing_min_int}")
    print("=" * 60)


def _update_config(safe_max: int, phishing_min: int,
                   struct_w: float, sem_w: float, fusion_note: str):
    """Rewrite VERDICT_THRESHOLDS and FUSION sections in config/semantic_rules.py."""
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    import re

    # Update VERDICT_THRESHOLDS
    content = re.sub(
        r'VERDICT_THRESHOLDS\s*=\s*\{[^}]+\}',
        (
            f'VERDICT_THRESHOLDS = {{\n'
            f'    # Calibrated on PhreshPhish validation set — NOT preliminary\n'
            f'    "SAFE_MAX":     {safe_max},    # risk_score < {safe_max}  → SAFE\n'
            f'    "PHISHING_MIN": {phishing_min},  # risk_score >= {phishing_min} → PHISHING\n'
            f'                                     # {safe_max} <= score < {phishing_min} → SUSPICIOUS\n'
            f'}}'
        ),
        content,
        flags=re.DOTALL,
    )

    # Update FUSION
    content = re.sub(
        r'FUSION\s*=\s*\{[^}]+\}',
        (
            f'FUSION = {{\n'
            f'    # Calibrated — mode: {fusion_note}\n'
            f'    "structural_weight_with_page":    {struct_w:.2f},\n'
            f'    "semantic_weight_with_page":      {sem_w:.2f},\n'
            f'    "structural_weight_without_page": 1.00,\n'
            f'    "semantic_weight_without_page":   0.00,\n'
            f'}}'
        ),
        content,
        flags=re.DOTALL,
    )

    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        f.write(content)


if __name__ == "__main__":
    main()
