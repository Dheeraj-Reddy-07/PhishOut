"""
PhishOut — Final Evaluation Script
===================================
*** LEGACY - DO NOT USE ***
This script expects PhreshPhish dataset features.
The project has moved to Phish360 (local dataset).
See docs/PROJECT_PLAN.md for current direction.

Original purpose:
Evaluates the trained PhishOut models on the held-out test set
and produces a comprehensive evaluation report.

This script is run ONCE after calibration is complete.
The test set is NEVER used for tuning.

Reports:
  - Accuracy, Precision, Recall, F1, ROC-AUC, FPR
  - Confusion matrix for each model
  - Side-by-side comparison table
  - Final selected model and verdict

Output:
  models/final_evaluation_results.json

Usage:
    python evaluate_final.py
"""
import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix,
)

DATA_DIR   = os.path.join(os.path.dirname(__file__), "dataset", "phreshphish")
MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")


def evaluate(model, scaler, X_test: np.ndarray, y_test: np.ndarray,
             model_name: str, feature_name: str) -> dict:
    X_s    = scaler.transform(X_test)
    y_pred = model.predict(X_s)
    y_prob = model.predict_proba(X_s)[:, 1]

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    return {
        "model":     model_name,
        "features":  feature_name,
        "accuracy":  round(accuracy_score(y_test, y_pred),  4),
        "precision": round(precision_score(y_test, y_pred), 4),
        "recall":    round(recall_score(y_test, y_pred),    4),
        "f1":        round(f1_score(y_test, y_pred),        4),
        "roc_auc":   round(roc_auc_score(y_test, y_prob),   4),
        "fpr":       round(fp / (fp + tn) if (fp + tn) > 0 else 0, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def print_table(metrics: list):
    print("\n" + "=" * 76)
    print(f"  FINAL CLEAN EVALUATION (untouched test set)")
    print("=" * 76)
    print(f"  {'Model':<26} {'Acc':>6} {'Prec':>6} {'Rec':>6} {'F1':>6} {'AUC':>6} {'FPR':>6}")
    print("  " + "─" * 70)
    for m in metrics:
        print(f"  {m['model']:<26} {m['accuracy']:>6.4f} {m['precision']:>6.4f} "
              f"{m['recall']:>6.4f} {m['f1']:>6.4f} {m['roc_auc']:>6.4f} {m['fpr']:>6.4f}")
    print("=" * 76)


def main():
    print("=" * 76)
    print("  PhishOut — Final Clean Evaluation")
    print("=" * 76)

    # ── Load test data ────────────────────────────────────────────────────────
    test_path = os.path.join(DATA_DIR, "test_features.parquet")
    if not os.path.exists(test_path):
        print("[ERROR] test_features.parquet not found.")
        sys.exit(1)

    test_df = pd.read_parquet(test_path)
    y_test  = test_df["label"].values.astype(int)

    struct_cols = [c for c in test_df.columns if c.startswith("s_")]
    sem_cols    = [c for c in test_df.columns if c.startswith("e_")]
    hybrid_cols = struct_cols + sem_cols

    print(f"\nTest set: {len(test_df):,} rows  "
          f"(benign={int((y_test==0).sum()):,}  phishing={int((y_test==1).sum()):,})")

    all_metrics = []

    # ── Load and evaluate structural-only ─────────────────────────────────────
    so_model_path  = os.path.join(MODELS_DIR, "structural_only_model.pkl")
    so_scaler_path = os.path.join(MODELS_DIR, "structural_only_scaler.pkl")
    if os.path.exists(so_model_path) and struct_cols:
        print("\n[Evaluating] Structural-only...")
        m = joblib.load(so_model_path)
        s = joblib.load(so_scaler_path)
        X = test_df[struct_cols].fillna(0).values.astype(np.float32)
        metrics = evaluate(m, s, X, y_test, "Structural-only", f"{len(struct_cols)} features")
        all_metrics.append(metrics)
        print(f"  F1={metrics['f1']:.4f}  AUC={metrics['roc_auc']:.4f}  FPR={metrics['fpr']:.4f}")
    else:
        print("[SKIP] Structural-only model not found or no structural columns.")

    # ── Load and evaluate semantic-only ───────────────────────────────────────
    sem_model_path  = os.path.join(MODELS_DIR, "semantic_only_model.pkl")
    sem_scaler_path = os.path.join(MODELS_DIR, "semantic_only_scaler.pkl")
    if os.path.exists(sem_model_path) and sem_cols:
        print("\n[Evaluating] Semantic-only...")
        m = joblib.load(sem_model_path)
        s = joblib.load(sem_scaler_path)
        X = test_df[sem_cols].fillna(0).values.astype(np.float32)
        metrics = evaluate(m, s, X, y_test, "Semantic-only", f"{len(sem_cols)} features")
        all_metrics.append(metrics)
        print(f"  F1={metrics['f1']:.4f}  AUC={metrics['roc_auc']:.4f}  FPR={metrics['fpr']:.4f}")
    else:
        print("[SKIP] Semantic-only model not found or no semantic columns.")

    # ── Load and evaluate hybrid ──────────────────────────────────────────────
    hy_model_path  = os.path.join(MODELS_DIR, "hybrid_phishout_model.pkl")
    hy_scaler_path = os.path.join(MODELS_DIR, "hybrid_phishout_scaler.pkl")
    if os.path.exists(hy_model_path) and hybrid_cols:
        print("\n[Evaluating] Hybrid (struct+sem)...")
        m = joblib.load(hy_model_path)
        s = joblib.load(hy_scaler_path)
        X = test_df[hybrid_cols].fillna(0).values.astype(np.float32)
        metrics = evaluate(m, s, X, y_test, "Hybrid (struct+sem)", f"{len(hybrid_cols)} features")
        all_metrics.append(metrics)
        print(f"  F1={metrics['f1']:.4f}  AUC={metrics['roc_auc']:.4f}  FPR={metrics['fpr']:.4f}")
    else:
        print("[SKIP] Hybrid model not found or no columns.")

    if not all_metrics:
        print("\n[ERROR] No models evaluated. Cannot produce comparison table.")
        sys.exit(1)

    # ── Print comparison table ─────────────────────────────────────────────────
    print_table(all_metrics)

    # ── Best model ────────────────────────────────────────────────────────────
    best_m = max(all_metrics, key=lambda m: m["f1"])
    print(f"\n✓ Best model on test set: {best_m['model']}  "
          f"(F1={best_m['f1']:.4f}  AUC={best_m['roc_auc']:.4f})")

    # ── Load calibration results ──────────────────────────────────────────────
    cal_path = os.path.join(MODELS_DIR, "calibration_results.json")
    if os.path.exists(cal_path):
        with open(cal_path) as f:
            cal = json.load(f)
        print(f"\nVerdict thresholds (calibrated):")
        print(f"  SAFE:       risk_score < {cal['calibrated_safe_max_score']}")
        print(f"  SUSPICIOUS: {cal['calibrated_safe_max_score']} ≤ score < {cal['calibrated_phish_min_score']}")
        print(f"  PHISHING:   risk_score ≥ {cal['calibrated_phish_min_score']}")
    else:
        cal = {}

    # ── Save results ──────────────────────────────────────────────────────────
    final_results = {
        "test_set_size": len(test_df),
        "test_benign":   int((y_test == 0).sum()),
        "test_phishing": int((y_test == 1).sum()),
        "all_metrics":   all_metrics,
        "best_model":    best_m["model"],
        "calibration":   cal,
    }
    out_path = os.path.join(MODELS_DIR, "final_evaluation_results.json")
    with open(out_path, "w") as f:
        json.dump(final_results, f, indent=2)
    print(f"\n✓ Final evaluation results saved: {out_path}")

    print("\n" + "=" * 76)
    print("  FINAL EVALUATION COMPLETE")
    print("=" * 76)


if __name__ == "__main__":
    main()
