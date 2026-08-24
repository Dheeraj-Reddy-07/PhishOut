"""
PhishOut — Hybrid Model Trainer
==================================
*** LEGACY - DO NOT USE ***
This script expects PhreshPhish dataset features.
The project has moved to Phish360 (local dataset).
See docs/PROJECT_PLAN.md for current direction.

Original purpose:
Trains and compares three models on the SAME train/test split:

  A. Structural-only (32 structural features, s_* columns)
  B. Semantic-only   (12 semantic features,   e_* columns)
  C. Hybrid          (32 + 12 = 44 features,  all numeric)

All three are evaluated on the SAME untouched test set.

Best-performing model (by F1) is saved as:
  models/structural_only_model.pkl   (replaces Phase 1 model)
  models/structural_only_scaler.pkl
  models/hybrid_phishout_model.pkl   (hybrid model)
  models/hybrid_phishout_scaler.pkl
  models/comparison_results_phreshphish.json

Usage:
    python train_hybrid_model.py
"""
import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier, VotingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix,
)

DATA_DIR   = os.path.join(os.path.dirname(__file__), "dataset", "phreshphish")
MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")
os.makedirs(MODELS_DIR, exist_ok=True)


# ── Feature column selection helpers ─────────────────────────────────────────

def get_struct_cols(df: pd.DataFrame) -> list:
    return [c for c in df.columns if c.startswith("s_")]


def get_sem_cols(df: pd.DataFrame) -> list:
    return [c for c in df.columns if c.startswith("e_")]


def get_hybrid_cols(df: pd.DataFrame) -> list:
    return get_struct_cols(df) + get_sem_cols(df)


# ── Classifier factory ────────────────────────────────────────────────────────

def build_classifier() -> CalibratedClassifierCV:
    """Build the GBM+RF VotingClassifier with probability calibration."""
    gbc = GradientBoostingClassifier(
        n_estimators=150, max_depth=5, learning_rate=0.1,
        random_state=42,
    )
    rfc = RandomForestClassifier(
        n_estimators=150, max_depth=12, random_state=42, n_jobs=-1,
    )
    voting = VotingClassifier(
        estimators=[("gbc", gbc), ("rfc", rfc)],
        voting="soft",
    )
    return CalibratedClassifierCV(voting, method="sigmoid", cv=5)


# ── Evaluation ────────────────────────────────────────────────────────────────

def evaluate(model, scaler, X_test: np.ndarray, y_test: np.ndarray, name: str) -> dict:
    X_s     = scaler.transform(X_test)
    y_pred  = model.predict(X_s)
    y_prob  = model.predict_proba(X_s)[:, 1]

    cm      = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    return {
        "model":     name,
        "accuracy":  round(accuracy_score(y_test, y_pred),  4),
        "precision": round(precision_score(y_test, y_pred), 4),
        "recall":    round(recall_score(y_test, y_pred),    4),
        "f1":        round(f1_score(y_test, y_pred),        4),
        "roc_auc":   round(roc_auc_score(y_test, y_prob),   4),
        "fpr":       round(fp / (fp + tn) if (fp + tn) > 0 else 0, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def print_metrics(m: dict):
    print(f"\n  ── {m['model']} ──")
    print(f"    Accuracy  : {m['accuracy']:.4f}")
    print(f"    Precision : {m['precision']:.4f}")
    print(f"    Recall    : {m['recall']:.4f}")
    print(f"    F1        : {m['f1']:.4f}")
    print(f"    ROC-AUC   : {m['roc_auc']:.4f}")
    print(f"    FPR       : {m['fpr']:.4f}")
    cm = m["confusion_matrix"]
    print(f"    Confusion : TN={cm['tn']}  FP={cm['fp']}  FN={cm['fn']}  TP={cm['tp']}")


def print_comparison_table(metrics: list):
    print("\n" + "=" * 70)
    print(f"  {'Model':<22} {'Acc':>6} {'Prec':>6} {'Rec':>6} {'F1':>6} {'AUC':>6} {'FPR':>6}")
    print("  " + "─" * 66)
    for m in metrics:
        print(f"  {m['model']:<22} {m['accuracy']:>6.4f} {m['precision']:>6.4f} "
              f"{m['recall']:>6.4f} {m['f1']:>6.4f} {m['roc_auc']:>6.4f} {m['fpr']:>6.4f}")
    print("=" * 70)


def train_model(name: str, cols: list, train_df: pd.DataFrame,
                X_test: np.ndarray, y_test: np.ndarray) -> tuple:
    """Train one model on given feature columns. Returns (model, scaler, metrics)."""
    print(f"\n[Training] {name}  ({len(cols)} features)...")

    X_train = train_df[cols].fillna(0).values.astype(np.float32)
    y_train = train_df["label"].values.astype(int)

    scaler    = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)

    model = build_classifier()
    model.fit(X_train_s, y_train)

    metrics = evaluate(model, scaler, X_test, y_test, name)
    print_metrics(metrics)

    return model, scaler, metrics


def main():
    print("=" * 70)
    print("  PhishOut — Hybrid Model Trainer (3-model comparison)")
    print("=" * 70)

    # ── Load data ─────────────────────────────────────────────────────────────
    train_path = os.path.join(DATA_DIR, "train_features.parquet")
    test_path  = os.path.join(DATA_DIR, "test_features.parquet")

    if not os.path.exists(train_path) or not os.path.exists(test_path):
        print("[ERROR] Feature files not found. Run extract_features_phreshphish.py first.")
        sys.exit(1)

    train_df = pd.read_parquet(train_path)
    test_df  = pd.read_parquet(test_path)

    struct_cols = get_struct_cols(train_df)
    sem_cols    = get_sem_cols(train_df)
    hybrid_cols = get_hybrid_cols(train_df)

    print(f"\nDataset: train={len(train_df):,}  test={len(test_df):,}")
    print(f"Structural features : {len(struct_cols)}")
    print(f"Semantic features   : {len(sem_cols)}")
    print(f"Hybrid features     : {len(hybrid_cols)}")

    y_test = test_df["label"].values.astype(int)

    all_metrics  = []
    saved_models = {}

    # ── Model A: Structural-only ───────────────────────────────────────────────
    if struct_cols:
        X_test_s  = test_df[struct_cols].fillna(0).values.astype(np.float32)
        struct_model, struct_scaler, struct_metrics = train_model(
            "Structural-only", struct_cols, train_df, X_test_s, y_test
        )
        all_metrics.append(struct_metrics)
        saved_models["structural"] = (struct_model, struct_scaler)

    # ── Model B: Semantic-only ─────────────────────────────────────────────────
    if sem_cols:
        X_test_e = test_df[sem_cols].fillna(0).values.astype(np.float32)
        sem_model, sem_scaler, sem_metrics = train_model(
            "Semantic-only", sem_cols, train_df, X_test_e, y_test
        )
        all_metrics.append(sem_metrics)
        saved_models["semantic"] = (sem_model, sem_scaler)

    # ── Model C: Hybrid ────────────────────────────────────────────────────────
    if hybrid_cols:
        X_test_h = test_df[hybrid_cols].fillna(0).values.astype(np.float32)
        hybrid_model, hybrid_scaler, hybrid_metrics = train_model(
            "Hybrid (struct+sem)", hybrid_cols, train_df, X_test_h, y_test
        )
        all_metrics.append(hybrid_metrics)
        saved_models["hybrid"] = (hybrid_model, hybrid_scaler)

    # ── Comparison table ───────────────────────────────────────────────────────
    print_comparison_table(all_metrics)

    # ── Determine best model ───────────────────────────────────────────────────
    best_metrics = max(all_metrics, key=lambda m: m["f1"])
    best_name    = best_metrics["model"]
    print(f"\n✓ Best model by F1: {best_name}  (F1={best_metrics['f1']:.4f})")

    if "Hybrid" in best_name:
        print("  → Hybrid outperforms structural-only. PhishOut will use the hybrid model.")
        winner_key = "hybrid"
    elif "Structural" in best_name:
        print("  → Structural-only is best. PhishOut will keep the structural model as primary.")
        winner_key = "structural"
    else:
        print("  → Semantic-only is best (unexpected). Defaulting to structural for safety.")
        winner_key = "structural"

    # ── Save all models ────────────────────────────────────────────────────────
    if "structural" in saved_models:
        joblib.dump(saved_models["structural"][0], os.path.join(MODELS_DIR, "structural_only_model.pkl"))
        joblib.dump(saved_models["structural"][1], os.path.join(MODELS_DIR, "structural_only_scaler.pkl"))
        print(f"  ✓ Saved structural_only_model.pkl")

    if "semantic" in saved_models:
        joblib.dump(saved_models["semantic"][0], os.path.join(MODELS_DIR, "semantic_only_model.pkl"))
        joblib.dump(saved_models["semantic"][1], os.path.join(MODELS_DIR, "semantic_only_scaler.pkl"))
        print(f"  ✓ Saved semantic_only_model.pkl")

    if "hybrid" in saved_models:
        joblib.dump(saved_models["hybrid"][0], os.path.join(MODELS_DIR, "hybrid_phishout_model.pkl"))
        joblib.dump(saved_models["hybrid"][1], os.path.join(MODELS_DIR, "hybrid_phishout_scaler.pkl"))
        print(f"  ✓ Saved hybrid_phishout_model.pkl")

    # Save the winner's feature columns so predictor knows what to load
    winner_model, winner_scaler = saved_models[winner_key]
    winner_cols = struct_cols if winner_key == "structural" else (
                  sem_cols    if winner_key == "semantic"   else hybrid_cols)

    joblib.dump(winner_model,  os.path.join(MODELS_DIR, "phishout_best_model.pkl"))
    joblib.dump(winner_scaler, os.path.join(MODELS_DIR, "phishout_best_scaler.pkl"))
    with open(os.path.join(MODELS_DIR, "phishout_best_config.json"), "w") as f:
        json.dump({
            "winner_type":         winner_key,
            "feature_columns":     winner_cols,
            "struct_cols":         struct_cols,
            "sem_cols":            sem_cols,
            "hybrid_cols":         hybrid_cols,
            "best_model_name":     best_name,
            "best_f1":             best_metrics["f1"],
        }, f, indent=2)
    print(f"  ✓ Saved phishout_best_model.pkl (type={winner_key})")

    # Save comparison results
    results = {
        "winner":            best_name,
        "winner_type":       winner_key,
        "train_size":        len(train_df),
        "test_size":         len(test_df),
        "struct_features":   len(struct_cols),
        "sem_features":      len(sem_cols),
        "hybrid_features":   len(hybrid_cols),
        "all_metrics":       all_metrics,
    }
    results_path = os.path.join(MODELS_DIR, "comparison_results_phreshphish.json")
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"  ✓ Saved comparison_results_phreshphish.json")

    print("\n" + "=" * 70)
    print("  Hybrid model training complete.")
    print("=" * 70)


if __name__ == "__main__":
    main()
