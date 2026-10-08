"""
PhishOut — Semantic-Only Model Trainer
=======================================
*** LEGACY - DO NOT USE ***
This script expects PhreshPhish dataset features.
The project has moved to Phish360 (local dataset).
See docs/PROJECT_PLAN.md for current direction.

Original purpose:
Trains a semantic-only model using the extracted semantic features
from the PhreshPhish dataset.

Uses only the 12 numeric semantic features (e_* columns) from
train_features.parquet / test_features.parquet.

The best model is saved as:
  models/semantic_model.pkl
  models/semantic_scaler.pkl
  models/semantic_model_results.json

Usage:
    python train_semantic_model.py
"""
import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix,
)
from sklearn.calibration import CalibratedClassifierCV

DATA_DIR   = os.path.join(os.path.dirname(__file__), "dataset", "phreshphish")
MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")
os.makedirs(MODELS_DIR, exist_ok=True)

# Semantic feature columns (e_ prefix = extracted, numeric only)
SEM_FEATURE_COLS = [
    "e_text_length", "e_password_fields", "e_text_email_fields", "e_forms",
    "e_external_links", "e_iframes", "e_scripts",
    "e_login_indicators", "e_credential_indicators", "e_payment_indicators",
    "e_urgency_indicators", "e_brand_indicators",
]


def evaluate(model, scaler, X_test, y_test, name: str) -> dict:
    """Evaluate a fitted model; return metrics dict."""
    X_scaled = scaler.transform(X_test)
    y_pred   = model.predict(X_scaled)
    y_prob   = model.predict_proba(X_scaled)[:, 1]

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    metrics = {
        "model":       name,
        "accuracy":    round(accuracy_score(y_test, y_pred),  4),
        "precision":   round(precision_score(y_test, y_pred), 4),
        "recall":      round(recall_score(y_test, y_pred),    4),
        "f1":          round(f1_score(y_test, y_pred),        4),
        "roc_auc":     round(roc_auc_score(y_test, y_prob),   4),
        "fpr":         round(fp / (fp + tn) if (fp + tn) > 0 else 0, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }
    return metrics


def print_metrics(m: dict):
    print(f"\n  ── {m['model']} ──")
    print(f"    Accuracy    : {m['accuracy']:.4f}")
    print(f"    Precision   : {m['precision']:.4f}")
    print(f"    Recall      : {m['recall']:.4f}")
    print(f"    F1          : {m['f1']:.4f}")
    print(f"    ROC-AUC     : {m['roc_auc']:.4f}")
    print(f"    FPR         : {m['fpr']:.4f}")
    cm = m['confusion_matrix']
    print(f"    Confusion   : TN={cm['tn']}  FP={cm['fp']}  FN={cm['fn']}  TP={cm['tp']}")


def main():
    print("=" * 60)
    print("  PhishOut — Semantic Model Trainer")
    print("=" * 60)

    # ── Load data ─────────────────────────────────────────────────────────────
    train_path = os.path.join(DATA_DIR, "train_features.parquet")
    test_path  = os.path.join(DATA_DIR, "test_features.parquet")

    if not os.path.exists(train_path) or not os.path.exists(test_path):
        print(f"[ERROR] Feature files not found. Run extract_features_phreshphish.py first.")
        sys.exit(1)

    train_df = pd.read_parquet(train_path)
    test_df  = pd.read_parquet(test_path)

    # Check feature availability
    available_sem = [c for c in SEM_FEATURE_COLS if c in train_df.columns]
    missing       = [c for c in SEM_FEATURE_COLS if c not in train_df.columns]
    if missing:
        print(f"[WARNING] Missing semantic columns: {missing}")
    if not available_sem:
        print("[ERROR] No semantic features available. Cannot train.")
        sys.exit(1)

    print(f"\nUsing {len(available_sem)} semantic features: {available_sem}")

    X_train = train_df[available_sem].fillna(0).values.astype(np.float32)
    y_train = train_df["label"].values.astype(int)
    X_test  = test_df[available_sem].fillna(0).values.astype(np.float32)
    y_test  = test_df["label"].values.astype(int)

    print(f"\nTrain: {len(X_train):,} rows  |  label dist: "
          f"benign={int((y_train==0).sum()):,}  phishing={int((y_train==1).sum()):,}")
    print(f"Test:  {len(X_test):,} rows   |  label dist: "
          f"benign={int((y_test==0).sum()):,}  phishing={int((y_test==1).sum()):,}")

    # ── Scale features ─────────────────────────────────────────────────────────
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)

    all_metrics = []
    trained_models = {}

    # ── Model A: Logistic Regression ───────────────────────────────────────────
    print("\n[Training] Logistic Regression...")
    lr = CalibratedClassifierCV(
        LogisticRegression(C=1.0, max_iter=2000, random_state=42),
        method="isotonic", cv=5,
    )
    lr.fit(X_train_s, y_train)
    lr_metrics = evaluate(lr, scaler, X_test, y_test, "Logistic Regression")
    all_metrics.append(lr_metrics)
    trained_models["Logistic Regression"] = lr
    print_metrics(lr_metrics)

    # Feature importance via underlying LR coefficients
    try:
        inner_lr = lr.calibrated_classifiers_[0].estimator
        coefs    = inner_lr.coef_[0]
        feat_imp_lr = sorted(zip(available_sem, coefs), key=lambda x: abs(x[1]), reverse=True)
        print("\n  Top 5 features (LR coefficient magnitude):")
        for feat, coef in feat_imp_lr[:5]:
            print(f"    {feat:35s}: {coef:+.4f}")
        lr_metrics["feature_importance"] = {f: round(float(c), 4) for f, c in feat_imp_lr}
    except Exception:
        pass

    # ── Model B: Random Forest ─────────────────────────────────────────────────
    print("\n[Training] Random Forest...")
    rf = CalibratedClassifierCV(
        RandomForestClassifier(n_estimators=200, max_depth=12,
                               random_state=42, n_jobs=-1),
        method="isotonic", cv=5,
    )
    rf.fit(X_train_s, y_train)
    rf_metrics = evaluate(rf, scaler, X_test, y_test, "Random Forest")
    all_metrics.append(rf_metrics)
    trained_models["Random Forest"] = rf
    print_metrics(rf_metrics)

    # Feature importance from RF
    try:
        inner_rf  = rf.calibrated_classifiers_[0].estimator
        importances = inner_rf.feature_importances_
        feat_imp_rf = sorted(zip(available_sem, importances), key=lambda x: x[1], reverse=True)
        print("\n  Top 5 features (RF importance):")
        for feat, imp in feat_imp_rf[:5]:
            print(f"    {feat:35s}: {imp:.4f}")
        rf_metrics["feature_importance"] = {f: round(float(i), 4) for f, i in feat_imp_rf}
    except Exception:
        pass

    # ── Select best model ──────────────────────────────────────────────────────
    best_name    = max(all_metrics, key=lambda m: m["f1"])["model"]
    best_model   = trained_models[best_name]
    best_metrics = next(m for m in all_metrics if m["model"] == best_name)

    print(f"\n✓ Best semantic model: {best_name}  (F1={best_metrics['f1']:.4f})")

    # ── Save ───────────────────────────────────────────────────────────────────
    sem_model_path  = os.path.join(MODELS_DIR, "semantic_model.pkl")
    sem_scaler_path = os.path.join(MODELS_DIR, "semantic_scaler.pkl")
    joblib.dump(best_model, sem_model_path)
    joblib.dump(scaler,     sem_scaler_path)

    results = {
        "best_model":          best_name,
        "semantic_features":   available_sem,
        "train_size":          len(X_train),
        "test_size":           len(X_test),
        "all_metrics":         all_metrics,
    }
    results_path = os.path.join(MODELS_DIR, "semantic_model_results.json")
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"✓ Model saved    : {sem_model_path}")
    print(f"✓ Scaler saved   : {sem_scaler_path}")
    print(f"✓ Results saved  : {results_path}")

    print("\n" + "=" * 60)
    print("  Semantic model training complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()
