"""
Phish360 Semantic-Only Model Trainer
=====================================
Trains a semantic-only model using the 12 semantic features from Phish360.

This is part of Phase 2 - Model Development for the PhishOut research project.

Usage:
    python train_phish360_semantic.py
"""
import os
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

# Paths
DATA_DIR = os.path.join(os.path.dirname(__file__), "dataset", "phish360", "processed")
MODELS_DIR = os.path.join(os.path.dirname(__file__), "models", "phish360")
os.makedirs(MODELS_DIR, exist_ok=True)

# Semantic feature column names (12 features)
SEMANTIC_FEATURES = [
    'password_fields', 'text_email_fields', 'forms', 'external_links',
    'iframes', 'scripts', 'login_indicators', 'credential_indicators',
    'payment_indicators', 'urgency_indicators', 'brand_indicators', 'text_length'
]


def evaluate_model(model, scaler, X_test, y_test, model_name):
    """Evaluate model and return metrics dict."""
    X_scaled = scaler.transform(X_test)
    y_pred = model.predict(X_scaled)
    y_prob = model.predict_proba(X_scaled)[:, 1]

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    return {
        "model": model_name,
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred), 4),
        "recall": round(recall_score(y_test, y_pred), 4),
        "f1": round(f1_score(y_test, y_pred), 4),
        "roc_auc": round(roc_auc_score(y_test, y_prob), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def print_metrics(metrics):
    """Print evaluation metrics."""
    print(f"\n  {metrics['model']} Results:")
    print(f"    Accuracy:  {metrics['accuracy']:.4f}")
    print(f"    Precision: {metrics['precision']:.4f}")
    print(f"    Recall:    {metrics['recall']:.4f}")
    print(f"    F1:        {metrics['f1']:.4f}")
    print(f"    ROC-AUC:   {metrics['roc_auc']:.4f}")
    cm = metrics['confusion_matrix']
    print(f"    Confusion: TN={cm['tn']}, FP={cm['fp']}, FN={cm['fn']}, TP={cm['tp']}")


def main():
    print("=" * 70)
    print("  Phish360 Semantic-Only Model Training")
    print("=" * 70)

    # Load datasets
    train_path = os.path.join(DATA_DIR, "train_features.parquet")
    val_path = os.path.join(DATA_DIR, "validation_features.parquet")
    test_path = os.path.join(DATA_DIR, "test_features.parquet")

    if not all(os.path.exists(p) for p in [train_path, val_path, test_path]):
        print("[ERROR] Phish360 feature files not found.")
        print(f"Expected: {train_path}, {val_path}, {test_path}")
        return

    train_df = pd.read_parquet(train_path)
    val_df = pd.read_parquet(val_path)
    test_df = pd.read_parquet(test_path)

    print(f"\nDataset sizes:")
    print(f"  Train:      {len(train_df):,} samples")
    print(f"  Validation: {len(val_df):,} samples")
    print(f"  Test:       {len(test_df):,} samples")

    # Extract semantic features
    X_train = train_df[SEMANTIC_FEATURES].fillna(0).values.astype(np.float32)
    y_train = train_df['label'].values.astype(int)

    X_val = val_df[SEMANTIC_FEATURES].fillna(0).values.astype(np.float32)
    y_val = val_df['label'].values.astype(int)

    X_test = test_df[SEMANTIC_FEATURES].fillna(0).values.astype(np.float32)
    y_test = test_df['label'].values.astype(int)

    print(f"\nSemantic features: {len(SEMANTIC_FEATURES)}")
    print(f"  Train distribution:      Legit={sum(y_train==0):,}, Phish={sum(y_train==1):,}")
    print(f"  Validation distribution: Legit={sum(y_val==0):,}, Phish={sum(y_val==1):,}")
    print(f"  Test distribution:       Legit={sum(y_test==0):,}, Phish={sum(y_test==1):,}")

    # Scale features
    print("\n[*] Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)

    # Build classifier
    print("[*] Training GradientBoostingClassifier...")
    gb = GradientBoostingClassifier(
        n_estimators=200,
        learning_rate=0.1,
        max_depth=4,
        min_samples_leaf=2,
        subsample=0.8,
        max_features="sqrt",
        random_state=42
    )

    print("[*] Training RandomForestClassifier...")
    rf = RandomForestClassifier(
        n_estimators=150,
        max_depth=10,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    print("[*] Building VotingClassifier ensemble...")
    ensemble = VotingClassifier(
        estimators=[("gb", gb), ("rf", rf)],
        voting="soft",
        weights=[0.6, 0.4],
    )

    # Train on training set
    print("[*] Training ensemble on training set...")
    ensemble.fit(X_train_scaled, y_train)

    # Calibrate probabilities using validation set
    print("[*] Calibrating probabilities using validation set...")
    try:
        calibrated = CalibratedClassifierCV(ensemble, method="sigmoid", cv="prefit")
        calibrated.fit(X_val_scaled, y_val)
    except Exception as e:
        print(f"[!] Prefit calibration failed: {e}, using 3-fold CV fallback")
        calibrated = CalibratedClassifierCV(ensemble, method="sigmoid", cv=3)
        calibrated.fit(X_train_scaled, y_train)

    # Evaluate on validation set
    print("\n" + "=" * 70)
    print("  Validation Set Evaluation")
    print("=" * 70)
    val_metrics = evaluate_model(calibrated, scaler, X_val, y_val, "Semantic-Only (Validation)")
    print_metrics(val_metrics)

    # Evaluate on test set (final evaluation, not used for decisions)
    print("\n" + "=" * 70)
    print("  Test Set Evaluation (Final)")
    print("=" * 70)
    test_metrics = evaluate_model(calibrated, scaler, X_test, y_test, "Semantic-Only (Test)")
    print_metrics(test_metrics)

    # Save model and scaler
    model_path = os.path.join(MODELS_DIR, "semantic_model.pkl")
    scaler_path = os.path.join(MODELS_DIR, "semantic_scaler.pkl")

    joblib.dump(calibrated, model_path)
    joblib.dump(scaler, scaler_path)

    print(f"\n[+] Model saved:  {model_path}")
    print(f"[+] Scaler saved: {scaler_path}")

    # Save results
    results = {
        "model_type": "semantic_only",
        "features": SEMANTIC_FEATURES,
        "n_features": len(SEMANTIC_FEATURES),
        "train_size": len(X_train),
        "validation_size": len(X_val),
        "test_size": len(X_test),
        "validation_metrics": val_metrics,
        "test_metrics": test_metrics,
    }

    results_path = os.path.join(MODELS_DIR, "semantic_results.json")
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"[+] Results saved: {results_path}")

    print("\n" + "=" * 70)
    print("  Semantic-only model training complete.")
    print("=" * 70)


if __name__ == "__main__":
    main()