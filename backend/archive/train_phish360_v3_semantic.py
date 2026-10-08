"""
Phish360 V3 Semantic Model Trainer
===================================
Trains a semantic model using 19 semantic features (15 V2 + 4 new V3 features) from Phish360 V3.

V3 Changes:
- Added 4 new features: link_to_form_ratio, text_to_script_ratio, credential_density, brand_context_score
- Total semantic features: 19 (was 15 in V2)
- Uses augmented training set with hard negatives (8,330 samples vs 7,730 in V2)

Usage:
    python train_phish360_v3_semantic.py
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

# Paths - V3 specific
DATA_DIR = os.path.join(os.path.dirname(__file__), "dataset", "phish360", "v3", "processed")
MODELS_DIR = os.path.join(os.path.dirname(__file__), "models", "phish360_v3")
os.makedirs(MODELS_DIR, exist_ok=True)

# Semantic feature column names (V3: 19 features including 4 new)
SEMANTIC_FEATURES = [
    'password_fields', 'text_email_fields', 'forms', 'external_links',
    'iframes', 'scripts', 'login_indicators', 'credential_indicators',
    'payment_indicators', 'urgency_indicators', 'brand_indicators', 'text_length',
    # V2 context features
    'domain_brand_consistency', 'form_action_same_origin', 'trusted_domain',
    # V3 new features
    'link_to_form_ratio', 'text_to_script_ratio', 'credential_density', 'brand_context_score'
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
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred),
        "recall": recall_score(y_test, y_pred),
        "f1": f1_score(y_test, y_pred),
        "roc_auc": roc_auc_score(y_test, y_prob),
        "confusion_matrix": {
            "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)
        },
        "false_positive_rate": fp / (tn + fp) if (tn + fp) > 0 else 0,
        "false_negative_rate": fn / (fn + tp) if (fn + tp) > 0 else 0,
    }


def main():
    """Train V3 semantic model with hard-negative augmentation."""
    
    print("=" * 80)
    print("V3 Step 4: Training V3 Semantic Model (19 features)")
    print("=" * 80)
    
    # Load augmented training set
    print("\nLoading augmented V3 training set...")
    train_df = pd.read_parquet(os.path.join(DATA_DIR, "train_features_augmented.parquet"))
    print(f"Training samples: {len(train_df):,}")
    
    # Load validation set (original V2 validation, not augmented)
    print("Loading validation set...")
    val_df = pd.read_parquet(os.path.join(DATA_DIR, "validation_features.parquet"))
    # Remove non-numeric columns like in training set
    non_numeric_cols = ['sample_id', 'url', 'domain', 'page_title', 'form_actions']
    cols_to_drop = [col for col in non_numeric_cols if col in val_df.columns and col != 'label']
    if cols_to_drop:
        val_df = val_df.drop(columns=cols_to_drop)
    val_df = val_df.fillna(0)
    print(f"Validation samples: {len(val_df):,}")
    
    # Load test set (original V2 test, not augmented)
    print("Loading test set...")
    test_df = pd.read_parquet(os.path.join(DATA_DIR, "test_features.parquet"))
    # Remove non-numeric columns like in training set
    cols_to_drop = [col for col in non_numeric_cols if col in test_df.columns and col != 'label']
    if cols_to_drop:
        test_df = test_df.drop(columns=cols_to_drop)
    test_df = test_df.fillna(0)
    print(f"Test samples: {len(test_df):,}")
    
    # Extract features and labels
    print("\nExtracting semantic features...")
    
    # Check which semantic features are available
    available_features = [f for f in SEMANTIC_FEATURES if f in train_df.columns]
    missing_features = [f for f in SEMANTIC_FEATURES if f not in train_df.columns]
    
    if missing_features:
        print(f"Warning: Missing semantic features: {missing_features}")
        print(f"Using available features: {available_features}")
    
    X_train = train_df[available_features].values
    y_train = train_df['label'].values
    
    # Ensure we have both classes
    print(f"Training label distribution: {np.bincount(y_train.astype(int))}")
    if len(np.unique(y_train)) < 2:
        raise ValueError("Training data contains only one class. Need both legitimate (0) and phishing (1).")
    
    X_val = val_df[available_features].values
    y_val = val_df['label'].values
    
    X_test = test_df[available_features].values
    y_test = test_df['label'].values
    
    print(f"Feature count: {len(available_features)}")
    print(f"Training samples: {len(X_train):,}")
    print(f"Validation samples: {len(X_val):,}")
    print(f"Test samples: {len(X_test):,}")
    
    # Scale features
    print("\nScaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)
    
    # Train base models (same architecture as V2)
    print("\nTraining base models...")
    
    gb_model = GradientBoostingClassifier(
        n_estimators=300,
        learning_rate=0.1,
        max_depth=5,
        random_state=42
    )
    
    rf_model = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        random_state=42
    )
    
    print("Training GradientBoostingClassifier...")
    gb_model.fit(X_train_scaled, y_train)
    
    print("Training RandomForestClassifier...")
    rf_model.fit(X_train_scaled, y_train)
    
    # Create voting classifier
    print("\nCreating VotingClassifier...")
    voting_model = VotingClassifier(
        estimators=[
            ('gb', gb_model),
            ('rf', rf_model)
        ],
        voting='soft'
    )
    
    print("Training VotingClassifier...")
    voting_model.fit(X_train_scaled, y_train)
    
    # Calibrate the model (fit on validation set for calibration)
    print("\nCalibrating model...")
    calibrated_model = CalibratedClassifierCV(voting_model, cv=5, method='sigmoid')
    calibrated_model.fit(X_train_scaled, y_train)
    
    # Evaluate on all sets
    print("\n" + "=" * 80)
    print("Model Evaluation")
    print("=" * 80)
    
    train_metrics = evaluate_model(calibrated_model, scaler, X_train, y_train, "V3 Semantic (Train)")
    val_metrics = evaluate_model(calibrated_model, scaler, X_val, y_val, "V3 Semantic (Validation)")
    test_metrics = evaluate_model(calibrated_model, scaler, X_test, y_test, "V3 Semantic (Test)")
    
    print(f"\n{train_metrics['model']}:")
    print(f"  Accuracy: {train_metrics['accuracy']:.4f}")
    print(f"  Precision: {train_metrics['precision']:.4f}")
    print(f"  Recall: {train_metrics['recall']:.4f}")
    print(f"  F1: {train_metrics['f1']:.4f}")
    print(f"  ROC-AUC: {train_metrics['roc_auc']:.4f}")
    
    print(f"\n{val_metrics['model']}:")
    print(f"  Accuracy: {val_metrics['accuracy']:.4f}")
    print(f"  Precision: {val_metrics['precision']:.4f}")
    print(f"  Recall: {val_metrics['recall']:.4f}")
    print(f"  F1: {val_metrics['f1']:.4f}")
    print(f"  ROC-AUC: {val_metrics['roc_auc']:.4f}")
    
    print(f"\n{test_metrics['model']}:")
    print(f"  Accuracy: {test_metrics['accuracy']:.4f}")
    print(f"  Precision: {test_metrics['precision']:.4f}")
    print(f"  Recall: {test_metrics['recall']:.4f}")
    print(f"  F1: {test_metrics['f1']:.4f}")
    print(f"  ROC-AUC: {test_metrics['roc_auc']:.4f}")
    print(f"  FPR: {test_metrics['false_positive_rate']:.4f}")
    print(f"  FNR: {test_metrics['false_negative_rate']:.4f}")
    
    # Save model and artifacts
    print("\n" + "=" * 80)
    print("Saving V3 Semantic Model")
    print("=" * 80)
    
    model_path = os.path.join(MODELS_DIR, "semantic_model.pkl")
    scaler_path = os.path.join(MODELS_DIR, "semantic_scaler.pkl")
    results_path = os.path.join(MODELS_DIR, "semantic_results.json")
    
    joblib.dump(calibrated_model, model_path)
    joblib.dump(scaler, scaler_path)
    
    results = {
        "model_type": "V3 Semantic (19 features)",
        "training_data": "Augmented with hard negatives (8,330 samples)",
        "feature_count": len(available_features),
        "semantic_features": available_features,
        "training_metrics": train_metrics,
        "validation_metrics": val_metrics,
        "test_metrics": test_metrics,
        "hard_negative_augmentation": {
            "original_samples": 7730,
            "hard_negative_samples": 600,
            "total_samples": 8330,
            "augmentation_percentage": 7.2
        }
    }
    
    with open(results_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"Saved model: {model_path}")
    print(f"Saved scaler: {scaler_path}")
    print(f"Saved results: {results_path}")
    
    print("\n" + "=" * 80)
    print("V3 Semantic Model Training Complete")
    print("=" * 80)
    print(f"Final Test F1: {test_metrics['f1']:.4f}")
    print(f"Final Test ROC-AUC: {test_metrics['roc_auc']:.4f}")
    print(f"Test FPR: {test_metrics['false_positive_rate']:.4f}")
    print("=" * 80)


if __name__ == "__main__":
    main()
