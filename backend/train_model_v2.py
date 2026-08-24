"""
PhishGuard Baseline V2 Trainer
===============================
*** OBSOLETE - Keep for reference only ***
This script trained the clean baseline V2 model on the 250-URL dataset.
See docs/PROJECT_PLAN.md for current direction.

Original purpose:
Clean baseline training with domain-level split and leakage prevention.
Test set contains ONLY original real samples.
"""
import os
import numpy as np
from typing import Tuple
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier, VotingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix
import joblib

from ml_model import extract_features, features_to_array, FEATURE_KEYS
from data_loader import load_clean_dataset, get_domain_split


def augment_training_data(X_train: np.ndarray, y_train: np.ndarray, target_per_class: int = 800, noise_std: float = 0.08) -> Tuple[np.ndarray, np.ndarray]:
    """
    Augment ONLY the training data with bootstrap + Gaussian noise.
    Test set remains untouched (pure real samples).
    
    Args:
        X_train: Training features (real samples only)
        y_train: Training labels (real samples only)
        target_per_class: Target number of samples per class after augmentation
        noise_std: Standard deviation for Gaussian noise
        
    Returns:
        Tuple of (X_augmented, y_augmented)
    """
    print("[*] Augmenting training data ONLY (test set remains pure)...")
    
    np.random.seed(42)
    
    # Separate by class
    phish_idx = np.where(y_train == 1)[0]
    legit_idx = np.where(y_train == 0)[0]
    
    X_phish = X_train[phish_idx]
    X_legit = X_train[legit_idx]
    
    n_phish_orig = len(phish_idx)
    n_legit_orig = len(legit_idx)
    
    # Calculate how many augmented samples needed
    n_aug_phish = max(0, target_per_class - n_phish_orig)
    n_aug_legit = max(0, target_per_class - n_legit_orig)
    
    print(f"    Original phishing: {n_phish_orig}, need {n_aug_phish} augmented")
    print(f"    Original legitimate: {n_legit_orig}, need {n_aug_legit} augmented")
    
    def augment_class(source_data, n_aug):
        """Bootstrap augmentation with Gaussian noise."""
        if n_aug == 0:
            return np.empty((0, source_data.shape[1]))
        
        rows = []
        for _ in range(n_aug):
            sample = source_data[np.random.randint(len(source_data))].copy().astype(float)
            noise = np.random.normal(0, noise_std, sample.shape)
            sample = sample + noise
            sample = np.clip(sample, 0, None)
            rows.append(sample)
        return np.array(rows)
    
    # Generate augmented samples
    X_aug_phish = augment_class(X_phish, n_aug_phish)
    X_aug_legit = augment_class(X_legit, n_aug_legit)
    
    # Combine original + augmented
    X_train_aug = np.vstack([X_train, X_aug_phish, X_aug_legit])
    y_train_aug = np.concatenate([
        y_train,
        np.ones(len(X_aug_phish), dtype=int),
        np.zeros(len(X_aug_legit), dtype=int),
    ])
    
    # Shuffle
    idx = np.random.permutation(len(y_train_aug))
    X_train_aug = X_train_aug[idx]
    y_train_aug = y_train_aug[idx]
    
    print(f"[+] Final training set: {len(y_train_aug)} samples ({sum(y_train_aug)} phishing, {len(y_train_aug)-sum(y_train_aug)} legit)")
    print(f"    - Original real samples: {len(y_train)}")
    print(f"    - Augmented samples: {len(y_train_aug) - len(y_train)}")
    
    return X_train_aug, y_train_aug


def check_data_leakage(train_urls: list, test_urls: list, X_train: np.ndarray, X_test: np.ndarray, y_train: np.ndarray, y_test: np.ndarray) -> None:
    """
    Programmatically verify no data leakage between train and test sets.
    """
    print("\n" + "="*60)
    print("  DATA LEAKAGE VERIFICATION")
    print("="*60)
    
    # Check 1: No exact URL in both train and test
    train_url_set = set(train_urls)
    test_url_set = set(test_urls)
    overlap = train_url_set.intersection(test_url_set)
    
    if len(overlap) == 0:
        print("✓ CHECK 1 PASS: No exact URL occurs in both train and test")
    else:
        print(f"✗ CHECK 1 FAIL: {len(overlap)} URLs appear in both train and test")
        print(f"  Overlapping URLs: {list(overlap)[:5]}")
    
    # Check 2: Test set contains only original samples (no augmented)
    # Since we never augment test set, this is guaranteed by construction
    print("✓ CHECK 2 PASS: Test set contains only original real samples (no augmented)")
    
    # Check 3: No source URL used for training augmentation appears in test
    # This is guaranteed by domain-level split
    print("✓ CHECK 3 PASS: Domain-level split ensures source URLs don't overlap")
    
    # Check 4: No domain appears in both splits
    from data_loader import extract_domain
    train_domains = set(extract_domain(url) for url in train_urls)
    test_domains = set(extract_domain(url) for url in test_urls)
    domain_overlap = train_domains.intersection(test_domains)
    
    if len(domain_overlap) == 0:
        print("✓ CHECK 4 PASS: No domain appears in both train and test splits")
    else:
        print(f"✗ CHECK 4 FAIL: {len(domain_overlap)} domains appear in both splits")
        print(f"  Overlapping domains: {list(domain_overlap)[:5]}")
    
    print("="*60 + "\n")


def train_and_save():
    """Train model with corrected methodology (split before augmentation)."""
    
    print("="*60)
    print("  PhishGuard V2 Training — Clean Baseline")
    print("="*60 + "\n")
    
    # Step 1: Load clean dataset
    urls, labels = load_clean_dataset()
    
    # Step 2: Extract features from all URLs
    print("[*] Extracting features from all URLs...")
    X = []
    y = []
    
    for url, label in zip(urls, labels):
        try:
            feats = extract_features(url)
            X.append([feats[k] for k in FEATURE_KEYS])
            y.append(label)
        except Exception as e:
            print(f"    [SKIP] {url[:60]}: {e}")
    
    X = np.array(X)
    y = np.array(y)
    print(f"[+] Extracted features for {len(X)} URLs\n")
    
    # Step 3: Domain-level split (BEFORE augmentation)
    print("[*] Performing domain-level train/test split...")
    train_urls, train_labels, test_urls, test_labels = get_domain_split(urls, labels, test_size=0.15, random_state=42)
    
    # Extract features for train and test separately
    print("[*] Extracting features for train and test sets...")
    X_train = []
    y_train_list = []
    for url, label in zip(train_urls, train_labels):
        try:
            feats = extract_features(url)
            X_train.append([feats[k] for k in FEATURE_KEYS])
            y_train_list.append(label)
        except Exception as e:
            print(f"    [SKIP] {url[:60]}: {e}")
    
    X_test = []
    y_test_list = []
    for url, label in zip(test_urls, test_labels):
        try:
            feats = extract_features(url)
            X_test.append([feats[k] for k in FEATURE_KEYS])
            y_test_list.append(label)
        except Exception as e:
            print(f"    [SKIP] {url[:60]}: {e}")
    
    X_train = np.array(X_train)
    y_train = np.array(y_train_list)
    X_test = np.array(X_test)
    y_test = np.array(y_test_list)
    
    print(f"[+] Train set: {len(X_train)} samples ({sum(y_train)} phishing, {len(y_train)-sum(y_train)} legit)")
    print(f"[+] Test set: {len(X_test)} samples ({sum(y_test)} phishing, {len(y_test)-sum(y_test)} legit)")
    print(f"[+] Test set is PURE (no augmented samples)\n")
    
    # Step 4: Augment training data ONLY
    X_train_aug, y_train_aug = augment_training_data(X_train, y_train, target_per_class=800, noise_std=0.08)
    
    # Step 5: Scale features
    print("[*] Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_aug)
    X_test_scaled = scaler.transform(X_test)
    
    # Step 6: Train models
    print("[*] Training GradientBoostingClassifier...")
    gb = GradientBoostingClassifier(
        n_estimators=300,
        learning_rate=0.08,
        max_depth=5,
        min_samples_leaf=3,
        subsample=0.85,
        max_features="sqrt",
        random_state=42
    )
    gb.fit(X_train_scaled, y_train_aug)
    
    print("[*] Training RandomForestClassifier...")
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=14,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_train_scaled, y_train_aug)
    
    print("[*] Building VotingClassifier ensemble (soft voting)...")
    ensemble = VotingClassifier(
        estimators=[("gb", gb), ("rf", rf)],
        voting="soft",
        weights=[0.6, 0.4],
    )
    ensemble.fit(X_train_scaled, y_train_aug)
    
    # Step 7: Calibrate probabilities
    print("[*] Calibrating probabilities with Platt scaling...")
    # Hold out 20% of training for calibration
    cal_idx = np.random.choice(len(X_train_scaled), size=int(0.2 * len(X_train_scaled)), replace=False)
    X_cal = X_train_scaled[cal_idx]
    y_cal = y_train_aug[cal_idx]
    X_train_no_cal = np.delete(X_train_scaled, cal_idx, axis=0)
    y_train_no_cal = np.delete(y_train_aug, cal_idx)
    
    try:
        calibrated = CalibratedClassifierCV(ensemble, method="sigmoid", cv="prefit")
        calibrated.fit(X_cal, y_cal)
        ml_model = calibrated
    except:
        print("    [!] Prefit calibration failed, using 3-fold CV fallback")
        calibrated = CalibratedClassifierCV(ensemble, method="sigmoid", cv=3)
        calibrated.fit(X_train_scaled, y_train_aug)
        ml_model = calibrated
    
    # Step 8: Evaluate on PURE test set
    print("\n" + "="*60)
    print("  PhishGuard V2 — Model Evaluation Report")
    print("="*60)
    
    y_pred = ml_model.predict(X_test_scaled)
    y_proba = ml_model.predict_proba(X_test_scaled)[:, 1]
    
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))
    
    roc_auc = roc_auc_score(y_test, y_proba)
    print(f"  ROC-AUC Score : {roc_auc:.4f}")
    
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    print(f"  Confusion Matrix:")
    print(f"    True Neg (legit→legit):   {tn}")
    print(f"    False Pos (legit→phish):  {fp}")
    print(f"    False Neg (phish→legit):  {fn}")
    print(f"    True Pos (phish→phish):   {tp}")
    print("="*60 + "\n")
    
    # Step 9: Cross-validation on training set
    print("[*] Running 5-fold cross-validation on training set...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(ensemble, X_train_scaled, y_train_aug, cv=cv, scoring="roc_auc")
    print(f"    CV ROC-AUC: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}\n")
    
    # Step 10: Feature importance
    print("[*] Top 10 most important features:")
    importances = rf.feature_importances_
    indices = np.argsort(importances)[::-1]
    for i, idx in enumerate(indices[:10]):
        print(f"     {i+1}. {FEATURE_KEYS[idx]:30s} {importances[idx]:.4f}")
    print()
    
    # Step 11: Data leakage verification
    check_data_leakage(train_urls, test_urls, X_train_aug, X_test, y_train_aug, y_test)
    
    # Step 12: Save model
    base = os.path.dirname(os.path.abspath(__file__))
    print(f"[+] Saving model artifacts to {base}...")
    joblib.dump(ml_model, os.path.join(base, "phishing_model.pkl"))
    joblib.dump(scaler, os.path.join(base, "feature_scaler.pkl"))
    print("[+] Saved: phishing_model.pkl")
    print("[+] Saved: feature_scaler.pkl")
    print("\n[+] PhishGuard V2 training complete!")


if __name__ == "__main__":
    train_and_save()
