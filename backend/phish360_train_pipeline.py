"""
PhishOut — Phase 2 Complete Training Pipeline (Phish360)
=========================================================
Runs the full research pipeline:
  1. Load & process Phish360 Parquet data
  2. Create leakage-free train/validation/test splits
  3. Extract 32 structural + 12 semantic features
  4. Save processed feature parquet files
  5. Train Model 1: Structural-only (32 features)
  6. Train Model 2: Semantic-only (12 features)
  7. Train Model 3: Hybrid (44 features)
  8. Train Model 4: Learned score-level fusion (Logistic Regression)
  9. Calibrate classification thresholds on validation set
  10. Final test evaluation (one-time, post-freeze)
  11. Save all artifacts + final report

Architecture:
  URL → 32 structural features → structural_model → p_struct
  HTML → 12 semantic features → semantic_model → p_sem
  [p_struct, p_sem] → LogisticRegression fusion → p_fusion → risk score

  Separately:
  [32 struct + 12 sem = 44 features] → hybrid_model → p_hybrid

Usage:
    cd backend
    python phish360_train_pipeline.py

Output:
    backend/dataset/phish360/processed/train_features.parquet
    backend/dataset/phish360/processed/validation_features.parquet
    backend/dataset/phish360/processed/test_features.parquet
    backend/models/phish360/structural_model.pkl
    backend/models/phish360/structural_scaler.pkl
    backend/models/phish360/semantic_model.pkl
    backend/models/phish360/semantic_scaler.pkl
    backend/models/phish360/hybrid_model.pkl
    backend/models/phish360/hybrid_scaler.pkl
    backend/models/phish360/fusion_model.pkl
    backend/models/phish360/fusion_config.json
    backend/models/phish360/val_predictions.json
    backend/models/phish360/test_results.json
    docs/model_training_report.md
"""
import os
import sys
import json
import time
import joblib
import numpy as np
import pandas as pd

from pathlib import Path
from datetime import datetime

# scikit-learn
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, average_precision_score,
    confusion_matrix,
)

# Add backend dir to path
_BACKEND = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _BACKEND)

from ml_model import extract_features, FEATURE_KEYS
from webpage_analyzer import extract_semantic_features_from_html

# ── Constants ─────────────────────────────────────────────────────────────────

PHISH360_SRC     = "D:/Downloads/phish360_parquet"
PROCESSED_DIR    = os.path.join(_BACKEND, "dataset", "phish360", "processed")
MODELS_DIR       = os.path.join(_BACKEND, "models", "phish360")
DOCS_DIR         = os.path.join(_BACKEND, "..", "docs")
RANDOM_SEED      = 42

TRAIN_PARQUET    = os.path.join(PROCESSED_DIR, "train_features.parquet")
VAL_PARQUET      = os.path.join(PROCESSED_DIR, "validation_features.parquet")
TEST_PARQUET     = os.path.join(PROCESSED_DIR, "test_features.parquet")

SEMANTIC_KEYS = [
    'password_fields', 'text_email_fields', 'forms', 'external_links',
    'iframes', 'scripts', 'login_indicators', 'credential_indicators',
    'payment_indicators', 'urgency_indicators', 'brand_indicators', 'text_length',
]


# ── Utilities ─────────────────────────────────────────────────────────────────

def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")


def compute_metrics(y_true, y_pred, y_prob, name="model"):
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    return {
        "model":     name,
        "accuracy":  round(float(accuracy_score(y_true, y_pred)),              4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall":    round(float(recall_score(y_true, y_pred, zero_division=0)),    4),
        "f1":        round(float(f1_score(y_true, y_pred, zero_division=0)),        4),
        "roc_auc":   round(float(roc_auc_score(y_true, y_prob)),               4),
        "pr_auc":    round(float(average_precision_score(y_true, y_prob)),      4),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
    }


def print_metrics(m):
    print(f"\n  ── {m['model']} ──")
    print(f"    Accuracy  : {m['accuracy']:.4f}")
    print(f"    Precision : {m['precision']:.4f}")
    print(f"    Recall    : {m['recall']:.4f}")
    print(f"    F1        : {m['f1']:.4f}")
    print(f"    ROC-AUC   : {m['roc_auc']:.4f}")
    print(f"    PR-AUC    : {m['pr_auc']:.4f}")
    print(f"    TN={m['tn']}  FP={m['fp']}  FN={m['fn']}  TP={m['tp']}")


def print_comparison_table(metrics_list):
    print("\n" + "=" * 80)
    print(f"  {'Model':<28} {'Acc':>6} {'Prec':>6} {'Rec':>6} {'F1':>6} {'AUC':>7} {'PR-AUC':>7}")
    print("  " + "─" * 74)
    for m in metrics_list:
        print(f"  {m['model']:<28} {m['accuracy']:>6.4f} {m['precision']:>6.4f} "
              f"{m['recall']:>6.4f} {m['f1']:>6.4f} {m['roc_auc']:>7.4f} {m['pr_auc']:>7.4f}")
    print("=" * 80)


def build_classifier():
    """GBM + RF soft-voting ensemble with probability calibration."""
    gbc = GradientBoostingClassifier(
        n_estimators=200, max_depth=5, learning_rate=0.08,
        min_samples_leaf=3, subsample=0.85, random_state=RANDOM_SEED,
    )
    rfc = RandomForestClassifier(
        n_estimators=200, max_depth=14, min_samples_leaf=2,
        class_weight="balanced", random_state=RANDOM_SEED, n_jobs=-1,
    )
    voting = VotingClassifier(
        estimators=[("gbc", gbc), ("rfc", rfc)],
        voting="soft",
    )
    return CalibratedClassifierCV(voting, method="sigmoid", cv=5)


# ── PHASE 1: Feature Extraction ───────────────────────────────────────────────

def phase1_extract_features():
    """
    Load Phish360 Parquet → extract features → save train/val/test parquet.
    Skips if all three output files already exist and are non-empty.
    """
    if (os.path.exists(TRAIN_PARQUET) and os.path.exists(VAL_PARQUET) and
            os.path.exists(TEST_PARQUET)):
        train_df = pd.read_parquet(TRAIN_PARQUET)
        val_df   = pd.read_parquet(VAL_PARQUET)
        test_df  = pd.read_parquet(TEST_PARQUET)
        if len(train_df) > 0 and len(val_df) > 0 and len(test_df) > 0:
            log(f"[SKIP] Processed feature files already exist.")
            log(f"  Train: {len(train_df)}, Val: {len(val_df)}, Test: {len(test_df)}")
            return train_df, val_df, test_df
        else:
            log("[WARN] Feature files exist but are empty — reprocessing.")

    log("=" * 60)
    log("PHASE 1 — Feature Extraction")
    log("=" * 60)

    os.makedirs(PROCESSED_DIR, exist_ok=True)

    phish_file = os.path.join(PHISH360_SRC, "Phish360_phish.parquet")
    legit_file = os.path.join(PHISH360_SRC, "Phish360_legit.parquet")

    if not os.path.exists(phish_file) or not os.path.exists(legit_file):
        raise FileNotFoundError(
            f"Phish360 Parquet files not found in {PHISH360_SRC}. "
            "Expected Phish360_phish.parquet and Phish360_legit.parquet."
        )

    log("Loading Phish360 Parquet files...")
    phish_df = pd.read_parquet(phish_file)
    legit_df = pd.read_parquet(legit_file)
    phish_df["label"] = 1
    legit_df["label"] = 0
    phish_df["url"]   = phish_df["URL"].astype(str).str.strip()
    legit_df["url"]   = legit_df["URL"].astype(str).str.strip()
    phish_df["html"]  = phish_df["full_html"]
    legit_df["html"]  = legit_df["full_html"]
    phish_df["sample_id"] = phish_df["folder_name"]
    legit_df["sample_id"] = legit_df["folder_name"]

    combined = pd.concat([phish_df, legit_df], ignore_index=True)
    log(f"  Total raw: {len(combined)} (phishing={phish_df['label'].sum()}, legit={legit_df['label'].sum()})")

    # Deduplicate URLs
    before = len(combined)
    combined = combined.drop_duplicates(subset=["url"], keep="first")
    combined = combined.dropna(subset=["url"])
    combined = combined[combined["label"].isin([0, 1])]
    log(f"  After dedup: {len(combined)} (removed {before - len(combined)})")

    # Extract registered domain for leakage-safe splitting
    try:
        import tldextract
        def reg_domain(url):
            try:
                e = tldextract.extract(url)
                return f"{e.domain}.{e.suffix}".lower() if e.domain and e.suffix else url.lower()
            except:
                return url.lower()
        combined["registered_domain"] = combined["url"].apply(reg_domain)
        log("  Registered domain extracted for leakage-safe splitting.")
    except ImportError:
        log("  tldextract not available; using netloc as domain key.")
        from urllib.parse import urlparse
        def reg_domain_fallback(url):
            try:
                return urlparse(url).netloc.lower()
            except:
                return url.lower()
        combined["registered_domain"] = combined["url"].apply(reg_domain_fallback)

    # Domain-aware stratified split: 72% train / 13% val / 15% test
    log("Creating leakage-safe domain-aware splits (72/13/15)...")
    combined = combined.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)

    # Group by registered_domain to prevent cross-split domain leakage
    domains = combined["registered_domain"].unique()
    np.random.seed(RANDOM_SEED)
    np.random.shuffle(domains)
    n = len(domains)
    n_test  = int(n * 0.15)
    n_val   = int(n * 0.13)
    test_domains  = set(domains[:n_test])
    val_domains   = set(domains[n_test:n_test + n_val])
    train_domains = set(domains[n_test + n_val:])

    test_df  = combined[combined["registered_domain"].isin(test_domains)].copy()
    val_df   = combined[combined["registered_domain"].isin(val_domains)].copy()
    train_df = combined[combined["registered_domain"].isin(train_domains)].copy()

    log(f"  Train: {len(train_df)} samples ({train_df['label'].sum()} phishing)")
    log(f"  Val  : {len(val_df)} samples ({val_df['label'].sum()} phishing)")
    log(f"  Test : {len(test_df)} samples ({test_df['label'].sum()} phishing)")

    # Verify zero leakage
    train_urls = set(train_df["url"])
    val_urls   = set(val_df["url"])
    test_urls  = set(test_df["url"])
    tv_url_overlap  = len(train_urls & val_urls)
    tt_url_overlap  = len(train_urls & test_urls)
    vt_url_overlap  = len(val_urls   & test_urls)
    train_doms = set(train_df["registered_domain"])
    val_doms   = set(val_df["registered_domain"])
    test_doms  = set(test_df["registered_domain"])
    tv_dom_overlap  = len(train_doms & val_doms)
    tt_dom_overlap  = len(train_doms & test_doms)
    vt_dom_overlap  = len(val_doms   & test_doms)
    log(f"  URL overlap  — Train-Val:{tv_url_overlap} Train-Test:{tt_url_overlap} Val-Test:{vt_url_overlap}")
    log(f"  Domain overlap — Train-Val:{tv_dom_overlap} Train-Test:{tt_dom_overlap} Val-Test:{vt_dom_overlap}")
    assert tv_url_overlap == 0 and tt_url_overlap == 0 and vt_url_overlap == 0, "URL leakage detected!"
    assert tv_dom_overlap == 0 and tt_dom_overlap == 0 and vt_dom_overlap == 0, "Domain leakage detected!"
    log("  Leakage validation PASSED.")

    # Extract features
    def extract_row_features(row):
        url  = row["url"]
        html = row["html"] if pd.notna(row.get("html", "")) else ""
        label = row["label"]
        sample_id = row.get("sample_id", "")
        reg_domain = row.get("registered_domain", "")

        # Structural features
        try:
            struct = extract_features(url)
        except Exception:
            struct = {k: 0 for k in FEATURE_KEYS}

        # Semantic features
        try:
            html_str = str(html) if html else ""
            sem_raw  = extract_semantic_features_from_html(html_str, url)
            sem = {k: sem_raw.get(k, 0) for k in SEMANTIC_KEYS}
        except Exception:
            sem = {k: 0 for k in SEMANTIC_KEYS}

        # Convert any list values to count (e.g. form_actions)
        for k, v in sem.items():
            if isinstance(v, list):
                sem[k] = len(v)
            elif v is None:
                sem[k] = 0

        return {
            "sample_id":         sample_id,
            "url":               url,
            "label":             int(label),
            "registered_domain": reg_domain,
            **struct,
            **sem,
        }

    def process_split(df, name):
        log(f"  Extracting features for {name} ({len(df)} samples)...")
        rows = []
        failed = 0
        t0 = time.time()
        for i, (_, row) in enumerate(df.iterrows()):
            try:
                rows.append(extract_row_features(row))
            except Exception:
                failed += 1
            if (i + 1) % 500 == 0:
                elapsed = time.time() - t0
                pct = 100 * (i + 1) / len(df)
                log(f"    {i+1}/{len(df)} ({pct:.0f}%) — {elapsed:.0f}s elapsed")
        log(f"  {name}: {len(rows)} succeeded, {failed} failed")
        return pd.DataFrame(rows)

    train_feat = process_split(train_df, "TRAIN")
    val_feat   = process_split(val_df,   "VALIDATION")
    test_feat  = process_split(test_df,  "TEST")

    # Save
    train_feat.to_parquet(TRAIN_PARQUET, index=False)
    val_feat.to_parquet(VAL_PARQUET,     index=False)
    test_feat.to_parquet(TEST_PARQUET,   index=False)

    log(f"  Saved: {TRAIN_PARQUET}")
    log(f"  Saved: {VAL_PARQUET}")
    log(f"  Saved: {TEST_PARQUET}")

    return train_feat, val_feat, test_feat


# ── PHASE 2: Model Training ───────────────────────────────────────────────────

def train_one_model(X_train, y_train, X_val, y_val, name):
    """Train classifier, return (model, scaler, val_probs, val_metrics)."""
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_val_s   = scaler.transform(X_val)

    model = build_classifier()
    log(f"  Fitting {name} ({X_train.shape[1]} features)...")
    model.fit(X_train_s, y_train)

    y_val_pred = model.predict(X_val_s)
    y_val_prob = model.predict_proba(X_val_s)[:, 1]
    metrics = compute_metrics(y_val, y_val_pred, y_val_prob, name=name + " [VAL]")
    print_metrics(metrics)

    return model, scaler, y_val_prob, metrics


def phase2_train_models(train_df, val_df):
    """Train all three models. Return artifacts and val_predictions dict."""
    log("=" * 60)
    log("PHASE 2 — Model Training")
    log("=" * 60)
    os.makedirs(MODELS_DIR, exist_ok=True)

    y_train = train_df["label"].values.astype(int)
    y_val   = val_df["label"].values.astype(int)

    # ── Structural features ──────────────────────────────────────────────────
    X_train_struct = train_df[FEATURE_KEYS].fillna(0).values.astype(np.float32)
    X_val_struct   = val_df[FEATURE_KEYS].fillna(0).values.astype(np.float32)

    # ── Semantic features ────────────────────────────────────────────────────
    sem_cols_avail = [c for c in SEMANTIC_KEYS if c in train_df.columns]
    log(f"  Semantic columns available: {sem_cols_avail}")
    X_train_sem = train_df[sem_cols_avail].fillna(0).values.astype(np.float32)
    X_val_sem   = val_df[sem_cols_avail].fillna(0).values.astype(np.float32)

    # ── Hybrid features (struct + sem) ───────────────────────────────────────
    hybrid_cols    = FEATURE_KEYS + sem_cols_avail
    X_train_hybrid = train_df[hybrid_cols].fillna(0).values.astype(np.float32)
    X_val_hybrid   = val_df[hybrid_cols].fillna(0).values.astype(np.float32)

    log(f"\n  Structural features : {len(FEATURE_KEYS)}")
    log(f"  Semantic features   : {len(sem_cols_avail)}")
    log(f"  Hybrid features     : {len(hybrid_cols)}")

    all_val_metrics = []
    val_probs = {}

    # Model 1: Structural-only
    log("\n[Model 1] Structural-only")
    struct_model, struct_scaler, struct_val_prob, struct_val_metrics = train_one_model(
        X_train_struct, y_train, X_val_struct, y_val, "Structural-only"
    )
    all_val_metrics.append(struct_val_metrics)
    val_probs["structural"] = struct_val_prob.tolist()
    joblib.dump(struct_model,  os.path.join(MODELS_DIR, "structural_model.pkl"))
    joblib.dump(struct_scaler, os.path.join(MODELS_DIR, "structural_scaler.pkl"))
    log("  Saved: structural_model.pkl + structural_scaler.pkl")

    # Model 2: Semantic-only
    log("\n[Model 2] Semantic-only")
    sem_model, sem_scaler, sem_val_prob, sem_val_metrics = train_one_model(
        X_train_sem, y_train, X_val_sem, y_val, "Semantic-only"
    )
    all_val_metrics.append(sem_val_metrics)
    val_probs["semantic"] = sem_val_prob.tolist()
    joblib.dump(sem_model,  os.path.join(MODELS_DIR, "semantic_model.pkl"))
    joblib.dump(sem_scaler, os.path.join(MODELS_DIR, "semantic_scaler.pkl"))
    log("  Saved: semantic_model.pkl + semantic_scaler.pkl")

    # Model 3: Hybrid (44 features)
    log("\n[Model 3] Hybrid (44 features)")
    hybrid_model, hybrid_scaler, hybrid_val_prob, hybrid_val_metrics = train_one_model(
        X_train_hybrid, y_train, X_val_hybrid, y_val, "Hybrid (44-feat)"
    )
    all_val_metrics.append(hybrid_val_metrics)
    val_probs["hybrid"] = hybrid_val_prob.tolist()
    joblib.dump(hybrid_model,  os.path.join(MODELS_DIR, "hybrid_model.pkl"))
    joblib.dump(hybrid_scaler, os.path.join(MODELS_DIR, "hybrid_scaler.pkl"))

    # Save hybrid feature column order
    with open(os.path.join(MODELS_DIR, "hybrid_feature_order.json"), "w") as f:
        json.dump(hybrid_cols, f, indent=2)
    log("  Saved: hybrid_model.pkl + hybrid_scaler.pkl + hybrid_feature_order.json")

    print("\n")
    print_comparison_table(all_val_metrics)

    return (
        struct_model, struct_scaler,
        sem_model, sem_scaler,
        hybrid_model, hybrid_scaler,
        val_probs, y_val, sem_cols_avail, hybrid_cols,
        all_val_metrics,
    )


# ── PHASE 3: Learned Score-Level Fusion ──────────────────────────────────────

def phase3_fusion(val_probs, y_val):
    """
    Train Logistic Regression fusion on validation predictions from
    independently-trained structural and semantic models.

    Inputs to fusion:
      - structural probability (from structural model on val set)
      - semantic probability   (from semantic model on val set)

    Target: true validation label.

    Returns: fusion_model, fusion_val_prob, fusion_val_metrics, fusion_config
    """
    log("=" * 60)
    log("PHASE 3 — Learned Score-Level Fusion")
    log("=" * 60)
    os.makedirs(MODELS_DIR, exist_ok=True)

    p_struct = np.array(val_probs["structural"])
    p_sem    = np.array(val_probs["semantic"])
    y_val_np = np.array(y_val)

    # Input to fusion: [p_structural, p_semantic]
    X_fusion = np.column_stack([p_struct, p_sem])

    log(f"  Fusion inputs: structural_prob + semantic_prob  (n={len(y_val_np)})")
    log(f"  Target: true validation label")
    log(f"  Fitting Logistic Regression fusion...")

    fusion_model = LogisticRegression(
        C=1.0, max_iter=2000, random_state=RANDOM_SEED
    )
    fusion_model.fit(X_fusion, y_val_np)

    fusion_val_prob = fusion_model.predict_proba(X_fusion)[:, 1]
    fusion_val_pred = fusion_model.predict(X_fusion)
    fusion_val_metrics = compute_metrics(
        y_val_np, fusion_val_pred, fusion_val_prob, name="Learned Fusion [VAL]"
    )
    print_metrics(fusion_val_metrics)

    coef      = fusion_model.coef_[0].tolist()
    intercept = float(fusion_model.intercept_[0])

    log(f"\n  Fusion LR coefficients:")
    log(f"    structural_prob coef : {coef[0]:+.4f}")
    log(f"    semantic_prob   coef : {coef[1]:+.4f}")
    log(f"    intercept            : {intercept:+.4f}")
    log(f"\n  Interpretation: P(phishing) = sigmoid({coef[0]:+.4f}*p_struct "
        f"{coef[1]:+.4f}*p_sem {intercept:+.4f})")

    fusion_config = {
        "fusion_type":      "logistic_regression",
        "features":         ["structural_prob", "semantic_prob"],
        "coef_structural":  coef[0],
        "coef_semantic":    coef[1],
        "intercept":        intercept,
        "val_size":         int(len(y_val_np)),
        "val_metrics":      fusion_val_metrics,
    }

    joblib.dump(fusion_model, os.path.join(MODELS_DIR, "fusion_model.pkl"))
    with open(os.path.join(MODELS_DIR, "fusion_config.json"), "w") as f:
        json.dump(fusion_config, f, indent=2)
    log("  Saved: fusion_model.pkl + fusion_config.json")

    return fusion_model, fusion_val_prob, fusion_val_metrics, fusion_config


# ── PHASE 4: Threshold Calibration ───────────────────────────────────────────

def phase4_calibrate(fusion_val_prob, hybrid_val_prob, y_val, all_val_metrics, fusion_val_metrics):
    """
    Select classification thresholds using ONLY validation data.
    The primary threshold is for the fusion model.
    Also compute risk score thresholds for SAFE/SUSPICIOUS/PHISHING.

    risk_score = probability × 100

    Returns: threshold_config
    """
    log("=" * 60)
    log("PHASE 4 — Threshold Calibration (validation only)")
    log("=" * 60)

    y_val_np = np.array(y_val)

    def best_threshold(y_true, y_prob, name):
        best_f1  = -1
        best_thr = 0.5
        for thr in np.arange(0.10, 0.91, 0.01):
            y_pred = (y_prob >= thr).astype(int)
            f1 = f1_score(y_true, y_pred, zero_division=0)
            if f1 > best_f1:
                best_f1  = f1
                best_thr = thr
        log(f"  {name}: best_threshold={best_thr:.2f}, best_val_F1={best_f1:.4f}")
        return round(float(best_thr), 2), round(float(best_f1), 4)

    fus_thr, fus_f1   = best_threshold(y_val_np, fusion_val_prob,  "Fusion")
    hyb_thr, hyb_f1   = best_threshold(y_val_np, hybrid_val_prob,  "Hybrid")

    # Risk score thresholds for SAFE/SUSPICIOUS/PHISHING
    # Derived from fusion probability thresholds on validation
    # SAFE:       fusion_prob < safe_max_prob   → risk_score < safe_max_score
    # SUSPICIOUS: safe_max ≤ prob < phish_min
    # PHISHING:   prob ≥ phishing_min_prob

    # Find SAFE/PHISHING probability thresholds by grid search (val only)
    best_combo = {"f1": -1}
    for safe_max in np.arange(0.15, 0.46, 0.02):
        for phish_min in np.arange(0.50, 0.86, 0.02):
            if safe_max >= phish_min:
                continue
            y_binary = np.where(fusion_val_prob >= phish_min, 1,
                       np.where(fusion_val_prob <  safe_max,  0, 2))
            y_bin    = (y_binary >= 1).astype(int)  # SUSPICIOUS → phishing (conservative)
            f1 = f1_score(y_val_np, y_bin, zero_division=0)
            if f1 > best_combo["f1"]:
                best_combo = {
                    "safe_max_prob":  round(float(safe_max), 2),
                    "phish_min_prob": round(float(phish_min), 2),
                    "f1":             round(float(f1), 4),
                }

    safe_max_score  = int(round(best_combo["safe_max_prob"]  * 100))
    phish_min_score = int(round(best_combo["phish_min_prob"] * 100))

    log(f"\n  Verdict thresholds (from fusion probability, val only):")
    log(f"    SAFE       : risk_score < {safe_max_score}  (prob < {best_combo['safe_max_prob']:.2f})")
    log(f"    SUSPICIOUS : {safe_max_score} ≤ risk_score < {phish_min_score}")
    log(f"    PHISHING   : risk_score ≥ {phish_min_score}  (prob ≥ {best_combo['phish_min_prob']:.2f})")
    log(f"    Val F1 (conservative): {best_combo['f1']:.4f}")

    threshold_config = {
        "fusion_threshold":           fus_thr,
        "hybrid_threshold":           hyb_thr,
        "safe_max_prob":              best_combo["safe_max_prob"],
        "phishing_min_prob":          best_combo["phish_min_prob"],
        "safe_max_risk_score":        safe_max_score,
        "phishing_min_risk_score":    phish_min_score,
        "risk_score_formula":         "probability × 100",
        "calibrated_on":              "validation set only",
        "val_size":                   int(len(y_val_np)),
        "val_f1_fusion_threshold":    fus_f1,
        "val_f1_hybrid_threshold":    hyb_f1,
        "val_f1_verdict_thresholds":  best_combo["f1"],
    }

    with open(os.path.join(MODELS_DIR, "threshold_config.json"), "w") as f:
        json.dump(threshold_config, f, indent=2)
    log("  Saved: threshold_config.json")

    return threshold_config


# ── PHASE 5: Final Test Evaluation ───────────────────────────────────────────

def phase5_final_test(
    test_df,
    struct_model, struct_scaler,
    sem_model, sem_scaler,
    hybrid_model, hybrid_scaler,
    fusion_model,
    sem_cols_avail, hybrid_cols,
    threshold_config,
):
    """
    ONE-TIME evaluation on the final test set.
    All decisions (thresholds, models, fusion) are now frozen.
    Test set was never touched during training, calibration, or threshold selection.
    """
    log("=" * 60)
    log("PHASE 5 — Final Test Evaluation (one-time, post-freeze)")
    log("=" * 60)
    log("  [TEST LEAKAGE CHECK] All model/fusion/threshold decisions FROZEN before this step.")
    log("  [TEST LEAKAGE CHECK] Test set was NOT used for: training, fusion fitting,")
    log("                        threshold selection, or any model selection decision.")

    y_test = test_df["label"].values.astype(int)

    X_test_struct = test_df[FEATURE_KEYS].fillna(0).values.astype(np.float32)
    X_test_sem    = test_df[sem_cols_avail].fillna(0).values.astype(np.float32)
    X_test_hybrid = test_df[hybrid_cols].fillna(0).values.astype(np.float32)

    all_test_metrics = []

    # Structural
    log("\n[Test] Structural-only")
    p_struct = struct_model.predict_proba(struct_scaler.transform(X_test_struct))[:, 1]
    y_struct_pred = (p_struct >= threshold_config["fusion_threshold"]).astype(int)
    m_struct = compute_metrics(y_test, y_struct_pred, p_struct, "Structural-only")
    print_metrics(m_struct)
    all_test_metrics.append(m_struct)

    # Semantic
    log("\n[Test] Semantic-only")
    p_sem = sem_model.predict_proba(sem_scaler.transform(X_test_sem))[:, 1]
    y_sem_pred = (p_sem >= 0.5).astype(int)
    m_sem = compute_metrics(y_test, y_sem_pred, p_sem, "Semantic-only")
    print_metrics(m_sem)
    all_test_metrics.append(m_sem)

    # Hybrid
    log("\n[Test] Hybrid (44-feat)")
    p_hybrid = hybrid_model.predict_proba(hybrid_scaler.transform(X_test_hybrid))[:, 1]
    y_hybrid_pred = (p_hybrid >= threshold_config["hybrid_threshold"]).astype(int)
    m_hybrid = compute_metrics(y_test, y_hybrid_pred, p_hybrid, "Hybrid (44-feat)")
    print_metrics(m_hybrid)
    all_test_metrics.append(m_hybrid)

    # Learned Fusion (PhishOut)
    log("\n[Test] Learned Fusion (PhishOut)")
    X_fusion_test = np.column_stack([p_struct, p_sem])
    p_fusion = fusion_model.predict_proba(X_fusion_test)[:, 1]
    y_fusion_pred = (p_fusion >= threshold_config["fusion_threshold"]).astype(int)
    m_fusion = compute_metrics(y_test, y_fusion_pred, p_fusion, "Learned Fusion (PhishOut)")
    print_metrics(m_fusion)
    all_test_metrics.append(m_fusion)

    # Comparison
    print("\n")
    print_comparison_table(all_test_metrics)

    # Save
    test_results = {
        "test_set_size":   int(len(y_test)),
        "test_legitimate": int((y_test == 0).sum()),
        "test_phishing":   int((y_test == 1).sum()),
        "evaluated_at":    datetime.now().isoformat(),
        "test_leakage":    "NONE — test set was untouched until all decisions frozen",
        "all_metrics":     all_test_metrics,
        "threshold_config": threshold_config,
    }
    out_path = os.path.join(MODELS_DIR, "test_results.json")
    with open(out_path, "w") as f:
        json.dump(test_results, f, indent=2)
    log(f"  Saved: {out_path}")

    return all_test_metrics, p_struct, p_sem, p_hybrid, p_fusion


# ── PHASE 6: Documentation ────────────────────────────────────────────────────

def phase6_documentation(
    train_df, val_df, test_df,
    all_val_metrics, fusion_val_metrics,
    all_test_metrics,
    threshold_config, fusion_config,
    sem_cols_avail, hybrid_cols,
):
    """Write docs/model_training_report.md"""
    log("=" * 60)
    log("PHASE 6 — Writing Documentation")
    log("=" * 60)

    def fmt_row(m):
        return (f"| {m['model']:<28} | {m['accuracy']:.4f} | {m['precision']:.4f} | "
                f"{m['recall']:.4f} | {m['f1']:.4f} | {m['roc_auc']:.4f} | {m['pr_auc']:.4f} | "
                f"{m['tn']} | {m['fp']} | {m['fn']} | {m['tp']} |")

    val_rows  = "\n".join(fmt_row(m) for m in all_val_metrics + [fusion_val_metrics])
    test_rows = "\n".join(fmt_row(m) for m in all_test_metrics)

    fc = fusion_config
    tc = threshold_config

    report = f"""# PhishOut — Model Training Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Dataset:** Phish360 (Parquet)

---

## 1. Dataset

| Split      | Samples | Phishing | Legitimate |
|------------|---------|----------|------------|
| Train      | {len(train_df)} | {int(train_df['label'].sum())} | {len(train_df) - int(train_df['label'].sum())} |
| Validation | {len(val_df)} | {int(val_df['label'].sum())} | {len(val_df) - int(val_df['label'].sum())} |
| Test       | {len(test_df)} | {int(test_df['label'].sum())} | {len(test_df) - int(test_df['label'].sum())} |

**Splitting methodology:** Domain-aware stratified split (registered domain groups assigned to a single split). Zero URL overlap and zero registered-domain overlap across all splits verified.

---

## 2. Features

| Group        | Count | Description |
|--------------|-------|-------------|
| Structural   | {len(FEATURE_KEYS)} | URL-based features: length, entropy, brand scores, TLD risk, etc. |
| Semantic     | {len(sem_cols_avail)} | HTML-based features: forms, passwords, keywords, iframes, scripts |
| **Hybrid**   | **{len(hybrid_cols)}** | All structural + semantic features combined |

**Structural feature list:** `{', '.join(FEATURE_KEYS)}`

**Semantic feature list:** `{', '.join(sem_cols_avail)}`

---

## 3. Model Architecture

### Models Trained

```
URL
 ↓
32 structural features → GBM+RF ensemble (structural_model) → p_structural
                                                                    ↓
HTML                                                    Logistic Regression Fusion
 ↓                                                      (LEARNED SCORE-LEVEL FUSION)
12 semantic features  → GBM+RF ensemble (semantic_model)  → p_semantic    ↓
                                                                    ↓
                                                             p_fusion → risk_score
Separately:
32 structural + 12 semantic = 44 features → GBM+RF ensemble (hybrid_model) → p_hybrid
```

**Note:** The hybrid model and the score-level fusion are **two separate experiments**.
The hybrid model is a 44-feature direct model. The fusion model takes outputs
(probabilities) of two independently-trained models as input.

### Base Classifier (all three models)
- GradientBoostingClassifier (n=200, depth=5, lr=0.08) + RandomForestClassifier (n=200, depth=14)
- Soft-voting VotingClassifier wrapped in CalibratedClassifierCV (sigmoid, cv=5)

### Fusion Model
- **Type:** Logistic Regression (sklearn)
- **Inputs:** [p_structural, p_semantic] from validation set predictions
- **Target:** True validation label
- **Learned coefficients:**
  - `structural_prob`: {fc['coef_structural']:+.4f}
  - `semantic_prob`:   {fc['coef_semantic']:+.4f}
  - `intercept`:       {fc['intercept']:+.4f}
- **Formula:** P(phishing) = sigmoid({fc['coef_structural']:+.4f}×p_struct {fc['coef_semantic']:+.4f}×p_sem {fc['intercept']:+.4f})

---

## 4. Validation Results (E2: Model Comparison)

> Used for model selection, fusion fitting, and threshold calibration ONLY.
> Never used for final test evaluation.

| Model | Acc | Prec | Rec | F1 | ROC-AUC | PR-AUC | TN | FP | FN | TP |
|-------|-----|------|-----|----|---------|--------|----|----|----|----|
{val_rows}

---

## 5. Calibration / Thresholds

**Calibrated on validation set only. Final test set was untouched.**

| Parameter | Value |
|-----------|-------|
| Classification threshold (fusion) | {tc['fusion_threshold']:.2f} |
| Classification threshold (hybrid) | {tc['hybrid_threshold']:.2f} |
| SAFE max probability | {tc['safe_max_prob']:.2f} |
| PHISHING min probability | {tc['phishing_min_prob']:.2f} |
| SAFE max risk score | < {tc['safe_max_risk_score']} |
| SUSPICIOUS risk score range | {tc['safe_max_risk_score']} – {tc['phishing_min_risk_score'] - 1} |
| PHISHING min risk score | ≥ {tc['phishing_min_risk_score']} |

**Risk score formula:** `risk_score = probability × 100`

---

## 6. Final Test Results (E1: Normal Detection)

> Evaluated ONCE on held-out test set after all model/fusion/threshold decisions were frozen.
> Test set was NOT used for any training, fusion, calibration, or selection decision.

**TEST LEAKAGE STATUS: NONE**

| Model | Acc | Prec | Rec | F1 | ROC-AUC | PR-AUC | TN | FP | FN | TP |
|-------|-----|------|-----|----|---------|--------|----|----|----|----|
{test_rows}

---

## 7. Methodology Notes

### Feature-Level Hybrid vs. Score-Level Fusion
- **Feature-level hybrid:** All 44 features concatenated and fed to a single classifier.
- **Score-level fusion:** Two independently-trained models (structural + semantic) each
  produce a probability; a Logistic Regression meta-model learns to combine these.
- These are **two distinct experiments** and should not be confused.

### Data Leakage Prevention
- Train/val/test split performed on registered-domain groups
- Zero URL overlap and zero registered-domain overlap across splits
- Final test set untouched until all model and threshold decisions frozen
- Thresholds selected exclusively on validation set

### Limitations
- Semantic model quality depends on HTML content quality in Phish360
- Score-level fusion was fitted on the same validation set used for threshold selection
  (could be improved with cross-validation in future work)
- E3 (feature robustness) and E4 (temporal generalization) are future phases

---

## 8. Model Files

| File | Description |
|------|-------------|
| `models/phish360/structural_model.pkl` | Structural-only GBM+RF model |
| `models/phish360/structural_scaler.pkl` | Structural StandardScaler |
| `models/phish360/semantic_model.pkl` | Semantic-only GBM+RF model |
| `models/phish360/semantic_scaler.pkl` | Semantic StandardScaler |
| `models/phish360/hybrid_model.pkl` | 44-feature hybrid GBM+RF model |
| `models/phish360/hybrid_scaler.pkl` | Hybrid StandardScaler |
| `models/phish360/fusion_model.pkl` | Learned LR fusion model |
| `models/phish360/fusion_config.json` | Fusion coefficients |
| `models/phish360/threshold_config.json` | Calibrated thresholds |
| `models/phish360/test_results.json` | Final test metrics |
| `dataset/phish360/processed/train_features.parquet` | Training features |
| `dataset/phish360/processed/validation_features.parquet` | Validation features |
| `dataset/phish360/processed/test_features.parquet` | Test features |

---

**END OF REPORT**
"""

    os.makedirs(DOCS_DIR, exist_ok=True)
    report_path = os.path.join(DOCS_DIR, "model_training_report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    log(f"  Saved: {report_path}")


# ── MAIN ──────────────────────────────────────────────────────────────────────

def main():
    t_start = time.time()
    print("=" * 70)
    print("  PhishOut — Phase 2 Complete Training Pipeline (Phish360)")
    print("=" * 70)

    # Phase 1: Feature extraction
    train_df, val_df, test_df = phase1_extract_features()

    # Phase 2: Train 3 models
    (
        struct_model, struct_scaler,
        sem_model, sem_scaler,
        hybrid_model, hybrid_scaler,
        val_probs, y_val, sem_cols_avail, hybrid_cols,
        all_val_metrics,
    ) = phase2_train_models(train_df, val_df)

    # Phase 3: Learned fusion
    fusion_model, fusion_val_prob, fusion_val_metrics, fusion_config = phase3_fusion(
        val_probs, y_val
    )

    # Phase 4: Calibrate thresholds (val only)
    hybrid_val_prob = np.array(val_probs["hybrid"])
    threshold_config = phase4_calibrate(
        fusion_val_prob, hybrid_val_prob, y_val,
        all_val_metrics, fusion_val_metrics
    )

    # Save all val predictions
    val_preds_path = os.path.join(MODELS_DIR, "val_predictions.json")
    with open(val_preds_path, "w") as f:
        json.dump({
            "structural": val_probs["structural"],
            "semantic":   val_probs["semantic"],
            "hybrid":     val_probs["hybrid"],
            "fusion":     fusion_val_prob.tolist(),
            "y_true":     [int(x) for x in y_val],
        }, f)
    log(f"  Saved: {val_preds_path}")

    # Phase 5: Final test evaluation (ALL decisions now frozen)
    all_test_metrics, p_struct, p_sem, p_hybrid, p_fusion = phase5_final_test(
        test_df,
        struct_model, struct_scaler,
        sem_model, sem_scaler,
        hybrid_model, hybrid_scaler,
        fusion_model,
        sem_cols_avail, hybrid_cols,
        threshold_config,
    )

    # Phase 6: Documentation
    phase6_documentation(
        train_df, val_df, test_df,
        all_val_metrics, fusion_val_metrics,
        all_test_metrics,
        threshold_config, fusion_config,
        sem_cols_avail, hybrid_cols,
    )

    elapsed = time.time() - t_start
    log(f"\nTotal elapsed: {elapsed/60:.1f} minutes")
    log("=" * 70)
    log("  Phase 2 COMPLETE. Next: E3 feature-level robustness (separate phase).")
    log("=" * 70)


if __name__ == "__main__":
    main()
