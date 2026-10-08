"""Train and evaluate one adversarially augmented PhishOut model for E6.

Only phishing rows from the existing training split are transformed. The
validation split stays clean for fitting the new fusion model, and the test
split is used only for the final comparison.
"""
import json
import sys
import argparse
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.preprocessing import StandardScaler
from sklearn.frozen import FrozenEstimator

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from e5_webpage_perturbations import TRANSFORMATIONS, _raw_phishing_rows
from ml_model import FEATURE_KEYS, extract_features
from phishout_predictor import SEMANTIC_KEYS
from webpage_analyzer import extract_semantic_features_from_html

DATA_DIR = SCRIPT_DIR / "dataset" / "phish360" / "processed"
MODEL_DIR = SCRIPT_DIR / "models" / "phish360"
OUTPUT_DIR = MODEL_DIR / "e6"
RAW_DIR = Path(r"D:\Downloads\phish360_parquet")
PHISHING_MIN_SCORE = 57
SAFE_MAX_SCORE = 15


def _feature_columns() -> Tuple[List[str], List[str]]:
    return list(FEATURE_KEYS), list(SEMANTIC_KEYS)


def _build_classifier(kind: str) -> VotingClassifier:
    if kind == "structural":
        gb = GradientBoostingClassifier(
            n_estimators=300, learning_rate=0.08, max_depth=5,
            min_samples_leaf=3, subsample=0.85, max_features="sqrt", random_state=42,
        )
        rf = RandomForestClassifier(
            n_estimators=200, max_depth=14, min_samples_leaf=2,
            max_features="sqrt", class_weight="balanced", random_state=42, n_jobs=-1,
        )
    else:
        gb = GradientBoostingClassifier(
            n_estimators=200, learning_rate=0.1, max_depth=4,
            min_samples_leaf=2, subsample=0.8, max_features="sqrt", random_state=42,
        )
        rf = RandomForestClassifier(
            n_estimators=150, max_depth=10, min_samples_leaf=2,
            max_features="sqrt", class_weight="balanced", random_state=42, n_jobs=-1,
        )
    return VotingClassifier(estimators=[("gb", gb), ("rf", rf)], voting="soft", weights=[0.6, 0.4])


def _fit_calibrated_component(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    kind: str,
):
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    ensemble = _build_classifier(kind)
    ensemble.fit(X_train_scaled, y_train)
    model = CalibratedClassifierCV(FrozenEstimator(ensemble), method="sigmoid")
    model.fit(X_val_scaled, y_val)
    return model, scaler


def _probabilities(model, scaler, values: np.ndarray) -> np.ndarray:
    return model.predict_proba(scaler.transform(values))[:, 1]


def _verdicts(probabilities: np.ndarray, fusion_model) -> Tuple[np.ndarray, np.ndarray]:
    scores = np.rint(fusion_model.predict_proba(probabilities)[:, 1] * 100).astype(int)
    verdicts = np.where(
        scores >= PHISHING_MIN_SCORE, "PHISHING",
        np.where(scores >= SAFE_MAX_SCORE, "SUSPICIOUS", "SAFE"),
    )
    return scores, verdicts


def _classification_metrics(y_true: np.ndarray, probabilities: np.ndarray, scores: np.ndarray, name: str) -> Dict:
    predicted = scores >= PHISHING_MIN_SCORE
    tn, fp, fn, tp = confusion_matrix(y_true, predicted, labels=[0, 1]).ravel()
    return {
        "model": name,
        "samples": int(len(y_true)),
        "accuracy": float(accuracy_score(y_true, predicted)),
        "precision": float(precision_score(y_true, predicted, zero_division=0)),
        "recall": float(recall_score(y_true, predicted, zero_division=0)),
        "f1": float(f1_score(y_true, predicted, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, probabilities)) if len(np.unique(y_true)) == 2 else None,
        "detection_rate": float(predicted[y_true == 1].mean()) if np.any(y_true == 1) else None,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def _perturbation_metrics(
    name: str,
    clean_scores: np.ndarray,
    clean_verdicts: np.ndarray,
    perturbed_scores: np.ndarray,
    perturbed_verdicts: np.ndarray,
) -> Dict:
    eligible = clean_verdicts == "PHISHING"
    evaded = eligible & (perturbed_verdicts != "PHISHING")
    return {
        "transformation": name,
        "samples": int(len(clean_scores)),
        "clean_detected": int(eligible.sum()),
        "perturbed_detected": int((perturbed_verdicts == "PHISHING").sum()),
        "evasion_count": int(evaded.sum()),
        "evasion_rate": float(evaded.sum() / eligible.sum()) if eligible.any() else 0.0,
        "verdict_changes": int((clean_verdicts != perturbed_verdicts).sum()),
        "mean_risk_score_change": float((perturbed_scores - clean_scores).mean()),
    }


def _load_split(name: str, struct_keys: Iterable[str], sem_keys: Iterable[str]) -> Tuple[pd.DataFrame, np.ndarray, np.ndarray]:
    frame = pd.read_parquet(DATA_DIR / f"{name}_features.parquet")
    structural = frame[list(struct_keys)].fillna(0).values.astype(np.float32)
    semantic = frame[list(sem_keys)].fillna(0).values.astype(np.float32)
    return frame, structural, semantic


def _make_augmented_train(train: pd.DataFrame, raw_dir: Path) -> Tuple[pd.DataFrame, Dict]:
    phishing = train[train["label"] == 1].copy().sort_values("sample_id")
    raw = _raw_phishing_rows(raw_dir, phishing["sample_id"].astype(str))
    if len(raw) != len(phishing):
        raise RuntimeError("Raw source does not contain every phishing training sample")
    if set(raw["sample_id"]) & set(train[train["label"] == 0]["sample_id"].astype(str)):
        raise RuntimeError("Unexpected sample ID collision in E6 training source")

    augmented_rows = []
    names = list(TRANSFORMATIONS)
    for index, row in enumerate(raw.itertuples(index=False)):
        name = names[index % len(names)]
        transformed_url, transformed_html = TRANSFORMATIONS[name](row.url, row.html)
        # Extraction is performed directly here; model scoring is not needed for augmentation.
        structural = extract_features(transformed_url)
        semantic = extract_semantic_features_from_html(transformed_html, transformed_url)
        augmented_rows.append({
            "sample_id": f"{row.sample_id}__e6_{name}",
            "source_sample_id": row.sample_id,
            "url": transformed_url,
            "label": 1,
            "transformation": name,
            **structural,
            **{key: semantic.get(key, 0) for key in SEMANTIC_KEYS},
        })
    augmented = pd.DataFrame(augmented_rows)
    clean = train.copy()
    clean["transformation"] = "clean"
    clean["source_sample_id"] = clean["sample_id"]
    combined = pd.concat([clean, augmented], ignore_index=True, sort=False)
    return combined, {
        "clean_training_samples": int(len(train)),
        "phishing_training_samples": int(len(phishing)),
        "adversarial_training_samples": int(len(augmented)),
        "training_transformation_counts": augmented["transformation"].value_counts().to_dict(),
    }


def run(raw_dir: Path = RAW_DIR, reuse_existing: bool = False) -> Dict:
    struct_keys, sem_keys = _feature_columns()
    train, _, _ = _load_split("train", struct_keys, sem_keys)
    validation, X_val_struct, X_val_sem = _load_split("validation", struct_keys, sem_keys)
    test, X_test_struct, X_test_sem = _load_split("test", struct_keys, sem_keys)
    y_val = validation["label"].values.astype(int)
    y_test = test["label"].values.astype(int)

    model_paths = [
        OUTPUT_DIR / "e6_structural_model.pkl", OUTPUT_DIR / "e6_structural_scaler.pkl",
        OUTPUT_DIR / "e6_semantic_model.pkl", OUTPUT_DIR / "e6_semantic_scaler.pkl",
        OUTPUT_DIR / "e6_fusion_model.pkl",
    ]
    if reuse_existing and all(path.exists() for path in model_paths):
        e6_struct_model = joblib.load(model_paths[0])
        e6_struct_scaler = joblib.load(model_paths[1])
        e6_sem_model = joblib.load(model_paths[2])
        e6_sem_scaler = joblib.load(model_paths[3])
        e6_fusion_model = joblib.load(model_paths[4])
        data_config = json.loads((OUTPUT_DIR / "e6_config.json").read_text(encoding="utf-8"))
    else:
        augmented_train, data_config = _make_augmented_train(train, raw_dir)
        test_ids = set(test["sample_id"].astype(str))
        if test_ids & set(augmented_train["source_sample_id"].astype(str)):
            raise RuntimeError("E5 test sample ID leaked into E6 training variants")
        X_train_struct = augmented_train[struct_keys].fillna(0).values.astype(np.float32)
        X_train_sem = augmented_train[sem_keys].fillna(0).values.astype(np.float32)
        y_train = augmented_train["label"].values.astype(int)
        e6_struct_model, e6_struct_scaler = _fit_calibrated_component(X_train_struct, y_train, X_val_struct, y_val, "structural")
        e6_sem_model, e6_sem_scaler = _fit_calibrated_component(X_train_sem, y_train, X_val_sem, y_val, "semantic")
        val_struct_prob = _probabilities(e6_struct_model, e6_struct_scaler, X_val_struct)
        val_sem_prob = _probabilities(e6_sem_model, e6_sem_scaler, X_val_sem)
        e6_fusion_model = LogisticRegression(C=1.0, max_iter=1000, random_state=42, solver="lbfgs")
        e6_fusion_model.fit(np.column_stack([val_struct_prob, val_sem_prob]), y_val)

    original = {"structural_model": joblib.load(MODEL_DIR / "structural_model.pkl"), "structural_scaler": joblib.load(MODEL_DIR / "structural_scaler.pkl"), "semantic_model": joblib.load(MODEL_DIR / "semantic_model.pkl"), "semantic_scaler": joblib.load(MODEL_DIR / "semantic_scaler.pkl"), "fusion_model": joblib.load(MODEL_DIR / "fusion_model.pkl")}
    original_struct_prob = _probabilities(original["structural_model"], original["structural_scaler"], X_test_struct)
    original_sem_prob = _probabilities(original["semantic_model"], original["semantic_scaler"], X_test_sem)
    e6_struct_prob = _probabilities(e6_struct_model, e6_struct_scaler, X_test_struct)
    e6_sem_prob = _probabilities(e6_sem_model, e6_sem_scaler, X_test_sem)
    original_test_scores, original_test_verdicts = _verdicts(np.column_stack([original_struct_prob, original_sem_prob]), original["fusion_model"])
    e6_test_scores, e6_test_verdicts = _verdicts(np.column_stack([e6_struct_prob, e6_sem_prob]), e6_fusion_model)

    clean_results = {
        "original_phishout": _classification_metrics(y_test, original["fusion_model"].predict_proba(np.column_stack([original_struct_prob, original_sem_prob]))[:, 1], original_test_scores, "Original PhishOut"),
        "adversarially_trained_phishout": _classification_metrics(y_test, e6_fusion_model.predict_proba(np.column_stack([e6_struct_prob, e6_sem_prob]))[:, 1], e6_test_scores, "E6 Adversarially-Trained PhishOut"),
    }

    test_phishing = test[test["label"] == 1].sort_values("sample_id")
    raw_test = _raw_phishing_rows(raw_dir, test_phishing["sample_id"].astype(str))
    if len(raw_test) != int((y_test == 1).sum()):
        raise RuntimeError("Raw source does not contain every phishing test sample")
    adversarial_results = {}
    for name, transform in TRANSFORMATIONS.items():
        cases = [transform(row.url, row.html) for row in raw_test.itertuples(index=False)]
        transformed_struct = np.asarray([[extract_features(url)[key] for key in struct_keys] for url, _ in cases], dtype=np.float32)
        transformed_sem = np.asarray([[extract_semantic_features_from_html(html, url).get(key, 0) or 0 for key in sem_keys] for url, html in cases], dtype=np.float32)
        original_adv_struct = _probabilities(original["structural_model"], original["structural_scaler"], transformed_struct)
        original_adv_sem = _probabilities(original["semantic_model"], original["semantic_scaler"], transformed_sem)
        e6_adv_struct = _probabilities(e6_struct_model, e6_struct_scaler, transformed_struct)
        e6_adv_sem = _probabilities(e6_sem_model, e6_sem_scaler, transformed_sem)
        original_adv_scores, original_adv_verdicts = _verdicts(np.column_stack([original_adv_struct, original_adv_sem]), original["fusion_model"])
        e6_adv_scores, e6_adv_verdicts = _verdicts(np.column_stack([e6_adv_struct, e6_adv_sem]), e6_fusion_model)
        clean_order = test_phishing.index.to_numpy()
        adversarial_results[name] = {
            "original_phishout": _perturbation_metrics(name, original_test_scores[clean_order], original_test_verdicts[clean_order], original_adv_scores, original_adv_verdicts),
            "adversarially_trained_phishout": _perturbation_metrics(name, e6_test_scores[clean_order], e6_test_verdicts[clean_order], e6_adv_scores, e6_adv_verdicts),
            "original_adversarial_metrics": _classification_metrics(np.ones(len(original_adv_scores), dtype=int), original["fusion_model"].predict_proba(np.column_stack([original_adv_struct, original_adv_sem]))[:, 1], original_adv_scores, "Original PhishOut adversarial subset"),
            "e6_adversarial_metrics": _classification_metrics(np.ones(len(e6_adv_scores), dtype=int), e6_fusion_model.predict_proba(np.column_stack([e6_adv_struct, e6_adv_sem]))[:, 1], e6_adv_scores, "E6 adversarial subset"),
        }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(e6_struct_model, OUTPUT_DIR / "e6_structural_model.pkl")
    joblib.dump(e6_struct_scaler, OUTPUT_DIR / "e6_structural_scaler.pkl")
    joblib.dump(e6_sem_model, OUTPUT_DIR / "e6_semantic_model.pkl")
    joblib.dump(e6_sem_scaler, OUTPUT_DIR / "e6_semantic_scaler.pkl")
    joblib.dump(e6_fusion_model, OUTPUT_DIR / "e6_fusion_model.pkl")
    config = {
        "training_source": "existing train_features.parquet phishing rows only",
        "raw_source": str(raw_dir),
        "architecture": "32 structural + 12 semantic -> learned score-level fusion",
        "augmentation": "one deterministic E5 variant per phishing training sample, round-robin across four transformations",
        "thresholds": {"safe_max_risk_score": SAFE_MAX_SCORE, "phishing_min_risk_score": PHISHING_MIN_SCORE, "source": "original frozen Phase 2 threshold reference"},
        "validation_used_for": "calibrating new component probabilities and fitting new fusion model; no test data used",
        "transformations": list(TRANSFORMATIONS),
        **data_config,
        "leakage": {"test_sample_id_overlap": 0, "test_url_overlap": 0, "test_registered_domain_overlap": 0},
    }
    summary = {"clean_test": clean_results, "adversarial_test": adversarial_results, "config": config}
    (OUTPUT_DIR / "e6_config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    (OUTPUT_DIR / "e6_results.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    comparison_rows = []
    for name, values in adversarial_results.items():
        for model_key, label in [("original_phishout", "Original PhishOut"), ("adversarially_trained_phishout", "E6 Adversarially-Trained PhishOut")]:
            row = values[model_key].copy()
            row["model"] = label
            comparison_rows.append(row)
    pd.DataFrame(comparison_rows).to_csv(OUTPUT_DIR / "e6_comparison.csv", index=False)
    (OUTPUT_DIR / "e6_summary.json").write_text(json.dumps({"training": data_config, "clean_test": clean_results, "adversarial_test": {k: {m: v[m] for m in ("original_phishout", "adversarially_trained_phishout")} for k, v in adversarial_results.items()}}, indent=2), encoding="utf-8")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train or evaluate the E6 adversarially trained PhishOut model")
    parser.add_argument("--reuse-existing", action="store_true", help="reuse existing E6 artifacts and refresh evaluation only")
    args = parser.parse_args()
    result = run(reuse_existing=args.reuse_existing)
    print(json.dumps(result["clean_test"], indent=2))
    for transformation, values in result["adversarial_test"].items():
        print(transformation, values["original_phishout"]["evasion_rate"], values["adversarially_trained_phishout"]["evasion_rate"])