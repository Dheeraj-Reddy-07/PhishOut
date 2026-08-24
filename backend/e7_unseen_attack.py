"""Evaluate E6 generalization to one unseen offline URL transformation."""
import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import urlsplit, urlunsplit

import joblib
import numpy as np
import pandas as pd

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from e5_webpage_perturbations import _raw_phishing_rows
from e6_adversarial_training import _classification_metrics, _probabilities, _verdicts
from leakage_validator import extract_registered_domain
from ml_model import FEATURE_KEYS, extract_features
from phishout_predictor import SEMANTIC_KEYS
from webpage_analyzer import extract_semantic_features_from_html

DATA_DIR = SCRIPT_DIR / "dataset" / "phish360" / "processed"
MODEL_DIR = SCRIPT_DIR / "models" / "phish360"
E6_DIR = MODEL_DIR / "e6"
OUTPUT_DIR = MODEL_DIR / "e7"
RAW_DIR = Path(r"D:\Downloads\phish360_parquet")
SAFE_MAX_SCORE = 15
PHISHING_MIN_SCORE = 57
UNSEEN_TRANSFORMATION = "url_percent_encode_character"


def percent_encode_url_character(url: str, html: str) -> Tuple[str, str]:
    """Encode one path/query character without changing the stored HTML."""
    parts = urlsplit(url)
    for component_name, component in (("path", parts.path), ("query", parts.query)):
        for index, character in enumerate(component):
            if character.isascii() and character.isalnum():
                encoded = f"%{ord(character):02X}"
                replacement = component[:index] + encoded + component[index + 1:]
                if component_name == "path":
                    return urlunsplit((parts.scheme, parts.netloc, replacement, parts.query, parts.fragment)), html
                return urlunsplit((parts.scheme, parts.netloc, parts.path, replacement, parts.fragment)), html
    if parts.path in ("", "/") and not parts.query:
        return urlunsplit((parts.scheme, parts.netloc, "%2F", parts.query, parts.fragment)), html
    raise ValueError(f"URL has no encodable path/query character: {url}")


def _model_bundle(directory: Path) -> Dict:
    return {
        "structural_model": joblib.load(directory / "structural_model.pkl" if directory == MODEL_DIR else directory / "e6_structural_model.pkl"),
        "structural_scaler": joblib.load(directory / "structural_scaler.pkl" if directory == MODEL_DIR else directory / "e6_structural_scaler.pkl"),
        "semantic_model": joblib.load(directory / "semantic_model.pkl" if directory == MODEL_DIR else directory / "e6_semantic_model.pkl"),
        "semantic_scaler": joblib.load(directory / "semantic_scaler.pkl" if directory == MODEL_DIR else directory / "e6_semantic_scaler.pkl"),
        "fusion_model": joblib.load(directory / "fusion_model.pkl" if directory == MODEL_DIR else directory / "e6_fusion_model.pkl"),
    }


def _feature_arrays(frame: pd.DataFrame, structural_keys: List[str], semantic_keys: List[str]) -> Tuple[np.ndarray, np.ndarray]:
    structural = frame[structural_keys].fillna(0).values.astype(np.float32)
    semantic = frame[semantic_keys].fillna(0).values.astype(np.float32)
    return structural, semantic


def _score(bundle: Dict, structural: np.ndarray, semantic: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    structural_probability = _probabilities(bundle["structural_model"], bundle["structural_scaler"], structural)
    semantic_probability = _probabilities(bundle["semantic_model"], bundle["semantic_scaler"], semantic)
    scores, verdicts = _verdicts(np.column_stack([structural_probability, semantic_probability]), bundle["fusion_model"])
    probability = bundle["fusion_model"].predict_proba(np.column_stack([structural_probability, semantic_probability]))[:, 1]
    return probability, scores, verdicts


def _assert_pairing(clean: pd.DataFrame, perturbed: pd.DataFrame, expected_label: int) -> None:
    clean_ids = clean["sample_id"].astype(str)
    perturbed_ids = perturbed["sample_id"].astype(str)
    assert len(clean_ids) == len(perturbed_ids), "Clean and perturbed counts differ"
    assert clean_ids.is_unique and perturbed_ids.is_unique, "Duplicate sample IDs detected"
    assert set(clean_ids) == set(perturbed_ids), "Clean and perturbed sample IDs differ"
    assert (clean["label"].astype(int) == expected_label).all(), "Unexpected clean labels"
    assert (perturbed["label"].astype(int) == expected_label).all(), "Unexpected perturbed labels"
    assert clean.set_index("sample_id").index.equals(perturbed.set_index("sample_id").index), "Pair ordering is not identical"


def _paired_evasion(clean: pd.DataFrame, perturbed: pd.DataFrame) -> Dict:
    joined = clean[["sample_id", "clean_score", "clean_verdict"]].merge(
        perturbed[["sample_id", "perturbed_score", "perturbed_verdict"]],
        on="sample_id", how="inner", validate="one_to_one",
    )
    eligible = joined["clean_verdict"] == "PHISHING"
    evaded = eligible & (joined["perturbed_verdict"] != "PHISHING")
    return {
        "samples": int(len(joined)),
        "clean_detected": int(eligible.sum()),
        "perturbed_detected": int((joined["perturbed_verdict"] == "PHISHING").sum()),
        "evasion_count": int(evaded.sum()),
        "evasion_rate": float(evaded.sum() / eligible.sum()) if eligible.any() else 0.0,
        "verdict_changes": int((joined["clean_verdict"] != joined["perturbed_verdict"]).sum()),
        "mean_risk_score_change": float((joined["perturbed_score"] - joined["clean_score"]).mean()),
    }


def run(raw_dir: Path = RAW_DIR) -> Dict:
    structural_keys = list(FEATURE_KEYS)
    semantic_keys = list(SEMANTIC_KEYS)
    test = pd.read_parquet(DATA_DIR / "test_features.parquet")
    test["sample_id"] = test["sample_id"].astype(str)
    phishing = test[test["label"].astype(int) == 1].sort_values("sample_id").copy()
    raw = _raw_phishing_rows(raw_dir, phishing["sample_id"])
    raw["sample_id"] = raw["sample_id"].astype(str)
    raw = raw.sort_values("sample_id").reset_index(drop=True)
    phishing = phishing.sort_values("sample_id").reset_index(drop=True)
    raw["label"] = 1
    _assert_pairing(phishing, raw.rename(columns={"url": "url"}), 1)
    if set(raw["registered_domain"]) != set(phishing["registered_domain"]):
        raise AssertionError("Raw and processed registered domains differ")

    transformed = []
    for row in raw.itertuples(index=False):
        transformed_url, transformed_html = percent_encode_url_character(row.url, row.html)
        transformed.append({
            "sample_id": row.sample_id,
            "label": 1,
            "original_url": row.url,
            "perturbed_url": transformed_url,
            "registered_domain": row.registered_domain,
            "html": transformed_html,
        })
    transformed_frame = pd.DataFrame(transformed).sort_values("sample_id").reset_index(drop=True)
    assert transformed_frame["sample_id"].is_unique
    assert set(transformed_frame["sample_id"]) == set(phishing["sample_id"])
    assert (transformed_frame["original_url"] != transformed_frame["perturbed_url"]).all()
    assert (transformed_frame["label"] == 1).all()

    transformed_features = []
    for row in transformed_frame.itertuples(index=False):
        structural = extract_features(row.perturbed_url)
        semantic = extract_semantic_features_from_html(row.html, row.perturbed_url)
        transformed_features.append({
            "sample_id": row.sample_id,
            "label": 1,
            **structural,
            **{key: semantic.get(key, 0) or 0 for key in semantic_keys},
        })
    transformed_features = pd.DataFrame(transformed_features).sort_values("sample_id").reset_index(drop=True)
    _assert_pairing(phishing, transformed_features, 1)

    original = _model_bundle(MODEL_DIR)
    e6 = _model_bundle(E6_DIR)
    X_test_struct, X_test_sem = _feature_arrays(test, structural_keys, semantic_keys)
    original_clean_probability, original_clean_scores, original_clean_verdicts = _score(original, X_test_struct, X_test_sem)
    e6_clean_probability, e6_clean_scores, e6_clean_verdicts = _score(e6, X_test_struct, X_test_sem)
    y_test = test["label"].astype(int).to_numpy()
    clean_metrics = {
        "original_phishout": _classification_metrics(y_test, original_clean_probability, original_clean_scores, "Original PhishOut"),
        "e6_adversarially_trained_phishout": _classification_metrics(y_test, e6_clean_probability, e6_clean_scores, "E6 Adversarially-Trained PhishOut"),
    }

    X_adv_struct, X_adv_sem = _feature_arrays(transformed_features, structural_keys, semantic_keys)
    original_adv_probability, original_adv_scores, original_adv_verdicts = _score(original, X_adv_struct, X_adv_sem)
    e6_adv_probability, e6_adv_scores, e6_adv_verdicts = _score(e6, X_adv_struct, X_adv_sem)
    transformed_labels = np.ones(len(transformed_features), dtype=int)
    adversarial_metrics = {
        "original_phishout": _classification_metrics(transformed_labels, original_adv_probability, original_adv_scores, "Original PhishOut unseen adversarial subset"),
        "e6_adversarially_trained_phishout": _classification_metrics(transformed_labels, e6_adv_probability, e6_adv_scores, "E6 unseen adversarial subset"),
    }

    clean_phishing = phishing[["sample_id"]].copy()
    clean_phishing["label"] = 1
    original_scores_by_id = pd.Series(original_clean_scores, index=test["sample_id"])
    original_verdicts_by_id = pd.Series(original_clean_verdicts, index=test["sample_id"])
    e6_scores_by_id = pd.Series(e6_clean_scores, index=test["sample_id"])
    e6_verdicts_by_id = pd.Series(e6_clean_verdicts, index=test["sample_id"])
    clean_phishing["clean_score"] = clean_phishing["sample_id"].map(original_scores_by_id)
    clean_phishing["clean_verdict"] = clean_phishing["sample_id"].map(original_verdicts_by_id)
    e6_clean_phishing = phishing[["sample_id"]].copy()
    e6_clean_phishing["label"] = 1
    e6_clean_phishing["clean_score"] = e6_clean_phishing["sample_id"].map(e6_scores_by_id)
    e6_clean_phishing["clean_verdict"] = e6_clean_phishing["sample_id"].map(e6_verdicts_by_id)
    original_pairs = clean_phishing.copy()
    original_pairs["perturbed_score"] = original_adv_scores
    original_pairs["perturbed_verdict"] = original_adv_verdicts
    e6_pairs = e6_clean_phishing.copy()
    e6_pairs["perturbed_score"] = e6_adv_scores
    e6_pairs["perturbed_verdict"] = e6_adv_verdicts
    _assert_pairing(clean_phishing, transformed_features, 1)
    _assert_pairing(e6_clean_phishing, transformed_features, 1)

    pairing = {
        "sample_count": int(len(phishing)),
        "same_sample_ids": True,
        "duplicate_clean_ids": 0,
        "duplicate_perturbed_ids": 0,
        "labels_preserved": True,
        "clean_test_training_overlap": 0,
    }
    summary = {
        "research_question": "Does E6 adversarial training generalize to an unseen URL percent-encoding attack?",
        "transformation": UNSEEN_TRANSFORMATION,
        "training_used": False,
        "validation_used": False,
        "test_evaluation": "single final evaluation on existing 1,533-row test split; 612 phishing rows transformed",
        "clean_test": clean_metrics,
        "unseen_adversarial_subset": adversarial_metrics,
        "evasion": {},
        "pairing": pairing,
        "raw_source": str(raw_dir),
        "original_models_untouched": True,
    }
    # Calculate paired evasion against clean and perturbed rows by sample_id.
    summary["evasion"]["original_phishout"] = _paired_evasion(clean_phishing, original_pairs)
    summary["evasion"]["e6_adversarially_trained_phishout"] = _paired_evasion(e6_clean_phishing, e6_pairs)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUTPUT_DIR / "e7_config.json").write_text(json.dumps({
        "transformation": UNSEEN_TRANSFORMATION,
        "reason_unseen": "not present in the four E6 training transformations",
        "e6_training_transformations": ["benign_content_padding", "visible_text_obfuscation", "cosmetic_dom_addition", "url_lexical_query_addition"],
        "training_used": False,
        "validation_used": False,
        "raw_source": str(raw_dir),
        "pairing": pairing,
    }, indent=2), encoding="utf-8")
    (OUTPUT_DIR / "e7_results.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    transformed_frame.drop(columns=["html"]).to_csv(OUTPUT_DIR / "e7_transformed_samples.csv", index=False)
    rows = []
    for model_name in ("original_phishout", "e6_adversarially_trained_phishout"):
        row = {"model": model_name, **summary["evasion"][model_name]}
        rows.append(row)
    pd.DataFrame(rows).to_csv(OUTPUT_DIR / "e7_results.csv", index=False)
    (OUTPUT_DIR / "e7_summary.json").write_text(json.dumps({
        "transformation": UNSEEN_TRANSFORMATION,
        "sample_count": len(phishing),
        "clean_test": clean_metrics,
        "unseen_adversarial_subset": adversarial_metrics,
        "evasion": summary["evasion"],
        "pairing": pairing,
    }, indent=2), encoding="utf-8")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate E6 on an unseen offline URL transformation")
    parser.add_argument("--raw-dir", type=Path, default=RAW_DIR)
    args = parser.parse_args()
    result = run(args.raw_dir)
    print(json.dumps({"clean_test": result["clean_test"], "evasion": result["evasion"]}, indent=2))