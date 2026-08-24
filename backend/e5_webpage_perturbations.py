"""Offline E5 webpage/URL-level robustness evaluation.

The runner reads raw Phish360 HTML from the external local source, mutates
copies in memory, re-extracts all model inputs, and scores them with the
frozen Phase 2 PhishOut models. It never fetches or writes a webpage.
"""
import argparse
import json
import re
import sys
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Tuple
from urllib.parse import urlsplit, urlunsplit

import numpy as np
import pandas as pd
from bs4 import BeautifulSoup, NavigableString

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from leakage_validator import extract_registered_domain
from ml_model import FEATURE_KEYS, extract_features, features_to_array
from webpage_analyzer import extract_semantic_features_from_html
from phishout_predictor import PhishOutPredictor, SEMANTIC_KEYS

DEFAULT_RAW_DIR = Path(r"D:\Downloads\phish360_parquet")
DEFAULT_PROCESSED_DIR = SCRIPT_DIR / "dataset" / "phish360" / "processed"
DEFAULT_OUTPUT_DIR = SCRIPT_DIR / "models" / "phish360" / "e5"


def add_benign_padding(url: str, html: str) -> Tuple[str, str]:
    soup = BeautifulSoup(html, "html.parser")
    body = soup.body or soup
    padding = soup.new_tag("section", attrs={"class": "site-information"})
    paragraph = soup.new_tag("p")
    paragraph.string = "Accessibility information, privacy details, and support resources."
    padding.append(paragraph)
    body.append(padding)
    return url, str(soup)


def obfuscate_visible_text(url: str, html: str) -> Tuple[str, str]:
    soup = BeautifulSoup(html, "html.parser")
    replacements = {
        "password": "pass-word",
        "verify": "ver-ify",
        "login": "log-in",
        "account": "acc-ount",
        "urgent": "ur-gent",
    }
    pattern = re.compile("|".join(re.escape(word) for word in replacements), re.IGNORECASE)
    for text_node in soup.find_all(string=True):
        if not isinstance(text_node, NavigableString):
            continue
        if text_node.parent.name in {"script", "style", "noscript"}:
            continue
        text_node.replace_with(pattern.sub(lambda match: replacements[match.group().lower()], str(text_node)))
    return url, str(soup)


def add_cosmetic_dom(url: str, html: str) -> Tuple[str, str]:
    soup = BeautifulSoup(html, "html.parser")
    body = soup.body or soup
    decoration = soup.new_tag("div", attrs={"class": "layout-spacer", "aria-hidden": "true"})
    decoration.append(soup.new_tag("header", attrs={"class": "site-header"}))
    decoration.append(soup.new_tag("footer", attrs={"class": "site-footer"}))
    body.insert(0, decoration)
    return url, str(soup)


def add_display_query_parameter(url: str, html: str) -> Tuple[str, str]:
    parts = urlsplit(url)
    query = f"{parts.query}&display=compact" if parts.query else "display=compact"
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment)), html


TRANSFORMATIONS: Dict[str, Callable[[str, str], Tuple[str, str]]] = {
    "benign_content_padding": add_benign_padding,
    "visible_text_obfuscation": obfuscate_visible_text,
    "cosmetic_dom_addition": add_cosmetic_dom,
    "url_lexical_query_addition": add_display_query_parameter,
}


def _load_frozen_scorer() -> Tuple[PhishOutPredictor, Dict]:
    predictor = PhishOutPredictor()
    if predictor._model_type != "phish360_learned_fusion":
        raise RuntimeError("Frozen Phish360 learned-fusion models could not be loaded")
    return predictor, predictor._threshold_cfg


def score_offline(predictor: PhishOutPredictor, url: str, html: str, thresholds: Dict) -> Dict:
    struct_features = extract_features(url)
    struct_array = features_to_array(struct_features)
    struct_probability = float(predictor._struct_model.predict_proba(
        predictor._struct_scaler.transform(struct_array)
    )[0, 1])

    semantic_raw = extract_semantic_features_from_html(html, url)
    semantic_values = [float(semantic_raw.get(key, 0) or 0) for key in SEMANTIC_KEYS]
    semantic_array = np.array(semantic_values).reshape(1, -1)
    semantic_probability = float(predictor._sem_model.predict_proba(
        predictor._sem_scaler.transform(semantic_array)
    )[0, 1])

    fusion_probability = float(predictor._fusion_model.predict_proba(
        np.array([[struct_probability, semantic_probability]])
    )[0, 1])
    risk_score = int(round(fusion_probability * 100))
    phishing_min = thresholds.get("phishing_min_risk_score", 57)
    safe_max = thresholds.get("safe_max_risk_score", 15)
    verdict = "PHISHING" if risk_score >= phishing_min else "SUSPICIOUS" if risk_score >= safe_max else "SAFE"
    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "fusion_probability": fusion_probability,
        "structural_probability": struct_probability,
        "semantic_probability": semantic_probability,
        "structural_features": struct_features,
        "semantic_features": semantic_raw,
    }


def score_offline_batch(
    predictor: PhishOutPredictor,
    cases: List[Tuple[str, str]],
    thresholds: Dict,
) -> List[Dict]:
    """Score stored URL/HTML cases in batches to avoid repeated model overhead."""
    structural_features = [extract_features(url) for url, _ in cases]
    structural_array = np.vstack([features_to_array(features) for features in structural_features])
    structural_probabilities = predictor._struct_model.predict_proba(
        predictor._struct_scaler.transform(structural_array)
    )[:, 1]

    semantic_features = [extract_semantic_features_from_html(html, url) for url, html in cases]
    semantic_array = np.asarray([
        [float(features.get(key, 0) or 0) for key in SEMANTIC_KEYS]
        for features in semantic_features
    ])
    semantic_probabilities = predictor._sem_model.predict_proba(
        predictor._sem_scaler.transform(semantic_array)
    )[:, 1]
    fusion_probabilities = predictor._fusion_model.predict_proba(
        np.column_stack([structural_probabilities, semantic_probabilities])
    )[:, 1]

    phishing_min = thresholds.get("phishing_min_risk_score", 57)
    safe_max = thresholds.get("safe_max_risk_score", 15)
    scored = []
    for index, probability in enumerate(fusion_probabilities):
        risk_score = int(round(float(probability) * 100))
        verdict = "PHISHING" if risk_score >= phishing_min else "SUSPICIOUS" if risk_score >= safe_max else "SAFE"
        scored.append({
            "risk_score": risk_score,
            "verdict": verdict,
            "fusion_probability": float(probability),
            "structural_probability": float(structural_probabilities[index]),
            "semantic_probability": float(semantic_probabilities[index]),
            "structural_features": structural_features[index],
            "semantic_features": semantic_features[index],
        })
    return scored


def _raw_phishing_rows(raw_dir: Path, sample_ids: Iterable[str]) -> pd.DataFrame:
    source = raw_dir / "Phish360_phish.parquet"
    raw = pd.read_parquet(source, columns=["folder_name", "URL", "full_html", "Class"])
    selected = raw[raw["folder_name"].isin(set(sample_ids))].copy()
    selected["url"] = selected["URL"].fillna("").astype(str).str.strip()
    selected["html"] = selected["full_html"].fillna("").astype(str)
    selected["label"] = 1
    selected["sample_id"] = selected["folder_name"].astype(str)
    selected["registered_domain"] = selected["url"].map(extract_registered_domain)
    return selected.sort_values("sample_id").reset_index(drop=True)


def _evaluate_rows(rows: pd.DataFrame, predictor: PhishOutPredictor, thresholds: Dict) -> Tuple[List[Dict], Dict]:
    records = []
    cases = []
    metadata = []
    for row in rows.itertuples(index=False):
        cases.append((row.url, row.html))
        metadata.append((row.sample_id, row.registered_domain, "clean"))
        for name, transform in TRANSFORMATIONS.items():
            perturbed_url, perturbed_html = transform(row.url, row.html)
            cases.append((perturbed_url, perturbed_html))
            metadata.append((row.sample_id, row.registered_domain, name))

    scored = score_offline_batch(predictor, cases, thresholds)
    clean_detected = 0
    score_index = 0
    for row in rows.itertuples(index=False):
        clean = scored[score_index]
        score_index += 1
        clean_detected += clean["verdict"] == "PHISHING"
        for name in TRANSFORMATIONS:
            transformed = scored[score_index]
            score_index += 1
            records.append({
                "sample_id": row.sample_id,
                "registered_domain": row.registered_domain,
                "transformation": name,
                "clean_risk_score": clean["risk_score"],
                "perturbed_risk_score": transformed["risk_score"],
                "clean_verdict": clean["verdict"],
                "perturbed_verdict": transformed["verdict"],
                "clean_detected": clean["verdict"] == "PHISHING",
                "evasion": clean["verdict"] == "PHISHING" and transformed["verdict"] != "PHISHING",
                "verdict_changed": clean["verdict"] != transformed["verdict"],
                "risk_score_change": transformed["risk_score"] - clean["risk_score"],
            })
    return records, {"clean_detected": int(clean_detected), "clean_total": len(rows)}


def _summarize(results: pd.DataFrame, clean: Dict, sample_count: int) -> Dict:
    summaries = []
    for name, group in results.groupby("transformation", sort=False):
        denominator = int(group["clean_detected"].sum())
        evaded = int(group["evasion"].sum())
        summaries.append({
            "transformation": name,
            "samples": len(group),
            "clean_detection_rate": clean["clean_detected"] / sample_count if sample_count else 0,
            "perturbed_detection_rate": float((group["perturbed_verdict"] == "PHISHING").mean()),
            "recall": float((group["perturbed_verdict"] == "PHISHING").mean()),
            "f1": _binary_f1(group["perturbed_verdict"] == "PHISHING"),
            "evasion_rate": evaded / denominator if denominator else 0,
            "clean_detected_denominator": denominator,
            "evasion_count": evaded,
            "verdict_changes": int(group["verdict_changed"].sum()),
            "mean_risk_score_change": float(group["risk_score_change"].mean()),
        })
    return {
        "research_question": "Can controlled URL/HTML changes reduce detection of unchanged phishing samples?",
        "sample_count": sample_count,
        "clean_detected": clean["clean_detected"],
        "transformations": summaries,
        "model_frozen": True,
        "offline_only": True,
    }


def _binary_f1(predicted_positive: pd.Series) -> float:
    """Compute F1 for this all-positive phishing evaluation population."""
    true_positive = int(predicted_positive.sum())
    false_negative = len(predicted_positive) - true_positive
    if true_positive == 0:
        return 0.0
    precision = true_positive / len(predicted_positive)
    recall = true_positive / (true_positive + false_negative)
    return 2 * precision * recall / (precision + recall)


def run(raw_dir: Path, processed_dir: Path, output_dir: Path, dev_count: int) -> Dict:
    train = pd.read_parquet(processed_dir / "train_features.parquet", columns=["sample_id", "url", "label", "registered_domain"])
    test = pd.read_parquet(processed_dir / "test_features.parquet", columns=["sample_id", "url", "label", "registered_domain"])
    train_phish = train[train["label"] == 1].sort_values("sample_id")
    test_phish = test[test["label"] == 1].sort_values("sample_id")
    dev_ids = set(train_phish.head(dev_count)["sample_id"])
    test_ids = set(test_phish["sample_id"])
    dev = _raw_phishing_rows(raw_dir, dev_ids)
    evaluation = _raw_phishing_rows(raw_dir, test_ids)
    if len(dev) != len(dev_ids) or len(evaluation) != len(test_ids):
        raise RuntimeError("Raw source does not contain every selected sample ID")
    if set(dev["sample_id"]) & set(evaluation["sample_id"]):
        raise RuntimeError("Sample ID leakage between development and evaluation rows")
    if set(dev["url"]) & set(evaluation["url"]):
        raise RuntimeError("URL leakage between development and evaluation rows")
    if set(dev["registered_domain"]) & set(evaluation["registered_domain"]):
        raise RuntimeError("Registered-domain leakage between development and evaluation rows")

    predictor, thresholds = _load_frozen_scorer()
    for row in dev.itertuples(index=False):
        for transform in TRANSFORMATIONS.values():
            transformed_url, transformed_html = transform(row.url, row.html)
            score_offline(predictor, transformed_url, transformed_html, thresholds)

    records, clean = _evaluate_rows(evaluation, predictor, thresholds)
    result_df = pd.DataFrame(records)
    summary = _summarize(result_df, clean, len(evaluation))
    summary.update({
        "raw_source": str(raw_dir),
        "development_samples": len(dev),
        "evaluation_sample_ids": sorted(test_ids),
        "leakage": {"url_overlap": 0, "registered_domain_overlap": 0, "sample_id_overlap": 0},
        "thresholds": {"safe_max_risk_score": thresholds.get("safe_max_risk_score", 15), "phishing_min_risk_score": thresholds.get("phishing_min_risk_score", 57)},
    })
    output_dir.mkdir(parents=True, exist_ok=True)
    result_df.to_csv(output_dir / "e5_results.csv", index=False)
    result_df.to_json(output_dir / "e5_results.json", orient="records", indent=2)
    (output_dir / "e5_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the offline PhishOut E5 evaluation")
    parser.add_argument("--raw-dir", type=Path, default=DEFAULT_RAW_DIR)
    parser.add_argument("--processed-dir", type=Path, default=DEFAULT_PROCESSED_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--dev-count", type=int, default=24)
    args = parser.parse_args()
    summary = run(args.raw_dir, args.processed_dir, args.output_dir, args.dev_count)
    for result in summary["transformations"]:
        print(f"{result['transformation']}: evasion_rate={result['evasion_rate']:.4f}, samples={result['samples']}")


if __name__ == "__main__":
    main()