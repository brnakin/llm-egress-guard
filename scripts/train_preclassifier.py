#!/usr/bin/env python3
"""
Train a lightweight pre-classifier (educational vs command vs text) using the
synthetic dataset we generated. Saves a sklearn pipeline (Tfidf + LogisticRegression)
as a joblib artifact.

Usage:
    python scripts/train_preclassifier.py \
        --train data/ml_training/preclf_train.jsonl \
        --eval data/ml_training/preclf_eval.jsonl \
        --output models/preclf_v1.joblib
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import joblib
import numpy as np
from sklearn import metrics
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer


LABELS = ("educational", "command", "text")


@dataclass
class Dataset:
    texts: list[str]
    labels: list[str]


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def build_dataset(objs: Iterable[dict]) -> Dataset:
    texts: list[str] = []
    labels: list[str] = []

    for obj in objs:
        label = obj.get("label")
        text = obj.get("text", "")
        seg_type = obj.get("segment_type")
        lang = obj.get("language")

        if label not in LABELS:
            continue  # skip unknown labels

        # Inject lightweight tokens for segment and language to help the model.
        tokens: list[str] = []
        if seg_type:
            tokens.append(f"SEGMENT_{seg_type}")
        if lang:
            tokens.append(f"LANG_{lang}")

        augmented_text = text
        if tokens:
            augmented_text = " ".join(tokens) + " " + augmented_text

        texts.append(augmented_text)
        labels.append(label)

    return Dataset(texts=texts, labels=labels)


def train_model(train_ds: Dataset, min_df: int, max_features: int) -> Pipeline:
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        min_df=min_df,
        max_features=max_features,
        sublinear_tf=True,
    )
    clf = LogisticRegression(
        max_iter=200,
        class_weight="balanced",
        n_jobs=-1,
    )
    pipe = Pipeline(
        [
            ("tfidf", vectorizer),
            ("clf", clf),
        ]
    )
    pipe.fit(train_ds.texts, train_ds.labels)
    return pipe


def evaluate(model: Pipeline, ds: Dataset) -> dict:
    preds = model.predict(ds.texts)
    acc = metrics.accuracy_score(ds.labels, preds)
    f1_macro = metrics.f1_score(ds.labels, preds, average="macro")
    report = metrics.classification_report(ds.labels, preds, labels=LABELS, output_dict=True)
    return {
        "accuracy": acc,
        "f1_macro": f1_macro,
        "report": report,
    }


def save_model(model: Pipeline, output: Path, metadata: dict) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "model": model,
        "metadata": metadata,
    }
    joblib.dump(payload, output)


def main() -> None:
    parser = argparse.ArgumentParser(description="Train pre-classifier (educational/command/text)")
    parser.add_argument("--train", required=True, type=Path, help="Train JSONL file")
    parser.add_argument("--eval", required=True, type=Path, help="Eval JSONL file")
    parser.add_argument("--output", required=True, type=Path, help="Output joblib path")
    parser.add_argument("--min-df", type=int, default=2, help="Tfidf min_df (default: 2)")
    parser.add_argument("--max-features", type=int, default=50000, help="Tfidf max_features (default: 50k)")
    args = parser.parse_args()

    if not args.train.exists():
        sys.exit(f"Train file not found: {args.train}")
    if not args.eval.exists():
        sys.exit(f"Eval file not found: {args.eval}")

    train_rows = read_jsonl(args.train)
    eval_rows = read_jsonl(args.eval)

    train_ds = build_dataset(train_rows)
    eval_ds = build_dataset(eval_rows)

    if not train_ds.texts or not eval_ds.texts:
        sys.exit("Train/eval datasets are empty or invalid.")

    print(f"Loaded train: {len(train_ds.texts)} samples, eval: {len(eval_ds.texts)} samples")

    model = train_model(train_ds, min_df=args.min_df, max_features=args.max_features)
    metrics_eval = evaluate(model, eval_ds)

    print("\nEval metrics:")
    print(f"  accuracy  : {metrics_eval['accuracy']:.4f}")
    print(f"  f1_macro  : {metrics_eval['f1_macro']:.4f}")
    print("\nClassification report:")
    for label in LABELS:
        if label in metrics_eval["report"]:
            r = metrics_eval["report"][label]
            print(
                f"  {label:12s} precision={r['precision']:.3f} "
                f"recall={r['recall']:.3f} f1={r['f1-score']:.3f}"
            )

    metadata = {
        "labels": LABELS,
        "min_df": args.min_df,
        "max_features": args.max_features,
        "train_samples": len(train_ds.texts),
        "eval_samples": len(eval_ds.texts),
        "metrics": {
            "accuracy": metrics_eval["accuracy"],
            "f1_macro": metrics_eval["f1_macro"],
        },
    }

    save_model(model, args.output, metadata)
    print(f"\nSaved model to: {args.output}")


if __name__ == "__main__":
    main()

