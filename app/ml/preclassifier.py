"""Lightweight pre-classifier with optional ML model loading."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib

KEYWORDS = {"curl", "wget", "powershell", "kubectl", "select", "insert", "delete"}


@dataclass(slots=True)
class PreClassifier:
    name: str = "heuristic-v0"

    def predict(self, text: str) -> str:
        lowered = text.lower()
        if any(keyword in lowered for keyword in KEYWORDS):
            return "command"
        return "text"


@dataclass(slots=True)
class ModelPreClassifier:
    name: str
    model: Any

    def predict(self, text: str) -> str:
        pred = self.model["model"].predict([text])[0]
        return str(pred)


def load_preclassifier(*, model_path: Path | None = None) -> PreClassifier:
    """Load the trained pre-classifier if available; fallback to heuristic."""
    path = model_path or Path("models/preclf_v1.joblib")
    if path.exists():
        try:
            artifact = joblib.load(path)
            return ModelPreClassifier(name=path.name, model=artifact)
        except Exception:
            return PreClassifier()
    return PreClassifier()
