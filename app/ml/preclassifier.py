"""Lightweight pre-classifier stub for Sprint 1."""

from __future__ import annotations

from dataclasses import dataclass

KEYWORDS = {"curl", "wget", "powershell", "kubectl", "SELECT", "INSERT", "DELETE"}


@dataclass(slots=True)
class PreClassifier:
    name: str = "heuristic-v0"

    def predict(self, text: str) -> str:
        lowered = text.lower()
        if any(keyword in lowered for keyword in KEYWORDS):
            return "command"
        return "text"


def load_preclassifier() -> PreClassifier:
    return PreClassifier()
