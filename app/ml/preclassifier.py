"""Lightweight pre-classifier with optional ML model loading and integrity checks."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib

KEYWORDS = {"curl", "wget", "powershell", "kubectl", "select", "insert", "delete"}
TRUSTED_MODEL_DIR = Path("models").resolve()


class ModelIntegrityError(Exception):
    """Raised when model integrity verification fails."""


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


def _sha256_file(path: Path) -> str:
    """Compute SHA256 hash of a file."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_model_integrity(model_path: Path, manifest_path: Path) -> None:
    """Verify model file against its manifest.

    Raises:
        ModelIntegrityError: If verification fails.
        FileNotFoundError: If manifest doesn't exist.
    """
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_sha = manifest.get("sha256")
    expected_size = manifest.get("size_bytes")

    actual_sha = _sha256_file(model_path)
    actual_size = model_path.stat().st_size

    errors: list[str] = []
    if expected_sha and expected_sha != actual_sha:
        errors.append(f"SHA256 mismatch: expected {expected_sha}, got {actual_sha}")
    if expected_size and expected_size != actual_size:
        errors.append(f"Size mismatch: expected {expected_size}, got {actual_size}")

    if errors:
        raise ModelIntegrityError("; ".join(errors))


def load_preclassifier(
    *,
    model_path: Path | None = None,
    manifest_path: Path | None = None,
    enforce_integrity: bool = True,
) -> PreClassifier | ModelPreClassifier:
    """Load the trained pre-classifier if available; fallback to heuristic.

    Args:
        model_path: Path to the model file. Defaults to models/preclf_v1.joblib.
        manifest_path: Path to the manifest file. Defaults to model_path with .manifest.json.
        enforce_integrity: If True, verify SHA256 before loading. Defaults to True.

    Returns:
        ModelPreClassifier if model loads successfully, PreClassifier otherwise.

    Raises:
        ModelIntegrityError: If integrity check fails and enforce_integrity is True.
        ValueError: If model path is outside trusted directory.
    """
    path = (model_path or Path("models/preclf_v1.joblib")).resolve()
    manifest = (manifest_path or path.with_suffix(".manifest.json")).resolve()

    if not path.exists():
        return PreClassifier()

    # Security: Verify model path is within trusted directory
    try:
        path.relative_to(TRUSTED_MODEL_DIR)
    except ValueError:
        raise ValueError(
            f"Model path {path} is outside trusted directory {TRUSTED_MODEL_DIR}"
        ) from None

    # Integrity check before loading untrusted pickle
    if enforce_integrity:
        _verify_model_integrity(path, manifest)

    try:
        artifact = joblib.load(path)
        return ModelPreClassifier(name=path.name, model=artifact)
    except Exception:
        return PreClassifier()
