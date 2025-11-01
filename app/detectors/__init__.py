"""Detector registry placeholder for Sprint 1."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any


def scan_all(content: str, *, rules: Sequence[Any] | None = None) -> list[Any]:
    """Run all detectors and return aggregated findings.

    Sprint 1 returns an empty list until detectors are implemented in Sprint 2.
    """

    del content, rules
    return []
