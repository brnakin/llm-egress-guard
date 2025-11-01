"""Actions applied after policy evaluation."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from app.normalize import NormalizationResult
from app.policy import PolicyDecision


def apply_actions(
    *,
    parsed_text: str,
    findings: Sequence[Any],
    decision: PolicyDecision,
    normalized: NormalizationResult,
) -> str:
    """Apply the configured actions to the text.

    Sprint 1 keeps the actions transparent (no modifications). Future sprints
    will mutate the response based on findings and policy decisions.
    """

    del findings, decision, normalized  # to be used in later sprints
    return parsed_text
