"""Optional spaCy validator placeholder."""

from __future__ import annotations

from collections.abc import Iterable


def validate_spans(spans: Iterable[str]) -> list[str]:
    """Return a filtered list of trusted spans.

    Sprint 1 short-circuits validation and returns the input spans unchanged.
    """

    return list(spans)
