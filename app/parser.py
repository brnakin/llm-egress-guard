"""Parser stage — placeholder for format-aware parsing in future sprints."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ParsedContent:
    text: str
    metadata: dict[str, Any] = field(default_factory=dict)


def parse_content(text: str, *, metadata: dict[str, Any] | None = None) -> ParsedContent:
    """Return a simple parsed view of the text.

    Sprint 1 keeps the parser minimal so detectors can iterate on raw text.
    """

    return ParsedContent(text=text, metadata=metadata or {})
