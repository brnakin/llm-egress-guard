"""Secret detector stubs."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any


def scan(text: str, *, rules: Sequence[Any] | None = None) -> list[Any]:
    del text, rules
    return []
