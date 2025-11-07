"""Actions applied after policy evaluation."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from threading import RLock
from typing import Any

import yaml

from app.normalize import NormalizationResult
from app.policy import PolicyDecision

SAFE_MESSAGES_PATH = Path("config/locales/en/safe_messages.yaml")
_SAFE_MESSAGES_CACHE: dict[Path, tuple[float, dict[str, dict[str, str]]]] = {}
_SAFE_MESSAGES_LOCK = RLock()


def apply_actions(
    *,
    parsed_text: str,
    findings: Sequence[Any],
    decision: PolicyDecision,
    normalized: NormalizationResult,
) -> str:
    """Apply masking, delinking, and block actions to the response text."""

    del normalized  # reserved for future use when span remapping is needed

    if decision.blocked:
        return _render_safe_message(decision.safe_message_key)

    replacements = _collect_replacements(findings)
    return _apply_replacements(parsed_text, replacements)


def _collect_replacements(findings: Sequence[Any]) -> list[tuple[int, int, str]]:
    replacements: list[tuple[int, int, str]] = []
    for finding in findings:
        action = getattr(finding, "action", "").lower()
        detail = getattr(finding, "detail", {}) or {}
        span = detail.get("span")
        if not isinstance(span, Sequence) or len(span) != 2:
            continue
        start, end = int(span[0]), int(span[1])
        replacement = _select_replacement(action, detail)
        if replacement is None:
            continue
        replacements.append((start, end, replacement))
    return replacements


def _select_replacement(action: str, detail: dict[str, Any]) -> str | None:
    if action == "mask":
        return str(detail.get("replacement") or detail.get("masked") or "[REDACTED]")
    if action == "delink":
        return str(detail.get("replacement") or "[redacted-url]")
    if action == "annotate":
        rule_id = detail.get("rule_id") or "annotated"
        return f"[flagged:{rule_id}]"
    if action == "remove":
        return ""
    # For block actions we return None because the entire response is replaced elsewhere.
    if action == "block":
        return None
    return str(detail.get("replacement") or detail.get("masked") or "[redacted]")


def _apply_replacements(text: str, replacements: list[tuple[int, int, str]]) -> str:
    if not replacements:
        return text

    ordered = sorted(replacements, key=lambda item: item[0])
    result_parts: list[str] = []
    cursor = 0
    for start, end, replacement in ordered:
        if start < cursor:
            continue
        result_parts.append(text[cursor:start])
        result_parts.append(replacement)
        cursor = max(cursor, end)
    result_parts.append(text[cursor:])
    return "".join(result_parts)


def _render_safe_message(key: str | None) -> str:
    messages = _safe_messages()
    entry = messages.get(key or "") or messages.get("blocked") or {}
    title = entry.get("title")
    description = entry.get("description")
    if title and description:
        return f"{title}: {description}"
    return description or title or "Response blocked due to policy violation."


def _safe_messages() -> dict[str, dict[str, str]]:
    path = SAFE_MESSAGES_PATH.resolve()
    try:
        mtime = path.stat().st_mtime
    except FileNotFoundError:
        with _SAFE_MESSAGES_LOCK:
            _SAFE_MESSAGES_CACHE.pop(path, None)
        return {}

    with _SAFE_MESSAGES_LOCK:
        cached = _SAFE_MESSAGES_CACHE.get(path)
        if cached and cached[0] == mtime:
            return cached[1]

    payload = path.read_text(encoding="utf-8")
    data = yaml.safe_load(payload) or {}
    safe_messages = data.get("safe_messages")
    if not isinstance(safe_messages, dict):
        parsed: dict[str, dict[str, str]] = {}
    else:
        parsed = {
            str(key): value
            for key, value in safe_messages.items()
            if isinstance(value, dict)
        }

    with _SAFE_MESSAGES_LOCK:
        _SAFE_MESSAGES_CACHE[path] = (mtime, parsed)

    return parsed
