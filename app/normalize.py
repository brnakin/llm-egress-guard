"""Text normalization utilities for the guard pipeline."""

from __future__ import annotations

import html
import logging
import re
import unicodedata
import urllib.parse
from collections.abc import Iterable
from dataclasses import dataclass, field
from time import perf_counter

LOGGER = logging.getLogger(__name__)

ZERO_WIDTH_CHARS: tuple[str, ...] = (
    "\u200b",  # zero width space
    "\u200c",  # zero width non-joiner
    "\u200d",  # zero width joiner
    "\u200e",  # left-to-right mark
    "\u200f",  # right-to-left mark
    "\u2060",  # word joiner
    "\ufeff",  # byte-order mark
)

_ALLOWED_CONTROL_CHARS: tuple[str, ...] = ("\n", "\r", "\t")

# Regex to count HTML entities (named and numeric)
_HTML_ENTITY_PATTERN = re.compile(r"&(?:[a-zA-Z]+|#x?[0-9a-fA-F]+);")


# Time budget for normalization (in seconds)
_TIME_BUDGET_SECONDS = 0.1


@dataclass(slots=True)
class NormalizationResult:
    """Outcome of the normalization stage."""

    text: str
    steps: list[str] = field(default_factory=list)
    entity_count: int = 0
    anomalies: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:  # pragma: no cover - convenience
        return bool(self.text)


def _count_html_entities(value: str) -> int:
    """Count HTML entities in the text."""
    return len(_HTML_ENTITY_PATTERN.findall(value))


def _safe_url_decode(value: str, *, max_passes: int = 2) -> tuple[str, bool, list[str]]:
    """URL decode with protection against excessive nested encoding.

    Args:
        value: Input string
        max_passes: Maximum number of decode passes (default 2 for double encoding)

    Returns:
        Tuple of (decoded_string, was_modified, anomalies)
    """
    anomalies: list[str] = []
    original = value
    passes = 0

    while passes < max_passes:
        try:
            decoded = urllib.parse.unquote(value)
        except Exception as e:
            LOGGER.warning("url_decode_failed", extra={"error": str(e), "length": len(value)})
            anomalies.append(f"url_decode_error: {type(e).__name__}")
            break

        if decoded == value:
            break

        value = decoded
        passes += 1

    if passes >= max_passes:
        anomalies.append("url_decode_max_passes_reached")

    return value, value != original, anomalies


def _html_unescape_known_entities(
    value: str, *, max_entities: int, max_output_length: int
) -> tuple[str, bool, list[str]]:
    """HTML unescape with limits on entity count and output length.

    Only processes standard named and numeric entities. Invalid entities are left unchanged.

    Args:
        value: Input string
        max_entities: Maximum number of entities to process
        max_output_length: Maximum output length

    Returns:
        Tuple of (unescaped_string, was_modified, anomalies)
    """
    anomalies: list[str] = []

    entity_count = _count_html_entities(value)
    if entity_count > max_entities:
        anomalies.append(f"html_entity_count_exceeded: {entity_count} > {max_entities}")
        LOGGER.warning(
            "html_unescape_skipped",
            extra={
                "reason": "entity_count_exceeded",
                "entity_count": entity_count,
                "max_entities": max_entities,
                "length": len(value),
            },
        )
        return value, False, anomalies

    try:
        unescaped = html.unescape(value)
    except Exception as e:
        LOGGER.warning("html_unescape_failed", extra={"error": str(e), "length": len(value)})
        anomalies.append(f"html_unescape_error: {type(e).__name__}")
        return value, False, anomalies

    if len(unescaped) > max_output_length:
        anomalies.append(f"html_output_length_exceeded: {len(unescaped)} > {max_output_length}")
        LOGGER.warning(
            "html_unescape_skipped",
            extra={
                "reason": "output_length_exceeded",
                "output_length": len(unescaped),
                "max_output_length": max_output_length,
            },
        )
        return value, False, anomalies

    # Detect potential double encoding by checking if result still contains entities
    if unescaped != value:
        remaining_entities = _count_html_entities(unescaped)
        if remaining_entities > 0 and remaining_entities < entity_count:
            anomalies.append(f"double_encoding_detected: {remaining_entities} entities remain")
            LOGGER.info(
                "double_encoding_detected",
                extra={
                    "original_entities": entity_count,
                    "remaining_entities": remaining_entities,
                },
            )

    return unescaped, unescaped != value, anomalies


def _strip_zero_width_characters(value: str) -> tuple[str, bool]:
    translation = {ord(char): None for char in ZERO_WIDTH_CHARS}
    stripped = value.translate(translation)
    return stripped, stripped != value


def _strip_control_characters(value: str) -> tuple[str, bool]:
    """Strip non-printable control characters except \\n, \\r, \\t."""
    result_chars: list[str] = []
    mutated = False
    for char in value:
        if char in _ALLOWED_CONTROL_CHARS:
            result_chars.append(char)
            continue
        category = unicodedata.category(char)
        if category.startswith("C"):
            mutated = True
            continue
        result_chars.append(char)
    result = "".join(result_chars)
    return result, mutated


_OBFUSCATION_AT_PATTERN = re.compile(r"(?i)(?:\[(?:at)\]|\((?:at)\)|\{(?:at)\}|\bat\b)")
_OBFUSCATION_DOT_PATTERN = re.compile(r"(?i)(?:\[(?:dot)\]|\((?:dot)\)|\{(?:dot)\}|\bdot\b)")


def _expand_obfuscations(value: str) -> tuple[str, bool]:
    original = value
    value = _OBFUSCATION_AT_PATTERN.sub("@", value)
    value = _OBFUSCATION_DOT_PATTERN.sub(".", value)
    # remove stray spaces around @ or .
    value = re.sub(r"\s*(?=@)", "", value)
    value = re.sub(r"(?<=@)\s+", "", value)
    value = re.sub(r"\s*(?=\.)", "", value)
    value = re.sub(r"(?<=\.)\s+", "", value)
    return value, value != original


def normalize_text(value: str | None, *, max_unescape: int = 1000) -> NormalizationResult:
    """Normalize the provided text for downstream detectors.

    Normalization Order (as per security specification):
    1. URL decode (with protection against nested encoding)
    2. HTML entity decode (with entity count and output length limits)
    3. Unicode NFKC normalization
    4. Strip zero-width characters and BOMs
    5. Strip non-printable control characters (except newline, carriage return, tab)

    Args:
        value: Input text to normalize (None becomes empty string)
        max_unescape: Maximum number of HTML entities to process (default 1000)

    Returns:
        NormalizationResult with normalized text, steps taken, entity count, and anomalies
    """
    start_time = perf_counter()
    steps: list[str] = []
    all_anomalies: list[str] = []
    entity_count = 0

    # Coerce None and non-strings
    if value is None:
        value = ""
    if not isinstance(value, str):  # pragma: no cover - guard against unexpected input
        value = str(value)
        steps.append("coerce_str")

    # Step 1: URL decode
    value, mutated, anomalies = _safe_url_decode(value, max_passes=2)
    all_anomalies.extend(anomalies)
    if mutated:
        steps.append("url_decode")

    # Step 2: HTML entity decode with limits
    elapsed = perf_counter() - start_time
    if elapsed > _TIME_BUDGET_SECONDS:
        LOGGER.warning(
            "normalization_time_budget_exceeded",
            extra={
                "elapsed_seconds": elapsed,
                "budget_seconds": _TIME_BUDGET_SECONDS,
                "step": "before_html_unescape",
            },
        )
        all_anomalies.append(f"time_budget_exceeded_at_html_unescape: {elapsed:.3f}s")
    else:
        entity_count = _count_html_entities(value)
        # Use max_unescape as both entity limit and output length limit
        value, mutated, anomalies = _html_unescape_known_entities(
            value, max_entities=max_unescape, max_output_length=max_unescape * 2
        )
        all_anomalies.extend(anomalies)
        if mutated:
            steps.append("html_unescape")

    # Step 3: Unicode NFKC normalization
    normalized = unicodedata.normalize("NFKC", value)
    if normalized != value:
        steps.append("nfkc")
    value = normalized

    # Step 4: Map homoglyphs and expand obfuscations
    value, mutated = _expand_obfuscations(value)
    if mutated:
        steps.append("expand_obfuscation")

    # Step 5: Strip zero-width characters
    value, mutated = _strip_zero_width_characters(value)
    if mutated:
        steps.append("strip_zero_width")

    # Step 6: Strip control characters
    value, mutated = _strip_control_characters(value)
    if mutated:
        steps.append("strip_control")

    # Normalize newlines for consistency (not in spec but useful)
    if "\r\n" in value:
        value = value.replace("\r\n", "\n")
        steps.append("normalize_newlines")

    # Final time check
    elapsed = perf_counter() - start_time
    if elapsed > _TIME_BUDGET_SECONDS:
        all_anomalies.append(f"total_time_exceeded: {elapsed:.3f}s")

    LOGGER.debug(
        "normalized text",
        extra={
            "steps": steps,
            "length": len(value),
            "entity_count": entity_count,
            "anomalies": all_anomalies,
            "elapsed_ms": elapsed * 1000,
        },
    )

    return NormalizationResult(
        text=value, steps=steps, entity_count=entity_count, anomalies=all_anomalies
    )


def normalize_many(
    values: Iterable[str | None], *, max_unescape: int = 1000
) -> list[NormalizationResult]:
    """Normalize a collection of strings eagerly.

    Args:
        values: Iterable of strings to normalize
        max_unescape: Maximum number of HTML entities to process per string

    Returns:
        List of NormalizationResult objects
    """
    return [normalize_text(value, max_unescape=max_unescape) for value in values]
