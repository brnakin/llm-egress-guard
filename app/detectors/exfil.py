"""Exfiltration detector implementations for large encoded blobs."""

from __future__ import annotations

import math
import re
from collections.abc import Sequence
from typing import Any

from app.pipeline import Finding
from app.policy import PolicyDefinition, PolicyRule

from . import common

BASE64_BLOB_REGEX = re.compile(r"(?:[A-Za-z0-9+/]{80}\s*){10,}")
HEX_BLOB_REGEX = re.compile(r"(?:[0-9A-Fa-f]{64}\s*){10,}")


def scan(
    text: str,
    *,
    policy: PolicyDefinition,
    metadata: dict[str, Any] | None = None,
    rules: Sequence[PolicyRule] | None = None,
) -> list[Finding]:
    selected_rules = list(rules) if rules is not None else list(policy.iter_rules("exfil"))
    findings: list[Finding] = []
    for rule in selected_rules:
        if rule.kind == "large_base64":
            matches = _scan_base64(text)
        elif rule.kind == "large_hex":
            matches = _scan_hex(text)
        else:
            continue
        findings.extend(
            common.build_findings(policy=policy, rule=rule, matches=matches, metadata=metadata)
        )
    return findings


def _scan_base64(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    results: list[tuple[str, tuple[int, int], dict[str, Any]]] = []
    for match in BASE64_BLOB_REGEX.finditer(text):
        blob = match.group(0)
        compact = re.sub(r"\s+", "", blob)
        if len(compact) < 800 or _entropy(compact) < 4.5:
            continue
        detail = {
            "masked": "[base64-blob]",
            "replacement": "[base64-blob]",
            "preview": "[truncated-blob]",
            "length": len(compact),
        }
        results.append((blob, match.span(), detail))
    return results


def _scan_hex(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    results: list[tuple[str, tuple[int, int], dict[str, Any]]] = []
    for match in HEX_BLOB_REGEX.finditer(text):
        blob = match.group(0)
        compact = re.sub(r"\s+", "", blob)
        if len(compact) < 640:  # 64 chars * 10 blocks
            continue
        detail = {
            "masked": "[hex-blob]",
            "replacement": "[hex-blob]",
            "preview": "[truncated-blob]",
            "length": len(compact),
        }
        results.append((blob, match.span(), detail))
    return results


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    entropy = 0.0
    for count in counts.values():
        probability = count / len(value)
        entropy -= probability * math.log(probability, 2)
    return entropy
