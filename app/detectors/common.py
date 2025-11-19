"""Shared helpers for detector implementations."""

from __future__ import annotations

import base64
import json
import re
from hashlib import sha256
from typing import Any, Iterable

import ipaddress

from app.pipeline import Finding
from app.policy import PolicyDefinition, PolicyRule

MASK_PLACEHOLDER = "[REDACTED]"
URL_PLACEHOLDER = "[redacted-url]"
CMD_PLACEHOLDER = "[command-blocked]"


def hash_snippet(value: str) -> str:
    digest = sha256(value.encode("utf-8", errors="ignore")).hexdigest()
    return f"sha256:{digest}"


def mask_preview(value: str, *, visible_prefix: int = 1, visible_suffix: int = 1) -> str:
    if not value:
        return MASK_PLACEHOLDER
    length = len(value)
    if length <= visible_prefix + visible_suffix:
        return MASK_PLACEHOLDER
    prefix = value[:visible_prefix]
    suffix = value[-visible_suffix:] if visible_suffix else ""
    return f"{prefix}{'*' * (length - (visible_prefix + visible_suffix))}{suffix}"


def truncate_preview(value: str, *, limit: int = 24) -> str:
    if len(value) <= limit:
        return value
    return f"{value[:limit]}..."


def is_allowlisted(
    *,
    policy: PolicyDefinition,
    rule: PolicyRule,
    candidate: str,
    metadata: dict[str, Any] | None,
) -> bool:
    tenant = None
    if metadata and metadata.get("tenant") is not None:
        tenant = str(metadata["tenant"])
    return policy.is_allowlisted(candidate, rule=rule, tenant=tenant)


def build_findings(
    *,
    policy: PolicyDefinition,
    rule: PolicyRule,
    matches: Iterable[tuple[str, tuple[int, int], dict[str, Any]]],
    metadata: dict[str, Any] | None,
) -> list[Finding]:
    findings: list[Finding] = []
    for value, span, extra_detail in matches:
        if is_allowlisted(policy=policy, rule=rule, candidate=value, metadata=metadata):
            continue
        detail: dict[str, Any] = {
            "span": [int(span[0]), int(span[1])],
            "kind": rule.kind,
            "snippet_hash": hash_snippet(value),
        }
        detail.update(extra_detail)
        detail.setdefault("rule_id", rule.id)
        findings.append(Finding(rule_id=rule.id, action=rule.action, type=rule.type, detail=detail))
    return findings


def iban_mod97(value: str) -> bool:
    """Validate IBAN using mod-97."""
    if not value:
        return False
    normalized = re.sub(r"\s+", "", value).upper()
    if len(normalized) < 4 or not normalized.isalnum():
        return False
    rearranged = normalized[4:] + normalized[:4]
    converted = ""
    for char in rearranged:
        if char.isdigit():
            converted += char
        else:
            converted += str(ord(char) - 55)  # A=10
    remainder = 0
    for chunk in re.findall(r"\d{1,9}", converted):
        remainder = int(str(remainder) + chunk) % 97
    return remainder == 1


def b64urlsafe_decode(value: str, *, max_bytes: int = 16384) -> bytes | None:
    """Decode URL-safe base64 with optional size guard."""
    if value is None:
        return None
    padded = value + "=" * ((4 - len(value) % 4) % 4)
    if len(padded) > max_bytes * 2:
        return None
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, OSError):
        return None


def is_structured_jwt(token: str) -> bool:
    """Heuristically validate JWT structure (header.alg + payload)."""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    header_bytes = b64urlsafe_decode(parts[0], max_bytes=2048)
    payload_bytes = b64urlsafe_decode(parts[1], max_bytes=4096)
    if not header_bytes or not payload_bytes:
        return False
    try:
        header = json.loads(header_bytes.decode("utf-8"))
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(header, dict) or "alg" not in header:
        return False
    if not isinstance(payload, dict):
        return False
    exp = payload.get("exp")
    if exp is not None and not isinstance(exp, (int, float)):
        return False
    return True


def is_private_ipv4(value: str) -> bool:
    """Return True if the given IPv4 is private/reserved."""
    try:
        ip_obj = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip_obj.version != 4:
        return False
    return bool(
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
    )
