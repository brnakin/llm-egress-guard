"""Shared helpers for detector implementations."""

from __future__ import annotations

from hashlib import sha256
from typing import Any, Iterable

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
