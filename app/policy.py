"""Policy loading and evaluation utilities."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(slots=True)
class PolicyRule:
    id: str
    type: str
    action: str
    kind: str | None = None
    pattern: str | None = None


@dataclass(slots=True)
class PolicyDefinition:
    policy_id: str
    tiers: str
    allowlist: list[str] = field(default_factory=list)
    rules: list[PolicyRule] = field(default_factory=list)


@dataclass(slots=True)
class PolicyStore:
    definitions: dict[str, PolicyDefinition]


@dataclass(slots=True)
class PolicyDecision:
    blocked: bool
    risk_score: int
    applied_rules: list[str] = field(default_factory=list)
    safe_message_key: str | None = None


def load_policy(path: Path) -> PolicyStore:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if data is None:
        raise ValueError(f"Policy file {path} is empty")

    definitions: dict[str, PolicyDefinition] = {}

    if "policies" in data:
        policies_iter = data["policies"].items()
    else:
        policies_iter = [("default", data)]

    for policy_id, content in policies_iter:
        rules = [
            PolicyRule(
                id=rule["id"],
                type=rule["type"],
                action=rule["action"],
                kind=rule.get("kind"),
                pattern=rule.get("pattern"),
            )
            for rule in content.get("rules", [])
        ]
        definitions[policy_id] = PolicyDefinition(
            policy_id=policy_id,
            tiers=content.get("tiers", "default"),
            allowlist=list(content.get("allowlist", [])),
            rules=rules,
        )

    return PolicyStore(definitions=definitions)


def select_policy(store: PolicyStore, policy_id: str) -> PolicyDefinition:
    if policy_id in store.definitions:
        return store.definitions[policy_id]
    return store.definitions.get("default") or next(iter(store.definitions.values()))


def evaluate(
    policy_def: PolicyDefinition,
    *,
    findings: list[Any],
    metadata: dict[str, Any] | None = None,
) -> PolicyDecision:
    del metadata  # unused in sprint 1
    blocked = any(getattr(finding, "action", None) == "block" for finding in findings)
    applied_rules = [getattr(finding, "rule_id", "?") for finding in findings]
    risk_score = min(len(findings) * 10, 100)
    return PolicyDecision(blocked=blocked, risk_score=risk_score, applied_rules=applied_rules)
