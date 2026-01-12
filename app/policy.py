"""Policy loading and evaluation utilities."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from typing import TYPE_CHECKING, Any

import yaml

if TYPE_CHECKING:
    from app.parser import ParsedContent

DEFAULT_RULE_WEIGHT = 10
_POLICY_CACHE: dict[Path, tuple[float, PolicyStore]] = {}
_POLICY_LOCK = RLock()

# Default context settings for risk adjustment
DEFAULT_CONTEXT_SETTINGS = {
    "enabled": True,
    "code_block_penalty": 15,  # Reduce risk score by 15 for findings in code blocks
    "explain_only_penalty": 25,  # Reduce risk score by 25 for educational context
    "link_context_bonus": 5,  # Increase risk by 5 for URLs in links (clickable)
}


@dataclass(slots=True)
class AllowlistEntry:
    """Represents a single allowlist matcher."""

    value: str | None = None
    regex: re.Pattern[str] | None = None
    rule_types: set[str] = field(default_factory=set)
    rule_kinds: set[str] = field(default_factory=set)
    rule_ids: set[str] = field(default_factory=set)
    tenants: set[str] = field(default_factory=set)

    def matches(
        self,
        candidate: str,
        *,
        rule_type: str,
        rule_kind: str | None,
        rule_id: str,
        tenant: str | None,
    ) -> bool:
        if self.rule_types and rule_type not in self.rule_types:
            return False
        if self.rule_kinds and (rule_kind is None or rule_kind not in self.rule_kinds):
            return False
        if self.rule_ids and rule_id not in self.rule_ids:
            return False
        if self.tenants and (tenant is None or tenant not in self.tenants):
            return False
        if self.value is not None and candidate == self.value:
            return True
        if self.regex and self.regex.search(candidate):
            return True
        return False


@dataclass(slots=True)
class PolicyRule:
    """A single policy rule."""

    id: str
    type: str
    action: str
    kind: str | None = None
    pattern: str | None = None
    severity: str = "medium"
    risk_weight: int = DEFAULT_RULE_WEIGHT
    safe_message: str | None = None


@dataclass(slots=True)
class ContextSettings:
    """Settings for context-based risk adjustment."""

    enabled: bool = True
    code_block_penalty: int = 15
    explain_only_penalty: int = 25
    link_context_bonus: int = 5


@dataclass(slots=True)
class PolicyDefinition:
    """A materialized policy ready for evaluation."""

    policy_id: str
    tiers: str
    allowlist: list[AllowlistEntry] = field(default_factory=list)
    rules: list[PolicyRule] = field(default_factory=list)
    context_settings: ContextSettings = field(default_factory=ContextSettings)

    def iter_rules(self, rule_type: str) -> Iterable[PolicyRule]:
        for rule in self.rules:
            if rule.type == rule_type:
                yield rule

    @property
    def rules_by_id(self) -> dict[str, PolicyRule]:
        return {rule.id: rule for rule in self.rules}

    def is_allowlisted(
        self,
        candidate: str,
        *,
        rule: PolicyRule,
        tenant: str | None = None,
    ) -> bool:
        for entry in self.allowlist:
            if entry.matches(
                candidate,
                rule_type=rule.type,
                rule_kind=rule.kind,
                rule_id=rule.id,
                tenant=tenant,
            ):
                return True
        return False


@dataclass(slots=True)
class PolicyStore:
    definitions: dict[str, PolicyDefinition]


@dataclass(slots=True)
class PolicyDecision:
    blocked: bool
    risk_score: int
    applied_rules: list[str] = field(default_factory=list)
    safe_message_key: str | None = None


def _parse_allowlist(
    entries: Sequence[Any],
    *,
    default_tenants: set[str] | None = None,
) -> list[AllowlistEntry]:
    parsed: list[AllowlistEntry] = []
    for raw in entries:
        if isinstance(raw, str):
            parsed.append(AllowlistEntry(value=raw, tenants=set(default_tenants or set())))
            continue
        if not isinstance(raw, dict):
            raise ValueError(f"Unsupported allowlist entry type: {type(raw)!r}")

        value = raw.get("value")
        regex_expr = raw.get("regex")
        if value is None and regex_expr is None:
            raise ValueError("Allowlist entry must define either 'value' or 'regex'")

        compiled = re.compile(regex_expr, re.IGNORECASE) if regex_expr else None
        rule_types = _ensure_set(raw.get("types"))
        rule_kinds = _ensure_set(raw.get("kinds"))
        rule_ids = _ensure_set(raw.get("rule_ids"))
        tenants = _ensure_set(raw.get("tenants"))
        if default_tenants:
            tenants |= default_tenants

        parsed.append(
            AllowlistEntry(
                value=value,
                regex=compiled,
                rule_types=rule_types,
                rule_kinds=rule_kinds,
                rule_ids=rule_ids,
                tenants=tenants,
            )
        )
    return parsed


def _ensure_set(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        return {value}
    return {str(item) for item in value}


def _collect_allowlist_entries(content: dict[str, Any]) -> list[AllowlistEntry]:
    combined: list[AllowlistEntry] = []

    base_entries = content.get("allowlist", []) or []
    combined.extend(_parse_allowlist(list(base_entries)))

    regex_entries = content.get("allowlist_regex", []) or []
    normalized_regex_entries: list[dict[str, Any]] = []
    for item in regex_entries:
        if isinstance(item, str):
            normalized_regex_entries.append({"regex": item})
        elif isinstance(item, dict):
            normalized_regex_entries.append(item)
        else:
            raise ValueError("allowlist_regex entries must be strings or dicts")
    combined.extend(_parse_allowlist(normalized_regex_entries))

    tenant_allowlist = content.get("tenant_allowlist", {}) or {}
    if isinstance(tenant_allowlist, dict):
        for tenant, tenant_entries in tenant_allowlist.items():
            entries_list: list[Any]
            if isinstance(tenant_entries, list | tuple):
                entries_list = list(tenant_entries)
            else:
                entries_list = [tenant_entries]
            combined.extend(_parse_allowlist(entries_list, default_tenants={str(tenant)}))
    else:
        raise ValueError("tenant_allowlist must be a mapping of tenant -> entries")

    return combined


def load_policy(path: Path, *, use_cache: bool = True) -> PolicyStore:
    resolved = path.resolve()
    try:
        mtime = resolved.stat().st_mtime
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"Policy file {resolved} not found") from exc

    if use_cache:
        with _POLICY_LOCK:
            cached = _POLICY_CACHE.get(resolved)
            if cached and cached[0] == mtime:
                return cached[1]

    data = yaml.safe_load(resolved.read_text(encoding="utf-8"))
    if data is None:
        raise ValueError(f"Policy file {resolved} is empty")

    definitions: dict[str, PolicyDefinition] = {}

    if "policies" in data:
        policies_iter = data["policies"].items()
    else:
        policies_iter = [("default", data)]

    for policy_id, content in policies_iter:
        allowlist = _collect_allowlist_entries(content)

        rules = [
            PolicyRule(
                id=rule["id"],
                type=rule["type"],
                action=rule["action"],
                kind=rule.get("kind"),
                pattern=rule.get("pattern"),
                severity=rule.get("severity", "medium"),
                risk_weight=int(rule.get("risk_weight", rule.get("weight", DEFAULT_RULE_WEIGHT))),
                safe_message=rule.get("safe_message"),
            )
            for rule in content.get("rules", [])
        ]

        # Parse context settings (Sprint 3)
        raw_context = content.get("context_settings", {}) or {}
        context_settings = ContextSettings(
            enabled=raw_context.get("enabled", DEFAULT_CONTEXT_SETTINGS["enabled"]),
            code_block_penalty=int(
                raw_context.get(
                    "code_block_penalty", DEFAULT_CONTEXT_SETTINGS["code_block_penalty"]
                )
            ),
            explain_only_penalty=int(
                raw_context.get(
                    "explain_only_penalty", DEFAULT_CONTEXT_SETTINGS["explain_only_penalty"]
                )
            ),
            link_context_bonus=int(
                raw_context.get(
                    "link_context_bonus", DEFAULT_CONTEXT_SETTINGS["link_context_bonus"]
                )
            ),
        )

        definitions[policy_id] = PolicyDefinition(
            policy_id=policy_id,
            tiers=content.get("tiers", "default"),
            allowlist=allowlist,
            rules=rules,
            context_settings=context_settings,
        )

    store = PolicyStore(definitions=definitions)

    if use_cache:
        with _POLICY_LOCK:
            _POLICY_CACHE[resolved] = (mtime, store)

    return store


def select_policy(store: PolicyStore, policy_id: str) -> PolicyDefinition:
    if policy_id in store.definitions:
        return store.definitions[policy_id]
    return store.definitions.get("default") or next(iter(store.definitions.values()))


def _apply_context_adjustment(
    finding: Any,
    base_risk: int,
    context_settings: ContextSettings,
) -> int:
    """Apply context-based risk adjustment to a finding.

    Args:
        finding: The finding to evaluate.
        base_risk: The base risk weight from the rule.
        context_settings: Context adjustment configuration.

    Returns:
        Adjusted risk score (can be negative for penalty adjustments).
    """
    if not context_settings.enabled:
        return base_risk

    adjusted = base_risk
    context = getattr(finding, "context", "text")
    explain_only = getattr(finding, "explain_only", False)
    finding_type = getattr(finding, "type", "")

    # Apply explain-only penalty (strongest reduction)
    # Only apply to command-type findings to avoid masking real PII/secrets
    if explain_only and finding_type == "cmd":
        adjusted -= context_settings.explain_only_penalty

    # Apply code block penalty (code is often educational/example)
    if context == "code" and not explain_only:  # Don't double-penalize
        adjusted -= context_settings.code_block_penalty

    # Apply link context bonus (clickable URLs are higher risk)
    if context == "link" and finding_type == "url":
        adjusted += context_settings.link_context_bonus

    # Ensure minimum of 0 for individual findings
    return max(adjusted, 0)


def evaluate(
    policy_def: PolicyDefinition,
    *,
    findings: list[Any],
    metadata: dict[str, Any] | None = None,
    parsed_content: ParsedContent | None = None,
    allow_explain_only_bypass: bool = False,
) -> PolicyDecision:
    """Evaluate findings against policy and return a decision.

    Args:
        policy_def: The policy definition to evaluate against.
        findings: List of findings from detectors.
        metadata: Reserved for future use.
        parsed_content: Reserved; context info is already in findings.
        allow_explain_only_bypass: If True, allow explain-only content to bypass
            blocking. Default is False for security (OWASP A04). Set to True only
            for tenants that explicitly opt-in to educational content bypass.

    Returns:
        PolicyDecision with blocked status, risk score, and applied rules.
    """
    del metadata  # reserved for future use
    del parsed_content  # context info is already in findings

    blocked = False
    applied_rules: list[str] = []
    safe_message_key: str | None = None
    risk_score = 0

    rules_by_id = policy_def.rules_by_id
    context_settings = policy_def.context_settings

    for finding in findings:
        rule_id = getattr(finding, "rule_id", "?")
        applied_rules.append(rule_id)

        rule = rules_by_id.get(rule_id)
        if rule is None:
            risk_score += DEFAULT_RULE_WEIGHT
            continue

        # Apply context-based risk adjustment
        base_weight = max(rule.risk_weight, 0)
        adjusted_weight = _apply_context_adjustment(finding, base_weight, context_settings)
        risk_score += adjusted_weight

        # Block decisions can be downgraded for educational/explain-only content
        # ONLY if allow_explain_only_bypass is explicitly enabled (opt-in)
        if rule.action == "block":
            explain_only = getattr(finding, "explain_only", False)
            finding_type = getattr(finding, "type", "")

            # Explain-only bypass is opt-in only (OWASP A04 hardening)
            if allow_explain_only_bypass and explain_only:
                # Explain-only command findings in code blocks should not block
                if finding_type == "cmd":
                    continue

                # Other explain-only findings with significantly reduced risk
                # can also be downgraded (threshold is half of default weight)
                if adjusted_weight < DEFAULT_RULE_WEIGHT // 2:
                    continue

            blocked = True
            safe_message_key = safe_message_key or rule.safe_message
        elif rule.safe_message and safe_message_key is None:
            safe_message_key = rule.safe_message

    risk_score = min(risk_score, 100)

    if blocked and safe_message_key is None:
        safe_message_key = "blocked"

    return PolicyDecision(
        blocked=blocked,
        risk_score=risk_score,
        applied_rules=applied_rules,
        safe_message_key=safe_message_key,
    )


def invalidate_policy_cache(path: Path | None = None) -> None:
    """Clear cached policy entries (all or a specific file)."""

    with _POLICY_LOCK:
        if path is None:
            _POLICY_CACHE.clear()
        else:
            _POLICY_CACHE.pop(path.resolve(), None)
