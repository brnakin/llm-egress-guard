"""Command detector implementations."""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any, Callable

from app.pipeline import Finding
from app.policy import PolicyDefinition, PolicyRule

from . import common

CURL_PIPE_REGEX = re.compile(r"\bcurl\s+[^\n|]+?\|\s*(?:sh|bash)\b", re.IGNORECASE)
WGET_PIPE_REGEX = re.compile(r"\bwget\s+[^\n|]+?\|\s*(?:sh|bash)\b", re.IGNORECASE)
POWERSHELL_ENC_REGEX = re.compile(r"\bpowershell(?:\.exe)?\s+-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]+", re.IGNORECASE)
INVOKE_WEBREQUEST_REGEX = re.compile(
    r"\binvoke-webrequest\s+[^\n;]+?(?:\|\s*iex|\|\s*invoke-expression)", re.IGNORECASE
)
POWERSHELL_IWR_REGEX = re.compile(r"\b(?:invoke-webrequest|iwr)\s+[^\n]+\|\s*powershell", re.IGNORECASE)
RM_RF_REGEX = re.compile(r"\brm\s+-rf\s+/(?:\S*)", re.IGNORECASE)
REG_ADD_REGEX = re.compile(r"\breg\s+add\s+[^\n]+", re.IGNORECASE)
CERTUTIL_REGEX = re.compile(r"\bcertutil\.exe?\s+-urlcache(?:\s+-split)?\s+-f\s+[^\s]+", re.IGNORECASE)
MSHTA_REGEX = re.compile(r"\bmshta\.exe?\s+[^\s]+", re.IGNORECASE)
RUNDLL32_REGEX = re.compile(r"\brundll32\.exe?\s+[^\s,]+,[^\s]+", re.IGNORECASE)


def scan(
    text: str,
    *,
    policy: PolicyDefinition,
    metadata: dict[str, Any] | None = None,
    rules: Sequence[PolicyRule] | None = None,
) -> list[Finding]:
    selected_rules = list(rules) if rules is not None else list(policy.iter_rules("cmd"))
    findings: list[Finding] = []
    for rule in selected_rules:
        matches = _run_scanner(rule, text)
        findings.extend(
            common.build_findings(policy=policy, rule=rule, matches=matches, metadata=metadata)
        )
    return findings


def _run_scanner(
    rule: PolicyRule,
    text: str,
) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    if rule.pattern:
        pattern = re.compile(rule.pattern, re.IGNORECASE)
        return _regex_matches(pattern, text)

    scanners: dict[str, Callable[[str], list[tuple[str, tuple[int, int], dict[str, Any]]]]] = {
        "curl_pipe": _scan_curl_pipe,
        "wget_pipe": _scan_wget_pipe,
        "powershell_encoded": _scan_powershell_encoded,
        "invoke_webrequest": _scan_invoke_webrequest,
        "powershell_iwr": _scan_powershell_iwr,
        "rm_rf": _scan_rm_rf,
        "reg_add": _scan_reg_add,
        "certutil": _scan_certutil,
        "mshta": _scan_mshta,
        "rundll32": _scan_rundll32,
    }
    scanner = scanners.get(rule.kind or "")
    if not scanner:
        return []
    return scanner(text)


def _regex_matches(
    pattern: re.Pattern[str],
    text: str,
) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    results: list[tuple[str, tuple[int, int], dict[str, Any]]] = []
    for match in pattern.finditer(text):
        command = match.group(0)
        detail = _command_detail(command, reason="pattern")
        results.append((command, match.span(), detail))
    return results


def _scan_curl_pipe(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    return _matches_with_reason(CURL_PIPE_REGEX, text, reason="curl_pipe")


def _scan_wget_pipe(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    return _matches_with_reason(WGET_PIPE_REGEX, text, reason="wget_pipe")


def _scan_powershell_encoded(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    return _matches_with_reason(POWERSHELL_ENC_REGEX, text, reason="powershell_encoded")


def _scan_invoke_webrequest(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    return _matches_with_reason(INVOKE_WEBREQUEST_REGEX, text, reason="invoke_webrequest")


def _scan_powershell_iwr(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    return _matches_with_reason(POWERSHELL_IWR_REGEX, text, reason="powershell_iwr")


def _scan_rm_rf(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    return _matches_with_reason(RM_RF_REGEX, text, reason="rm_rf")


def _scan_reg_add(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    return _matches_with_reason(REG_ADD_REGEX, text, reason="reg_add")


def _scan_certutil(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    return _matches_with_reason(CERTUTIL_REGEX, text, reason="certutil")


def _scan_mshta(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    return _matches_with_reason(MSHTA_REGEX, text, reason="mshta")


def _scan_rundll32(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    return _matches_with_reason(RUNDLL32_REGEX, text, reason="rundll32")


def _matches_with_reason(
    pattern: re.Pattern[str],
    text: str,
    *,
    reason: str,
) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    results: list[tuple[str, tuple[int, int], dict[str, Any]]] = []
    for match in pattern.finditer(text):
        command = match.group(0)
        detail = _command_detail(command, reason=reason)
        results.append((command, match.span(), detail))
    return results


def _command_detail(command: str, *, reason: str) -> dict[str, Any]:
    preview = common.truncate_preview(command, limit=60)
    return {
        "masked": common.CMD_PLACEHOLDER,
        "replacement": common.CMD_PLACEHOLDER,
        "preview": preview,
        "reason": reason,
    }
