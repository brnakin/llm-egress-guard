"""URL risk detector implementations."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence
from typing import Any, Callable

from app.pipeline import Finding
from app.policy import PolicyDefinition, PolicyRule

from . import common

IP_URL_REGEX = re.compile(r"\bhttps?://(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?:/[^\s]*)?", re.IGNORECASE)
DATA_URL_REGEX = re.compile(r"\bdata:[^,\s]{1,100},[^\s]+", re.IGNORECASE)
EXECUTABLE_URL_REGEX = re.compile(
    r"\b(?:https?|ftp)://[^\s]+?\.(?:exe|msi|bat|cmd|ps1|psm1|js|scr|vbs|jar|zip|tgz|tar\.gz|sh|dll)(?:[?#][^\s]*)?",
    re.IGNORECASE,
)
CREDENTIAL_URL_REGEX = re.compile(r"\bhttps?://[^/\s:@]+:[^@\s]+@[^\s]+", re.IGNORECASE)
SHORTENER_DOMAINS = {
    "bit.ly",
    "goo.gl",
    "tinyurl.com",
    "t.co",
    "ow.ly",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "rebrand.ly",
    "buff.ly",
}
SUSPICIOUS_TLDS = {
    ".zip",
    ".mov",
    ".country",
    ".support",
    ".top",
    ".xyz",
    ".click",
    ".gq",
    ".work",
    ".kim",
}


def scan(
    text: str,
    *,
    policy: PolicyDefinition,
    metadata: dict[str, Any] | None = None,
    rules: Sequence[PolicyRule] | None = None,
) -> list[Finding]:
    selected_rules = list(rules) if rules is not None else list(policy.iter_rules("url"))
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
        "ip": _scan_ip_urls,
        "ip_literal": _scan_ip_urls,
        "data": _scan_data_urls,
        "data_uri": _scan_data_urls,
        "risky_extension": _scan_executable_urls,
        "executable_ext": _scan_executable_urls,
        "cred_in_url": _scan_credential_urls,
        "shortener": _scan_shorteners,
        "suspicious_tld": _scan_suspicious_tld,
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
        url = match.group(0)
        detail = _url_detail(url, reason="pattern")
        results.append((url, match.span(), detail))
    return results


def _scan_ip_urls(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    results: list[tuple[str, tuple[int, int], dict[str, Any]]] = []
    for match in IP_URL_REGEX.finditer(text):
        url = match.group(0)
        if not _ip_in_url(url):
            continue
        detail = _url_detail(url, reason="ip_url")
        results.append((url, match.span(), detail))
    return results


def _scan_data_urls(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    results: list[tuple[str, tuple[int, int], dict[str, Any]]] = []
    for match in DATA_URL_REGEX.finditer(text):
        url = match.group(0)
        detail = _url_detail(url, reason="data_url")
        results.append((url, match.span(), detail))
    return results


def _scan_executable_urls(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    results: list[tuple[str, tuple[int, int], dict[str, Any]]] = []
    for match in EXECUTABLE_URL_REGEX.finditer(text):
        url = match.group(0)
        detail = _url_detail(url, reason="executable_ext")
        results.append((url, match.span(), detail))
    return results


def _scan_credential_urls(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    results: list[tuple[str, tuple[int, int], dict[str, Any]]] = []
    for match in CREDENTIAL_URL_REGEX.finditer(text):
        url = match.group(0)
        detail = _url_detail(url, reason="cred_in_url")
        results.append((url, match.span(), detail))
    return results


def _scan_shorteners(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    results: list[tuple[str, tuple[int, int], dict[str, Any]]] = []
    for match in re.finditer(r"\bhttps?://[^\s]+", text, re.IGNORECASE):
        url = match.group(0)
        hostname = _extract_hostname(url)
        if hostname and hostname.lower() in SHORTENER_DOMAINS:
            detail = _url_detail(url, reason="shortener")
            results.append((url, match.span(), detail))
    return results


def _scan_suspicious_tld(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    results: list[tuple[str, tuple[int, int], dict[str, Any]]] = []
    for match in re.finditer(r"\bhttps?://[^\s]+", text, re.IGNORECASE):
        url = match.group(0)
        hostname = _extract_hostname(url)
        if hostname and any(hostname.lower().endswith(tld) for tld in SUSPICIOUS_TLDS):
            detail = _url_detail(url, reason="suspicious_tld")
            results.append((url, match.span(), detail))
    return results


def _ip_in_url(url: str) -> bool:
    match = re.search(r"https?://(?P<ip>(?:\d{1,3}\.){3}\d{1,3})", url, re.IGNORECASE)
    if not match:
        return False
    ip_str = match.group("ip")
    try:
        ipaddress.IPv4Address(ip_str)
    except ipaddress.AddressValueError:
        return False
    return True


def _url_detail(url: str, *, reason: str) -> dict[str, Any]:
    preview = common.truncate_preview(url, limit=48)
    return {
        "masked": common.URL_PLACEHOLDER,
        "replacement": common.URL_PLACEHOLDER,
        "preview": preview,
        "reason": reason,
    }


def _extract_hostname(url: str) -> str | None:
    match = re.match(r"https?://([^/]+)", url, re.IGNORECASE)
    if not match:
        return None
    hostname = match.group(1)
    return hostname.split(":", 1)[0]
