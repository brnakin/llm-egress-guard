"""PII detector implementations."""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from app.pipeline import Finding
from app.policy import PolicyDefinition, PolicyRule

from . import common

EMAIL_REGEX = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
IBAN_TR_REGEX = re.compile(r"\bTR\d{2}(?:\s*\d{4}){5}\s*\d{2}\b", re.IGNORECASE)
IBAN_DE_REGEX = re.compile(r"\bDE\d{2}(?:\s*\d{4}){4}\s*\d{2}\b", re.IGNORECASE)
TCKN_REGEX = re.compile(r"\b\d{11}\b")
PAN_REGEX = re.compile(
    r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b"
)
IPV4_REGEX = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")

PHONE_PATTERNS: dict[str, re.Pattern[str]] = {
    "phone_tr": re.compile(r"\b(?:\+?90|0)?\s?(?:5\d{2}|[2348]\d{2})[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}\b"),
    "phone_en": re.compile(r"\b(?:\+?1|\+?44)?[-.\s]?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "phone_de": re.compile(r"\b(?:\+?49)?[\s-]?(?:\(0\))?(?:1\d{2}|[2-9]\d{1,3})[\s-]?\d{3,8}\b"),
    "phone_fr": re.compile(r"\b(?:\+?33|0)[\s.-]?[1-9](?:[\s.-]?\d{2}){4}\b"),
    "phone_es": re.compile(r"\b(?:\+?34)?\s?(?:[67]\d{2}|9\d{2})\s?\d{3}\s?\d{3}\b"),
    "phone_it": re.compile(r"\b(?:\+?39)?\s?3\d{2}\s?\d{3}\s?\d{4}\b"),
    "phone_pt": re.compile(r"\b(?:\+?351)?\s?9\d{2}\s?\d{3}\s?\d{3}\b"),
    "phone_hi": re.compile(r"\b(?:\+?91)?\s?[6-9]\d{4}\s?\d{5}\b"),
    "phone_zh": re.compile(r"\b(?:\+?86)?\s?1[3-9]\d{9}\b"),
    "phone_ru": re.compile(r"\b(?:\+?7|8)\s?\d{3}\s?\d{3}\s?\d{2}\s?\d{2}\b"),
    "phone": re.compile(r"\b(?:\+?\d{1,3}[\s\-.]?)?(?:\(?\d{2,4}\)?[\s\-.]?){2,3}\d{2,4}\b"),
}


def scan(
    text: str,
    *,
    policy: PolicyDefinition,
    metadata: dict[str, Any] | None = None,
    rules: Sequence[PolicyRule] | None = None,
) -> list[Finding]:
    selected_rules = list(rules) if rules is not None else list(policy.iter_rules("pii"))
    findings: list[Finding] = []
    for rule in selected_rules:
        if rule.kind == "email":
            matches = _scan_emails(text)
        elif rule.kind and rule.kind.startswith("phone"):
            matches = _scan_phone(text, pattern_key=rule.kind)
        elif rule.kind == "iban_tr":
            matches = _scan_iban(text, regex=IBAN_TR_REGEX, country="TR")
        elif rule.kind == "iban_de":
            matches = _scan_iban(text, regex=IBAN_DE_REGEX, country="DE")
        elif rule.kind == "tckn":
            matches = _scan_tckn(text)
        elif rule.kind == "pan":
            matches = _scan_pan(text)
        elif rule.kind == "ipv4":
            matches = _scan_ipv4(text)
        else:
            continue
        findings.extend(
            common.build_findings(policy=policy, rule=rule, matches=matches, metadata=metadata)
        )
    return findings


def _scan_emails(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    results: list[tuple[str, tuple[int, int], dict[str, Any]]] = []
    for match in EMAIL_REGEX.finditer(text):
        value = match.group(0)
        masked = _mask_email(value)
        detail = {
            "masked": masked,
            "replacement": masked,
            "preview": masked,
        }
        results.append((value, match.span(), detail))
    return results


def _scan_phone(text: str, *, pattern_key: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    pattern = PHONE_PATTERNS.get(pattern_key) or PHONE_PATTERNS["phone"]
    results: list[tuple[str, tuple[int, int], dict[str, Any]]] = []
    for match in pattern.finditer(text):
        raw = match.group(0)
        digits = re.sub(r"\D", "", raw)
        if len(digits) < 9 or len(digits) > 15:
            continue
        masked = f"***{digits[-2:]}" if len(digits) > 2 else common.MASK_PLACEHOLDER
        detail = {
            "masked": masked,
            "replacement": masked,
            "preview": masked,
            "pattern": pattern_key,
        }
        results.append((raw, match.span(), detail))
    return results


def _scan_iban(
    text: str,
    *,
    regex: re.Pattern[str],
    country: str,
) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    results: list[tuple[str, tuple[int, int], dict[str, Any]]] = []
    for match in regex.finditer(text):
        raw = match.group(0)
        normalized = re.sub(r"\s+", "", raw).upper()
        expected_length = 26 if country == "TR" else 22
        if len(normalized) != expected_length or not normalized.startswith(country):
            continue
        masked = f"{country}****************{normalized[-4:]}"
        detail = {
            "masked": masked,
            "replacement": masked,
            "preview": masked,
        }
        results.append((raw, match.span(), detail))
    return results


def _scan_tckn(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    results: list[tuple[str, tuple[int, int], dict[str, Any]]] = []
    for match in TCKN_REGEX.finditer(text):
        candidate = match.group(0)
        if not _is_valid_tckn(candidate):
            continue
        masked = f"********{candidate[-3:]}"
        detail = {
            "masked": masked,
            "replacement": masked,
            "preview": masked,
        }
        results.append((candidate, match.span(), detail))
    return results


def _scan_pan(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    results: list[tuple[str, tuple[int, int], dict[str, Any]]] = []
    for match in PAN_REGEX.finditer(text):
        candidate = match.group(0)
        if not _passes_luhn(candidate):
            continue
        masked = f"**** **** **** {candidate[-4:]}"
        detail = {
            "masked": masked,
            "replacement": masked,
            "preview": masked,
        }
        results.append((candidate, match.span(), detail))
    return results


def _scan_ipv4(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    results: list[tuple[str, tuple[int, int], dict[str, Any]]] = []
    for match in IPV4_REGEX.finditer(text):
        ip = match.group(0)
        masked = "[ip-redacted]"
        detail = {
            "masked": masked,
            "replacement": masked,
            "preview": ip,
        }
        results.append((ip, match.span(), detail))
    return results


def _passes_luhn(value: str) -> bool:
    digits = [int(char) for char in value if char.isdigit()]
    checksum = 0
    parity = len(digits) % 2
    for idx, digit in enumerate(digits):
        if idx % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _mask_email(value: str) -> str:
    local, _, domain = value.partition("@")
    if not local:
        return common.MASK_PLACEHOLDER
    if len(local) <= 2:
        return f"{local[0]}*@{domain}" if local else common.MASK_PLACEHOLDER
    masked_local = f"{local[0]}***{local[-1]}"
    return f"{masked_local}@{domain}"


def _is_valid_tckn(value: str) -> bool:
    if len(value) != 11 or not value.isdigit() or value[0] == "0":
        return False
    digits = [int(char) for char in value]
    odd_sum = sum(digits[0:9:2])
    even_sum = sum(digits[1:8:2])
    tenth = (odd_sum * 7 - even_sum) % 10
    if digits[9] != tenth:
        return False
    if digits[10] != sum(digits[:10]) % 10:
        return False
    return True
