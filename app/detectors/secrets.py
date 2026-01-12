"""Secret detector implementations."""

from __future__ import annotations

import base64
import math
import re
from collections.abc import Callable, Sequence
from typing import Any

from app.pipeline import Finding
from app.policy import PolicyDefinition, PolicyRule

from . import common

JWT_REGEX = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+\b")
AWS_ACCESS_KEY_REGEX = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
AWS_SECRET_KEY_REGEX = re.compile(
    r"\b(?=[0-9A-Za-z/+]{40}\b)(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[+/])[0-9A-Za-z/+]{40}\b"
)
OPENAI_API_KEY_REGEX = re.compile(r"\bsk-(?:live|test)?-[A-Za-z0-9]{20,48}\b")
GITHUB_TOKEN_REGEX = re.compile(r"\bgh[psour]_[A-Za-z0-9]{36,}\b")
SLACK_TOKEN_REGEX = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")
STRIPE_TOKEN_REGEX = re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b")
TWILIO_TOKEN_REGEX = re.compile(r"\bSK[0-9a-fA-F]{32}\b")
AZURE_SAS_REGEX = re.compile(r"se=[^&]+&sp=[^&]+&sig=[^&]+", re.IGNORECASE)
PEM_BLOCK_REGEX = re.compile(
    r"-----BEGIN (?:RSA|EC|DSA)? ?PRIVATE KEY-----[\s\S]+?-----END (?:RSA|EC|DSA)? ?PRIVATE KEY-----"
)
GCP_SA_REGEX = re.compile(
    r'"type"\s*:\s*"service_account"[\s\S]{0,2000}?"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----"',
    re.IGNORECASE,
)
GENERIC_TOKEN_REGEX = re.compile(r"\b[a-zA-Z0-9/+_=]{32,}\b")


def scan(
    text: str,
    *,
    policy: PolicyDefinition,
    metadata: dict[str, Any] | None = None,
    rules: Sequence[PolicyRule] | None = None,
) -> list[Finding]:
    selected_rules = list(rules) if rules is not None else list(policy.iter_rules("secret"))
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
        "jwt": _scan_jwt,
        "aws_access_key": _scan_aws_access_keys,
        "aws_secret_key": _scan_aws_secret_keys,
        "openai_api_key": _scan_openai_keys,
        "github_token": _scan_github_tokens,
        "slack_token": _scan_slack_tokens,
        "stripe_key": _scan_stripe_keys,
        "twilio_key": _scan_twilio_keys,
        "azure_sas": _scan_azure_sas,
        "gcp_service_account": _scan_gcp_service_accounts,
        "pem_private_key": _scan_pem_blocks,
        "high_entropy": _scan_high_entropy_tokens,
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
        value = match.group(0)
        detail = {
            "masked": "[secret]",
            "replacement": "[secret]",
            "preview": "[secret]",
        }
        results.append((value, match.span(), detail))
    return results


def _scan_jwt(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    results: list[tuple[str, tuple[int, int], dict[str, Any]]] = []
    for match in JWT_REGEX.finditer(text):
        token = match.group(0)
        if not _looks_like_jwt(token):
            continue
        detail = {
            "masked": "[jwt-token]",
            "replacement": "[jwt-token]",
            "preview": "[secret]",
            "reason": "jwt_signature",
        }
        results.append((token, match.span(), detail))
    return results


def _scan_aws_access_keys(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    results: list[tuple[str, tuple[int, int], dict[str, Any]]] = []
    for match in AWS_ACCESS_KEY_REGEX.finditer(text):
        key = match.group(0)
        detail = {
            "masked": "[aws-access-key]",
            "replacement": "[aws-access-key]",
            "preview": "[secret]",
            "reason": "aws_access_key",
        }
        results.append((key, match.span(), detail))
    return results


def _scan_aws_secret_keys(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    results: list[tuple[str, tuple[int, int], dict[str, Any]]] = []
    for match in AWS_SECRET_KEY_REGEX.finditer(text):
        token = match.group(0)
        entropy = _shannon_entropy(token)
        if entropy < 3.5:
            continue
        detail = {
            "masked": "[aws-secret-key]",
            "replacement": "[aws-secret-key]",
            "preview": "[secret]",
            "entropy": round(entropy, 2),
            "reason": "aws_secret_key",
        }
        results.append((token, match.span(), detail))
    return results


def _scan_openai_keys(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    results: list[tuple[str, tuple[int, int], dict[str, Any]]] = []
    for match in OPENAI_API_KEY_REGEX.finditer(text):
        key = match.group(0)
        detail = {
            "masked": "[openai-key]",
            "replacement": "[openai-key]",
            "preview": "[secret]",
            "reason": "openai_api_key",
        }
        results.append((key, match.span(), detail))
    return results


def _scan_github_tokens(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    return _matches_with_placeholder(GITHUB_TOKEN_REGEX, text, token_type="github-token")


def _scan_slack_tokens(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    return _matches_with_placeholder(SLACK_TOKEN_REGEX, text, token_type="slack-token")


def _scan_stripe_keys(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    return _matches_with_placeholder(STRIPE_TOKEN_REGEX, text, token_type="stripe-key")


def _scan_twilio_keys(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    return _matches_with_placeholder(TWILIO_TOKEN_REGEX, text, token_type="twilio-key")


def _scan_azure_sas(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    return _matches_with_placeholder(AZURE_SAS_REGEX, text, token_type="azure-sas")


def _scan_pem_blocks(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    results: list[tuple[str, tuple[int, int], dict[str, Any]]] = []
    for match in PEM_BLOCK_REGEX.finditer(text):
        block = match.group(0)
        detail = {
            "masked": "[pem-private-key]",
            "replacement": "[pem-private-key]",
            "preview": "[secret]",
            "reason": "pem_private_key",
        }
        results.append((block, match.span(), detail))
    return results


def _scan_gcp_service_accounts(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    results: list[tuple[str, tuple[int, int], dict[str, Any]]] = []
    for match in GCP_SA_REGEX.finditer(text):
        block = match.group(0)
        detail = {
            "masked": "[gcp-service-account]",
            "replacement": "[gcp-service-account]",
            "preview": "[secret]",
            "reason": "gcp_service_account",
        }
        results.append((block, match.span(), detail))
    return results


def _scan_high_entropy_tokens(text: str) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    results: list[tuple[str, tuple[int, int], dict[str, Any]]] = []
    seen: set[str] = set()
    for match in GENERIC_TOKEN_REGEX.finditer(text):
        token = match.group(0)
        if token in seen:
            continue
        seen.add(token)
        entropy = _shannon_entropy(token)
        if entropy < 3.5:
            continue
        if not any(char.islower() for char in token):
            continue
        if not any(char.isupper() for char in token):
            continue
        if not any(char.isdigit() for char in token):
            continue
        detail = {
            "masked": "[token]",
            "replacement": "[token]",
            "preview": "[secret]",
            "entropy": round(entropy, 2),
            "reason": "high_entropy",
        }
        results.append((token, match.span(), detail))
    return results


def _matches_with_placeholder(
    pattern: re.Pattern[str],
    text: str,
    *,
    token_type: str,
) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    results: list[tuple[str, tuple[int, int], dict[str, Any]]] = []
    for match in pattern.finditer(text):
        value = match.group(0)
        detail = {
            "masked": f"[{token_type}]",
            "replacement": f"[{token_type}]",
            "preview": "[secret]",
            "reason": token_type,
        }
        results.append((value, match.span(), detail))
    return results


def _looks_like_jwt(token: str) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    for segment in parts:
        try:
            base64.urlsafe_b64decode(_pad_base64(segment))
        except (base64.binascii.Error, ValueError):
            return False
    return True


def _pad_base64(segment: str) -> str:
    padding = len(segment) % 4
    if padding:
        segment += "=" * (4 - padding)
    return segment


def _shannon_entropy(value: str) -> float:
    length = len(value)
    if length == 0:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log(probability, 2)
    return entropy
