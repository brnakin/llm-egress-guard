"""Generate synthetic secret tokens for regression inputs without storing literals."""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from hashlib import sha256


def _concat(*parts: str) -> str:
    return "".join(parts)


def _stripe_key() -> str:
    suffix = "D3M0FAK3VALUE1234567890AB"
    return _concat("sk_", "live", "_", suffix)


def _twilio_key() -> str:
    body = "1234abcd5678ef90fedcba0987654321"
    return _concat("S", "K", body)


def _slack_token() -> str:
    part1 = "1234ABCD5678"
    part2 = "98XY76CD54AB"
    secret = "klmnopqrstuvwx"
    return _concat("xox", "b-", part1, "-", part2, "-", secret)


def _openai_live_key() -> str:
    suffix = "L1V3KeyABCDEF1234567890ABCDEF1234567890"
    return _concat("sk", "-", "live", "-", suffix)


def _openai_project_key() -> str:
    suffix = "PR0JectKeyAbCdEf1234567890GhIjKlMnOpQr"
    return _concat("sk", "-", "proj", "-", suffix)


def _github_pat() -> str:
    suffix = "1234567890abcdef1234567890abcdef1234"
    return _concat("gh", "p_", suffix)


def _github_high_entropy() -> str:
    return "ZX9aBc8DeF7gHi6Jk5Lm4No3Pq2Rs1Tu0VwXY"


def _aws_access_key() -> str:
    return _concat("AKI", "A", "1234567890ABCDEF")


def _aws_secret_key() -> str:
    alphabet = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/"
    repeated = (alphabet * 2)[:40]
    return repeated


def _azure_sas_url() -> str:
    base = _concat("https://", "storage", ".blob.core.windows.net/container/file.txt")
    params = [
        "sv=2021-06-08",
        "st=2025-01-01T00%3A00%3A00Z",
        "se=2025-01-02T00%3A00%3A00Z",
        "sp=rl",
        "sig=abc123FAKE-SIGNATURE987654321",
    ]
    return base + "?" + "&".join(params)


def _pem_block() -> str:
    lines = [
        "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKcw",
        "ggSjAgEAAoIBAQC3x0l3Qe4p1EXA6i2GQm9z",
        "0b3u8q3j4v2Lw0YgK3Pj1u3Z9e1OZlHhG5Q8",
    ]
    return "\n".join(["-----BEGIN PRIVATE KEY-----", *lines, "-----END PRIVATE KEY-----"])


def _pem_snippet() -> str:
    line = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCFAKEDEMO=="
    return "\n".join(["-----BEGIN PRIVATE KEY-----", line, "-----END PRIVATE KEY-----"])


def _gcp_sa_json() -> str:
    pem_lines = (
        "-----BEGIN PRIVATE KEY-----\\n"
        "MIIBdemoPrivateKeyBlock1234567890ABCD==\\n"
        "-----END PRIVATE KEY-----\\n"
    )
    payload = {
        "type": "service_account",
        "project_id": "demo-project",
        "private_key_id": "abc123demo",
        "private_key": pem_lines,
        "client_email": "demo@demo.iam.gserviceaccount.com",
    }
    return json.dumps(payload, indent=2)


def _high_entropy_token() -> str:
    digest = sha256(b"llm-egress-guard-high-entropy").digest()
    token = base64.b64encode(digest).decode().rstrip("=")
    return token[:34]


def _jwt_token(subject: str) -> str:
    header = {"alg": "HS256", "typ": "JWT", "kid": "demo-key"}
    payload = {
        "sub": subject,
        "aud": "guard",
        "exp": 1999999999,
        "tenant": "acme",
        "scope": "read:all write:limited",
    }
    header_b64 = (
        base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode())
        .decode()
        .rstrip("=")
    )
    payload_b64 = (
        base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode())
        .decode()
        .rstrip("=")
    )
    signature = (
        base64.urlsafe_b64encode(f"sig:{subject}:demo-signature-verify-hash".encode())
        .decode()
        .rstrip("=")
    )
    return ".".join([header_b64, payload_b64, signature])


PLACEHOLDER_FACTORIES: dict[str, Callable[[], str]] = {
    "{{STRIPE_KEY}}": _stripe_key,
    "{{TWILIO_KEY}}": _twilio_key,
    "{{SLACK_TOKEN}}": _slack_token,
    "{{OPENAI_LIVE_KEY}}": _openai_live_key,
    "{{OPENAI_PROJECT_KEY}}": _openai_project_key,
    "{{GITHUB_PAT}}": _github_pat,
    "{{GITHUB_HIGH_ENTROPY}}": _github_high_entropy,
    "{{AWS_ACCESS_KEY}}": _aws_access_key,
    "{{AWS_SECRET_KEY}}": _aws_secret_key,
    "{{AZURE_SAS_URL}}": _azure_sas_url,
    "{{PEM_PRIVATE_BLOCK}}": _pem_block,
    "{{PEM_PRIVATE_SNIPPET}}": _pem_snippet,
    "{{GCP_SA_JSON}}": _gcp_sa_json,
    "{{HIGH_ENTROPY_TOKEN}}": _high_entropy_token,
    "{{JWT_ACCESS_TOKEN}}": lambda: _jwt_token("access-user"),
    "{{JWT_SAMPLE_TOKEN}}": lambda: _jwt_token("sample-user"),
}

PLACEHOLDER_CACHE: dict[str, str] = {}


def apply_placeholders(text: str) -> str:
    """Replace placeholder markers inside a text blob with synthetic secrets."""

    result = text
    for marker, factory in PLACEHOLDER_FACTORIES.items():
        if marker not in result:
            continue
        value = PLACEHOLDER_CACHE.setdefault(marker, factory())
        result = result.replace(marker, value)
    return result


def get_placeholder(name: str) -> str:
    """Return the concrete value for a specific placeholder marker."""

    marker = name if name.startswith("{{") else f"{{{{{name}}}}}"
    factory = PLACEHOLDER_FACTORIES.get(marker)
    if not factory:
        raise KeyError(f"Unknown placeholder {name}")
    return PLACEHOLDER_CACHE.setdefault(marker, factory())


__all__ = ["apply_placeholders", "get_placeholder"]
