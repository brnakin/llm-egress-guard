"""Pipeline orchestration for the guard service."""

from __future__ import annotations

from dataclasses import dataclass, field
from time import perf_counter
from typing import Any

import structlog

from app import actions, metrics, normalize, parser, policy
from app.settings import Settings

LOGGER = structlog.get_logger(__name__)


@dataclass(slots=True)
class GuardRequest:
    response: str
    policy_id: str = "default"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Finding:
    rule_id: str
    action: str
    type: str
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class PipelineResult:
    response: str
    findings: list[Finding]
    blocked: bool
    risk_score: int
    policy_id: str
    latency_ms: float
    version: str

    def asdict(self) -> dict[str, Any]:
        return {
            "response": self.response,
            "findings": [finding.__dict__ for finding in self.findings],
            "blocked": self.blocked,
            "risk_score": self.risk_score,
            "policy_id": self.policy_id,
            "latency_ms": self.latency_ms,
            "version": self.version,
        }


def run_pipeline(guard_request: GuardRequest, *, settings: Settings) -> PipelineResult:
    """Execute the guard pipeline for a single response."""

    start = perf_counter()
    LOGGER.info("pipeline.start", policy_id=guard_request.policy_id)

    normalized = normalize.normalize_text(guard_request.response)
    parsed = parser.parse_content(normalized.text, metadata=guard_request.metadata)

    loaded_policy = policy.load_policy(settings.policy_path)
    policy_view = policy.select_policy(loaded_policy, guard_request.policy_id)

    findings: list[Finding] = []
    # Future sprints: call detectors and populate findings

    decision = policy.evaluate(policy_view, findings=findings, metadata=guard_request.metadata)

    sanitized_text = actions.apply_actions(
        parsed_text=parsed.text,
        findings=findings,
        decision=decision,
        normalized=normalized,
    )

    latency_ms = (perf_counter() - start) * 1000
    metrics.observe_guard_run(latency_ms=latency_ms, findings=findings, blocked=decision.blocked)

    LOGGER.info(
        "pipeline.end",
        policy_id=guard_request.policy_id,
        blocked=decision.blocked,
        findings=len(findings),
        latency_ms=latency_ms,
    )

    return PipelineResult(
        response=sanitized_text,
        findings=findings,
        blocked=decision.blocked,
        risk_score=decision.risk_score,
        policy_id=guard_request.policy_id,
        latency_ms=latency_ms,
        version=settings.model_version,
    )
