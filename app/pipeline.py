"""Pipeline orchestration for the guard service."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
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
    # Context fields added by parser integration (Sprint 3)
    context: str = "text"  # Segment type: "text", "code", "link"
    explain_only: bool = False  # True if finding is in educational context


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
            "findings": [asdict(finding) for finding in self.findings],
            "blocked": self.blocked,
            "risk_score": self.risk_score,
            "policy_id": self.policy_id,
            "latency_ms": self.latency_ms,
            "version": self.version,
        }


def _annotate_findings_with_context(
    findings: list[Finding],
    parsed: parser.ParsedContent,
) -> None:
    """Annotate findings with segment context information.

    This enables context-aware risk adjustment in policy evaluation.
    Findings in code blocks marked as explain-only will receive reduced risk scores.

    Args:
        findings: List of detector findings to annotate.
        parsed: Parsed content with segment information.
    """
    for finding in findings:
        # Extract span from finding detail
        span = finding.detail.get("span")
        if span and len(span) >= 2:
            start, end = span[0], span[1]
            context_type, explain_only = parser.get_context_for_finding(
                start, end, parsed
            )
            finding.context = context_type
            finding.explain_only = explain_only
        # If no span available, default to text context (already set)


def _validate_pii_findings(
    findings: list[Finding],
    parsed: parser.ParsedContent,
    *,
    settings: Settings,
) -> list[Finding]:
    """Optionally validate PII findings with spaCy to reduce false positives."""
    if not settings.feature_ml_validator or not findings:
        return findings

    try:
        from app.ml.validator_spacy import get_validator
    except Exception:
        return findings

    validator = get_validator(languages=["en", "de"])
    validated: list[Finding] = []

    for finding in findings:
        if finding.type != "pii":
            validated.append(finding)
            continue

        kind = (finding.detail or {}).get("kind")
        expected_type: str | None = None
        if kind == "email":
            expected_type = "EMAIL"
        else:
            validated.append(finding)
            continue

        span = (finding.detail or {}).get("span")
        if not isinstance(span, (list, tuple)) or len(span) < 2:
            validated.append(finding)
            continue

        start, end = int(span[0]), int(span[1])
        snippet = parsed.text[start:end]
        result = validator.validate_span(snippet, expected_type)
        if result.is_valid and result.confidence >= validator.confidence_threshold:
            validated.append(finding)
        else:
            LOGGER.info(
                "ml_validator_rejected",
                rule_id=getattr(finding, "rule_id", "?"),
                kind=kind,
                snippet_hash=(finding.detail or {}).get("snippet_hash"),
            )

    return validated


def run_pipeline(guard_request: GuardRequest, *, settings: Settings) -> PipelineResult:
    """Execute the guard pipeline for a single response."""

    start = perf_counter()
    LOGGER.info("pipeline.start", policy_id=guard_request.policy_id)

    normalized = normalize.normalize_text(guard_request.response)

    # Parse content into segments for context-aware processing
    # ML pre-classifier can be passed here when available (Sprint 3)
    ml_preclassifier = None
    if settings.feature_ml_preclf:
        try:
            from app.ml.preclassifier import load_preclassifier

            ml_preclassifier = load_preclassifier(
                model_path=settings.preclf_model_path,
                manifest_path=settings.preclf_manifest_path,
                enforce_integrity=settings.enforce_model_integrity,
            )
            metrics.observe_ml_preclf_load(status="success")
        except Exception:
            metrics.observe_ml_preclf_load(status="fail")
            ml_preclassifier = None  # Fall back to heuristic inside parser

    if settings.feature_context_parsing:
        parsed = parser.parse_content(
            normalized.text,
            metadata=guard_request.metadata,
            ml_preclassifier=ml_preclassifier,
            shadow_mode=settings.shadow_mode,
            detect_explain_only_enabled=True,
        )
    else:
        parsed = parser.ParsedContent(
            text=normalized.text,
            segments=[
                parser.Segment(
                    type="text",
                    content=normalized.text,
                    start=0,
                    end=len(normalized.text),
                    metadata={},
                    explain_only=False,
                )
            ]
            if normalized.text
            else [],
            metadata=guard_request.metadata or {},
        )

    loaded_policy = policy.load_policy(settings.policy_path)
    policy_view = policy.select_policy(loaded_policy, guard_request.policy_id)

    findings: list[Finding] = []
    metadata = guard_request.metadata or {}
    rules_by_id = policy_view.rules_by_id

    from app.detectors import scan_all  # imported lazily to avoid circular imports

    for detector_name, detector_findings, detector_latency in scan_all(
        parsed.text,
        policy=policy_view,
        metadata=metadata,
    ):
        severities = []
        for finding in detector_findings:
            rule = rules_by_id.get(finding.rule_id)
            if rule is not None:
                severities.append(rule.severity)

        metrics.observe_detector(
            detector=detector_name,
            latency_ms=detector_latency,
            severities=severities,
        )

        findings.extend(detector_findings)
        if any(finding.action == "block" for finding in detector_findings):
            break

    findings = _validate_pii_findings(findings, parsed, settings=settings)

    # Annotate findings with segment context for risk adjustment
    _annotate_findings_with_context(findings, parsed)

    # Observe context metrics
    metrics.observe_context(parsed)

    decision = policy.evaluate(
        policy_view,
        findings=findings,
        metadata=guard_request.metadata,
        parsed_content=parsed,
        allow_explain_only_bypass=settings.allow_explain_only_bypass,
    )

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
