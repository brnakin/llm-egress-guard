"""Prometheus metrics helpers."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
)

if TYPE_CHECKING:
    from app.parser import ParsedContent

REGISTRY = CollectorRegistry()

GUARD_LATENCY = Histogram(
    "egress_guard_latency_seconds",
    "Latency of guard pipeline executions",
    buckets=(0.005, 0.01, 0.02, 0.04, 0.08, 0.16, 0.32, 0.64, 1.28),
    registry=REGISTRY,
)

RULE_HITS = Counter(
    "egress_guard_rule_hits_total",
    "Number of times each rule fired",
    labelnames=("rule_id",),
    registry=REGISTRY,
)

BLOCKED_TOTAL = Counter(
    "egress_guard_blocked_total",
    "Number of responses blocked",
    registry=REGISTRY,
)

DETECTOR_LATENCY = Histogram(
    "egress_guard_detector_latency_seconds",
    "Latency of individual detector executions",
    labelnames=("detector",),
    buckets=(0.001, 0.003, 0.005, 0.01, 0.02, 0.04, 0.08, 0.16),
    registry=REGISTRY,
)

RULE_SEVERITY = Counter(
    "egress_guard_rule_severity_total",
    "Number of rule hits grouped by severity",
    labelnames=("severity",),
    registry=REGISTRY,
)

# Sprint 3: Context-aware metrics
CONTEXT_TYPE_TOTAL = Counter(
    "egress_guard_context_type_total",
    "Count of segments by type (text, code, link)",
    labelnames=("type",),
    registry=REGISTRY,
)

EXPLAIN_ONLY_TOTAL = Counter(
    "egress_guard_explain_only_total",
    "Count of explain-only (educational) segments detected",
    registry=REGISTRY,
)

# ML pre-classifier load status
ML_PRECLF_LOAD_TOTAL = Counter(
    "egress_guard_ml_preclf_load_total",
    "Count of ML pre-classifier load attempts",
    labelnames=("status",),
    registry=REGISTRY,
)

# ML shadow/A-B disagreements
ML_PRECLF_SHADOW_TOTAL = Counter(
    "egress_guard_ml_preclf_shadow_total",
    "Count of ML vs heuristic disagreements in shadow mode",
    labelnames=("ml_pred", "heuristic", "final"),
    registry=REGISTRY,
)


def observe_guard_run(*, latency_ms: float, findings: Sequence[Any], blocked: bool) -> None:
    GUARD_LATENCY.observe(latency_ms / 1000.0)
    if blocked:
        BLOCKED_TOTAL.inc()
    for finding in findings:
        rule_id = getattr(finding, "rule_id", "unknown")
        RULE_HITS.labels(rule_id=rule_id).inc()


def observe_detector(*, detector: str, latency_ms: float, severities: Sequence[str]) -> None:
    DETECTOR_LATENCY.labels(detector=detector).observe(latency_ms / 1000.0)
    for severity in severities:
        key = severity or "unknown"
        RULE_SEVERITY.labels(severity=key).inc()


def observe_context(parsed_content: ParsedContent) -> None:
    """Record context-related metrics from parsed content.

    Args:
        parsed_content: Parsed content with segment information.
    """
    for segment in parsed_content.segments:
        CONTEXT_TYPE_TOTAL.labels(type=segment.type).inc()
        if segment.explain_only:
            EXPLAIN_ONLY_TOTAL.inc()


def observe_ml_preclf_load(status: str) -> None:
    """Track ML pre-classifier load attempts."""
    ML_PRECLF_LOAD_TOTAL.labels(status=status).inc()


def observe_ml_shadow(ml_pred: str, heuristic: str, final: str) -> None:
    """Track disagreements between ML prediction and heuristic (shadow mode)."""
    ML_PRECLF_SHADOW_TOTAL.labels(ml_pred=ml_pred, heuristic=heuristic, final=final).inc()


def render_metrics() -> tuple[bytes, str]:
    payload = generate_latest(REGISTRY)
    return payload, CONTENT_TYPE_LATEST
