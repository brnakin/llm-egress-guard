"""Prometheus metrics helpers."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
)

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


def render_metrics() -> tuple[bytes, str]:
    payload = generate_latest(REGISTRY)
    return payload, CONTENT_TYPE_LATEST
