"""Detector registry orchestrating all detector runs."""

from __future__ import annotations

from collections.abc import Iterator
from time import perf_counter

from app.pipeline import Finding
from app.policy import PolicyDefinition

from . import cmd, exfil, pii, secrets, url


def scan_all(
    content: str,
    *,
    policy: PolicyDefinition,
    metadata: dict[str, object] | None = None,
) -> Iterator[tuple[str, list[Finding], float]]:
    """Run each detector and yield findings with latency metrics."""

    detectors = (
        ("pii", pii.scan),
        ("exfil", exfil.scan),
        ("secret", secrets.scan),
        ("url", url.scan),
        ("cmd", cmd.scan),
    )

    for detector_name, detector_func in detectors:
        start = perf_counter()
        findings = detector_func(content, policy=policy, metadata=metadata)
        latency_ms = (perf_counter() - start) * 1000
        yield detector_name, findings, latency_ms
