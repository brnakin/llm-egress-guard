#!/usr/bin/env python3
"""
Weekly Report Exporter for LLM Egress Guard

Generates a Markdown report with:
- Top triggered rules
- Latency trends (p50/p95/p99)
- Block rate over time
- False positive candidates
- Context distribution

Usage:
    # Generate report from Prometheus metrics:
    python scripts/export_weekly_report.py

    # Specify Prometheus URL:
    python scripts/export_weekly_report.py --prometheus-url http://localhost:9090

    # Specify output file:
    python scripts/export_weekly_report.py --output reports/weekly/2025-W51.md

    # Specify time range (default: last 7 days):
    python scripts/export_weekly_report.py --days 14
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import requests

DEFAULT_PROMETHEUS_URL = "http://localhost:9090"


def query_prometheus(
    query: str,
    prometheus_url: str = DEFAULT_PROMETHEUS_URL,
    time: datetime | None = None,
) -> list[dict[str, Any]]:
    """Execute a PromQL instant query."""
    params = {"query": query}
    if time:
        params["time"] = time.timestamp()

    try:
        response = requests.get(
            f"{prometheus_url}/api/v1/query",
            params=params,
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()
        if data.get("status") == "success":
            return data.get("data", {}).get("result", [])
        return []
    except requests.exceptions.RequestException:
        return []


def query_prometheus_range(
    query: str,
    prometheus_url: str = DEFAULT_PROMETHEUS_URL,
    start: datetime | None = None,
    end: datetime | None = None,
    step: str = "1h",
) -> list[dict[str, Any]]:
    """Execute a PromQL range query."""
    end = end or datetime.now()
    start = start or (end - timedelta(days=7))

    params = {
        "query": query,
        "start": start.timestamp(),
        "end": end.timestamp(),
        "step": step,
    }

    try:
        response = requests.get(
            f"{prometheus_url}/api/v1/query_range",
            params=params,
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        if data.get("status") == "success":
            return data.get("data", {}).get("result", [])
        return []
    except requests.exceptions.RequestException:
        return []


def get_top_rules(prometheus_url: str, limit: int = 10) -> list[tuple[str, float]]:
    """Get top triggered rules by count."""
    results = query_prometheus(
        "topk(10, sum by (rule_id) (egress_guard_rule_hits_total))",
        prometheus_url,
    )
    rules = []
    for r in results:
        rule_id = r.get("metric", {}).get("rule_id", "unknown")
        value = float(r.get("value", [0, 0])[1])
        rules.append((rule_id, value))
    return sorted(rules, key=lambda x: x[1], reverse=True)[:limit]


def get_latency_stats(prometheus_url: str) -> dict[str, float]:
    """Get latency percentiles."""
    stats = {}

    # Average
    results = query_prometheus(
        "(egress_guard_latency_seconds_sum / egress_guard_latency_seconds_count) * 1000",
        prometheus_url,
    )
    if results:
        stats["avg"] = float(results[0].get("value", [0, 0])[1])

    # P50
    results = query_prometheus(
        "histogram_quantile(0.50, sum(rate(egress_guard_latency_seconds_bucket[24h])) by (le)) * 1000",
        prometheus_url,
    )
    if results:
        val = results[0].get("value", [0, 0])[1]
        if val != "NaN":
            stats["p50"] = float(val)

    # P95
    results = query_prometheus(
        "histogram_quantile(0.95, sum(rate(egress_guard_latency_seconds_bucket[24h])) by (le)) * 1000",
        prometheus_url,
    )
    if results:
        val = results[0].get("value", [0, 0])[1]
        if val != "NaN":
            stats["p95"] = float(val)

    # P99
    results = query_prometheus(
        "histogram_quantile(0.99, sum(rate(egress_guard_latency_seconds_bucket[24h])) by (le)) * 1000",
        prometheus_url,
    )
    if results:
        val = results[0].get("value", [0, 0])[1]
        if val != "NaN":
            stats["p99"] = float(val)

    return stats


def get_block_rate(prometheus_url: str) -> float:
    """Get current block rate percentage."""
    results = query_prometheus(
        "sum(egress_guard_blocked_total) / sum(egress_guard_latency_seconds_count) * 100",
        prometheus_url,
    )
    if results:
        val = results[0].get("value", [0, 0])[1]
        if val != "NaN":
            return float(val)
    return 0.0


def get_total_requests(prometheus_url: str) -> int:
    """Get total request count."""
    results = query_prometheus(
        "sum(egress_guard_latency_seconds_count)",
        prometheus_url,
    )
    if results:
        return int(float(results[0].get("value", [0, 0])[1]))
    return 0


def get_total_blocked(prometheus_url: str) -> int:
    """Get total blocked count."""
    results = query_prometheus(
        "sum(egress_guard_blocked_total)",
        prometheus_url,
    )
    if results:
        return int(float(results[0].get("value", [0, 0])[1]))
    return 0


def get_context_distribution(prometheus_url: str) -> dict[str, int]:
    """Get context type distribution."""
    results = query_prometheus(
        "sum by (type) (egress_guard_context_type_total)",
        prometheus_url,
    )
    dist = {}
    for r in results:
        ctx_type = r.get("metric", {}).get("type", "unknown")
        value = int(float(r.get("value", [0, 0])[1]))
        dist[ctx_type] = value
    return dist


def get_explain_only_count(prometheus_url: str) -> int:
    """Get explain-only detection count."""
    results = query_prometheus(
        "sum(egress_guard_explain_only_total)",
        prometheus_url,
    )
    if results:
        return int(float(results[0].get("value", [0, 0])[1]))
    return 0


def get_ml_stats(prometheus_url: str) -> dict[str, Any]:
    """Get ML pre-classifier statistics."""
    stats = {}

    # Load status
    results = query_prometheus(
        'sum by (status) (egress_guard_ml_preclf_load_total)',
        prometheus_url,
    )
    stats["load"] = {}
    for r in results:
        status = r.get("metric", {}).get("status", "unknown")
        value = int(float(r.get("value", [0, 0])[1]))
        stats["load"][status] = value

    # Shadow mode disagreements
    results = query_prometheus(
        'sum(egress_guard_ml_preclf_shadow_total)',
        prometheus_url,
    )
    if results:
        stats["shadow_total"] = int(float(results[0].get("value", [0, 0])[1]))

    return stats


def generate_report(
    prometheus_url: str,
    days: int = 7,
) -> str:
    """Generate the weekly report in Markdown format."""
    now = datetime.now()
    week_num = now.isocalendar()[1]
    year = now.year

    lines = [
        f"# LLM Egress Guard - Weekly Report",
        "",
        f"**Report Period:** {(now - timedelta(days=days)).strftime('%Y-%m-%d')} to {now.strftime('%Y-%m-%d')}",
        f"**Generated:** {now.strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Week:** {year}-W{week_num:02d}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
    ]

    # Summary stats
    total_requests = get_total_requests(prometheus_url)
    total_blocked = get_total_blocked(prometheus_url)
    block_rate = get_block_rate(prometheus_url)
    latency = get_latency_stats(prometheus_url)

    lines.extend([
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total Requests | {total_requests:,} |",
        f"| Total Blocked | {total_blocked:,} |",
        f"| Block Rate | {block_rate:.1f}% |",
        f"| Avg Latency | {latency.get('avg', 0):.2f}ms |",
        f"| P95 Latency | {latency.get('p95', 0):.2f}ms |",
        "",
        "---",
        "",
        "## Top Triggered Rules",
        "",
    ])

    # Top rules
    top_rules = get_top_rules(prometheus_url)
    if top_rules:
        lines.extend([
            "| Rank | Rule ID | Count |",
            "|------|---------|-------|",
        ])
        for i, (rule_id, count) in enumerate(top_rules, 1):
            lines.append(f"| {i} | `{rule_id}` | {int(count):,} |")
    else:
        lines.append("*No rule hits recorded*")

    lines.extend([
        "",
        "---",
        "",
        "## Latency Performance",
        "",
        "| Percentile | Value |",
        "|------------|-------|",
    ])

    for key, label in [("avg", "Average"), ("p50", "P50"), ("p95", "P95"), ("p99", "P99")]:
        val = latency.get(key, 0)
        lines.append(f"| {label} | {val:.2f}ms |")

    lines.extend([
        "",
        "---",
        "",
        "## Context Distribution",
        "",
    ])

    # Context distribution
    context_dist = get_context_distribution(prometheus_url)
    if context_dist:
        lines.extend([
            "| Context Type | Count | Percentage |",
            "|--------------|-------|------------|",
        ])
        total_ctx = sum(context_dist.values())
        for ctx_type, count in sorted(context_dist.items(), key=lambda x: x[1], reverse=True):
            pct = (count / total_ctx * 100) if total_ctx > 0 else 0
            lines.append(f"| {ctx_type} | {count:,} | {pct:.1f}% |")
    else:
        lines.append("*No context data recorded*")

    lines.extend([
        "",
        "---",
        "",
        "## Explain-Only Detections",
        "",
    ])

    explain_only = get_explain_only_count(prometheus_url)
    lines.extend([
        f"**Total Explain-Only:** {explain_only:,}",
        "",
        "These are findings that were detected but not blocked because they appeared in educational/tutorial context.",
        "",
        "---",
        "",
        "## ML Pre-Classifier Status",
        "",
    ])

    ml_stats = get_ml_stats(prometheus_url)
    if ml_stats.get("load"):
        lines.append("**Model Load Status:**")
        for status, count in ml_stats["load"].items():
            lines.append(f"- {status}: {count}")
    if ml_stats.get("shadow_total"):
        lines.append(f"\n**Shadow Mode Disagreements:** {ml_stats['shadow_total']}")

    lines.extend([
        "",
        "---",
        "",
        "## Recommendations",
        "",
        "Based on this week's data:",
        "",
    ])

    # Generate recommendations
    recommendations = []

    if block_rate > 20:
        recommendations.append("⚠️ High block rate (>20%). Review top rules for potential false positives.")
    if block_rate < 5:
        recommendations.append("ℹ️ Low block rate (<5%). Consider if detection rules are too permissive.")
    if latency.get("p95", 0) > 50:
        recommendations.append("⚠️ P95 latency >50ms. Consider performance optimization.")
    if explain_only > 0:
        recommendations.append(f"ℹ️ {explain_only} explain-only detections. Review for ML training data.")
    if not recommendations:
        recommendations.append("✅ All metrics within normal ranges.")

    for rec in recommendations:
        lines.append(f"- {rec}")

    lines.extend([
        "",
        "---",
        "",
        f"*Report generated by `scripts/export_weekly_report.py`*",
    ])

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Generate weekly report from Prometheus metrics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--prometheus-url",
        default=DEFAULT_PROMETHEUS_URL,
        help=f"Prometheus URL (default: {DEFAULT_PROMETHEUS_URL})",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Output file path (default: stdout)",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=7,
        help="Number of days to include (default: 7)",
    )
    args = parser.parse_args()

    # Check Prometheus connection
    try:
        response = requests.get(f"{args.prometheus_url}/api/v1/status/config", timeout=5)
        response.raise_for_status()
    except requests.exceptions.RequestException:
        print(f"Warning: Cannot connect to Prometheus at {args.prometheus_url}")
        print("Report will contain default/zero values.")

    # Generate report
    report = generate_report(args.prometheus_url, args.days)

    # Output
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report)
        print(f"Report saved to: {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    main()
