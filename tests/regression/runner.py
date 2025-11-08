"""Regression runner for the LLM Egress Guard corpus."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import os
import sys
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.pipeline import GuardRequest, run_pipeline
from app.settings import Settings
from tests.regression.detector_matrix import SCENARIOS, run_matrix
from tests.regression.placeholders import apply_placeholders


@dataclass(slots=True)
class GoldenExpectation:
    blocked: bool
    rule_ids: list[str]


def main() -> None:
    os.chdir(REPO_ROOT)

    parser = argparse.ArgumentParser(description="Regression runner and detector matrix generator.")
    parser.add_argument(
        "--matrix-report",
        action="store_true",
        help="Additionally run the detector matrix scenarios and write JSON/markdown outputs.",
    )
    parser.add_argument(
        "--matrix-json",
        type=Path,
        default=Path("tests/regression/artifacts/detector_matrix_results.json"),
        help="Path for detector matrix JSON output.",
    )
    parser.add_argument(
        "--matrix-markdown",
        type=Path,
        default=Path("tests/regression/artifacts/detector_matrix_analysis.md"),
        help="Path for detector matrix analyst-style summary.",
    )
    args = parser.parse_args()

    corpus_dir = Path(__file__).parent / "corpus_v1"
    golden_file = Path(__file__).parent / "golden_v1.jsonl"

    if not golden_file.exists():
        raise SystemExit("Golden file not found. Generate it before running regression tests.")

    settings = Settings()
    _run_golden_suite(corpus_dir, golden_file, settings)

    if args.matrix_report:
        _run_matrix_reports(settings, args.matrix_json, args.matrix_markdown)


def _run_golden_suite(corpus_dir: Path, golden_file: Path, settings: Settings) -> None:
    golden = _load_golden(golden_file)
    failures: list[str] = []
    processed = 0

    for sample_path in sorted(corpus_dir.rglob("*.txt")):
        rel_path = sample_path.relative_to(corpus_dir).as_posix()
        expected = golden.get(rel_path)
        if not expected:
            failures.append(f"Missing golden expectation for {rel_path}")
            continue

        text = sample_path.read_text(encoding="utf-8")
        text = apply_placeholders(text)
        result = run_pipeline(GuardRequest(response=text), settings=settings)
        processed += 1

        actual_rules = sorted(f.rule_id for f in result.findings)
        expected_rules = sorted(expected.rule_ids)

        if result.blocked != expected.blocked:
            failures.append(f"{rel_path}: blocked={result.blocked} (expected {expected.blocked})")

        if actual_rules != expected_rules:
            failures.append(f"{rel_path}: rules {actual_rules} != expected {expected_rules}")

    missing_samples = set(golden) - {
        path.relative_to(corpus_dir).as_posix() for path in corpus_dir.rglob("*.txt")
    }
    for sample in sorted(missing_samples):
        failures.append(f"Golden expectation has no sample: {sample}")

    if failures:
        raise SystemExit("Regression mismatches:\n" + "\n".join(failures))

    print(f"Regression suite passed for {processed} samples.")


def _run_matrix_reports(settings: Settings, json_path: Path, markdown_path: Path) -> None:
    results = run_matrix(settings)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    analyst_notes: dict[str, str] = {
        "pii-phone-tr": "Legitimate contact info; masked output is sufficient unless volume spikes.",
        "pii-pan-spaced": "Valid PAN detected; block confirmed, follow up with tenant to ensure leak is contained.",
        "pii-email": "Low-risk PII; mask only, no further action unless repeated.",
        "pii-ipv4": "Public IP surfaced; review context if tenant expects internal addresses to stay hidden.",
        "secret-openai": "High entropy API key; block and rotate credentials.",
        "secret-jwt": "JWT dump; verify upstream logs for compromise and expire associated sessions.",
        "url-cred": "Credential-in-URL plus executable download; classify as malware attempt and alert SOC.",
        "url-data-uri": "Inline base64 payload; treat as potential exfil and review upstream prompts.",
        "cmd-curl-bash": "Command chaining to remote script; escalate as attempted data exfiltration.",
        "cmd-powershell-enc": "Encoded PowerShell command; suspicious automation, notify blue team.",
        "exfil-base64": "Blob under threshold; monitor for repetition or growth.",
        "exfil-hex": "Hex payload below limits; benign, but keep sample for tuning.",
    }

    lines = [
        "# Detector Matrix Analysis",
        "",
        f"_Generated at {datetime.now(timezone.utc).isoformat()}Z_",
        "",
        "| Scenario | Blocked | Risk | Rules | Actions | Notes |",
        "|----------|---------|------|-------|---------|-------|",
    ]
    for payload in results:
        findings = payload["findings"]
        rule_list = ", ".join(sorted({f["rule_id"] for f in findings})) or "-"
        action_list = ", ".join(sorted({f["action"] for f in findings})) or "-"
        note = "High risk" if payload["blocked"] else "Allowed/masked"
        lines.append(
            f"| {payload['scenario']} | {payload['blocked']} | {payload['risk_score']} | {rule_list} | {action_list} | {note} |"
        )

    lines.extend(["", "## Analyst Notes", ""])
    seen: set[str] = set()
    for payload in results:
        scenario = payload["scenario"]
        if scenario in seen:
            continue
        seen.add(scenario)
        note = analyst_notes.get(scenario, "Review context with tenant; no automated action defined.")
        lines.append(f"- **{scenario}** – {note}")

    lines.extend(
        [
            "",
            "## Detailed Findings",
            "",
            "| Scenario | Rule ID | Action | Type | Preview | Metadata |",
            "|----------|---------|--------|------|---------|----------|",
        ]
    )
    for payload in results:
        findings = payload["findings"]
        meta = payload.get("metadata") or {}
        meta_str = ", ".join(f"{k}={v}" for k, v in meta.items()) or "-"
        if not findings:
            lines.append(f"| {payload['scenario']} | - | - | - | - | {meta_str} |")
            continue
        for finding in findings:
            detail = finding.get("detail") or {}
            preview = detail.get("preview") or "-"
            lines.append(
                f"| {payload['scenario']} | {finding.get('rule_id')} | {finding.get('action')} | {finding.get('type')} | {preview} | {meta_str} |"
            )

    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Detector matrix saved to {json_path} and {markdown_path}.")


def _load_golden(path: Path) -> dict[str, GoldenExpectation]:
    expectations: dict[str, GoldenExpectation] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        sample = payload["sample"]
        expectations[sample] = GoldenExpectation(
            blocked=bool(payload.get("blocked", False)),
            rule_ids=list(payload.get("rule_ids", [])),
        )
    return expectations


if __name__ == "__main__":
    main()
