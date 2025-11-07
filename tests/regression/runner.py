"""Regression runner for the LLM Egress Guard corpus."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from app.pipeline import GuardRequest, run_pipeline
from app.settings import Settings


@dataclass(slots=True)
class GoldenExpectation:
    blocked: bool
    rule_ids: list[str]


def main() -> None:
    corpus_dir = Path(__file__).parent / "corpus_v1"
    golden_file = Path(__file__).parent / "golden_v1.jsonl"

    if not golden_file.exists():
        raise SystemExit("Golden file not found. Generate it before running regression tests.")

    golden = _load_golden(golden_file)
    settings = Settings()
    failures: list[str] = []
    processed = 0

    for sample_path in sorted(corpus_dir.rglob("*.txt")):
        rel_path = sample_path.relative_to(corpus_dir).as_posix()
        expected = golden.get(rel_path)
        if not expected:
            failures.append(f"Missing golden expectation for {rel_path}")
            continue

        text = sample_path.read_text(encoding="utf-8")
        result = run_pipeline(GuardRequest(response=text), settings=settings)
        processed += 1

        actual_rules = sorted(f.rule_id for f in result.findings)
        expected_rules = sorted(expected.rule_ids)

        if result.blocked != expected.blocked:
            failures.append(
                f"{rel_path}: blocked={result.blocked} (expected {expected.blocked})"
            )

        if actual_rules != expected_rules:
            failures.append(
                f"{rel_path}: rules {actual_rules} != expected {expected_rules}"
            )

    missing_samples = set(golden) - {
        path.relative_to(corpus_dir).as_posix() for path in corpus_dir.rglob("*.txt")
    }
    for sample in sorted(missing_samples):
        failures.append(f"Golden expectation has no sample: {sample}")

    if failures:
        raise SystemExit("Regression mismatches:\n" + "\n".join(failures))

    print(f"Regression suite passed for {processed} samples.")


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
