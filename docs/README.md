# Documentation Index

Use this file as the quick reference for where each major document lives and what it covers.

## Overview

| File | Description |
|------|-------------|
| [`README.md`](../README.md) | Project setup, execution flow, metrics, and sprint summaries. |
| [`NORMALIZATION_SECURITY.md`](../NORMALIZATION_SECURITY.md) | Technical details for the normalization layer’s security measures. |
| [`docs/README.md`](./README.md) | (This file) Central index for all docs. |
| [`reports/Sprint-4-Report.md`](../reports/Sprint-4-Report.md) | Sprint 4: ML pre-classifier v1, shadow metrics, manifest/checksum. |
| [`reports/Sprint-3-Report.md`](../reports/Sprint-3-Report.md) | Sprint 3: Context-aware parsing, explain-only heuristic, FP reduction. |

## Test & Corpus References

| File | Description |
|------|-------------|
| [`tests/regression/README.md`](../tests/regression/README.md) | Regression corpus categories, sample naming, and how to refresh golden outputs. |
| [`tests/regression/golden_v1.jsonl`](../tests/regression/golden_v1.jsonl) | Expected outcomes for every sample (auto-generated; read the README first). |
| [`tests/regression/golden_manifest.json`](../tests/regression/golden_manifest.json) | Version tag, timestamp, and sample-count metadata for the golden file. |

## Tools & Scripts

| File | Description |
|------|-------------|
| [`scripts/demo_policy_reload.py`](../scripts/demo_policy_reload.py) | Interactive policy/safe-message hot-reload demo (`PYTHONPATH=. python scripts/demo_policy_reload.py`). |
| [`scripts/train_preclassifier.py`](../scripts/train_preclassifier.py) | Train TF-IDF + LR pre-classifier and print metrics. |
| [`scripts/check_preclf_model.py`](../scripts/check_preclf_model.py) | Verify model checksum against manifest. |

## Sprint Reports

| File | Description |
|------|-------------|
| [`reports/README.md`](../reports/README.md) | Sprint report index. |
| [`reports/Sprint-1-Report.{md,pdf,docx}`](../reports/) | Sprint 1 deliverables and decisions. |
| [`reports/Sprint-2-Report.{md,pdf,docx}`](../reports/) | Sprint 2 detector/policy work and open items. |
| [`reports/Sprint-3-Report.{md,pdf,docx}`](../reports/) | Sprint 3 context-aware parsing, explain-only heuristic, FP reduction. |
| [`reports/Sprint-4-Report.{md,pdf}`](../reports/) | Sprint 4 ML pre-classifier v1, shadow metrics, manifest/checksum. |

## Additional Notes

- For CI, benchmarking, or scripting details see `Makefile`, `ci/github-actions.yml`, and the `scripts/` directory.
- When adding new docs, append them to this index to keep navigation simple.
