"""Regression runner placeholder for Sprint 1.

Loads corpus samples and compares sanitized outputs against golden expectations.
"""

from __future__ import annotations

from pathlib import Path


def main() -> None:
    corpus_dir = Path(__file__).parent / "corpus_v1"
    golden_file = Path(__file__).parent / "golden_v1.jsonl"

    if not golden_file.exists():
        raise SystemExit("Golden file not found. Generate it before running regression tests.")

    print(f"Would process corpus in {corpus_dir} and compare with {golden_file}.")


if __name__ == "__main__":
    main()
