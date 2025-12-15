#!/usr/bin/env python3
"""
Verify the pre-classifier model file against its manifest.

Usage:
    python scripts/check_preclf_model.py \
        --model models/preclf_v1.joblib \
        --manifest models/preclf_v1.manifest.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Check preclf model against manifest")
    parser.add_argument("--model", required=True, type=Path, help="Path to model joblib")
    parser.add_argument("--manifest", required=True, type=Path, help="Path to manifest JSON")
    args = parser.parse_args()

    if not args.model.exists():
        sys.exit(f"❌ Model file not found: {args.model}")
    if not args.manifest.exists():
        sys.exit(f"❌ Manifest file not found: {args.manifest}")

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    expected_sha = manifest.get("sha256")
    expected_size = manifest.get("size_bytes")

    actual_sha = sha256_file(args.model)
    actual_size = args.model.stat().st_size

    errors = []
    if expected_sha and expected_sha != actual_sha:
        errors.append(f"SHA mismatch: expected {expected_sha}, got {actual_sha}")
    if expected_size and expected_size != actual_size:
        errors.append(f"Size mismatch: expected {expected_size}, got {actual_size}")

    if errors:
        print("❌ Model verification failed:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)

    print("✅ Model verification passed.")
    print(f"  file : {args.model}")
    print(f"  sha  : {actual_sha}")
    print(f"  size : {actual_size}")


if __name__ == "__main__":
    main()





