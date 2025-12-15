#!/usr/bin/env python3
"""
Validate and combine ML training data from JSONL files.

Usage:
    python scripts/validate_training_data.py --input data/ml_training/output_*.jsonl
    python scripts/validate_training_data.py --combine --output data/ml_training/preclf_train.jsonl
"""

import argparse
import json
import random
import sys
from collections import Counter
from pathlib import Path


VALID_LABELS = {"educational", "command", "text"}
VALID_SEGMENT_TYPES = {"code", "text"}
VALID_LANGUAGES = {"en", "de", "tr", "es", "fr", "zh", "ru", "pt", "ja", "ko"}


def validate_sample(sample: dict, line_num: int, filename: str) -> list[str]:
    """Validate a single sample and return list of errors."""
    errors = []
    
    # Check required fields
    if "text" not in sample:
        errors.append(f"Missing 'text' field")
    elif not isinstance(sample["text"], str):
        errors.append(f"'text' must be a string")
    elif len(sample["text"].strip()) == 0:
        errors.append(f"'text' is empty")
    
    if "label" not in sample:
        errors.append(f"Missing 'label' field")
    elif sample["label"] not in VALID_LABELS:
        errors.append(f"Invalid label '{sample['label']}', must be one of {VALID_LABELS}")
    
    # Check optional fields
    if "segment_type" in sample and sample["segment_type"] not in VALID_SEGMENT_TYPES:
        errors.append(f"Invalid segment_type '{sample['segment_type']}', must be one of {VALID_SEGMENT_TYPES}")
    
    if "language" in sample and sample["language"] not in VALID_LANGUAGES:
        errors.append(f"Invalid language '{sample['language']}', must be one of {VALID_LANGUAGES}")
    
    # Content validation
    if "text" in sample and "label" in sample:
        text_lower = sample["text"].lower()
        
        # Educational samples should have warning keywords
        if sample["label"] == "educational":
            edu_keywords = ["warning", "never", "dangerous", "example", "caution", 
                          "avoid", "do not run", "unsafe", "malicious", "tutorial",
                          "warnung", "niemals", "uyarı", "asla", "advertencia", 
                          "nunca", "avertissement", "jamais", "警告", "切勿"]
            has_keyword = any(kw in text_lower for kw in edu_keywords)
            if not has_keyword:
                errors.append(f"Educational sample missing warning keywords")
        
        # Command samples should NOT have warning keywords
        if sample["label"] == "command":
            warning_keywords = ["warning", "never", "dangerous", "caution", "avoid", 
                              "do not run", "unsafe", "example of", "demonstrates"]
            has_warning = any(kw in text_lower for kw in warning_keywords)
            if has_warning:
                errors.append(f"Command sample contains warning keywords (should be educational?)")
    
    return errors


def validate_file(filepath: Path) -> tuple[list[dict], list[str]]:
    """Validate a JSONL file and return valid samples and errors."""
    valid_samples = []
    all_errors = []
    
    with open(filepath, encoding="utf-8") as f:
        lines = f.readlines()
    
    for i, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        
        # Skip markdown formatting that might have been included
        if line.startswith("```") or line.startswith("#"):
            continue
        
        try:
            sample = json.loads(line)
        except json.JSONDecodeError as e:
            all_errors.append(f"{filepath}:{i}: JSON parse error: {e}")
            continue
        
        errors = validate_sample(sample, i, str(filepath))
        if errors:
            for error in errors:
                all_errors.append(f"{filepath}:{i}: {error}")
        else:
            valid_samples.append(sample)
    
    return valid_samples, all_errors


def print_stats(samples: list[dict]) -> None:
    """Print statistics about the samples."""
    label_counts = Counter(s["label"] for s in samples)
    segment_counts = Counter(s.get("segment_type", "unknown") for s in samples)
    lang_counts = Counter(s.get("language", "en") for s in samples)
    
    print("\n📊 Dataset Statistics:")
    print(f"   Total samples: {len(samples)}")
    print("\n   Labels:")
    for label, count in sorted(label_counts.items()):
        pct = count / len(samples) * 100
        print(f"      {label}: {count} ({pct:.1f}%)")
    
    print("\n   Segment Types:")
    for stype, count in sorted(segment_counts.items()):
        pct = count / len(samples) * 100
        print(f"      {stype}: {count} ({pct:.1f}%)")
    
    if len(lang_counts) > 1 or "en" not in lang_counts:
        print("\n   Languages:")
        for lang, count in sorted(lang_counts.items()):
            pct = count / len(samples) * 100
            print(f"      {lang}: {count} ({pct:.1f}%)")


def main():
    parser = argparse.ArgumentParser(description="Validate ML training data")
    parser.add_argument("--input", "-i", nargs="+", help="Input JSONL files to validate")
    parser.add_argument("--combine", "-c", action="store_true", help="Combine all valid samples")
    parser.add_argument("--output", "-o", help="Output file for combined data")
    parser.add_argument("--split", type=float, default=0.8, help="Train/eval split ratio (default: 0.8)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed errors")
    args = parser.parse_args()
    
    if not args.input:
        # Default to data/ml_training/output_*.jsonl
        data_dir = Path("data/ml_training")
        if data_dir.exists():
            args.input = list(data_dir.glob("output_*.jsonl"))
        if not args.input:
            print("❌ No input files specified and no output_*.jsonl files found")
            sys.exit(1)
    
    # Convert to Path objects
    input_files = [Path(f) for f in args.input]
    
    # Validate all files
    all_samples = []
    all_errors = []
    
    print("🔍 Validating files...")
    for filepath in input_files:
        if not filepath.exists():
            print(f"   ⚠️  {filepath}: File not found")
            continue
        
        samples, errors = validate_file(filepath)
        all_samples.extend(samples)
        all_errors.extend(errors)
        
        status = "✅" if not errors else "⚠️"
        print(f"   {status} {filepath}: {len(samples)} valid, {len(errors)} errors")
    
    # Show errors
    if all_errors:
        print(f"\n⚠️  Found {len(all_errors)} validation errors:")
        if args.verbose:
            for error in all_errors[:50]:  # Limit to first 50
                print(f"   {error}")
            if len(all_errors) > 50:
                print(f"   ... and {len(all_errors) - 50} more errors")
        else:
            print("   Use --verbose to see details")
    
    if not all_samples:
        print("\n❌ No valid samples found!")
        sys.exit(1)
    
    # Print statistics
    print_stats(all_samples)
    
    # Combine and save if requested
    if args.combine:
        if not args.output:
            args.output = "data/ml_training/preclf_combined.jsonl"
        
        # Shuffle samples
        random.shuffle(all_samples)
        
        # Split into train/eval
        split_idx = int(len(all_samples) * args.split)
        train_samples = all_samples[:split_idx]
        eval_samples = all_samples[split_idx:]
        
        # Save combined file
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, "w", encoding="utf-8") as f:
            for sample in all_samples:
                f.write(json.dumps(sample, ensure_ascii=False) + "\n")
        print(f"\n💾 Saved combined data to: {output_path}")
        
        # Save train/eval splits
        train_path = output_path.parent / "preclf_train.jsonl"
        eval_path = output_path.parent / "preclf_eval.jsonl"
        
        with open(train_path, "w", encoding="utf-8") as f:
            for sample in train_samples:
                f.write(json.dumps(sample, ensure_ascii=False) + "\n")
        print(f"   Train set: {train_path} ({len(train_samples)} samples)")
        
        with open(eval_path, "w", encoding="utf-8") as f:
            for sample in eval_samples:
                f.write(json.dumps(sample, ensure_ascii=False) + "\n")
        print(f"   Eval set: {eval_path} ({len(eval_samples)} samples)")
    
    print("\n✅ Validation complete!")
    
    # Exit with error code if there were validation errors
    if all_errors:
        sys.exit(1)


if __name__ == "__main__":
    main()

