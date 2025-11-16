# Regression Corpus Overview

This directory contains the corpus and golden outputs used by `tests/regression/runner.py` to validate LLM Egress Guard detections. The corpus currently covers six categories with multilingual positives and tricky negatives.

## Categories & Samples

| Category | Count | Examples |
|----------|-------|----------|
| `clean`  | 10    | `clean/how-to-stir-fry.txt`, `clean/regex-concept.txt`, `clean/tricky-negative-email.txt` |
| `pii`    | 21    | `pii/tr-phone-format.txt`, `pii/de-iban.txt`, `pii/pan-spaced.txt`, `pii/mixed-ip-bilingual.txt` |
| `secrets`| 17    | `secrets/jwt-access.txt`, `secrets/aws-keys.txt`, `secrets/openai-key.txt`, `secrets/pem-private.txt` |
| `url`    | 15    | `url/data-uri-svg.txt`, `url/cred-in-url.txt`, `url/shortener-link.txt`, `url/suspicious-tld.txt` |
| `cmd`    | 15    | `cmd/curl-bash.txt`, `cmd/powershell-enc.txt`, `cmd/certutil-dl.txt`, `cmd/reg-add.txt` |
| `exfil`  | 9     | `exfil/base64-dump.txt`, `exfil/hex-stream.txt`, `exfil/mixed-entropy.txt`, `exfil/safe-csv-like.txt` |

Each sample is a plain-text file containing an LLM response. File names mirror the `title` field from the synthetic prompt to make cross-referencing easier.

## Golden Outputs

- `tests/regression/golden_v1.jsonl` holds the expected outcomes (blocked flag + rule IDs) for every sample.
- `tests/regression/golden_manifest.json` records the current golden version (`v1.1`), generation time, sample count, and notes. Bump the version and metadata every sprint when the golden file changes.
- Regenerate after adding/editing samples:

  ```bash
  conda activate "LLM Egress Guard"
  python tests/regression/runner.py
  ```

  The runner recomputes outputs with the current policy and rewrites `golden_v1.jsonl`. Review diff to ensure rule hits match expectations before committing.

## Adding New Samples

1. Drop the `.txt` file under `tests/regression/corpus_v1/<category>/`.
2. Re-run the runner to refresh the golden file.
3. Verify `tests/regression/runner.py` reports “Regression suite passed …”.
 4. Commit both the new sample(s) and updated golden file so CI sees consistent state.

> Tip: When regenerating golden outputs for a new sprint, update the manifest with a semantic tag (e.g., `v1.2`), the timestamp, total sample count, and a short note about what changed.

### Synthetic Secret Placeholders

- Secret files only store realistic-looking placeholder markers (`{{STRIPE_KEY}}`, `{{AWS_SECRET_KEY}}`, etc.).
- `tests/regression/placeholders.py` expands those markers into deterministic synthetic values at runtime so no risky literals ever live in git.
- When adding a new secret type, use its placeholder in the corpus file first, then implement the generator with the same name in `placeholders.py`.
- Both the runner and detector matrix scripts apply placeholders automatically; external scripts should call `from tests.regression.placeholders import apply_placeholders`.

## Detector Matrix Report

`python tests/regression/runner.py --matrix-report`

- Runs curated demo scenarios across detectors via the pipeline.
- Saves raw JSON to `tests/regression/artifacts/detector_matrix_results.json` and analyst-style Markdown to `tests/regression/artifacts/detector_matrix_analysis.md`.
- Handy for SOC/analyst training to showcase every detector hit in one command.

Use this README as the index when expanding the corpus (e.g., tracking ATT&CK techniques, locales, or FP challenge cases).
