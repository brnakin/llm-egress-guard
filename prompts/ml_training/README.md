# ML Pre-Classifier Training Data Generation

This directory contains prompts for generating synthetic training data for the LLM Egress Guard ML pre-classifier model.

## Overview

The ML pre-classifier is designed to classify LLM output segments as:
- **`educational`** - Security tutorials, warnings, documentation (should NOT be blocked)
- **`command`** - Direct instructions to execute dangerous commands (SHOULD be blocked)
- **`text`** - Clean text without dangerous commands (should NOT be blocked)

## Synthetic Data Generation Principles

This approach follows established best practices for synthetic data generation:

| Principle | Implementation |
|-----------|----------------|
| **Consistency** | Single model for all generation (uniform style/format) |
| **Diversity** | Achieved through varied prompts, not multiple models |
| **Reproducibility** | Same model, same format, documented process |
| **Quality Control** | Validation script + manual review |
| **Avoiding Model Collapse** | Single generator model reduces bias mixing |

### Why Single Model Strategy?

Research shows that using multiple models for synthetic data generation can lead to:
- Inconsistent output formats and styles
- Mixed biases from different model architectures
- Difficulty in quality control and validation
- Reduced reproducibility

**Diversity should come from varied prompts and scenarios, not from different models.**

## Directory Structure

```
prompts/ml_training/
├── README.md                      # This file
├── 01_educational_security.md     # Educational security content (25 samples)
├── 02_malicious_commands.md       # Malicious command instructions (25 samples)
├── 03_educational_advanced.md     # Advanced educational content (25 samples)
├── 04_command_sophisticated.md    # Sophisticated malicious content (25 samples)
├── 05_clean_text.md               # Clean documentation text (25 samples)
├── 06_edge_cases.md               # Ambiguous edge cases (25 samples)
└── 07_multilingual.md             # Multilingual educational content (25 samples)

data/ml_training/
├── output_01.jsonl                # Generated output from prompt 01
├── output_02.jsonl                # Generated output from prompt 02
├── ...
├── preclf_train.jsonl             # Combined training data (80%)
└── preclf_eval.jsonl              # Evaluation split (20%)
```

## Target Dataset

| Label | Target Samples | Description |
|-------|----------------|-------------|
| `educational` | ~100 | Commands in educational context |
| `command` | ~50 | Direct malicious instructions |
| `text` | ~25 | Clean text without commands |
| **Total** | **~175** | Minimum viable dataset |

## Model Selection Strategy

### Primary Model: GPT-5.1-Codex-Max (xhigh)

Based on the latest benchmarks (SWE/Terminal):

| Benchmark | GPT-5.1-Codex | GPT-5.1-Codex-Max |
|-----------|---------------|-------------------|
| SWE-bench Verified (n=500) | 73.7% | **77.9%** |
| SWE-Lancer IC SWE | 66.3% | **79.9%** |
| Terminal-Bench 2.0 | 52.8% | **58.1%** |

**Why GPT-5.1-Codex-Max:**
1. Highest coding accuracy across SWE/terminal benchmarks
2. Fewer thinking tokens (more efficient, more consistent)
3. Fewer tool calls, more focused outputs
4. Strong at instruction-following + code/command generation

### Backup Models (if quota/limits hit)
- **GPT-5.1-Codex (high)** — same family, slightly lower accuracy
- **Claude Sonnet 4.5** — for multilingual/educational text if Codex is unavailable

### Model Priority

```
┌─────────────────────────────────────────┐
│           MODEL PRIORITY                │
├─────────────────────────────────────────┤
│  1. GPT-5.1-Codex-Max (Primary)         │
│  2. GPT-5.1-Codex (Backup)              │
│  3. Claude Sonnet 4.5 (Secondary Backup)│
│  4. Ollama llama3:70b (Local/Unlimited) │
└─────────────────────────────────────────┘
```

## Prompt Files

All prompts should be run with the **SAME MODEL** for consistency.

### 01_educational_security.md
- **Purpose:** Generate educational security content with dangerous commands shown as examples/warnings
- **Label:** `educational`
- **Samples:** 25
- **Diversity Source:** Different command types (curl, wget, powershell, reverse shells, rm)

### 02_malicious_commands.md
- **Purpose:** Generate direct malicious instructions without educational framing
- **Label:** `command`
- **Samples:** 25
- **Diversity Source:** Different attack scenarios (fake repair, optimization, updates)

### 03_educational_advanced.md
- **Purpose:** Generate sophisticated educational content (MITRE ATT&CK, CVEs, pen testing)
- **Label:** `educational`
- **Samples:** 25
- **Diversity Source:** Different documentation types (ATT&CK, CVE, incident response)

### 04_command_sophisticated.md
- **Purpose:** Generate convincing malicious instructions that appear helpful
- **Label:** `command`
- **Samples:** 25
- **Diversity Source:** Different professional contexts (DevOps, dev tools, troubleshooting)

### 05_clean_text.md
- **Purpose:** Generate safe text without dangerous commands
- **Label:** `text`
- **Samples:** 25
- **Diversity Source:** Different content types (docs, tutorials, descriptions)

### 06_edge_cases.md
- **Purpose:** Generate ambiguous edge cases to test model boundaries
- **Label:** Mixed (`educational`, `command`, `text`)
- **Samples:** 25
- **Diversity Source:** Different ambiguity types (weak context, questions, historical)

### 07_multilingual.md
- **Purpose:** Generate educational content in German, Turkish, Spanish, French, Chinese
- **Label:** `educational`
- **Samples:** 25 (5 per language)
- **Diversity Source:** Different languages and cultural styles

## Usage Instructions

### Step 1: Generate Data with Single Model

#### Using Cursor IDE (Recommended)

**IMPORTANT:** Use the SAME model (GPT-5.1-Codex-Max) for ALL prompts. If quota is hit, switch to GPT-5.1-Codex.

```
For each prompt file (01 through 07):

1. Open the prompt file (e.g., 01_educational_security.md)
2. Copy the entire content
3. Open a new chat → Select "GPT-5.1-Codex-Max (xhigh)"
4. Paste the prompt and send
5. Copy the JSONL output (only the JSON lines, no markdown)
6. Save to data/ml_training/output_01.jsonl
7. Repeat for next prompt file with SAME model
```

#### Execution Order

```bash
# Primary (GPT-5.1-Codex-Max)
Prompt 01 → Codex-Max → output_01.jsonl  ✓
Prompt 02 → Codex-Max → output_02.jsonl  ✓
Prompt 03 → Codex-Max → output_03.jsonl  ✓
Prompt 04 → Codex-Max → output_04.jsonl  ✓
Prompt 05 → Codex-Max → output_05.jsonl  ✓
Prompt 06 → Codex-Max → output_06.jsonl  ✓
Prompt 07 → Codex-Max → output_07.jsonl  ✓

# If Codex-Max limit reached, switch to Codex (high)
```

#### Using Ollama (Local, Unlimited - Alternative)

If you prefer unlimited local generation:

```bash
# Install a capable model
ollama pull llama3:70b

# Generate all prompts with the SAME model
cd /path/to/llm-egress-guard

for i in 01 02 03 04 05 06 07; do
    echo "Generating output_${i}.jsonl..."
    cat prompts/ml_training/${i}_*.md | ollama run llama3:70b > data/ml_training/output_${i}.jsonl
done
```

### Step 2: Validate After Each Batch

Validate immediately after generating each file:

```bash
# Validate single file
python scripts/validate_training_data.py -v --input data/ml_training/output_01.jsonl

# Check for consistency issues
# - Format should be identical across files
# - Labels should match the prompt category
# - No markdown artifacts in output
```

### Step 3: Combine and Split Data

After all 7 prompts are complete:

```bash
cd /path/to/llm-egress-guard

# Validate all outputs
python scripts/validate_training_data.py -v

# Combine and create train/eval splits
python scripts/validate_training_data.py --combine --output data/ml_training/preclf_combined.jsonl
```

### Step 4: Verify Final Dataset

```bash
# Check label distribution
echo "=== Label Distribution ==="
grep -c '"label": "educational"' data/ml_training/preclf_train.jsonl
grep -c '"label": "command"' data/ml_training/preclf_train.jsonl  
grep -c '"label": "text"' data/ml_training/preclf_train.jsonl

# Expected approximate distribution:
# educational: ~80-100 samples
# command: ~50 samples
# text: ~25 samples
```

## Output Format Specification

Each line in the JSONL files must be a valid JSON object with these fields:

```json
{
  "text": "The full LLM response text with proper \\n newlines",
  "label": "educational|command|text",
  "segment_type": "code|text",
  "language": "en"
}
```

### Field Definitions

| Field | Type | Required | Values |
|-------|------|----------|--------|
| `text` | string | Yes | Full text content with `\n` for newlines |
| `label` | string | Yes | `educational`, `command`, or `text` |
| `segment_type` | string | Yes | `code` (has code blocks) or `text` (no code blocks) |
| `language` | string | No | ISO 639-1 code: `en`, `de`, `tr`, `es`, `fr`, `zh` |

## Quality Checklist

### Per-File Validation (after each prompt)

- [ ] JSONL lines parse correctly (no markdown artifacts)
- [ ] All samples have `text` and `label` fields
- [ ] Labels match the prompt category
- [ ] Format is consistent with previous outputs

### Final Dataset Validation

- [ ] All 7 output files generated
- [ ] Total ~175 samples
- [ ] Label distribution is reasonable
- [ ] No duplicate samples
- [ ] Manual spot-check: 10 random samples reviewed

## Troubleshooting

### Model outputs markdown instead of JSONL

The prompt explicitly asks for "OUTPUT ONLY JSONL LINES". If the model still outputs markdown:

1. **Re-prompt:** Add "Remember: Output ONLY valid JSONL lines, no explanations"
2. **Manual extraction:** Copy only the JSON lines from the output
3. **Clean up:** Remove ```jsonl markers if present

### Inconsistent format between files

If outputs from different sessions have different formats:

1. Check if you accidentally used a different model
2. Re-generate the inconsistent file with the correct model
3. Use the validation script to identify format differences

### Label imbalance

If final dataset has too few samples of one label:

1. Run the relevant prompt again to generate more samples
2. Ask the model to "generate 10 more samples" in the same session
3. Manually verify labels are correct

### Opus limit reached mid-session

1. Save current progress
2. Switch to Sonnet 4.5 for remaining prompts
3. Document which prompts used which model (for reproducibility)

## Consistency Guidelines

To maintain consistency across all generated data:

### DO ✅

- Use the same model for as many prompts as possible
- Validate each output immediately after generation
- Keep the same JSONL format throughout
- Document which model was used for each file

### DON'T ❌

- Mix many different models (max 2 from same family)
- Skip validation between batches
- Change the output format mid-generation
- Generate without reviewing output quality

## Next Steps After Data Generation

1. **Train the Model:**
   ```bash
   python scripts/train_preclassifier.py \
       --train data/ml_training/preclf_train.jsonl \
       --eval data/ml_training/preclf_eval.jsonl \
       --output models/preclf_v1.joblib
   ```

2. **Evaluate Performance:**
   ```bash
   python scripts/evaluate_preclassifier.py \
       --model models/preclf_v1.joblib \
       --test data/ml_training/preclf_eval.jsonl
   ```

3. **Integrate with Pipeline:**
   - Update `app/ml/preclassifier.py` to load the trained model
   - Enable via `FEATURE_ML_PRECLF=true`

## Privacy & Security Notes

- **No real secrets:** All samples use placeholder URLs and fictional domains
- **No PII:** Generated content should not contain real personal information
- **Git-safe:** JSONL files can be committed (no sensitive data)
- **Sanitize:** If using real-world examples, sanitize before adding to training data

## References

- [Synthetic Data Best Practices](https://www.sas.com/insights/articles/analytics/harnessing-synthetic-data-to-fuel-ai-breakthroughs.html)
- [Model Collapse in LLMs](https://arxiv.org/abs/2305.17493)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
