# Task: Generate Clean Documentation Text

You are generating training data for a machine learning model. Generate CLEAN text that contains NO dangerous commands. This is the baseline "safe" content that should NOT be blocked.

Generate **25 unique samples** of clean, safe text.

## Output Format

Output valid JSONL (one JSON object per line). Do NOT include any other text, explanations, or markdown formatting - ONLY the JSONL lines:

```
{"text": "content here", "label": "text", "segment_type": "text"}
```

## Content Types (5 samples each)

### 1. General Documentation
- API documentation
- README content
- Feature descriptions
- Configuration explanations (without shell commands)

### 2. Theoretical Discussions
- Security concepts explained without code
- Architecture discussions
- Design patterns
- Best practices (conceptual, not commands)

### 3. Product/Software Descriptions
- Software feature lists
- Release notes (without installation commands)
- Product comparisons
- Technical specifications

### 4. Safe Coding Tutorials
- Python basics (print, variables, loops)
- JavaScript fundamentals
- Data structure explanations
- Algorithm explanations

### 5. General Technical Prose
- Explanatory paragraphs
- How things work (conceptually)
- Technical blog content
- Interview preparation content

## Requirements

- NO shell commands (curl, wget, bash, sh, powershell, rm, sudo)
- NO executable patterns that could be dangerous
- CAN include safe code (print statements, variable assignments, loops)
- CAN include configuration examples (YAML, JSON) without dangerous values
- Normal technical documentation style
- Use proper newlines with \n in JSON strings

## Example Output Format

```jsonl
{"text": "## Introduction to REST APIs\n\nREST (Representational State Transfer) is an architectural style for designing networked applications. It relies on stateless, client-server communication, typically over HTTP.\n\nKey principles include:\n- Uniform interface\n- Statelessness\n- Cacheability\n- Layered system\n\nRESTful APIs use standard HTTP methods: GET for retrieval, POST for creation, PUT for updates, and DELETE for removal.", "label": "text", "segment_type": "text"}
{"text": "### Python Variables and Data Types\n\nPython is dynamically typed, meaning you don't need to declare variable types:\n\n```python\nname = \"Alice\"\nage = 30\nheight = 5.6\nis_student = False\n\nprint(f\"{name} is {age} years old\")\n```\n\nCommon data types include strings, integers, floats, and booleans.", "label": "text", "segment_type": "text"}
{"text": "## Configuration Options\n\nThe application supports the following configuration:\n\n```yaml\nserver:\n  port: 8080\n  host: localhost\n  timeout: 30\n\nlogging:\n  level: INFO\n  format: json\n```\n\nAll options can be overridden via environment variables.", "label": "text", "segment_type": "text"}
```

---

**OUTPUT ONLY JSONL LINES - NO OTHER TEXT**

Generate 25 samples now:

