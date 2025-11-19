# LLM Egress Guard — Repository Skeleton + PRD + Technical PRD
**Version:** 1.0  
**Date:** 17 October 2025  
**Owner:** <you>  
**Decision Log:** VM + Docker Compose + Nginx for MVP; No streaming in MVP; Lightweight ML (pre-classifier + optional NER validator); Potential hybrid later (Lambda + HTTP API for sync, EC2 for streaming if added).

---

## 1) Repository Skeleton (proposed)

```text
egress-guard/
├─ README.md
├─ LICENSE
├─ .gitignore
├─ Makefile
├─ docker-compose.yml
├─ nginx/
│  ├─ nginx.conf                # TLS termination, rate-limit, proxy /guard
│  └─ certs/                    # fullchain.pem, privkey.pem (dev/self-signed)
├─ config/
│  ├─ policy.yaml               # default policy (RO mount in prod)
│  └─ locales/
│     └─ en/safe_messages.yaml  # user-facing safe messages
├─ app/
│  ├─ main.py                   # FastAPI entrypoint (sync /guard, /healthz, /metrics)
│  ├─ pipeline.py               # normalize → parse → detect → decide → act
│  ├─ normalize.py              # Unicode NFKC, ZWSP, bounded decode/unescape
│  ├─ parser.py                 # format-aware v1 (markdown/code/link split)
│  ├─ policy.py                 # YAML loader, tiers, allowlist, rule registry
│  ├─ actions.py                # mask, delink, block, annotate
│  ├─ detectors/
│  │  ├─ pii.py                 # email, phone, IBAN (TR/DE), TCKN simple check
│  │  ├─ secrets.py             # JWT, AKIA, sk-*, entropy-based tokens
│  │  ├─ url.py                 # IP URLs, data: scheme, risky extensions
│  │  ├─ cmd.py                 # curl|bash, Invoke-WebRequest, powershell -enc, rm -rf, reg add
│  │  └─ exfil.py               # base64/hex blob detector with entropy thresholds
│  ├─ ml/
│  │  ├─ preclassifier.py       # TF-IDF + Logistic Regression (code/command vs text)
│  │  ├─ validator_spacy.py     # optional NER validator (email/phone/person)
│  │  └─ models/
│  │     └─ model_preclf.pkl    # small serialized model (<10 MB)
│  ├─ metrics.py                # p50/p95, rule hits; /metrics (Prometheus)
│  ├─ schemas/
│  │  ├─ api_request.json       # JSON Schema for POST /guard request
│  │  └─ api_response.json      # JSON Schema for response
│  └─ settings.py               # env parsing, feature flags (ML on/off, shadow mode)
├─ transports/
│  ├─ http_fastapi_sync.py      # FastAPI transport (VM/Nginx)
│  └─ aws_lambda_handler.py     # (future/optional) Lambda adapter for sync path
├─ tests/
│  ├─ unit/
│  │  ├─ test_normalize.py
│  │  ├─ test_detectors.py
│  │  └─ test_actions.py
│  ├─ regression/
│  │  ├─ corpus_v1/
│  │  │  ├─ clean/*.txt
│  │  │  ├─ pii/*.txt
│  │  │  ├─ secrets/*.txt
│  │  │  ├─ url/*.txt
│  │  │  ├─ cmd/*.txt
│  │  │  └─ exfil/*.txt
│  │  ├─ README.md              # corpus guide + placeholder workflow
│  │  ├─ golden_v1.jsonl        # expected outcomes for corpus_v1
│  │  ├─ golden_manifest.json   # version metadata for golden files
│  │  ├─ placeholders.py        # synthetic secret generators ({{TOKEN}} markers)
│  │  ├─ detector_matrix.py     # scripted scenarios for demos
│  │  ├─ artifacts/             # generated JSON/Markdown reports (gitignored)
│  │  └─ runner.py              # compare outputs vs golden + matrix reports
│  └─ ml/
│     ├─ data/
│     │  ├─ preclf_train.jsonl
│     │  └─ preclf_eval.jsonl
│     └─ train_preclf.ipynb     # simple notebook to train TF-IDF + LR
├─ ci/
  └─ github-actions.yml        # (post-MVP, optional)
scripts/
   ├─ bench.sh                  # quick p95/p99 micro-bench (vegeta/hey)
   └─ export_weekly_report.py   # (post-MVP) top rules, p95 trend, FP candidates
```

**Makefile (excerpt)**
```makefile
up: ; docker compose up -d --build
logs: ; docker compose logs -f app
bench: ; ./scripts/bench.sh
regression: ; python tests/regression/runner.py
lint: ; ruff app tests && black --check app tests
format: ; black app tests
```

**docker-compose.yml (excerpt)**
```yaml
version: "3.9"
services:
  app:
    build: ./app
    environment:
      POLICY_FILE: /app/config/policy.yaml
      LOG_LEVEL: info
      METRICS_ENABLED: "true"
      FEATURE_ML_PRECLF: "true"
      FEATURE_ML_VALIDATOR: "false"   # can be toggled later
      SHADOW_MODE: "false"
    volumes:
      - ./config:/app/config:ro
    ports:
      - "127.0.0.1:8080:8080"
    restart: unless-stopped
  nginx:
    image: nginx:alpine
    depends_on: [app]
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/certs:/etc/nginx/certs:ro
    ports:
      - "443:443"
    restart: unless-stopped
```

**nginx/nginx.conf (excerpt)**
```nginx
server {
  listen 443 ssl http2;
  server_name YOUR_DOMAIN;
  ssl_certificate     /etc/nginx/certs/fullchain.pem;
  ssl_certificate_key /etc/nginx/certs/privkey.pem;
  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
  location = /healthz { return 200 "ok\n"; }
  location /guard {
    limit_req zone=egress_guard burst=20 nodelay;
    proxy_pass http://app:8080/guard;
    proxy_set_header X-Request-ID $request_id;
    proxy_read_timeout 10s; proxy_send_timeout 10s;
  }
  location /metrics { allow 127.0.0.1; deny all; proxy_pass http://app:8080/metrics; }
  location / { return 404; }
}
```

---

## 2) Product Requirements Document (PRD)

### 2.1 Overview
**Problem:** Enterprises need a deterministic, low-latency guardrail to prevent **secrets/PII/command/URL risks** from leaking through LLM outputs.  
**Solution:** A model-agnostic **Egress Guard** that inspects LLM responses and **masks/delinks/blocks/transforms** risky content, with **policy-driven decisions**, **telemetry**, and **lightweight ML** to reduce false positives.  
**MVP Decision:** **No streaming** in MVP (single-shot responses). **Runtime:** **VM + Docker Compose + Nginx**.

### 2.2 Goals / Non-Goals
**Goals**
- G1: Stop or neutralize risky content in LLM outputs with **deterministic policy** (PII, Secrets, URL, CMD, Exfil/high entropy).
- G2: Provide **low-latency** (p95 < 40 ms for 1–3K chars) decisions.
- G3: Offer clear **audit logs** and minimal PII exposure (snippet hashing, masking only); when regression samples require realistic tokens, use placeholder markers rendered at runtime.
- G4: Include **light ML** (pre-classifier; optional NER validator) to cut false positives and enable context-aware risk tuning.
- G5: Simple **/guard** API usable by any LLM app (RAG, chat, agent).

**Non-Goals (MVP)**
- N1: Streaming (SSE/HTTP chunk) processing.
- N2: Format-aware parser (markdown/code/link splitting).
- N3: NER-based PII validator (multi-language).
- N4: SIEM connector/templates & weekly report automation.
- N5: Heavy ML or LLM-as-judge moderation.

### 2.3 Personas & Use Cases
- **AI Platform Engineer:** Integrates /guard into LLM gateway/app.
- **Security Engineer (Blue Team):** Reviews findings, tunes policies, watches FP/TPR.
- **Developer:** Tests locally, reads safe messages, evaluates latency.

Use cases: PII masking, secret blocking, dangerous command/URL defanging, policy tiers per tenant.

### 2.4 Scope (MVP)
- Pipeline: normalize → parse → detect → decide → act → log
- Detectors: PII, Secrets, URL Risk, Command, Exfil/high entropy blobs
- Policy: YAML (tiers, allowlist/denylist, rule ids, thresholds, actions)
- API: `POST /guard` (sync). Healthz, metrics.
- Telemetry: p50/p95, rule hits, basic risk score.
- Tests: ≥150 samples; regression harness with placeholder templating + detector matrix demo.

### 2.5 Success Metrics & KPIs (Student Project Targets)
- **Detection (guidance):** Catch rate **80–90%** on your corpus (PII/Secrets/URL/CMD/Exfil); False Positive rate **≤ 10%** (improve over time)
- **Performance (guidance):** Aim for median < **40 ms**, p95 < **80 ms** on 1–3K chars (single vCPU); document actuals
- **Privacy (required):** No raw secrets/PII in logs; only masked text + `snippet_hash`. Regression fixtures must use placeholder markers (`{{TOKEN}}`) rendered at runtime so the repo never stores literal secrets.
- **Observability (minimal):** p50/p95 latency and rule‑hit counts available (CLI or simple dashboard)
- **Testing (minimal):** ≥ **100** labeled samples, golden manifest, placeholder renderer, and a detector-matrix script for demos.

### 2.6 Release Plan
- 12-week plan in 2-week sprints (see TPRD sprints).  
- MVP tag **v0.1.0**; **v0.2.x** includes format-aware v1 + optional SIEM templates.  
- **Streaming** reserved for **v0.3.x** (post-MVP).

### 2.7 Risks & Mitigations (PRD)
- High FP → Policy tiers + ML pre-classifier + validator + format-aware; detector matrix reviews highlight FP sources.
- Latency drift → Short-circuit, bounded decode, linear-time regex.
- Privacy → No raw snippets in logs; only hashes + masked samples. Regression samples rely on placeholder templating to keep repo secret-free while still exercising detectors.
- Operational → Dockerized, restart policy, health checks; GitHub push protection enforced via placeholder corpus + golden manifest process.

### 2.8 Acceptance Criteria (PRD — Student Scope)
- Core pipeline works end‑to‑end: normalize → detect (PII/Secrets/URL/CMD/Exfil) → decide → act → log
- Policy YAML controls behavior (tiers, allowlist) and is reloadable without rebuild
- Demonstrate **4 scenarios**: (1) email mask, (2) JWT block, (3) `curl|bash` block + safe message, (4) base64/hex exfil block with snippet hashing
- Basic metrics visible (p50/p95, rule hits); latency within **reasonable** bounds for demo (< ~80 ms p95 preferred; if higher, documented)
- Regression suite runs and passes **must‑have** cases (≥ **80%** pass rate initially; improvements noted) using placeholder-marked corpus and detector matrix demo.
- Logs contain no raw sensitive content; snippet hashes + placeholders ensure reproducible investigations without storing secrets.
- Manual deployment documented (README) with `docker compose up -d`

---

## 3) Technical PRD (TPRD)

### 3.1 Architecture (MVP, no streaming)
```
Client → HTTPS 443 → Nginx (TLS, rate-limit) → FastAPI (/guard)
   normalize (NFKC, ZWSP, unescape-bounded)
   → (ML PreClassifier: code/command vs text) [light, optional per request]
   → detect (regex/entropy/denylist: PII, Secrets, URL, CMD)
   → (ML Validator: spaCy small NER) [optional, only on uncertain hits]
   → decide (policy tiers, allowlist)
   → act (mask/delink/block/annotate)
   → log (JSON lines, snippet_hash; /metrics)
```

### 3.2 API Contract
**Endpoint:** `POST /guard`  
**Request (schema excerpt):**
```json
{
  "response": "string (LLM output)",
  "policy_id": "default",
  "metadata": {"request_id": "abc-123", "tenant": "acme"}
}
```
**Response:**
```json
{
  "response": "sanitized text",
  "findings": [
    {"rule_id":"PII-EMAIL","action":"mask","offsets":[100,112]},
    {"rule_id":"URL-DANGEROUS","action":"delink"}
  ],
  "blocked": false,
  "risk_score": 25,
  "latency_ms": 12,
  "policy_id": "default",
  "version": "0.1.0"
}
```
**Other endpoints:**
- `GET /healthz` → 200 `ok`
- `GET /metrics` → Prometheus metrics (restricted to localhost)

### 3.3 Policy Schema (YAML excerpt)
```yaml
tiers: "med"
allowlist: []
rules:
  - id: PII-EMAIL
    type: pii
    kind: email
    action: mask
  - id: SECRET-JWT
    type: secret
    kind: jwt
    action: block
  - id: URL-DANGEROUS
    type: url
    kind: ip_or_dataurl_or_exe
    action: delink
  - id: CMD-CURL-BASH
    type: cmd
    pattern: "curl\s+[^|]+\|\s*bash"
    action: block
```

### 3.4 Logging Schema (JSON lines)
```json
{
  "ts":"2025-10-17T09:45:12Z",
  "request_id":"abc-123",
  "policy_id":"default",
  "rule_id":"PII-EMAIL",
  "severity":"medium",
  "action":"mask",
  "latency_ms":9,
  "blocked":false,
  "snippet_hash":"sha256:...",
  "tenant":"acme"
}
```

### 3.5 ML Components (lightweight)
- **Pre-Classifier (required, light):**
  - **Model:** TF-IDF (char+word n-grams) + Logistic Regression (sklearn)
  - **Task:** `code/command` vs `text`
  - **Use:** Adjust CMD detector thresholds/enablement; reduce FP in narrative text
  - **Budget:** < 2 ms per request (after TF-IDF transform); model < 10 MB

- **NER Validator (optional):**
  - **Model:** spaCy small
  - **Task:** Confirm regex-detected PII (email/phone/person) when ambiguous
  - **Use:** Second-opinion to reduce FP; only run on candidate spans
  - **Budget:** Feature-flagged; may be disabled by default in MVP

**Feature Flags:** `FEATURE_ML_PRECLF`, `FEATURE_ML_VALIDATOR`, `SHADOW_MODE`

### 3.6 Performance Targets
- p95 < 40 ms for 1–3K chars (single vCPU)  
- Regex linear-time; per-detector watchdog timeouts  
- Short-circuit on high-severity hits

### 3.7 Security & Privacy
- TLS at Nginx; HSTS; strong ciphers  
- Read-only policy mount; signed bundles planned post-MVP  
- No raw sensitive content in logs; only hashes + masked snippets  
- Deny-by-default: on internal error return `safe_message`

### 3.8 Deployment
- **Runtime:** Ubuntu 22.04/24.04 on t4g.small/t3.small  
- **Containers:** Nginx (443) + App (127.0.0.1:8080) via Docker Compose  
- **Certificates:** Let’s Encrypt or self-signed for dev  
- **Observability:** /metrics (local), Nginx access/error logs

### 3.9 Testing Strategy
- Unit tests for normalizer, detectors, actions  
- Regression suite: ≥150 samples (v1), golden outputs  
- Micro-bench: vegeta/hey at 5–20 rps bursts

### 3.10 CI/CD (Post-MVP)
- **MVP:** manual deployment only — `docker compose pull && up -d` on the VM; versioned images (tags) are enough.
- **Post-MVP (optional):** add GitHub Actions for lint → unit → regression → build image → image scan → notify. Enable when team/scale requires automation.

### 3.11 Roadmap (post-MVP)
- **v0.2.x:** Format-aware parser v1 (markdown/code/link), NER validator (multi-lang PII), SIEM connector/webhook exporters (KQL/SPL templates, alert runbooks) **and Weekly Report automation**
- **v0.3.x:** Streaming (chunk API): `chunk_id`, `final_chunk`, `partial_findings`; progressive actions (delink → mask → block)
- **Hybrid Option:** Keep sync path on Lambda + HTTP API; add separate streaming endpoint on EC2 (path or subdomain)

### 3.12 2-Week Sprints (12 weeks total)
- **Sprint 1 (Oct 17–Oct 30):** Skeleton, normalizer v1, stubs, Compose+Nginx dev TLS, initial tests
- **Sprint 2 (Oct 31–Nov 13):** Detectors v1 (PII/Secrets/URL/CMD), policy YAML, telemetry basics
- **Sprint 3 (Nov 14–Nov 27):** ML Pre-Classifier (train+integrate), A/B tests, FP reduction
- **Sprint 4 (Nov 28–Dec 11):** Dashboard mini, hardening & RO mounts (NER validator moved post-MVP)
- **Sprint 5 (Dec 12–Dec 25):** Corpus v2 + regression runner, CI wiring (format-aware moved post-MVP)
- **Sprint 6 (Dec 26–Jan 8):** Tuning, risk score v1, report & demo scenarios (weekly report moved post-MVP)

### 3.13 Acceptance (TPRD — Student Scope)
- Functional: `/guard`, `/healthz`, `/metrics` behave as specified; actions mask/delink/block applied correctly across PII/Secrets/URL/CMD/Exfil.
- Performance: single‑vCPU dev box achieves **documented** median and p95; any deviations explained with profiling notes.
- Quality: unit tests for normalizer/detectors/actions; regression runner over ≥100 samples plus detector matrix demo and placeholder templating.
- ML (if enabled): pre‑classifier integrated behind a feature flag; adds ≤ ~5 ms median (measured).
- Security/Privacy: TLS via Nginx; RO policy mount; error path returns safe message; no raw sensitive logs, regression corpus uses placeholders so repo stays secret-free.
- Demo package: ≥4 scenario scripts (PII mask, JWT block, curl|bash block, exfil block) + screenshots or short clip; README with run, test, policy-tuning, and placeholder instructions.

**End of Document**
