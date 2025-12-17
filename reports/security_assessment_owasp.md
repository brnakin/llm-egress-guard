# LLM Egress Guard – OWASP-Oriented Security Assessment (English)

## Scope and References
- Reviewed components: `app/` (FastAPI service, pipeline, detectors), `transports/http_fastapi_sync.py`, `config/policy.yaml`, ML loaders (`app/ml/preclassifier.py`), metrics (`app/metrics.py`).
- OWASP Top 10 (2021) and relevant Cheat Sheets: Attack Surface Analysis, Authentication, Security Misconfiguration, Denial of Service, Deserialization, Logging & Monitoring.

## Architecture and Attack Surface
- HTTP endpoints: `/guard` (processes LLM output), `/healthz`, `/metrics`.
- Default deployment: FastAPI/uvicorn listening on `0.0.0.0:8080`, no authentication or rate limiting defined.
- Policy and ML artifacts are loaded from disk based on environment-provided paths without integrity controls.

## Findings (Code-Referenced, Detailed)
1) **Broken Access Control & Security Misconfiguration (A01, A05) — High**  
   - Evidence: `app/main.py` exposes `/guard` and `/metrics` with no authZ/authN; `transports/http_fastapi_sync.py` binds `0.0.0.0:8080` with `reload=True`; `app/settings.py` sets `metrics_enabled=True` by default.  
   - Impact: Any network peer can submit arbitrary payloads for scanning, observe blocking behavior, or scrape Prometheus metrics revealing rule names, counts, and latency. Increases blast radius for brute-force evasion and reconnaissance.  
   - Exploitation: Internet-exposed `/metrics` endpoint is scraped to enumerate rules and blocked totals; `/guard` is hammered with crafted samples to probe which patterns evade blocking.  
   - Recommendations (critical): Enforce authentication/authorization (API key/OIDC/mTLS) on `/guard` and `/metrics`; move metrics behind an internal interface; default `METRICS_ENABLED` to `False`; add reverse-proxy rate limits and IP restrictions; in production bind to `127.0.0.1` and disable `reload`.

2) **Software/Data Integrity Failures – Insecure Deserialization (A08) — High**  
   - Evidence: `app/ml/preclassifier.py::load_preclassifier` loads a pickle-based `joblib` artifact from `PRECLF_MODEL_PATH` without signature/hash verification or path hardening.  
   - Impact: Malicious pickle can achieve remote code execution during app startup or first request. Supply-chain or file-system tampering leads directly to code execution under service privileges.  
   - Recommendations (high): Avoid pickle for untrusted artifacts; require SHA256/signature verification before load; restrict model path to a fixed, read-only directory; prefer safer formats (ONNX/JSON) or load the model in a sandboxed, low-privilege process.

3) **Insecure Design – Over-permissive Policy Downgrade (A04) — High**  
   - Evidence: `app/policy.py` `_apply_context_adjustment` and `evaluate` reduce risk weights and can skip `block` actions when findings are marked `explain_only` or appear in code blocks. Heuristics/ML can zero out weights and bypass blocking for `cmd` findings.  
   - Impact: Dangerous commands/URLs/secrets can evade blocking by wrapping them in fenced code blocks with benign language (“example”, “do not run”), lowering risk below thresholds.  
   - Recommendations (high): Disable explain-only downgrades by default or make them tenant-opt-in; enforce a non-bypassable minimum for `block` actions on critical types (cmd/secret/url); add an explicit allowlist for educational contexts instead of heuristic auto-downgrade; log when downgrades occur.

4) **Denial of Service Exposure (A01/A05/A11) — High**  
   - Evidence: `/guard` accepts unbounded request bodies; detectors run multiple regex-heavy scans and optional ML load without size or time caps; no rate limiting or per-request timeout exists.  
   - Impact: Large payloads (MBs of base64/hex or URL lists) or pathological regex inputs can exhaust CPU/memory and starve worker threads, leading to service unavailability.  
   - Recommendations (high): Enforce max body size (e.g., 256–512 KB) and request timeouts; implement rate limiting and concurrency caps; add regex timeouts/fail-fast guards; return 413/408 for over-limit requests; add circuit breakers and health probes.

5) **Security Logging & Monitoring Gaps (A09) — Medium**  
   - Evidence: Structlog is configured, but there is no auth, and security-relevant context (client identity/IP/headers) is not captured; metrics are exposed without protection.  
   - Impact: Hard to detect abuse, brute-force probing, or DoS attempts; limited forensics.  
   - Recommendations (medium): Add security-focused log schema (with PII redaction); log auth failures, blocked requests, limit violations, and downgrades; protect metrics with auth and alerts on error/latency anomalies.

## Recommended Mitigations and Hardening Steps
- **Access Control & Exposure**: Require authZ/authN on `/guard` and `/metrics`; restrict metrics to internal networks; default `METRICS_ENABLED=False`; deploy behind a reverse proxy with IP allowlists and rate limits; disable uvicorn reload and bind to loopback in production.
- **Input/Resource Limits**: Cap request body size and parsing time; set detector and pipeline timeouts; implement rate limiting and concurrency guards; return explicit 413/408 responses for over-limit requests.
- **Artifact Integrity**: Enforce SHA256/signature verification for policy/model artifacts; reject paths outside trusted directories; avoid pickle for untrusted inputs or sandbox the loader.
- **Policy Downgrade Controls**: Make explain-only/context risk reductions opt-in per tenant; define non-bypassable critical rules; record and alert on any downgrade of `block` actions.
- **Logging/Monitoring**: Standardize security logs (tenant/request ID, decision, rule IDs, redacted spans); protect metrics endpoint; set alerts on block rates, detector errors, latency spikes.
- **Deployment Hygiene**: Terminate TLS at the edge with HSTS and secure headers; keep `.env` secrets out of images; set safe defaults (`FEATURE_ML_PRECLF` only when a verified model is present, `SHADOW_MODE=False` in prod).

## Quick Hardening Checklist (OWASP-Aligned)
- A01 Broken Access Control: AuthZ on all non-health endpoints; rate limiting; internal-only metrics.
- A05 Security Misconfiguration: Secure defaults, private bind, no dev reload in prod.
- A08 Software/Data Integrity Failures: Signed/hashed artifacts; no unsafe pickle loads.
- A11 DoS: Body size/time/concurrency limits; regex safeguards; circuit breakers.
- A09 Logging & Monitoring: Redacted security logs; protected metrics; alerting in place.

## Remediation Plan (Suggested Order)
1) Gate `/guard` and `/metrics` with auth; move metrics behind internal ingress; disable `reload` and change bind to loopback.  
2) Add body-size and request-time limits plus rate limiting and regex/pipeline timeouts.  
3) Harden model/policy loading with signature/hash verification and trusted paths; remove/replace pickle where feasible.  
4) Make explain-only downgrades opt-in and add non-bypassable blocking for critical rules.  
5) Implement security logging schema and metrics alerting; run abuse/stress tests to validate limits.

---

## Remediation Status (Updated: Dec 17, 2025)

| Finding | Status | Implementation |
|---------|--------|----------------|
| **A01/A05: Access Control** | ✅ Fixed | `verify_api_key` in `app/main.py`; `REQUIRE_API_KEY` + `API_KEY` settings |
| **A05: Security Misconfiguration** | ✅ Fixed | `transports/http_fastapi_sync.py` binds `127.0.0.1`; reload via env |
| **A08: Model Integrity** | ✅ Fixed | SHA256 verification in `load_preclassifier`; path hardening to `models/` |
| **A04: Policy Downgrade** | ✅ Fixed | `allow_explain_only_bypass` opt-in (default=False) in `policy.evaluate()` |
| **A11: DoS - Body Size** | ✅ Fixed | `MAX_REQUEST_SIZE_BYTES` (512KB default) enforced via middleware |
| **A11: DoS - Concurrency** | ✅ Fixed | `MAX_CONCURRENT_GUARD_REQUESTS` (10 default) via semaphore |
| **A11: DoS - Timeout** | ✅ Fixed | `REQUEST_TIMEOUT_SECONDS` (30s default) with 408 response |
| **A09: Security Logging** | ✅ Fixed | Structured logging for auth failures, size limits, timeouts |

### New Settings Added (`app/settings.py`)

```bash
# Security & Auth
REQUIRE_API_KEY=false      # Set true in production
API_KEY=<secret>           # Required if REQUIRE_API_KEY=true

# DoS Protection
MAX_CONCURRENT_GUARD_REQUESTS=10
MAX_REQUEST_SIZE_BYTES=524288  # 512KB
REQUEST_TIMEOUT_SECONDS=30.0

# Model Integrity
ENFORCE_MODEL_INTEGRITY=true
PRECLF_MANIFEST_PATH=models/preclf_v1.manifest.json

# Policy Downgrade Controls
ALLOW_EXPLAIN_ONLY_BYPASS=false  # Opt-in per tenant
```

### Remaining Recommendations (Low Priority)
- External rate limiting via reverse proxy (nginx/Traefik)
- Regex timeout guards in detectors
- Grafana dashboards for security metrics alerting

