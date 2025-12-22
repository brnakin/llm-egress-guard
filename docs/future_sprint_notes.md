# Notes for Future Sprints

> **Updated:** Dec 22, 2025 — Reflects completion of Sprint 5 (observability stack, security hardening).

---

## ✅ Completed Items (Sprint 3-5)

### Context-Aware Parser Segmentation (Sprint 3)
- ✅ `app/parser.py` emits `text/code/link` segments with metadata
- ✅ Context penalties/bonuses applied in `app/policy.py`
- ✅ "Explain-only" detection reduces FPs on tutorial content
- ✅ Metrics: `egress_guard_context_type_total`, `egress_guard_explain_only_total`

### ML Pre-Classifier v1 (Sprint 4)
- ✅ TF-IDF + Logistic Regression model (`models/preclf_v1.joblib`)
- ✅ Eval: Accuracy 0.8857, F1 macro 0.8604, <2ms latency
- ✅ Feature flag: `FEATURE_ML_PRECLF=true`
- ✅ Shadow mode: `SHADOW_MODE=true` logs ML vs heuristic disagreements
- ✅ Model manifest + checksum verification (`scripts/check_preclf_model.py`)

### Observability Stack (Sprint 5)
- ✅ Prometheus integration with 15s scrape interval
- ✅ Grafana with auto-provisioned datasources and dashboards
- ✅ Dashboard panels: Request Rate, Block Rate, Latency, Rule Hits, Context Distribution
- ✅ Setup guide: `docs/observability-setup.md`

### Security Hardening - OWASP (Sprint 5)
- ✅ **Authentication (A01/A05):** API key gate (`REQUIRE_API_KEY`, `API_KEY`)
- ✅ **DoS Protection (A11):** Request size limits, timeouts, concurrency control
- ✅ **Model Integrity (A08):** SHA256 verification before loading ML artifacts
- ✅ **Policy Controls (A04):** `ALLOW_EXPLAIN_ONLY_BYPASS` prevents bypasses
- ✅ **Security Assessment:** `reports/security_assessment_owasp.md`

---

## 🔄 Remaining Work (Sprint 6+)

### Demo Package (Priority: High)
Goal: 4 scenario scripts with screenshots/video for demonstrations.

| Task | Description |
|------|-------------|
| `DEMO-01` | Email masking demo script |
| `DEMO-02` | JWT blocking demo script |
| `DEMO-03` | `curl\|bash` blocking + safe message demo |
| `DEMO-04` | Base64/hex exfil blocking demo |

Exit criteria: 4 runnable scripts, terminal output or screenshots.

### SIEM / Alert Integrations (Priority: Medium)
Goal: Push rule hits/blocks to Splunk/ELK/webhooks for SOC visibility.

| Task | Description |
|------|-------------|
| `SIEM-201` | Telemetry bus: queue, backpressure metrics, secure payload serialization |
| `SIEM-202` | Splunk HEC + Elastic bulk clients with retry/backoff |
| `SIEM-203` | Generic webhook sink, curl templates, SOC runbooks |

Exit criteria: <5s delivery, `/guard` unaffected by emitter failures, dashboards ready.

### Streaming Support (Priority: Medium)
Goal: Support chat interfaces without blocking on full response.

- Pass-through stream, buffer window, scan, release architecture
- Incremental scanning for long-running LLM outputs
- WebSocket or SSE transport option

### spaCy Validator Integration (Priority: Low)
Goal: Double-check regex PII hits with NER model.

| Task | Description |
|------|-------------|
| `PAR-302` | Lazy-load spaCy model, disagreement telemetry |
| `PAR-303` | Per-tenant toggles, Docker/runtime docs, rollback checklist |

Note: spaCy model bloats the container; keep optional and lazy-loaded.

### Performance Optimization (Priority: Low)
- Aho-Corasick multi-pattern matching for trigger keywords
- Parallel detector execution for large inputs
- Currently ~1.76ms avg latency is acceptable

---

## 📋 Configuration Reference

### Current Feature Flags
```bash
# ML Pre-Classifier
export FEATURE_ML_PRECLF=true
export PRECLF_MODEL_PATH=models/preclf_v1.joblib
export SHADOW_MODE=false  # Set true for A/B logging

# Security (Production)
export REQUIRE_API_KEY=true
export API_KEY="your-secret-key"
export ENFORCE_MODEL_INTEGRITY=true
export ALLOW_EXPLAIN_ONLY_BYPASS=false

# DoS Protection
export MAX_REQUEST_SIZE_BYTES=524288  # 512KB
export REQUEST_TIMEOUT_SECONDS=30
export MAX_CONCURRENT_GUARD_REQUESTS=10
```

### Observability
```bash
docker compose up -d
# Prometheus: http://localhost:9090
# Grafana: http://localhost:3000 (admin/admin)
```

---

## 📊 Current Metrics

| Metric | Value | Notes |
|--------|-------|-------|
| Avg Latency | ~1.76ms | Pipeline only, excludes HTTP overhead |
| Block Rate | ~15.7% | Varies by traffic pattern |
| ML Accuracy | 88.57% | TF-IDF + LR on synthetic data |
| ML F1 Macro | 86.04% | Educational 0.923, Command 0.889, Text 0.769 |

---

## 🎯 Sprint 6 Focus

1. **Demo Package** — 4 scenario scripts for demonstrations
2. **SIEM Integration** — Enable SOC visibility via Splunk/Elastic/webhooks
3. **Production Tuning** — Based on shadow-mode findings and Grafana metrics

---

*Last updated: Dec 22, 2025*
