# LLM Egress Guard

Deterministic data loss prevention (DLP) layer that normalizes, inspects, and sanitizes LLM responses before they leave the platform.

> 📘 **Documentation Guide:** For a quick index of every Markdown file, see [docs/README.md](docs/README.md). It links to the normalization security notes, regression corpus guide, and sprint reports.
>
> 🗂 **Sprint Reports:** Each sprint ships Markdown and PDF copies under `reports/` (`Sprint-*-Report.{md,pdf}`). Latest: Sprint 5 (observability stack + security hardening).

Current highlights (through Sprint 5):
- Detector suite for PII (email/phone/IBAN/TCKN/PAN/IP), secrets (JWT, cloud/API keys, PEM blocks, high entropy), URL risks (data URIs, credentials-in-URL, suspicious TLD/shorteners), command/script chains, and encoded exfil blobs.
- Policy schema with risk-weighted rules, severity tiers, allowlist regex + tenant overrides, and localized safe messages.
- Action engine that masks/delinks text or returns safe messages when blocking.
- Context-aware parsing with explain-only (educational) detection to reduce FPs on tutorial content.
- **Security hardening** (OWASP-aligned): API key authentication, request size/timeout limits, concurrency control, model integrity verification (SHA256), and policy downgrade controls.
- **Observability stack**: Prometheus + Grafana with auto-provisioned dashboards for metrics visualization (request rate, latency, block rate, rule hits, context distribution).
- Prometheus telemetry for pipeline latency, detector latency, rule hits, severity counters, context type, explain-only counts, and ML pre-clf load/shadow metrics.
- Regression corpus + golden runner, FastAPI integration tests, and CI automation (Ruff, Black, pytest, regression).
- Synthetic secret placeholder system (`tests/regression/placeholders.py`) so the repo never stores real-looking keys while detectors still receive realistic payloads.
- Detector matrix harness (`tests/regression/detector_matrix.py`) that produces JSON + analyst Markdown for demos via a single command.
- ML Pre-Classifier v1 (TF-IDF + LogisticRegression) behind a feature flag; manifest + checksum verifier (`scripts/check_preclf_model.py`); shadow/A-B logging of ML vs heuristic disagreements.

The full specification lives in `llm_egress_guard_repo_skeleton_prd_technical_prd.md`.

## 1. Environment

Create the mandated conda environment and install dependencies:

```bash
conda create -y -p "$HOME/.conda/envs/LLM Egress Guard" python=3.11
source "$(conda info --base)/etc/profile.d/conda.sh"
conda activate "$HOME/.conda/envs/LLM Egress Guard"
pip install -e .[dev]

# Download spaCy models for the PII validator (EN/DE)
python -m spacy download en_core_web_sm
python -m spacy download de_core_news_sm
# (Optional) Disable validator if you need a lighter env:
# export FEATURE_ML_VALIDATOR=false
```

> The space in the environment path is intentional. Always activate this environment before running any commands for the project.

## 2. Running the API

### Local (uvicorn)

```bash
conda activate "$HOME/.conda/envs/LLM Egress Guard"
uvicorn transports.http_fastapi_sync:app --host 0.0.0.0 --port 8080 --reload
```

- `POST /guard` — inspect a response payload  
- `GET /healthz` — liveness check  
- `GET /metrics` — Prometheus text format (enabled for localhost)

### Docker Compose + Nginx TLS

```bash
docker compose up -d --build
# Guard proxied via https://localhost/guard (self-signed cert)
# Prometheus: http://localhost:9090
# Grafana: http://localhost:3000 (admin/admin)
```

The Compose stack builds the FastAPI service, Prometheus, Grafana, and Nginx with dev certificates located in `nginx/certs/`. See [docs/observability-setup.md](docs/observability-setup.md) for the full observability guide.

## 3. Tests & Tooling

```bash
make lint                     # ruff + black --check
pytest tests/unit -q          # unit tests (normalizer + detectors + API)
python tests/regression/runner.py           # corpus vs. golden outputs
python tests/regression/runner.py --matrix-report  # detector matrix JSON + Markdown
PYTHONPATH=. python scripts/demo_policy_reload.py  # policy hot-reload demo
```

- Regression runner automatically renders placeholder markers (e.g., `{{STRIPE_KEY}}`, `{{JWT_SAMPLE_TOKEN}}`) into deterministic synthetic secrets before invoking the pipeline.
- The `--matrix-report` flag saves demo responses under `tests/regression/artifacts/` for SOC runbooks; the directory is gitignored by default.

`ci/github-actions.yml` mirrors the same checks on every push/PR.

## Demo Scripts

- `python scripts/demo_scenarios.py` runs the four PRD demos (email mask, JWT block, curl|bash block, exfil block). Override the endpoint with `--api-url` (default `http://127.0.0.1:8080/guard` for uvicorn).
- Shell version: `API_URL=https://localhost/guard ./scripts/demo_scenarios.sh` (use `-k` with curl because docker-compose uses self-signed TLS via Nginx).
- To populate the new ML Grafana panels, keep `FEATURE_ML_PRECLF=true`, `SHADOW_MODE=true`, and run a few demo requests so Prometheus can scrape metrics.

## 4. Project Layout

```text
app/                 FastAPI app, pipeline, detectors, policy/actions, ML modules
config/              Default policy, allowlists, localized safe messages
grafana/             Grafana provisioning (datasources, dashboards)
models/              ML model artifacts (preclf_v1.joblib, manifests)
nginx/               Dev reverse proxy + self-signed TLS
prometheus/          Prometheus configuration
tests/               Unit, API, and regression corpora
reports/             Sprint reports and security assessments
docs/                Documentation (setup guides, notes)
docker-compose.yml   Full stack (FastAPI + Nginx + Prometheus + Grafana)
Makefile             Convenience commands wrapping the conda env
```

## 5. Metrics & Observability

- `/metrics` exposes Prometheus series:
  - `egress_guard_latency_seconds` (pipeline p50/p95, ~1.6ms avg)
  - `egress_guard_detector_latency_seconds{detector}` for each detector stage
  - `egress_guard_rule_hits_total{rule_id}` + `egress_guard_rule_severity_total{severity}`
  - `egress_guard_blocked_total`
  - `egress_guard_context_type_total{type}` + `egress_guard_explain_only_total`
  - `egress_guard_ml_preclf_load_total{status}` + `egress_guard_ml_preclf_shadow_total{ml_pred,heuristic,final}`
- **Grafana Dashboard** (auto-provisioned):
  - Overview: Request Rate, Block Rate, Avg Latency, Total Findings
  - Performance: Latency Percentiles (p50/p90/p99), Blocked vs Allowed Requests
  - Detection: Rule Hits Distribution, Context Type Distribution, Explain-Only Detections
  - Top Rules: Bar chart and time series
- Structured logs (JSON) include request id, policy, findings, latency, and snippet hashes.

## 6. Security Hardening

OWASP-aligned security controls (see [reports/security_assessment_owasp.md](reports/security_assessment_owasp.md)):

| Control | Setting | Default |
|---------|---------|---------|
| API Key Authentication | `REQUIRE_API_KEY`, `API_KEY` | Disabled |
| Request Size Limit | `MAX_REQUEST_SIZE_BYTES` | 512KB |
| Request Timeout | `REQUEST_TIMEOUT_SECONDS` | 30s |
| Concurrency Limit | `MAX_CONCURRENT_GUARD_REQUESTS` | 10 |
| Model Integrity | `ENFORCE_MODEL_INTEGRITY` | Enabled |
| Explain-Only Bypass | `ALLOW_EXPLAIN_ONLY_BYPASS` | Disabled |

Production deployment should enable `REQUIRE_API_KEY=true` and set a strong `API_KEY`.

## 7. Next Steps

- ✅ ~~Add Grafana dashboards for ML/context metrics.~~ (Completed in Sprint 5)
- ✅ ~~Security hardening (OWASP audit, auth, rate limiting).~~ (Completed in Sprint 5)
- Optional SIEM/alert exports and weekly telemetry reports once ingestion stabilizes.
- Continue regression corpus expansion (multilingual/tutorial-heavy cases) and tuning based on shadow-mode findings.
- (Optional) CI enforcement of model checksum via `scripts/check_preclf_model.py`.
- Streaming support for chat interfaces (pass-through stream, buffer window, scan, release).
- Post-MVP follow-ups: wire SIEM connectors and the AWS Lambda transport adapter.
