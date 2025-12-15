# LLM Egress Guard

Deterministic data loss prevention (DLP) layer that normalizes, inspects, and sanitizes LLM responses before they leave the platform.

> 📘 **Documentation Guide:** For a quick index of every Markdown file, see [docs/README.md](docs/README.md). It links to the normalization security notes, regression corpus guide, and sprint reports.
>
> 🗂 **Sprint Reports:** Each sprint ships Markdown, PDF, and DOCX copies under `reports/` (`Sprint-*-Report.{md,pdf,docx}`). Latest: Sprint 4 (ML pre-classifier v1 + shadow metrics).

Current highlights (through Sprint 4):
- Detector suite for PII (email/phone/IBAN/TCKN/PAN/IP), secrets (JWT, cloud/API keys, PEM blocks, high entropy), URL risks (data URIs, credentials-in-URL, suspicious TLD/shorteners), command/script chains, and encoded exfil blobs.
- Policy schema with risk-weighted rules, severity tiers, allowlist regex + tenant overrides, and localized safe messages.
- Action engine that masks/delinks text or returns safe messages when blocking.
- Context-aware parsing with explain-only (educational) detection to reduce FPs on tutorial content.
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
```

The Compose stack builds the FastAPI service and exposes Nginx with dev certificates located in `nginx/certs/`.

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

## 4. Project Layout

```text
app/                 FastAPI app, pipeline, detectors, policy/actions
config/              Default policy, allowlists, localized safe messages
nginx/               Dev reverse proxy + self-signed TLS
tests/               Unit, API, and regression corpora
docker-compose.yml   Dev stack (FastAPI + Nginx)
Makefile             Convenience commands wrapping the conda env
```

## 5. Metrics & Observability

- `/metrics` exposes Prometheus series:
  - `egress_guard_latency_seconds` (pipeline p50/p95)
  - `egress_guard_detector_latency_seconds{detector}` for each detector stage
  - `egress_guard_rule_hits_total{rule_id}` + `egress_guard_rule_severity_total{severity}`
  - `egress_guard_blocked_total`
  - `egress_guard_context_type_total{type}` + `egress_guard_explain_only_total`
  - `egress_guard_ml_preclf_load_total{status}` + `egress_guard_ml_preclf_shadow_total{ml_pred,heuristic,final}`
- Structured logs (JSON) include request id, policy, findings, latency, and snippet hashes.

## 6. Next Steps

- Add Grafana dashboards for ML/context metrics.
- Optional SIEM/alert exports and weekly telemetry reports once ingestion stabilizes.
- Continue regression corpus expansion (multilingual/tutorial-heavy cases) and tuning based on shadow-mode findings.
- (Optional) CI enforcement of model checksum via `scripts/check_preclf_model.py`.
