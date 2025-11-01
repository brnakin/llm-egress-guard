# LLM Egress Guard

Deterministic data loss prevention (DLP) layer that normalizes, inspects, and sanitizes LLM responses before they leave the platform.

Sprint 1 delivers:
- Repository skeleton aligned with the PRD/TPRD
- Normalizer v1 (Unicode NFKC, zero-width stripping, bounded HTML unescape)
- Stubs for parser, detectors, policy, actions, ML, and transports
- Docker Compose stack (FastAPI + Nginx with self-signed TLS for dev)
- Initial unit tests for the normalizer

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
make test       # pytest (normalizer coverage in Sprint 1)
make lint       # ruff + black --check
make format     # black
```

Regression, bench, and detectors will be fleshed out in subsequent sprints.

## 4. Project Layout

```text
app/                 Python package (FastAPI app, pipeline, stubs)
config/              Default policy + localized safe messages
nginx/               Dev reverse proxy + self-signed TLS
tests/               Unit tests (normalizer v1 in Sprint 1)
docker-compose.yml   Dev stack (FastAPI + Nginx)
Makefile             Convenience commands wrapping the conda env
```

## 5. Next Steps

- Implement detectors (PII, secrets, URL, command) per Sprint 2
- Flesh out policy enforcement and action mutations
- Expand regression corpus and ML components (later sprints)
