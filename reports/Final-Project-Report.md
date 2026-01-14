## LLM Egress Guard — Detailed Project Report (Essay Format)

**Project:** LLM Egress Guard (Deterministic DLP layer for LLM outputs)  
**Author:** Baran Akin (per sprint reports)  
**Date:** 2026-01-13  
**Repository:** `llm-egress-guard` (GitHub: `https://github.com/brnakin/llm-egress-guard`)  
**License:** MIT (see `LICENSE`)  

This report is written as a long-form essay with structured headings (mirroring the provided example) and is based on a review of the **entire repository**, including:
- Source code under `app/` and `transports/`
- All documentation and Markdown files (`README.md`, `docs/*`, `reports/*`, `prompts/*`, `NORMALIZATION_SECURITY.md`, `llm_egress_guard_repo_skeleton_prd_technical_prd.md`)
- Configuration and infrastructure (`docker-compose.yml`, `nginx/`, `prometheus/`, `grafana/`, `config/`)
- Test suites (unit tests and regression corpus + golden outputs)
- Scripts used for demos, training, validation, and reporting
- Packaged metadata (`pyproject.toml`, `setup.cfg`, `llm_egress_guard.egg-info/`)

### Table of Contents

- [Table of Contents](#table-of-contents)
- [1. Introduction & Problem Motivation](#1-introduction--problem-motivation)
  - [1.1 Why Egress Guarding Is a Distinct Security Layer](#11-why-egress-guarding-is-a-distinct-security-layer)
  - [1.2 What This Repository Builds (and What It Intentionally Does Not)](#12-what-this-repository-builds-and-what-it-intentionally-does-not)
  - [1.3 How to Read This Report](#13-how-to-read-this-report)
- [2. Problem Statement](#2-problem-statement)
  - [2.1 Threat Model and Trust Boundaries](#21-threat-model-and-trust-boundaries)
  - [2.2 Functional Requirements and Non-Requirements](#22-functional-requirements-and-non-requirements)
  - [2.3 Success Criteria and Evaluation Philosophy](#23-success-criteria-and-evaluation-philosophy)
- [3. Background & Literature Review](#3-background--literature-review)
  - [3.1 Deterministic DLP vs. LLM-Based Moderation](#31-deterministic-dlp-vs-llm-based-moderation)
  - [3.2 Normalization, Encoding Attacks, and Defensive Parsing](#32-normalization-encoding-attacks-and-defensive-parsing)
  - [3.3 OWASP Top 10 and Security Controls Used Here](#33-owasp-top-10-and-security-controls-used-here)
  - [3.4 Observability as a Security Primitive](#34-observability-as-a-security-primitive)
- [4. Data](#4-data)
  - [4.1 Regression Corpus as “Ground Truth” for Guard Behavior](#41-regression-corpus-as-ground-truth-for-guard-behavior)
  - [4.2 Synthetic Secret Placeholders (Keeping Git Clean While Testing Realistically)](#42-synthetic-secret-placeholders-keeping-git-clean-while-testing-realistically)
  - [4.3 ML Training Data: Prompts, Outputs, Validation, and Splits](#43-ml-training-data-prompts-outputs-validation-and-splits)
- [5. Model and Analysis](#5-model-and-analysis)
  - [5.1 High-Level Architecture and Deployment Modes](#51-high-level-architecture-and-deployment-modes)
  - [5.2 API Contract and Schemas](#52-api-contract-and-schemas)
  - [5.3 Pipeline Walkthrough: Normalize → Parse → Detect → Decide → Act](#53-pipeline-walkthrough-normalize--parse--detect--decide--act)
  - [5.4 Normalization Layer Deep Dive (`app/normalize.py`)](#54-normalization-layer-deep-dive-appnormalizepy)
  - [5.5 Parsing and Context (“Explain-Only”) (`app/parser.py`)](#55-parsing-and-context-explain-only-appparserpy)
  - [5.6 Detector Suite (PII, Secrets, URLs, Commands, Exfil)](#56-detector-suite-pii-secrets-urls-commands-exfil)
  - [5.7 Policy Engine and Risk Scoring (`app/policy.py` + `config/policy.yaml`)](#57-policy-engine-and-risk-scoring-apppolicypy--configpolicyyaml)
  - [5.8 Action Engine and Safe Messages (`app/actions.py` + `config/locales/...`)](#58-action-engine-and-safe-messages-appactionspy--configlocalesen)
  - [5.9 ML Components (Pre-Classifier + spaCy Validator)](#59-ml-components-pre-classifier--spacy-validator)
  - [5.10 Security Hardening in the FastAPI Layer (`app/main.py`) and Edge Proxy (`nginx/nginx.conf`)](#510-security-hardening-in-the-fastapi-layer-appmainpy-and-edge-proxy-nginxnginxconf)
  - [5.11 Observability Stack (Prometheus + Grafana + Weekly Export)](#511-observability-stack-prometheus--grafana--weekly-export)
  - [5.12 SIEM Integration Module (`app/siem/*`)](#512-siem-integration-module-appsiem)
  - [5.13 Testing Strategy: Unit, Regression, Matrix Reports](#513-testing-strategy-unit-regression-matrix-reports)
  - [5.14 Packaging and Dependency Management](#514-packaging-and-dependency-management)
- [6. Results and Recommendations](#6-results-and-recommendations)
  - [6.1 Sprint-by-Sprint Outcomes (Sprint 1 → Sprint 5)](#61-sprint-by-sprint-outcomes-sprint-1--sprint-5)
  - [6.2 Quality Results (Unit Tests, Regression Suite, Matrix Artifacts)](#62-quality-results-unit-tests-regression-suite-matrix-artifacts)
  - [6.3 Performance Results and Operational Metrics](#63-performance-results-and-operational-metrics)
  - [6.4 Security Posture and OWASP Remediation](#64-security-posture-and-owasp-remediation)
  - [6.5 Limitations and Known Gaps](#65-limitations-and-known-gaps)
  - [6.6 Recommendations and Future Work](#66-recommendations-and-future-work)
  - [6.7 Repository Coverage Checklist (All Artifacts Mentioned)](#67-repository-coverage-checklist-all-artifacts-mentioned)
- [7. Conclusions](#7-conclusions)
- [8. Acknowledgements](#8-acknowledgements)
- [9. References](#9-references)

## 1. Introduction & Problem Motivation

Modern LLM applications are increasingly deployed in environments where the “output” of the model is not merely a text string but a security-relevant artifact. It might be forwarded to a customer, pasted into an email, stored in logs, or used downstream by an automated tool. In that setting, the output becomes a **data egress channel**, and any flaws in the upstream prompt, retrieval system, or model alignment can become **data loss** or **harmful instruction** events.

The core idea behind the **LLM Egress Guard** project (see `README.md` and `llm_egress_guard_repo_skeleton_prd_technical_prd.md`) is to treat the boundary between “LLM output” and “leaving the platform” as a **security control point**. Instead of relying solely on training-time alignment or on ad‑hoc prompt rules, the system implements a deterministic “last-mile” filter that:
- **Normalizes** suspicious encodings and obfuscations,
- **Detects** sensitive or dangerous patterns using a rule-driven detector suite,
- **Decides** using a configurable risk-weighted policy,
- **Acts** by masking, delinking, or blocking content,
- **Observes** outcomes via metrics and structured logs.

This is intentionally different from a generic moderation service. The Egress Guard is designed as a *deterministic DLP layer* targeted at concrete leak and exploitation patterns (PII, secrets, exfil blobs, malicious command chains, risky URLs).

### 1.1 Why Egress Guarding Is a Distinct Security Layer

The “egress guard” framing is valuable because it acknowledges a practical reality: in many systems, there will always be uncertainty upstream. Retrieval might fetch a confidential document. A user might insert prompt injection instructions. An agent might inadvertently copy credentials from a debug log. A model might comply with malicious prompts or hallucinate realistic credentials. In other words:

- **Input controls** (prompt templates, content filters, retrieval restrictions) are necessary but not sufficient.
- **Model behavior** is probabilistic and not fully controllable.
- **Output controls** can be deterministic, measurable, and policy-driven.

The LLM Egress Guard is designed as the output control layer. It is essentially a “DLP proxy for model responses,” with additional knowledge about LLM-specific risks such as “curl|bash” chains or embedded data URIs.

The PRD/TPRD (`llm_egress_guard_repo_skeleton_prd_technical_prd.md`) further emphasizes this philosophy by requiring:
- A single-shot synchronous `/guard` API (MVP),
- Deterministic detections and actions,
- A regression corpus with golden outputs to prevent drift,
- Observability via Prometheus and dashboards,
- Security hardening aligned with OWASP guidance.

### 1.2 What This Repository Builds (and What It Intentionally Does Not)

The repository implements a working service, not just a concept. As of Sprint 5 (see `reports/Sprint-5-Report.md`), the repo includes:

- **A FastAPI service** (entrypoint `app/main.py`, transport `transports/http_fastapi_sync.py`)
- **A hardened normalization pipeline** (`app/normalize.py`, documented in `NORMALIZATION_SECURITY.md`)
- **Context-aware parsing** to reduce false positives (`app/parser.py`)
- **Detectors** for PII, secrets, URL risks, command chains, and encoded exfil blobs (`app/detectors/*`)
- **A policy engine** with risk weights, allowlists, and context adjustments (`app/policy.py`, config in `config/policy.yaml`)
- **An action layer** that masks/delinks/blocks and returns localized safe messages (`app/actions.py`, `config/locales/en/safe_messages.yaml`)
- **Observability**: Prometheus metrics and an auto-provisioned Grafana dashboard (`app/metrics.py`, `prometheus/`, `grafana/`, `docs/observability-setup.md`)
- **Optional ML**: a lightweight pre-classifier with integrity checks and shadow instrumentation (`app/ml/preclassifier.py`, `models/preclf_v1.*`, `reports/Sprint-4-Report.md`)
- **SIEM connector module** for Splunk/Elasticsearch/webhooks (`app/siem/*`), designed to be integrated for event export
- **Tests**: unit tests (`tests/unit/*`) and a regression corpus + runner (`tests/regression/*`)
- **Demo and operations scripts** (`scripts/*`), including scenario demos and weekly report export
- **Deployment**: Dockerfile, docker-compose, and Nginx TLS proxy (`app/Dockerfile`, `docker-compose.yml`, `nginx/`)

Equally important are what the repo **does not** do yet (explicitly stated in the PRD/TPRD and sprint notes):
- **Streaming** support is not part of the MVP; it is planned as future work (see PRD/TPRD and `docs/future_sprint_notes.md`).
- **CI wiring and enforcement** evolves with the repo: the current implementation uses a GitHub Actions workflow under `.github/workflows/ci.yml` (see `docs/ci-wiring-guide.md`), while legacy references to `ci/github-actions.yml` may exist in older documents.
- **In-pipeline SIEM emission** is not wired into the main pipeline flow yet; connectors exist as modules for future integration.

### 1.3 How to Read This Report

The rest of this document is organized to match a typical course or project report:
- Section 2 formalizes the problem.
- Section 3 situates the work in relevant security practices (normalization, OWASP controls, DLP principles).
- Section 4 describes the data used for evaluation (regression corpus and ML training data).
- Section 5 is a “technical essay” explaining how the system works, mapping to concrete repo files.
- Section 6 summarizes results and presents recommendations, including a checklist ensuring that all major repo artifacts are referenced.

## 2. Problem Statement

The LLM Egress Guard project addresses a specific security problem: **LLM-generated responses can leak sensitive information or provide operationally dangerous instructions**, and those outputs often traverse organizational boundaries (internal-to-external) with minimal scrutiny.

### 2.1 Threat Model and Trust Boundaries

The trust boundary is best expressed as:

```text
Upstream LLM + retrieval + user inputs  →  LLM response  →  (Egress Guard)  →  external recipient / downstream tool
```

The Egress Guard assumes upstream components may be compromised or fallible:
- **Prompt injection and data exfiltration**: user instructions or retrieved content can coerce an LLM into producing secrets/PII.
- **Operational misuse**: LLMs can emit command chains that are dangerous if copied/pasted (e.g., “curl | bash”, PowerShell encoded).
- **Credential leakage**: API keys, JWTs, service account files, and PEM blocks can appear in outputs from logs or hallucinations.
- **Malicious links**: data URIs, credential-in-URL patterns, shorteners, and suspicious TLDs increase click‑risk.
- **Encoding obfuscation**: attackers can hide payloads using URL encoding, HTML entities, zero-width characters, or multi-layer encoding.
- **Denial of service**: because the guard executes multiple scans, it can be a DoS target (large payloads, regex stress).

The guard must therefore operate under the security principle of **fail-safe defaults**: if it cannot confidently process a response, it should be able to block or return a safe message rather than risk leaking harmful content.

### 2.2 Functional Requirements and Non-Requirements

Based on the PRD/TPRD (`llm_egress_guard_repo_skeleton_prd_technical_prd.md`) and the implemented code (`app/*`), the key functional requirements are:

- **Deterministic scanning** across:
  - PII: email/phone/IBAN/TCKN/PAN/IPv4 (implemented in `app/detectors/pii.py`)
  - Secrets: JWT, cloud/API keys, PEM blocks, high entropy tokens (implemented in `app/detectors/secrets.py`)
  - URLs: data URIs, executable extensions, IP literals, credentials-in-URL, shorteners, suspicious TLDs (implemented in `app/detectors/url.py`)
  - Commands: shell/powershell chains and suspicious utilities (implemented in `app/detectors/cmd.py`)
  - Exfil: large base64/hex blobs (implemented in `app/detectors/exfil.py`)
- **Policy-driven decisions** using a YAML policy definition with:
  - `risk_weight` and `severity` per rule (`config/policy.yaml`)
  - allowlists and tenant allowlists (`config/policy.yaml`, parsed by `app/policy.py`)
  - context adjustments for findings in code blocks or links (`app/policy.py` + parser)
- **Actions**:
  - mask (replace sensitive spans), delink (replace URLs), block (replace full response with safe message), annotate/remove (supported in `app/actions.py`)
- **Observability**:
  - Prometheus metrics exposed by `/metrics` (`app/metrics.py`, endpoint in `app/main.py`)
  - Grafana dashboard and Prometheus config for a full stack (`grafana/`, `prometheus/`, `docker-compose.yml`)
- **Testability**:
  - unit tests (`tests/unit/*`)
  - regression suite with golden outputs (`tests/regression/*`)

Non-requirements (explicit or implied):
- **Streaming** output guarding: deferred (see PRD/TPRD and `docs/future_sprint_notes.md`).
- **LLM-as-a-judge** moderation: not used; the system remains deterministic.
- **Deep semantic reasoning about intent**: only a lightweight pre-classifier exists, primarily for context classification, not full semantic security judgement.

### 2.3 Success Criteria and Evaluation Philosophy

The repository defines success in pragmatic, measurable terms:
- The guard should block or neutralize sensitive/dangerous content deterministically.
- Behavior should remain stable as code evolves; this is enforced by regression tests with golden outputs (`tests/regression/golden_v1.jsonl` + `tests/regression/runner.py`).
- Latency should remain low enough for production usage; Sprint reports provide microbench and measured results (see `README.md` and `reports/Sprint-5-Report.md`).
- Security posture should follow common guidance (OWASP Top 10 2021 audit and remediation tracked in `reports/security_assessment_owasp.md`).
- Observability should allow analysis of block rates, rule hit rates, and performance drift (Prometheus + Grafana).

This “engineering-first” evaluation philosophy is essential for guardrails: in practice, stakeholders care about predictable behavior and explainability. A deterministic guard is easier to review, tune, and audit than a probabilistic moderation model.

## 3. Background & Literature Review

This project draws from multiple strands of security practice: classic DLP, secure parsing/normalization, OWASP-style defensive controls, and modern observability patterns.

### 3.1 Deterministic DLP vs. LLM-Based Moderation

Traditional DLP systems typically operate by scanning data egress channels (email, web uploads, logs) for patterns such as PII formats, high-entropy secrets, or document fingerprints. Those systems prioritize:
- **Determinism**: the same input yields the same decision,
- **Auditability**: detections can be explained by rule IDs,
- **Policy control**: organizations tune rules for their risk posture.

By contrast, LLM-based moderation is probabilistic and can be inconsistent, especially for edge cases. The LLM Egress Guard deliberately chooses determinism as a design constraint. Detectors are regex/heuristic driven (`app/detectors/*`), and policy decisions are rule-based (`app/policy.py`).

The repo does include a minimal ML component (Sprint 4) but only as a **lightweight pre-classifier** for context classification. Even that ML component is behind feature flags and is instrumented in “shadow mode” (`SHADOW_MODE`) to compare ML vs heuristic without automatically changing decisions.

### 3.2 Normalization, Encoding Attacks, and Defensive Parsing

A recurring theme in security engineering is that detectors and filters fail if inputs can be disguised through encoding and obfuscation. The project’s normalization layer (see `NORMALIZATION_SECURITY.md` and `app/normalize.py`) follows a fixed order:

- URL decoding (bounded passes)
- HTML entity decoding (bounded entity count + bounded output length)
- Unicode normalization (NFKC)
- stripping of zero-width characters
- stripping of control characters

This aligns with common defensive guidance:
- Decode outer encodings before inner encodings (URL before HTML) to avoid bypasses.
- Enforce bounds to avoid expansion bombs and DoS.
- Normalize Unicode to reduce homoglyph and formatting trickery.

The parser layer (`app/parser.py`) addresses a different but related issue: false positives. In real LLM outputs, security tutorials often contain commands inside fenced code blocks. A naive detector will block those commands even when the user intent is educational. The project introduces **segmentation** and **explain-only detection** to mark code segments that appear in a teaching context, which then feeds policy risk adjustments.

This “normalize, then segment” approach mirrors modern secure input handling:
- Normalize to make inputs canonical.
- Segment to interpret context (text vs code vs link).
- Apply policy decisions with context-aware adjustments.

### 3.3 OWASP Top 10 and Security Controls Used Here

The repository explicitly uses an OWASP-oriented assessment document (`reports/security_assessment_owasp.md`) and tracks remediation status into code. Key controls include:
- **Authentication**: optional API key gate (`REQUIRE_API_KEY`, `API_KEY`) implemented in `app/main.py`.
- **Resource limits**: request size limit (`MAX_REQUEST_SIZE_BYTES`), request timeout (`REQUEST_TIMEOUT_SECONDS`), and concurrency guard (`MAX_CONCURRENT_GUARD_REQUESTS`) in `app/main.py`.
- **Model integrity**: SHA256 verification against `models/preclf_v1.manifest.json` before loading `models/preclf_v1.joblib` (`app/ml/preclassifier.py`).
- **Policy downgrade controls**: explain-only bypass requires explicit opt-in via `ALLOW_EXPLAIN_ONLY_BYPASS` (`app/policy.py` and `app/settings.py`).
- **Deployment hygiene**: Nginx TLS and rate limiting (`nginx/nginx.conf`), metrics access restrictions at the proxy layer.

This is an important aspect of the project: an egress guard is itself a security-critical service. If it can be bypassed, abused, or DoS’ed, the whole architecture collapses. The project therefore treats the guard as a hardened perimeter component, not a toy microservice.

### 3.4 Observability as a Security Primitive

Observability is not only about performance; it is also about detection and governance:
- If block rates spike, it might indicate an attack, a prompt injection trend, or a policy misconfiguration.
- If a particular rule triggers frequently, it might indicate an active leak source.
- If detector latencies increase, it might indicate pathological inputs (a DoS attempt) or an implementation regression.

The project’s observability stack (Sprint 5) is built with:
- Prometheus scrape config (`prometheus/prometheus.yml`)
- Grafana provisioning (`grafana/provisioning/*`)
- A prebuilt dashboard JSON (`grafana/dashboards/egress-guard.json`)
- A documentation guide (`docs/observability-setup.md`)
- A weekly report exporter (`scripts/export_weekly_report.py`) that queries Prometheus and produces a Markdown report.

This observability focus is consistent with OWASP A09 (“Security Logging and Monitoring Failures”) in that it explicitly designs for visibility and operational response.

## 4. Data

Unlike many ML-heavy projects, the LLM Egress Guard’s “data” is primarily the set of examples and corpora used to test deterministic detectors and policies, plus the synthetic dataset used to train the optional pre-classifier.

### 4.1 Regression Corpus as “Ground Truth” for Guard Behavior

The main evaluation dataset is the regression corpus under `tests/regression/corpus_v1/`. The corpus is categorized into:
- `clean/` — safe outputs that should not be blocked
- `pii/` — examples containing emails, phones, IBANs, TCKN, PAN, IPs
- `secrets/` — examples containing synthetic secrets (JWTs, keys, PEM blocks)
- `url/` — risky URLs (data URIs, shorteners, suspicious TLDs, credential-in-URL)
- `cmd/` — dangerous commands (curl|bash, PowerShell encoded, certutil, etc.)
- `exfil/` — encoded blob content for exfil detection

The corpus guide (`tests/regression/README.md`) provides both counts and examples. In the current snapshot, `golden_manifest.json` indicates **100 samples** and a version tag of `v1.4` (generated 2026-01-12). The regression suite compares the output of the current pipeline against a golden expectation file (`tests/regression/golden_v1.jsonl`), where each record stores:
- the sample path,
- whether it should be blocked,
- which rule IDs should fire.

This “golden file” approach is a strong fit for deterministic guardrails:
- It turns guard behavior into a contract.
- It makes changes explicit (if a rule changes, the golden file must be updated intentionally).
- It supports CI gating and prevents accidental regressions.

The runner (`tests/regression/runner.py`) supports both validation and golden updates (`--update-golden`), and it also supports generating a detector matrix report (`--matrix-report`).

### 4.2 Synthetic Secret Placeholders (Keeping Git Clean While Testing Realistically)

Storing real-looking secrets in Git is dangerous, and Git hosting providers may block commits due to secret scanning and push protection. The project solves this by using **placeholder markers** inside regression samples, such as:
- `{{OPENAI_PROJECT_KEY}}`
- `{{AWS_ACCESS_KEY}}`
- `{{JWT_SAMPLE_TOKEN}}`

These placeholders are expanded at runtime by `tests/regression/placeholders.py`. The placeholder generator creates deterministic synthetic tokens that still match detector regexes, ensuring detectors are exercised realistically without placing actual secret strings in the repository.

This mechanism is referenced across the repo:
- `README.md` highlights placeholder usage as a key design point.
- `tests/regression/README.md` documents the workflow for adding new placeholders.
- `tests/regression/runner.py` automatically calls `apply_placeholders()`.
- `tests/regression/detector_matrix.py` also applies placeholders for demo scenarios.
- `tests/unit/test_ci_demo.py` uses `get_placeholder()` to prove the pipeline blocks a synthetic secret in CI.

From a security engineering perspective, this placeholder system is a best practice:
- It reduces repository risk.
- It keeps regression tests stable and deterministic.
- It decouples “detector realism” from “secret hygiene”.

### 4.3 ML Training Data: Prompts, Outputs, Validation, and Splits

The optional ML component in this repo is the **pre-classifier** trained on synthetic data. The training pipeline is documented and implemented via:

- **Prompt sources**: `prompts/ml_training/*`
  - `prompts/ml_training/README.md` describes strategy and format.
  - `01_educational_security.md`, `02_malicious_commands.md`, `03_educational_advanced.md`, `04_command_sophisticated.md`, `05_clean_text.md`, `06_edge_cases.md`, `07_multilingual.md` define how to generate JSONL samples.
- **Generated outputs**: `data/ml_training/output_*.jsonl` and `data/ml_training/output_*.json` (as present in the repo)
- **Combined/split files**: `data/ml_training/preclf_train.jsonl` and `data/ml_training/preclf_eval.jsonl`
- **Validation & splitting tool**: `scripts/validate_training_data.py`
- **Training tool**: `scripts/train_preclassifier.py`
- **Model artifacts**: `models/preclf_v1.joblib` + manifest `models/preclf_v1.manifest.json`
- **Evaluation notes**: `reports/notes_preclf_v1.md` and sprint reports.

The dataset is designed for a three-class classification problem:
- `educational` — commands in tutorial/warning context (should generally not lead to blocking if policy allows an educational bypass)
- `command` — direct, executable malicious instructions (should be blocked)
- `text` — safe text (should be allowed)

The prompt set intentionally varies:
- writing styles (advisory vs blog vs lecture),
- command families (curl/wget/powershell/reverse shells/rm -rf),
- languages (German, Turkish, Spanish, French, Chinese; see `07_multilingual.md`),
- ambiguous edge cases (questions, past tense, weak warning context; see `06_edge_cases.md`).

The repository includes a concrete model manifest with metrics (accuracy ~0.8857, macro F1 ~0.8604) in `models/preclf_v1.manifest.json`, and additional training notes in `reports/notes_preclf_v1.md`.

## 5. Model and Analysis

This section is the technical core of the report. It explains how the guard is built and how the repository’s modules fit together.

### 5.1 High-Level Architecture and Deployment Modes

There are two primary ways to run the service:
- **Local dev**: `uvicorn transports.http_fastapi_sync:app --host 0.0.0.0 --port 8080 --reload` (documented in `README.md`)
- **Full stack**: `docker compose up -d --build` (stack defined in `docker-compose.yml`)

The production-like architecture follows the PRD/TPRD:

```text
Client → Nginx (TLS termination + rate limiting) → FastAPI (/guard)
   normalize → parse → detect → policy decide → action → response
                    ↘ metrics/logs ↙
Prometheus (scrape /metrics) → Grafana (dashboards)
```

Concrete infrastructure mapping:
- **App container**: built from `app/Dockerfile`, serving FastAPI via uvicorn.
- **Nginx**: `nginx/nginx.conf` provides TLS on 443 using dev certificates in `nginx/certs/fullchain.pem` and `nginx/certs/privkey.pem`, rate limits `/guard`, restricts `/metrics` to specific IPs.
- **Prometheus**: `prometheus/prometheus.yml` scrapes `app:8080/metrics` at a 15s interval.
- **Grafana**: `grafana/provisioning/*` auto-provisions the Prometheus datasource and loads `grafana/dashboards/egress-guard.json`.

The deployment choices reflect two key goals:
- **Deterministic guard behavior** with minimal operational complexity,
- **Observability-first operations**, enabling performance and security monitoring.

The following diagrams (stored under `docs/`) match the implemented architecture and can be included as figures in exported Word/PDF versions of this report:

- `docs/system-design.png` — high-level system design
- `docs/request-lifecycle.png` — request lifecycle and pipeline stages
- `docs/deployment-runtime.png` — docker-compose/Nginx runtime layout

### 5.2 API Contract and Schemas

The service exposes three primary endpoints (implemented in `app/main.py`):
- `GET /healthz` — liveness probe (returns `ok`)
- `POST /guard` — scans an LLM response and returns sanitized output + findings
- `GET /metrics` — Prometheus metrics (feature-gated by `METRICS_ENABLED` and also can be protected by API key)

The repo includes JSON schema definitions:
- `app/schemas/api_request.json`
- `app/schemas/api_response.json`

The request schema requires:
- `response` (string)
- optional `policy_id` (default `default`)
- optional `metadata` (free-form object)

The response includes:
- sanitized `response`
- list of `findings`
- `blocked` boolean
- `risk_score` (0–100)
- `policy_id`, `latency_ms`, `version`

This schema design is important: it surfaces both the **transformed response** and the **evidence** (rule IDs, actions, details) needed for audit and tuning.

### 5.3 Pipeline Walkthrough: Normalize → Parse → Detect → Decide → Act

The pipeline is orchestrated in `app/pipeline.py` and is invoked from the FastAPI `/guard` endpoint. Conceptually:

1. Normalize input text (`app/normalize.py`)
2. Parse into segments (`app/parser.py`) if context parsing enabled
3. Load and select policy (`app/policy.py`, YAML `config/policy.yaml`)
4. Scan via detector suite (`app/detectors/__init__.py` runs detectors in sequence)
5. Optionally validate PII with spaCy validator (`app/ml/validator_spacy.py`)
6. Annotate findings with context (text/code/link + explain_only)
7. Evaluate policy and compute risk score (`app/policy.py`)
8. Apply actions (mask/delink or block via safe message) (`app/actions.py`)
9. Emit metrics (`app/metrics.py`) and structured logs (`structlog` configured in `app/main.py`)

Notable engineering decisions visible in the implementation:
- **Short-circuit on block**: detectors run sequentially, and the pipeline breaks early if a detector returns a “block” action finding. This reduces latency for high-risk outputs (see loop in `app/pipeline.py`).
- **Caching by modification time**: policy loading uses an mtime-based cache (`app/policy.py`), and safe messages also use mtime-based caching (`app/actions.py`). This supports “hot reload” style development and avoids repeated expensive parsing.
- **Best-effort ML**: ML preclassifier loading failures are caught, and the pipeline falls back to heuristics; metrics record load status.
- **Instrument everything**: the pipeline observes both overall latency and per-detector latency and rule hits via Prometheus histograms/counters.

### 5.4 Normalization Layer Deep Dive (`app/normalize.py`)

Normalization is security-critical because it prevents bypasses through obfuscation. The implementation matches the dedicated security doc (`NORMALIZATION_SECURITY.md`).

Key features:
- **Fixed normalization order**:
  - URL decode (max 2 passes)
  - HTML entity unescape (bounded)
  - Unicode NFKC
  - expand common obfuscations like “(at)” / “(dot)” into `@` / `.`
  - strip zero-width characters and BOM
  - strip control characters (except `\n`, `\r`, `\t`)
- **Entity DoS protections**:
  - counts HTML entities with a regex before decoding
  - skips HTML unescape if entity count exceeds threshold (`max_unescape`, default 1000)
  - caps output length after unescape (`max_unescape * 2`)
- **Time budget**:
  - overall time budget (0.1s) prevents pathological inputs from consuming too much CPU
- **Anomaly tracking**:
  - records anomalies such as entity overflow, double encoding, max URL decode passes reached, and time budget issues

In DLP systems, normalization is often underestimated. In this project it is treated as a first-class module with extensive tests (`tests/unit/test_normalize.py`) and its own security documentation (`NORMALIZATION_SECURITY.md`).

### 5.5 Parsing and Context (“Explain-Only”) (`app/parser.py`)

The parser introduces context awareness to reduce false positives (Sprint 3). It segments Markdown-ish content into:
- **text** segments
- **code** segments (fenced blocks and inline code)
- **link** segments (Markdown links and raw URLs)

Explain-only detection is heuristic-driven and uses a context window around code segments to check for educational keywords (e.g., “warning”, “example”, “do not run”). It can also use the ML pre-classifier if provided.

Key aspects:
- **Offset preservation**: segments store `start` and `end` indices in the original text, ensuring detectors’ span offsets remain meaningful.
- **Explain-only only applies to code**: commands in prose are treated as suspicious; code blocks are where tutorials typically place “dangerous example” commands.
- **Shadow mode instrumentation**: if `SHADOW_MODE=true`, parser will record ML vs heuristic differences using `egress_guard_ml_preclf_shadow_total`.

Extensive parser tests are implemented in `tests/unit/test_parser.py`, covering segmentation logic, offset correctness, link parsing, edge cases, and explain-only behavior.

### 5.6 Detector Suite (PII, Secrets, URLs, Commands, Exfil)

Detectors are orchestrated by `app/detectors/__init__.py` via the `scan_all()` generator. The order is:
- PII (`pii`)
- Exfil (`exfil`)
- Secret (`secret`)
- URL (`url`)
- Command (`cmd`)

This order is a pragmatic engineering tradeoff:
- PII and exfil can be detected quickly and are relevant to data leakage.
- Secrets often require immediate blocking.
- URLs and commands are scanned after, with early short-circuit if a “block” action is found.

All detectors share common helpers in `app/detectors/common.py`:
- `hash_snippet()` creates a SHA256 digest prefix `sha256:...` for audit without storing the raw match.
- `build_findings()` produces `Finding` objects with consistent detail fields, including span, kind, snippet_hash, and rule_id.
- `is_allowlisted()` consults allowlist entries from policy definition.

Below is a conceptual overview of each detector family.

#### 5.6.1 PII detector (`app/detectors/pii.py`)

PII detections include:
- **Email**: `EMAIL_REGEX` and `_mask_email()` to mask the local part while keeping the domain.
- **Phones**: multiple locale patterns (TR/EN/DE/FR/ES/IT/PT/HI/ZH/RU), plus a generic fallback. The detector normalizes digits and enforces length range.
- **IBAN (TR/DE)**: regex patterns for TR and DE formats; the implementation masks the majority of digits. (Note: the repo also contains a mod-97 validator helper `iban_mod97()` in `app/detectors/common.py`, but the PII detector currently uses length and prefix checks rather than mod‑97.)
- **TCKN**: 11-digit Turkish national ID with checksum validation (`_is_valid_tckn()`).
- **PAN**: payment card numbers with Luhn check (`_passes_luhn()`); policy blocks PAN by default (`PII-PAN` in `config/policy.yaml`).
- **IPv4**: detects IPv4 addresses and masks with `[ip-redacted]` in output while preserving preview in findings.

The PII detector is tuned for a DLP use case: generally mask low/medium PII, but block critical PII (PAN) depending on policy.

#### 5.6.2 Secret detector (`app/detectors/secrets.py`)

Secrets cover:
- **JWT** (regex plus base64 structure check)
- **AWS Access Key** (AKIA…)
- **AWS Secret Key** (40 chars with mixed classes + entropy threshold)
- **OpenAI-style key patterns**, GitHub tokens, Slack tokens, Stripe keys, Twilio keys
- **Azure SAS query patterns**
- **GCP service account JSON blocks**
- **PEM private key blocks**
- **High entropy tokens**: generic base64-like token regex plus Shannon entropy and character-class checks

The detector deliberately uses placeholders like `[secret]` in previews and replacements, reducing the risk of leaking partial secrets in logs or responses.

The “high entropy” rule (`SECRET-HIGH-ENTROPY`) is important as a catch-all: it catches secrets that do not match a specific vendor regex but are still likely credentials.

#### 5.6.3 URL detector (`app/detectors/url.py`)

URL risk detection includes:
- URLs with **IP literals** (potential internal infrastructure or direct-to-IP malware links)
- **Data URIs** (often used to embed payloads)
- URLs ending in **executable/archive extensions** (exe, msi, ps1, js, zip, tar.gz, etc.)
- URLs with **credentials embedded** (`user:pass@host`)
- **Shortener domains** (bit.ly, t.co, etc.)
- **Suspicious TLDs** (zip, xyz, click, etc.) — not always malicious, but higher risk

Actions vary by policy:
- Some URL risks are blocked (e.g., credentials-in-URL, data URIs).
- Others are “delinked” (replaced with `[redacted-url]`), reducing clickability.

#### 5.6.4 Command detector (`app/detectors/cmd.py`)

Commands cover typical malware delivery and destructive patterns:
- `curl ... | bash` and `wget ... | bash`
- PowerShell encoded commands (`powershell -enc ...`)
- Invoke-WebRequest piped to IEX
- `rm -rf /...`
- Windows persistence/infection helpers (`reg add`, `certutil`, `mshta`, `rundll32`)

In the default policy (`config/policy.yaml`), command rules are generally `block` with high risk weights, reflecting that an LLM emitting such commands is often an unacceptable risk in a production environment.

#### 5.6.5 Exfil detector (`app/detectors/exfil.py`)

Exfiltration detection targets large encoded blobs:
- **Base64 blobs**: detects repeated base64 blocks, compacts whitespace, then checks minimum length and entropy threshold.
- **Hex blobs**: detects repeated hex blocks and checks length.

This detector focuses on data egress patterns: large base64 or hex dumps are commonly used to move secrets or files in a copy/paste channel.

### 5.7 Policy Engine and Risk Scoring (`app/policy.py` + `config/policy.yaml`)

Policy is defined in YAML (`config/policy.yaml`) and loaded by `app/policy.py` with an mtime cache. The policy defines:
- **Context settings** (Sprint 3): `code_block_penalty`, `explain_only_penalty`, `link_context_bonus`.
- **Allowlists**:
  - `allowlist` for exact values,
  - `allowlist_regex` for regex matches,
  - `tenant_allowlist` for per-tenant exceptions.
- **Rules**: each has an `id`, `type`, `kind`, `action`, `severity`, `risk_weight`, and optional `safe_message`.

Policy evaluation (`app/policy.py::evaluate`) computes:
- a cumulative `risk_score` (capped at 100),
- `blocked` boolean if any block action rules apply (subject to explain-only bypass control),
- `safe_message_key` to control which user-facing message is returned on block.

Context adjustment is applied per finding via `_apply_context_adjustment()`:
- If a finding is in a code block, risk may be reduced.
- If it is explain-only (educational) and is a command finding, risk may be further reduced.
- If it is a URL finding in a link segment, risk may be increased.

However, Sprint 5 hardening also introduces a crucial safeguard: **explain-only bypass of blocking is opt-in** (`ALLOW_EXPLAIN_ONLY_BYPASS`). If that setting is false (default), explain-only context does not override a rule’s `block` action. This change addresses the OWASP assessment’s concern that educational framing could be used as a bypass.

### 5.8 Action Engine and Safe Messages (`app/actions.py` + `config/locales/en/`)

Actions are applied after policy decision:
- If `blocked=True`, the entire response is replaced with a safe message (loaded from `config/locales/en/safe_messages.yaml`).
- If not blocked, findings are converted into span replacements and applied in order:
  - `mask` uses `detail.replacement` or `detail.masked`,
  - `delink` replaces URLs with `[redacted-url]`,
  - `remove` deletes spans,
  - `annotate` inserts a `[flagged:...]` marker (supported, though not heavily used in policy).

Safe messages are localized through a YAML file and cached by mtime. The default messages include:
- `blocked` — “Response blocked …”
- `masked` — “Content masked …”
- `delinked` — “Dangerous link removed …”
- `exfil_blocked` — “Transfer blocked …”

This separation between decision and message is significant: it allows organizations to tailor the user experience and compliance language without changing detector code.

### 5.9 ML Components (Pre-Classifier + spaCy Validator)

The project includes two ML-related modules:

- **Pre-classifier** (`app/ml/preclassifier.py`):
  - A heuristic fallback classifier (`PreClassifier`) checks for command-ish keywords.
  - A model classifier (`ModelPreClassifier`) loads `models/preclf_v1.joblib` (joblib/pickle) and predicts one of `educational`, `command`, or `text`.
  - Integrity check: `_verify_model_integrity()` compares SHA256 and size against `models/preclf_v1.manifest.json` and enforces a trusted directory (`models/`).
  - The pipeline loads the preclassifier when `FEATURE_ML_PRECLF=true` and records load metrics (`egress_guard_ml_preclf_load_total{status}`).
  - The parser can record shadow disagreements in `SHADOW_MODE`.

- **spaCy validator** (`app/ml/validator_spacy.py`):
  - Provides a multi-language NER-based validator for PII spans, intended to reduce regex false positives.
  - Uses lazy model loading and supports EN/DE and a multilingual fallback for TR.
  - The pipeline currently uses it only to validate email findings (when `FEATURE_ML_VALIDATOR=true`), and it is designed to be best-effort (fallback behavior if models are missing).

In terms of project design, these ML modules are optional accelerators:
- The system can work purely deterministically without ML.
- ML is used primarily to reduce false positives and to classify intent in ambiguous contexts.
- Security hardening treats the model artifact as untrusted until verified.

### 5.10 Security Hardening in the FastAPI Layer (`app/main.py`) and Edge Proxy (`nginx/nginx.conf`)

The OWASP remediation work (Sprint 5) is implemented in two layers:

- **FastAPI layer** (`app/main.py`):
  - **API key authentication** via `verify_api_key()` (gated by `REQUIRE_API_KEY`).
  - **Request size limit** middleware for `/guard` using `MAX_REQUEST_SIZE_BYTES`.
  - **Concurrency control** with an asyncio semaphore (`MAX_CONCURRENT_GUARD_REQUESTS`).
  - **Request timeout** using `asyncio.wait_for()` (`REQUEST_TIMEOUT_SECONDS`).
  - **Metrics endpoint gating** by `METRICS_ENABLED` and optional API key.
  - **Structured security logging** via `structlog` logger `security`.

- **Nginx layer** (`nginx/nginx.conf`):
  - TLS termination using certs under `nginx/certs/`.
  - Rate limiting via `limit_req_zone` and `limit_req`.
  - Restricts `/metrics` to localhost and known Docker bridge IPs, denying others.

This layered approach is defense-in-depth:
- Even if app-level auth is misconfigured, Nginx still rate limits and restricts metrics.
- Even if Nginx is bypassed (direct access to app), app-level limits and auth can be enabled.

### 5.11 Observability Stack (Prometheus + Grafana + Weekly Export)

Observability is implemented with:
- Prometheus client library in `app/metrics.py`
- `/metrics` endpoint in `app/main.py`
- Prometheus config `prometheus/prometheus.yml`
- Grafana provisioning files `grafana/provisioning/*`
- Dashboard JSON `grafana/dashboards/egress-guard.json`
- Operational guide `docs/observability-setup.md`
- Weekly report exporter `scripts/export_weekly_report.py`

Metrics include:
- Pipeline latency histogram `egress_guard_latency_seconds` with quantiles computed in Grafana.
- Per-detector latency `egress_guard_detector_latency_seconds{detector}`.
- Rule hits `egress_guard_rule_hits_total{rule_id}`.
- Severity counts `egress_guard_rule_severity_total{severity}`.
- Blocked total `egress_guard_blocked_total`.
- Context distribution `egress_guard_context_type_total{type}` and explain-only `egress_guard_explain_only_total`.
- ML load and shadow disagreements `egress_guard_ml_preclf_load_total{status}` and `egress_guard_ml_preclf_shadow_total{ml_pred,heuristic,final}`.

Grafana’s dashboard panels correspond to those metrics and present:
- Request rate, block rate, average latency, total findings,
- latency percentiles (p50/p90/p99),
- blocked vs allowed request rates,
- rule hit distribution and top rules,
- context distribution and explain-only counts,
- ML load status and shadow disagreements.

Finally, `scripts/export_weekly_report.py` queries Prometheus via HTTP and generates a Markdown report containing top rules, latency stats, block rate, context distribution, explain-only count, and ML status. This provides a “governance” artifact that can be shared with stakeholders.

### 5.12 SIEM Integration Module (`app/siem/*`)

The SIEM module exists as a forward-looking integration capability:
- `app/siem/config.py` defines environment-driven configuration for Splunk, Elasticsearch, and webhook connectors.
- `app/siem/connectors.py` implements connectors with retry logic and SSL controls.
- `app/siem/manager.py` provides batching, flushing, queue backpressure, and metrics tracking for event delivery.
- `app/siem/__init__.py` exposes a clean import surface.

In its current state, the SIEM module is not invoked by the main pipeline. This is consistent with the PRD’s earlier “post-MVP” SIEM integration notes and the future sprint notes (`docs/future_sprint_notes.md`) that list SIEM integration as future work. Nevertheless, the module is sufficiently fleshed out to be integrated with minimal additional glue (for example, emitting a SIEM event for each blocked finding).

### 5.13 Testing Strategy: Unit, Regression, Matrix Reports

Testing is a major strength of this repository:

- **Unit tests** in `tests/unit/` cover:
  - normalization security properties (`tests/unit/test_normalize.py`)
  - parser segmentation and explain-only logic (`tests/unit/test_parser.py`)
  - detector behavior and pipeline integration (`tests/unit/test_detectors.py`)
  - API integration behavior (`tests/unit/test_api.py`)
  - CI demo checks verifying blocking of synthetic secrets and PAN (`tests/unit/test_ci_demo.py`)

- **Regression tests** in `tests/regression/` include:
  - corpus samples `tests/regression/corpus_v1/**.txt`
  - golden expectations `tests/regression/golden_v1.jsonl`
  - manifest metadata `tests/regression/golden_manifest.json`
  - placeholder generator `tests/regression/placeholders.py`
  - runner `tests/regression/runner.py`
  - detector matrix scenarios `tests/regression/detector_matrix.py`
  - generated artifacts `tests/regression/artifacts/detector_matrix_results.json` and `detector_matrix_analysis.md`

The detector matrix artifacts demonstrate a “SOC-friendly” summary of scenarios and recommended analyst actions, which is a pragmatic and often overlooked aspect of shipping security tooling.

### 5.14 Packaging and Dependency Management

The project is packaged as `llm-egress-guard` with:
- `pyproject.toml` defining dependencies, dev extras, and tooling config for Black/Ruff/Pytest.
- `setup.cfg` providing additional packaging metadata.
- `llm_egress_guard.egg-info/` containing built metadata like `PKG-INFO`, `requires.txt`, and `SOURCES.txt`.

The declared runtime dependencies include FastAPI, uvicorn, pydantic, pydantic-settings, PyYAML, structlog, JSON logging, orjson, Prometheus client, and spaCy.

An important practical note, visible from code and scripts:
- ML training and model loading in practice require `joblib` and `scikit-learn` (and `numpy`), and the demo/report scripts use `requests`.
- These packages are not declared in `pyproject.toml` dependencies in the current snapshot.
- The runtime pipeline catches ML import/load failures and continues, but fully enabling the pre-classifier requires those dependencies to be installed.

This is not unusual in student projects (where conda environments may include additional libraries). For production readiness, dependency declarations should be aligned with actual usage and feature flags defaults.

## 6. Results and Recommendations

### 6.1 Sprint-by-Sprint Outcomes (Sprint 1 → Sprint 5)

The sprint reports in `reports/` provide a narrative of incremental delivery:

- **Sprint 1** (`reports/Sprint-1-Report.md`):  
  Delivered the project skeleton, FastAPI endpoints, normalization pipeline with security controls, and initial tests. Produced the core infrastructure: Docker + Nginx TLS, metrics endpoint, and documentation. Normalization security is further documented in `NORMALIZATION_SECURITY.md`.

- **Sprint 2** (`reports/Sprint-2-Report.md`):  
  Implemented detector suite v1, policy engine with risk weights and allowlists, actions (mask/delink/block), telemetry metrics, regression corpus + golden runner, and CI wiring intent. Introduced placeholders to avoid secret leakage in Git.

- **Sprint 3** (`reports/Sprint-3-Report.md`):  
  Added context-aware parsing (text/code/link), explain-only heuristic detection, context-based risk adjustments, and extensive parser tests. Reduced false positives for educational content (while later sprints tightened bypass behavior for security).

- **Sprint 4** (`reports/Sprint-4-Report.md`):  
  Trained and integrated ML pre-classifier v1 (TF-IDF + LogisticRegression), added shadow mode metrics, created model manifest and checksum verification, and deferred dashboards/CI enforcement to Sprint 5.

- **Sprint 5** (`reports/Sprint-5-Report.md`):  
  Completed observability stack (Prometheus + Grafana with provisioning), delivered OWASP-aligned security hardening (auth, DoS controls, model integrity, policy downgrade controls), and updated documentation and security assessment (`reports/security_assessment_owasp.md`).

This sprint progression is coherent: build skeleton → implement detectors and policy → reduce FP via context parsing → add ML in controlled way → harden and operationalize with observability and security controls.

### 6.2 Quality Results (Unit Tests, Regression Suite, Matrix Artifacts)

Evidence of quality is spread across tests and reports:
- The normalization module has extensive tests verifying security properties (entity bounds, double encoding, time budget behavior).
- Parser tests cover a wide range of segmentation cases and offsets.
- Detector tests validate core detections (email masking, allowlist behavior, AWS key detection, URL risk detection, command matching, exfil blob detection).
- API tests confirm masking, blocking, and delinking behavior via FastAPI `TestClient`.
- CI demo tests ensure that secrets and PAN are blocked under default settings.

Regression suite results are encoded in the golden file (`tests/regression/golden_v1.jsonl`) and the manifest (`tests/regression/golden_manifest.json`). The runner will fail if expected rule IDs or blocked flags change.

The detector matrix artifacts (`tests/regression/artifacts/detector_matrix_analysis.md` and `.json`) show curated scenarios and provide analyst-style notes. This is a valuable deliverable because it bridges engineering outputs (rule hits) and SOC workflows (triage and response guidance).

### 6.3 Performance Results and Operational Metrics

Performance is tracked through:
- microbench script `scripts/bench.sh` (vegeta/hey),
- Prometheus histograms for overall and per-detector latency,
- Grafana dashboard panels for percentiles and rates.

Sprint 5 reports and dashboard configuration indicate:
- pipeline-only average latency around ~1–2ms in typical conditions (excluding HTTP overhead),
- a block rate that varies by traffic but is measurable and charted,
- p99 latency within acceptable bounds for an MVP (cold start and long payloads can push higher).

The architecture supports production tuning by:
- short-circuiting on high-risk detections,
- bounding normalization work,
- enforcing request size/timeout/concurrency limits.

### 6.4 Security Posture and OWASP Remediation

The security assessment (`reports/security_assessment_owasp.md`) is unusually detailed for a course project. It identifies issues typical of early-stage services (unauthenticated endpoints, unsafe model deserialization, policy downgrade risks, DoS exposures, logging gaps) and then tracks remediations that were implemented in Sprint 5.

Concrete remediations visible in code:
- API key gate (`app/main.py`)
- binding defaults and reload controls (`transports/http_fastapi_sync.py`)
- request limits + concurrency + timeout controls (`app/main.py`, settings in `app/settings.py`)
- model integrity checks and trusted path enforcement (`app/ml/preclassifier.py`)
- explain-only bypass opt-in (`app/policy.py`, `ALLOW_EXPLAIN_ONLY_BYPASS`)
- proxy rate limiting and metrics restriction (`nginx/nginx.conf`)

From a security engineering standpoint, this is the correct direction: guardrails must not themselves create a new high-risk service.

### 6.5 Limitations and Known Gaps

Even with a strong implementation, there are limitations worth noting:

- **No streaming support**: The guard operates on a full response payload. For chat streaming, a different architecture (buffered scanning or incremental scanning) is needed. This is explicitly deferred in the PRD and `docs/future_sprint_notes.md`.

- **Explain-only tradeoff is policy-sensitive**: The project introduced explain-only detection to reduce false positives (Sprint 3), but later hardening disables bypass by default (Sprint 5). This is a real-world tension: educational content reduction vs bypass risk. The repo resolves it by requiring explicit opt-in.

- **ML dependency alignment**: The pre-classifier model is stored and referenced, but loading it in a minimal environment requires `joblib` and `scikit-learn` at runtime (and training requires `numpy` and scikit-learn). Similarly, demo/report scripts use `requests`. These dependencies are not declared in `pyproject.toml` in the current snapshot. The pipeline fails gracefully (ML becomes “best-effort”), but productionizing ML would require dependency declaration or separate extras.

- **CI documentation drift (minor)**: Older docs may reference a legacy path (`ci/github-actions.yml`), but the current workflow lives under `.github/workflows/ci.yml`. This is primarily a documentation synchronization issue.

- **SIEM integration not wired into pipeline**: The SIEM module exists, but the pipeline does not emit events to it yet. Future sprint notes call out SIEM integration work as a next step.

- **Detector limitations and false positives**: Regex-based phone detection is inherently prone to false positives, especially with broad patterns. The presence of optional spaCy validator is a mitigation strategy but is not fully applied to all PII kinds.

### 6.6 Recommendations and Future Work

Based on the repo’s current state and its explicit roadmap (PRD + sprint notes), the highest-value next steps are:

- **Streaming guard support** (future sprint): implement buffered window scanning with incremental release, or support an async scan mode for long responses.

- **CI maintenance**: keep docs pointing to `.github/workflows/ci.yml` and ensure the workflow remains aligned with `Makefile` targets and regression expectations. Expand it over time to include any new checks (e.g., stricter regression gating, model checksum verification, packaging checks) as the project evolves.

- **Dependency hygiene**:
  - add `requests` for demo/report scripts,
  - add `joblib` and `scikit-learn` under an optional extra (e.g., `[project.optional-dependencies].ml`) or explicitly document that ML is only supported in the conda environment.

- **Model loading performance**: consider caching the loaded pre-classifier in memory rather than loading on every request, especially if the model grows in size.

- **SIEM wiring**: integrate `app/siem/manager.py` into the pipeline such that:
  - block events and high-severity findings emit SIEM events asynchronously,
  - failures do not affect `/guard` latency (backpressure and retry handling already exist).

- **Policy tuning and tenant governance**:
  - formalize policy versioning and per-tenant override mechanism,
  - build an internal “policy linter” to ensure safe defaults (no accidental bypass rules).

- **Security metrics and alerting**:
  - add alerts for spikes in block rates, request size rejections, and timeouts,
  - track auth failures as Prometheus metrics to detect probing.

### 6.7 Repository Coverage Checklist (All Artifacts Mentioned)

This section enumerates the major repository artifacts reviewed and referenced throughout the report. The goal is to make explicit that the report covers the full codebase and documentation set.

- **Root-level project files**
  - **`README.md`**: setup, run instructions, metrics overview, project layout.
  - **`LICENSE`**: MIT license.
  - **`pyproject.toml`** and **`setup.cfg`**: packaging metadata and dependencies.
  - **`Makefile`**: convenience targets (install, lint, tests, regression, bench).
  - **`docker-compose.yml`**: full stack (app + nginx + prometheus + grafana).
  - **`llm_egress_guard_repo_skeleton_prd_technical_prd.md`**: PRD + TPRD specification and roadmap.
  - **`NORMALIZATION_SECURITY.md`**: normalization security design document.
  - **`llm_egress_guard.egg-info/*`**: built distribution metadata (e.g., `PKG-INFO`).
  - **`.github/workflows/ci.yml`**: GitHub Actions workflow for lint + tests (current CI wiring).

- **Application code (`app/`)**
  - **Core**: `app/main.py`, `app/pipeline.py`, `app/normalize.py`, `app/parser.py`, `app/policy.py`, `app/actions.py`, `app/settings.py`, `app/metrics.py`, `app/__init__.py`.
  - **Detectors**: `app/detectors/__init__.py`, `app/detectors/common.py`, `app/detectors/pii.py`, `app/detectors/secrets.py`, `app/detectors/url.py`, `app/detectors/cmd.py`, `app/detectors/exfil.py`.
  - **ML**: `app/ml/preclassifier.py`, `app/ml/validator_spacy.py`, `app/ml/__init__.py`.
  - **SIEM**: `app/siem/__init__.py`, `app/siem/config.py`, `app/siem/connectors.py`, `app/siem/manager.py`.
  - **Schemas**: `app/schemas/api_request.json`, `app/schemas/api_response.json`.
  - **Container build**: `app/Dockerfile`.

- **Transports (`transports/`)**
  - **`transports/http_fastapi_sync.py`**: uvicorn runner defaults.
  - **`transports/aws_lambda_handler.py`**: stub for future Lambda transport.

- **Configuration (`config/`)**
  - **`config/policy.yaml`**: risk-weighted policy rules, allowlists, context settings.
  - **`config/locales/en/safe_messages.yaml`**: localized safe messages.

- **Observability and infra**
  - **`nginx/nginx.conf`** and **`nginx/certs/*`**: TLS proxy and dev certs.
  - **`prometheus/prometheus.yml`**: scrape config.
  - **`grafana/dashboards/egress-guard.json`**: dashboard definition.
  - **`grafana/provisioning/datasources/prometheus.yml`** and **`grafana/provisioning/dashboards/dashboard.yml`**: provisioning.

- **Documentation (`docs/`)**
  - **`docs/README.md`**: doc index.
  - **`docs/observability-setup.md`**: Prometheus/Grafana setup guide.
  - **`docs/ci-wiring-guide.md`**: CI wiring rationale and workflow template.
  - **`docs/future_sprint_notes.md`**: roadmap status and future work.

- **Reports (`reports/`)**
  - **`reports/README.md`**: report index and formats.
  - **Sprint reports**: `reports/Sprint-1-Report.md` (+ `.pdf`, `.docx`), `reports/Sprint-2-Report.md` (+ `.pdf`, `.docx`, `.html`), `reports/Sprint-3-Report.md` (+ `.pdf`), `reports/Sprint-4-Report.md` (+ `.pdf`), `reports/Sprint-5-Report.md` (+ `.pdf`).
  - **Security and ML notes**: `reports/security_assessment_owasp.md`, `reports/notes_preclf_v1.md`.

- **Prompts and ML data generation**
  - **`prompts/ml_training/README.md`** and prompt files `01_educational_security.md` through `07_multilingual.md`.
  - **`data/ml_training/*`**: generated datasets and train/eval splits (`preclf_train.jsonl`, `preclf_eval.jsonl`, plus `output_*` files).

- **Model artifacts (`models/`)**
  - **`models/preclf_v1.joblib`**: model artifact (binary).
  - **`models/preclf_v1.manifest.json`**: sha256, size, sample counts, metrics.

- **Scripts (`scripts/`)**
  - **Demo**: `scripts/demo_scenarios.py`, `scripts/demo_scenarios.sh`.
  - **Policy hot-reload**: `scripts/demo_policy_reload.py`.
  - **ML tooling**: `scripts/train_preclassifier.py`, `scripts/check_preclf_model.py`, `scripts/validate_training_data.py`.
  - **Ops**: `scripts/export_weekly_report.py`.
  - **Benchmarking**: `scripts/bench.sh`.

- **Tests (`tests/`)**
  - **Unit tests**: `tests/unit/test_api.py`, `tests/unit/test_ci_demo.py`, `tests/unit/test_detectors.py`, `tests/unit/test_parser.py`, `tests/unit/test_normalize.py`.
  - **Regression tests**:
    - `tests/regression/README.md`, `tests/regression/runner.py`, `tests/regression/placeholders.py`, `tests/regression/detector_matrix.py`,
    - `tests/regression/golden_v1.jsonl`, `tests/regression/golden_manifest.json`,
    - `tests/regression/corpus_v1/*` categorized `.txt` samples,
    - `tests/regression/artifacts/detector_matrix_results.json` and `tests/regression/artifacts/detector_matrix_analysis.md` (pre-generated artifacts).

## 7. Conclusions

The LLM Egress Guard repository demonstrates a mature and coherent approach to a hard security problem: controlling data leakage and dangerous outputs from LLM systems. It does so not by relying on probabilistic moderation, but by building a deterministic, testable, and policy-driven service with strong security hygiene.

The project’s strongest qualities are:
- security-aware normalization with bounded decoding and anomaly tracking,
- a well-structured detector suite covering real-world leak and exploitation patterns,
- context-aware parsing to reduce false positives (with hardened opt-in bypass behavior),
- robust policy controls (risk weights, allowlists, tenant overrides),
- serious attention to observability (Prometheus + Grafana + weekly export),
- a disciplined testing strategy (unit + regression golden + detector matrix),
- explicit OWASP-aligned security hardening and documentation.

The primary next steps for production-grade completeness are operational rather than conceptual: implement CI wiring in the repository, align dependencies with optional ML and scripts, and integrate SIEM emissions into the pipeline. With those improvements, the system would form a strong foundation for a real-world “LLM gateway” or “AI platform” egress control plane.

## 8. Acknowledgements

This project’s structure and delivery cadence are informed by the PRD/TPRD and sprint reporting discipline present in the repository:
- Sprint reports in `reports/` document the incremental engineering work and decisions.
- The OWASP security assessment and remediation tracking (`reports/security_assessment_owasp.md`) strongly shaped the final hardened design.
- The regression corpus and placeholder approach (`tests/regression/*`) reflect practical security engineering constraints around secret handling in source control.

## 9. References

- **Project documents (in-repo)**
  - `llm_egress_guard_repo_skeleton_prd_technical_prd.md`
  - `README.md`
  - `NORMALIZATION_SECURITY.md`
  - `docs/README.md`
  - `docs/observability-setup.md`
  - `docs/ci-wiring-guide.md`
  - `docs/future_sprint_notes.md`
  - Sprint reports: `reports/Sprint-1-Report.md` … `reports/Sprint-5-Report.md`
  - Security assessment: `reports/security_assessment_owasp.md`

- **Standards, frameworks, and external guidance**
  - OWASP Cross Site Scripting Prevention Cheat Sheet: `https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html`
  - Unicode Normalization Forms (UAX #15 / TR15): `https://unicode.org/reports/tr15/`
  - CWE-838: Inappropriate Encoding for Output Context: `https://cwe.mitre.org/data/definitions/838.html`
  - Prometheus documentation: `https://prometheus.io/docs/`
  - Grafana documentation: `https://grafana.com/docs/`
  - MITRE ATT&CK Framework: `https://attack.mitre.org/`

