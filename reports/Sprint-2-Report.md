# Sprint 2 Completion Report: LLM Egress Guard

**Project:** LLM Egress Guard - Data Loss Prevention for LLM Outputs  
**Sprint:** Sprint 2 (November 1 - November 14, 2025)  
**Status:** [COMPLETE]  
**Prepared by:** Baran Akin  
**Date:** November 14, 2025

---

## Executive Summary

Sprint 2 delivers the first production-ready detector stack, risk-weighted policy engine, and observability required for MVP demos. The guard can now block or sanitize secrets, PII, risky URLs, command chains, and large exfil attempts deterministically while exposing rule hits, detector latency, and safe messages via API/metrics/logs. Regression corpus + CI automation ensure future iterations stay stable.

---

## Objectives & Status

| Objective | Description | Status |
|-----------|-------------|--------|
| Detector v1 | Implement regex/heuristic detectors for PII, secrets, URLs, commands, exfil | ✅ |
| Policy YAML | Introduce risk_weight, severity, allowlist regex + tenant overrides | ✅ |
| Actions & Safe Messages | Mask/delink/block with localized responses | ✅ |
| Telemetry | Prometheus metrics for pipeline + detector latency and rule hits | ✅ |
| Regression & CI | Corpus + golden runner, FastAPI tests, GitHub Actions | ✅ |

---

## Implementation Details

1. **Policy & Actions**
   - `config/policy.yaml` upgraded to version 2 with 40+ golden rules, risk weights, and tenant-aware allowlists. New safe messages added for masking, delinking, and exfil blocks.
   - `app/policy.py` now parses `allowlist_regex`, `tenant_allowlist`, and computes risk scores via `risk_weight`. Safe messages flow through `PolicyDecision`.
   - `app/actions.py` applies in-place replacements (mask/delink/remove) or returns localized safe messages when blocking.

2. **Detectors**
   - **PII (`app/detectors/pii.py`)**: Email, multi-language phone formats (TR/EN/DE/FR/ES/IT/PT/HI/ZH/RU), IBAN (TR/DE), TCKN, PAN with Luhn, IPv4.
   - **Secrets (`app/detectors/secrets.py`)**: JWT, AWS access & secret keys, OpenAI, GitHub, Slack, Stripe, Twilio, Azure SAS, GCP service accounts, PEM blocks, entropy fallback.
   - **URL (`app/detectors/url.py`)**: Data URIs, executable extensions, IP literals, credentials-in-URL, URL shorteners, suspicious TLDs.
   - **Commands (`app/detectors/cmd.py`)**: curl|bash, wget|sh, powershell encoded/IWR, invoke-webrequest, rm -rf, reg add, certutil, mshta, rundll32.
   - **Exfil (`app/detectors/exfil.py`)**: Large Base64/hex blobs with entropy thresholds.
   - Detector registry/pipeline integrates latency metrics and short-circuits on block actions.

3. **Telemetry**
   - `app/metrics.py` adds per-detector latency histogram and rule severity counters. `/metrics` now exposes pipeline p50/p95, blocked totals, rule hits, and severity tallies for dashboards.

4. **Testing & Tooling**
   - `tests/unit/test_detectors.py` expanded to cover new detector types; `tests/unit/test_api.py` validates FastAPI behavior (mask, block, delink scenarios).
   - Regression suite (`tests/regression/corpus_v1`) now holds ~60 labeled samples (PII, secrets, URL, CMD, Exfil, clean). `tests/regression/runner.py` compares results with `golden_v1.jsonl`.
   - CI workflow (`ci/github-actions.yml`) runs Ruff, Black, pytest, and regression runner on every push/PR.

---

## Issues & Resolutions

| Issue | Impact | Resolution |
|-------|--------|------------|
| Missing temp directory in sandbox | Pytest couldn’t create temp files in some environments | Runner now honours `TMPDIR`, docs mention workaround |
| Policy weight ambiguity | `weight` vs. `risk_weight` naming caused confusion | Unified on `risk_weight`, updated loaders + YAML |
| Secrets preview leaking data | Early preview strings showed partial secrets | All secrets/exfil previews replaced with placeholders |

---

## Testing & Quality

- `pytest` (unit + API): 100% pass (52 tests).  
- `tests/regression/runner.py`: all corpus samples match golden expectations.  
- `ruff check app tests` & `black --check app tests`: pass.  
- FastAPI integration tests validate masking, blocking (JWT), and delinking flows.

---

## Performance & Telemetry

- Pipeline latency: ~8–12 ms median on 1K-char samples (local dev).  
- Detector latency histograms show <2 ms per detector for typical inputs.  
- `/metrics` exposes `egress_guard_latency_seconds`, `egress_guard_detector_latency_seconds`, `egress_guard_rule_hits_total`, `egress_guard_rule_severity_total`, `egress_guard_blocked_total`.

---

## Usage Guide (Sprint 2 Additions)

1. **Run API** – same as Sprint 1, but now returns masked/blocked text per policy.
2. **Regression** – `python tests/regression/runner.py` (requires `POLICY_FILE` env if custom).
3. **CI locally** – run `ruff`, `black --check`, `pytest`, regression runner.
4. **Metrics** – curl `http://localhost:8080/metrics` (behind Nginx allowlist in prod).

---

## Recommendations & Next Steps

1. Add context-aware tuning (e.g., risk down-weight in “explain” responses) and ML pre-classifier toggles.
2. Expand regression corpus with multilingual narratives & FP cases, feed results into ATT&CK mapping.
3. Build export tooling for SIEM / weekly reports and integrate /metrics with dashboards.
4. Plan Sprint 3 focus on parser/context and optional ML validator.

## Open Items / Gaps

- **Policy hot-reload**: settings/policy files are still re-read on every request; introduce timestamp-based caching + reload hooks to cut latency and ease ops changes.
- **Golden versioning**: the new corpus is larger, but `golden_v1.jsonl` snapshots aren’t version-tagged; tracking changes per sprint will help audits and rollbacks.
- **Context-aware mitigation**: explanatory outputs (e.g., “rm -rf / açıklaması”) are detected but actions are binary; add risk dampening to reduce false positives in guidance scenarios.
- **SIEM/alert integration**: telemetry is local-only; exporting rule hits/blocks to external monitoring remains open.

---

**Sprint 2 Status:** ✅ Complete — detectors, policy, telemetry, regression, and CI ready for demo.
