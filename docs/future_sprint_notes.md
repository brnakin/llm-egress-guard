# Notes for the Future Sprint

These notes summarize how we plan to finish the Sprint 2 carryover work and highlight the gaps that must be closed before the next demo.

> Security and engineering reviewers validated the current state of the guard and produced the baseline summarized below. Treat these notes as the authoritative planning artifact for Sprint 3 and beyond.

## Security Review Snapshot
- **Maturity:** The MVP is verified as stable with hardened normalization, deterministic testing, and telemetry. We are officially exiting Sprint 2 with a working guard.
- **Critical bottlenecks:** Context-Aware Parsing (`app/parser.py`) and Performance scaling (`app/pipeline.py`) must be addressed immediately to keep false positives down and latency predictable.
- **Roadmap impact:** Reorder the backlog so Context-Aware Parsing lands in Sprint 3, the ML Pre-classifier (`app/ml/preclassifier.py`) in Sprint 4, and defer secondary initiatives until those are complete.
- **Baseline:** This review is signed off by security engineering and should be referenced for design justifications, demos, and stakeholder updates.

## Context-Aware Parser Segmentation
- The parser module is still a stub; we need it to emit `text/code/link/table` segments so command and PII detectors can apply context penalties or bonuses.
- It should build on the normalized text and emit metadata that the regression runner can persist for analysis.
- Once complete, “explain-only” command passages should generate fewer false positives because their scores can be lowered before policy evaluation.

---

## Lightweight ML Layer
- Feature flags (`FEATURE_ML_PRECLF`, `FEATURE_ML_VALIDATOR`) exist, but the actual `app/ml/` services and artifacts are missing.
- Pre-classifier will run in shadow mode first to feed risk scores to the command detector; the spaCy validator will double-check regex PII hits.
- Targets: <2 ms added p95 latency and ≥0.9 AUC. Model artifacts must be packaged via CI.

---

## Telemetry & Test Integration
- `/metrics` currently exposes latency and rule hits; we must add new counters such as pre-classifier decisions, validator agree-rate, and queue depth.
- Regression runner should report context/ML outcomes so we can measure FP reductions.
- ML evaluation (AUC, agree-rate) has to become part of the pipeline or CI step.

---

## Scope Creep
- Each improvement should stay within a clear epic/ticket (e.g., CA-101 vs PAR-301) with defined acceptance criteria.
- Heavy items (spaCy, SIEM emitters) must not start until parser and pre-classifier are functional; enforce WIP limits.

---

## Data / Label Gap
- TF-IDF and validator training both need ≥200 labeled “instruction vs execution” examples; we must plan a placeholder-based corpus pipeline.
- Follow privacy rules while collecting data: rely on snippet hashes and synthetic placeholders so raw secrets/PII never land in git.

---

## Model Size / Performance Risk
- The spaCy model will bloat the container; it must stay optional and lazy-loaded.
- The pre-classifier model must remain <10 MB with <2 ms p95 overhead; otherwise consider lighter alternatives (Presidio, rule-based heuristics).

---

## Policy Misalignment
- Rules like “penalize PII inside code blocks” must be overrideable per tenant.
- Add context penalty/bonus knobs to `config/policy.yaml` and document how operators can adjust them safely.

---

## Telemetry / Privacy
- If validator disagreement samples are logged, store only masked snippets + hashes; otherwise emit metrics only.
- SIEM/alert integrations must minimize tenant identifiers and restrict outbound payload fields to what SOC tooling actually needs.

---

- **Context-aware risk tuning & ML pre-classifier enablement:** Goal is to cut false positives on explain-only command snippets without weakening blocks on real payloads. Work covers normalization tags (`explain_only`), lightweight TF-IDF → LR model, feature flag plumbing, Prometheus counters, and regression-proof exit criteria (<2% latency hit, ≥90% precision). Dependencies: ≥200 labeled samples, CI packaging, documentation for tuning/rollback.

  - `CA-101 Data Labeling & Dedup`: corpus expansion + `explain_only` tagging hook.
  - `CA-102 TF-IDF Pre-classifier Service`: inference helper (`app/ml/preclassifier.py`), feature flag, pipeline traces.
  - `CA-103 Policy & Metrics Integration`: risk-weight wiring, Prometheus counter/histogram, tuning docs.

---

- **SIEM / alert integrations:** Goal is to push rule hits/blocks to Splunk/ELK/webhooks. Work includes an emitter abstraction, queue/backpressure metrics, Splunk HEC + Elastic bulk clients, webhook sink, and SOC runbooks. Exit criteria: <5s delivery, `/guard` unaffected by emitter failures, dashboards/screenshots ready.

  - `SIEM-201 Telemetry Bus`: queue, backpressure metrics, secure payload serialization.
  - `SIEM-202 Splunk & Elastic Emitters`: HEC/Bulk clients with retry/backoff + unit tests.
  - `SIEM-203 Webhook + Runbooks`: generic webhook sink, curl templates, SOC dashboards, observable failure paths.

---

**Parser + ML validator:** Goal is format-aware detection with spaCy confirmation of regex PII hits. Work spans Markdown/code parser, detectors consuming `segment.context`, spaCy pipeline packaging, caching, and feature flags. Exit criteria: parser coverage in regression corpus, ≥95% spaCy agreement, detector matrix demonstrating lower FP.

  - `PAR-301 Markdown/Code Parser`: structured segments + regression fixtures.
  - `PAR-302 spaCy Validator Integration`: lazy-load model, disagreement telemetry.
  - `PAR-303 Feature Flags & Ops Docs`: per-tenant toggles, Docker/runtime docs, rollback checklist.

---

Sprint focus: clearing context-aware tuning plus telemetry bus first unlocks ML risk scoring and outbound visibility; remaining epics stay on deck for subsequent iterations.

---

## Executive Summary (Security Review)
You have built a solid, security-first MVP foundation. The project maturity is surprisingly high for an early-stage tool, particularly regarding normalization security and deterministic testing. You are effectively at the "Sprint 2 Complete" stage as documented, with a working pipeline, robust regex-based detection, and telemetry.
However, to claim "Production Readiness" or handle real-world LLM traffic, you have two critical engineering bottlenecks to address: Context-Awareness (the parser is a stub) and Performance Scaling (linear regex execution). This summary distills the external security review feedback and anchors the next sprint plans.

### 1. Strong Points (Keep Doing This)
*   **Security-First Normalization (`app/normalize.py`):**
    *   Your approach to normalization (URL → HTML → NFKC → Strip) is excellent. Most DLP tools fail here by allowing simple bypasses like `%26lt;` or zero-width spaces.
    *   The resource limits (entity counts, expansion checks) and "fail-secure" defaults prevent DoS attacks against the guard itself.
*   **Quality Assurance & Testing:**
    *   The Golden File / Regression Runner (`tests/regression`) is the right way to test DLP. It prevents regression loops where fixing a False Positive (FP) breaks a True Positive (TP).
    *   **Placeholder Injection:** Using `{{TOKEN}}` markers and rendering secrets at runtime for tests is a best practice. It keeps your repo free of actual secrets while testing the detectors realistically.
*   **Detector Logic:**
    *   **Validation over matching:** You aren't just matching regexes; you are validating them (Luhn algorithm for PAN, checksums for TCKN, Base64 checks for JWTs). This significantly reduces "alert fatigue."
    *   **Entropy Checks:** The implementation of Shannon entropy for high-entropy blobs and AWS secrets is mathematically sound.

### 2. Critical Gaps & Engineering Feedback
#### A. The "Context" Gap (Priority: High)
*   **Observation:** `app/parser.py` is currently a pass-through stub. `app/pipeline.py` passes the full text to all detectors.
*   **Risk:** LLMs frequently output code tutorials. If an LLM writes: "You can use `curl -X POST...`" in a markdown code block, your current cmd detector will likely flag it as a "Command Injection" risk, generating false positives on explain-only snippets.
*   **Feedback:** You need the Context-Aware Parser immediately.
*   **Action:** Update `parser.py` to split text into segments: `[("text", "Here is the code"), ("code", "curl ...")]`.
*   **Action:** Modify `scan_all` to allow detectors to subscribe to specific contexts (e.g., cmd detector should potentially be stricter in code blocks but lenient in text blocks, or vice-versa depending on your threat model).

#### B. Linear Scanning Performance (Priority: Medium)
*   **Observation:** In `app/pipeline.py`, `scan_all` iterates through every detector sequentially.
*   **Risk:** You currently have ~40 regex rules. If this grows to 400 (common in DLP), your latency will spike linearly. The < 40ms target will be missed on large inputs, especially when combined with context-aware segmentation overhead.
*   **Feedback:**
    *   **Short Term:** Keep as is, it's fine for MVP.
    *   **Long Term:** Implement a Multi-Pass architecture. Use a fast string search algorithm (like Aho-Corasick) to scan for "trigger keywords" first. Only run complex regexes (like the AWS Secret Key regex) if a relevant keyword (e.g., "AKIA", "aws", "key") is present.

#### C. ML Components are Stubs (Priority: Medium)
*   **Observation:** `app/ml/preclassifier.py` is a keyword heuristic (if "curl" in text...).
*   **Risk:** This is too brittle. It will miss obfuscated commands and flag harmless discussions about commands.
*   **Feedback:** As per your Sprint 3 notes, moving to a TF-IDF + Logistic Regression model is the correct next step. It is lightweight enough (<2ms) to run on CPU and will vastly outperform keyword lists for classifying "Intent" (Malicious Command vs. Educational Text).
*   **Action:** Stand up TF-IDF feature extraction plus small LR weights in `app/ml/preclassifier.py`, wire it behind `FEATURE_ML_PRECLF`, and track precision/latency in Prometheus.

### 3. Security & Logic Audit
I reviewed your detector logic specifically:
*   **JWT Detector (`app/detectors/secrets.py`):**
    *   **Code:** `_looks_like_jwt` checks for 3 parts and valid Base64.
    *   **Verdict:** Good. Prevents FPs on random dot-separated strings.
*   **Email Masking (`app/detectors/pii.py`):**
    *   **Code:** `f"{local[0]}***{local[-1]}@{domain}"`
    *   **Verdict:** Safe. It preserves the domain (useful for security context) while hiding the user.
*   **Policy Evaluation (`app/policy.py`):**
    *   **Code:** `risk_score = min(risk_score, 100)`
    *   **Verdict:** Good. Cap the score to normalize downstream consumption (SIEMs/Dashboards).

### 4. Recommended Roadmap Adjustments
Your current roadmap is good, but I would re-order slightly to prioritize the False Positive problem:
1.  **Sprint 3 (Immediate):** Context-Aware Parsing. Before adding ML, you need to know where the text is (Code vs. Prose). This yields the biggest ROI for reducing False Positives and is now the top backlog item per review sign-off.
2.  **Sprint 4:** ML Pre-classifier. Once you have segments, use ML to classify the intent of those segments. Deliver TF-IDF + Logistic Regression along with CI-packaged artifacts.
3.  **Sprint 5:** Streaming Support. (Currently listed as Post-MVP).
    *   **Note:** For a chat interface, waiting for the full response (blocking) feels sluggish. You will eventually need a "Pass-through stream, buffer window, scan, release" architecture.

### Final Verdict
*   **Status:** ✅ Solid MVP.
*   **Next Move:** Focus entirely on `app/parser.py`. The difference between a "toy" DLP and a usable one is understanding Markdown/Code structure.
*   **Baseline:** This feedback serves as the verified reference for the next development phase; keep it attached to sprint planning artifacts and demo decks.
