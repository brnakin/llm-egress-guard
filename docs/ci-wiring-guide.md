# CI/CD Wiring with GitHub Actions

This document explains why we need CI/CD automation, how GitHub Actions fits into LLM Egress Guard, and provides a practical implementation guide.

---

## Why Do We Need CI Wiring?

### The Problem Without CI

Without Continuous Integration (CI), every code change requires manual verification:

```
Developer commits code → Manual testing → Manual lint check → Manual regression → Hope nothing breaks
```

**Issues:**
1. **Human Error**: Easy to forget running tests before commit
2. **Inconsistent Environment**: "Works on my machine" syndrome
3. **Slow Feedback**: Bugs discovered late in the process
4. **No Quality Gate**: Bad code can reach production

### The Solution With CI

With CI, every code change is automatically verified:

```
Developer commits → GitHub Actions triggers → Lint → Test → Regression → Build → ✅/❌ Report
```

**Benefits:**
1. **Automated Quality Gate**: No manual checks needed
2. **Consistent Environment**: Tests run in clean, reproducible containers
3. **Fast Feedback**: Know within minutes if code breaks something
4. **Documentation**: Build history shows what was tested and when

---

## How GitHub Actions Works

### Basic Concept

GitHub Actions is a CI/CD platform built into GitHub. When you push code:

1. GitHub detects the push
2. Reads `.github/workflows/*.yml` files
3. Spins up virtual machines (runners)
4. Executes the defined jobs
5. Reports results back to the PR/commit

### Key Components

| Component | Description | Example |
|-----------|-------------|---------|
| **Workflow** | The entire CI pipeline | `ci.yml` |
| **Trigger** | What starts the workflow | `push`, `pull_request` |
| **Job** | A set of steps that run together | `lint`, `test`, `build` |
| **Step** | Individual command or action | `pip install`, `pytest` |
| **Runner** | VM that executes jobs | `ubuntu-latest` |

---

## LLM Egress Guard CI Pipeline

### What We Want to Automate

| Stage | Purpose | Tools |
|-------|---------|-------|
| **Lint** | Code style and errors | Ruff, Black |
| **Unit Tests** | Core logic verification | pytest |
| **Regression** | Golden output comparison | `runner.py` |
| **Model Check** | ML model integrity | `check_preclf_model.py` |
| **Build** | Docker image creation | `docker build` |

### Pipeline Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                        GitHub Actions                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   push/PR                                                            │
│      │                                                               │
│      ▼                                                               │
│   ┌──────┐    ┌──────┐    ┌────────────┐    ┌───────┐    ┌───────┐ │
│   │ Lint │───▶│ Test │───▶│ Regression │───▶│ Model │───▶│ Build │ │
│   └──────┘    └──────┘    └────────────┘    └───────┘    └───────┘ │
│      │           │              │               │            │      │
│      ▼           ▼              ▼               ▼            ▼      │
│    Ruff       pytest        runner.py      checksum      Docker     │
│    Black                                   verify        image      │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### When It Runs

- **On Push to `main`**: Full pipeline → ensures main branch is always clean
- **On Pull Request**: Full pipeline → catch issues before merge
- **On Schedule** (optional): Weekly regression runs → detect environment drift

---

## Benefits for LLM Egress Guard

### 1. Detector Regression Prevention

When you modify a regex pattern in `app/detectors/pii.py`:
- CI automatically runs all 100+ regression samples
- If any expected detection fails, CI blocks the merge
- You know immediately which samples broke

### 2. ML Model Integrity

When someone accidentally commits a different model file:
- CI verifies SHA256 checksum against manifest
- If checksum doesn't match, pipeline fails
- Prevents deploying tampered/wrong models

### 3. Code Quality Enforcement

Team members can't merge code that:
- Has linting errors (Ruff)
- Has formatting issues (Black)
- Fails unit tests

### 4. Documentation of Changes

Every PR shows:
- ✅/❌ status for each check
- Logs of what ran and what failed
- History of all previous runs

---

## Implementation

### Step 1: Create Workflow File

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install ruff black
      - run: ruff check app tests
      - run: black --check app tests

  test:
    runs-on: ubuntu-latest
    needs: lint
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -e .[dev]
      - run: pytest tests/unit -q

  regression:
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -e .[dev]
      - run: python tests/regression/runner.py

  model-check:
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -e .[dev]
      - run: python scripts/check_preclf_model.py --model models/preclf_v1.joblib --manifest models/preclf_v1.manifest.json

  build:
    runs-on: ubuntu-latest
    needs: [regression, model-check]
    steps:
      - uses: actions/checkout@v4
      - run: docker build -t llm-egress-guard:${{ github.sha }} .
```

### Step 2: Enable in GitHub

1. Push the workflow file to your repository
2. Go to repository → Settings → Actions → General
3. Select "Allow all actions and reusable workflows"
4. Save

### Step 3: Protect Main Branch (Optional but Recommended)

1. Go to Settings → Branches → Add rule
2. Branch name pattern: `main`
3. Enable "Require status checks to pass before merging"
4. Select the CI jobs as required checks

---

## Cost & Resources

### GitHub Actions Free Tier

| Plan | Minutes/Month | Storage |
|------|---------------|---------|
| Free | 2,000 | 500 MB |
| Pro | 3,000 | 1 GB |
| Team | 3,000 | 2 GB |

### Our Estimated Usage

| Job | Duration | Per Day (10 pushes) | Per Month |
|-----|----------|---------------------|-----------|
| Lint | ~30s | 5 min | 150 min |
| Test | ~1 min | 10 min | 300 min |
| Regression | ~2 min | 20 min | 600 min |
| Model Check | ~30s | 5 min | 150 min |
| Build | ~3 min | 30 min | 900 min |
| **Total** | ~7 min | 70 min | **2,100 min** |

**Verdict:** Free tier is sufficient for our project.

---

## Summary

| Question | Answer |
|----------|--------|
| Why CI? | Automated quality gates, fast feedback, consistent testing |
| What tool? | GitHub Actions (free, integrated with GitHub) |
| What to automate? | Lint, unit tests, regression, model check, Docker build |
| When does it run? | On every push and PR to `main` |
| Cost? | Free (within 2,000 min/month limit) |

---

## Next Steps

1. ✅ Workflow file exists at `ci/github-actions.yml`
2. Move to `.github/workflows/ci.yml` for GitHub to detect it
3. Push to GitHub and verify workflow runs
4. Add branch protection rules

---

*Last updated: Dec 22, 2025*

