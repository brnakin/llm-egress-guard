# LLM Egress Guard - Observability Setup Guide

This guide explains step-by-step how to set up metric collection and visualization with Prometheus and Grafana for LLM Egress Guard.

---

## 📋 Table of Contents

1. [Requirements](#requirements)
2. [Architecture](#architecture)
3. [Quick Start](#quick-start)
4. [Docker Compose Configuration](#docker-compose-configuration)
5. [Prometheus Configuration](#prometheus-configuration)
6. [Grafana Configuration](#grafana-configuration)
7. [Startup and Verification](#startup-and-verification)
8. [Dashboard Panels](#dashboard-panels)
9. [Troubleshooting](#troubleshooting)

---

## Requirements

- **Docker** >= 20.10
- **Docker Compose** >= 2.0
- **Disk space**: ~500MB (for images)
- **RAM**: ~512MB (for all services)

### Installation Check

```bash
# Check Docker version
docker --version
# Check Docker Compose version
docker compose version
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Docker Network                            │
│                                                                  │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐    │
│  │              │     │              │     │              │    │
│  │  LLM Egress  │────▶│  Prometheus  │────▶│   Grafana    │    │
│  │    Guard     │     │              │     │              │    │
│  │   :8080      │     │   :9090      │     │   :3000      │    │
│  │              │     │              │     │              │    │
│  └──────────────┘     └──────────────┘     └──────────────┘    │
│        │                     │                    │             │
│        │ /metrics            │ scrape             │ query       │
│        └─────────────────────┘                    │             │
│                                                   │             │
└───────────────────────────────────────────────────┼─────────────┘
                                                    │
                                            ┌───────▼───────┐
                                            │   Browser     │
                                            │ localhost:3000│
                                            └───────────────┘
```

### Data Flow

1. **LLM Egress Guard** → `/metrics` endpoint serves metrics in Prometheus format
2. **Prometheus** → Scrapes the `/metrics` endpoint every 15 seconds
3. **Grafana** → Pulls data from Prometheus and visualizes it in dashboards

---

## Quick Start

```bash
# 1. Navigate to project directory
cd /home/baran/project-courses/llm-egress-guard

# 2. Start all services
docker compose up -d

# 3. Check that services are running
docker compose ps

# 4. Access Grafana
# URL: http://localhost:3000
# Username: admin
# Password: admin
```

---

## Docker Compose Configuration

### File: `docker-compose.yml`

```yaml
version: "3.8"

services:
  # Main application
  egress-guard:
    build: .
    ports:
      - "8080:8080"
    environment:
      - REQUIRE_API_KEY=false  # For development
      - METRICS_ENABLED=true
      - LOG_LEVEL=info
    volumes:
      - ./config:/app/config:ro
      - ./models:/app/models:ro
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/healthz"]
      interval: 30s
      timeout: 10s
      retries: 3
    networks:
      - egress-network

  # Prometheus - Metric collection
  prometheus:
    image: prom/prometheus:v2.47.0
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--storage.tsdb.retention.time=15d'
      - '--web.enable-lifecycle'
    networks:
      - egress-network
    depends_on:
      - egress-guard

  # Grafana - Visualization
  grafana:
    image: grafana/grafana:10.1.0
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes:
      - ./grafana/provisioning:/etc/grafana/provisioning:ro
      - ./grafana/dashboards:/var/lib/grafana/dashboards:ro
      - grafana-data:/var/lib/grafana
    networks:
      - egress-network
    depends_on:
      - prometheus

networks:
  egress-network:
    driver: bridge

volumes:
  prometheus-data:
  grafana-data:
```

---

## Prometheus Configuration

### File: `prometheus/prometheus.yml`

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'egress-guard'
    static_configs:
      - targets: ['egress-guard:8080']
    metrics_path: /metrics
    # If API key is required:
    # authorization:
    #   type: Bearer
    #   credentials: 'your-api-key'
```

### Prometheus Targets

| Target | Port | Path | Description |
|--------|------|------|-------------|
| egress-guard | 8080 | /metrics | Main application metrics |

---

## Grafana Configuration

### Datasource Provisioning

**File:** `grafana/provisioning/datasources/prometheus.yml`

```yaml
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: false
```

### Dashboard Provisioning

**File:** `grafana/provisioning/dashboards/dashboard.yml`

```yaml
apiVersion: 1

providers:
  - name: 'LLM Egress Guard'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    editable: true
    options:
      path: /var/lib/grafana/dashboards
```

---

## Startup and Verification

### Step 1: Create Directory Structure

```bash
mkdir -p prometheus
mkdir -p grafana/provisioning/datasources
mkdir -p grafana/provisioning/dashboards
mkdir -p grafana/dashboards
```

### Step 2: Start Services

```bash
docker compose up -d
```

### Step 3: Check Services

```bash
# Check status of all services
docker compose ps

# Expected output:
# NAME                STATUS
# egress-guard        running (healthy)
# prometheus          running
# grafana             running
```

### Step 4: Verify Prometheus

```bash
# Check Prometheus targets page
curl -s http://localhost:9090/api/v1/targets | jq '.data.activeTargets[].health'
# Expected: "up"
```

### Step 5: Login to Grafana

1. Open in browser: http://localhost:3000
2. Username: `admin`
3. Password: `admin`
4. You may be prompted to change the password on first login

### Step 6: Check Dashboard

1. From the left menu, select **Dashboards** → **Browse**
2. Select the **LLM Egress Guard** dashboard
3. Verify that metrics are being displayed

---

## Dashboard Panels

### Available Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `egress_guard_latency_seconds` | Histogram | Request processing time |
| `egress_guard_blocked_total` | Counter | Number of blocked requests |
| `egress_guard_findings_total` | Counter | Number of detected findings |
| `egress_guard_rule_hits_total` | Counter | Rule match counts |
| `egress_guard_context_type_total` | Counter | Segment types (text/code/link) |
| `egress_guard_explain_only_total` | Counter | Educational content detections |
| `egress_guard_ml_preclf_load_total` | Counter | ML model load status |

### Dashboard Panels

1. **Request Rate** - Requests processed per second
2. **Latency Percentiles** - p50, p90, p99 latency times
3. **Block Rate** - Percentage of blocked requests
4. **Top Rules** - Most frequently triggered rules
5. **Context Distribution** - Text/Code/Link distribution
6. **ML Status** - Model load success/error status

---

## Troubleshooting

### Issue: Prometheus target shows "down"

```bash
# Check container logs
docker compose logs egress-guard

# Test network connection
docker compose exec prometheus wget -qO- http://egress-guard:8080/healthz
```

**Solution:** Ensure the `egress-guard` container is running.

### Issue: Grafana datasource cannot connect

```bash
# Test Prometheus access
docker compose exec grafana wget -qO- http://prometheus:9090/api/v1/status/config
```

**Solution:** Verify that all containers are on the same network.

### Issue: Metrics not showing

```bash
# Manually check metrics
curl -s http://localhost:8080/metrics | head -20
```

**Solution:** Ensure `METRICS_ENABLED=true` is set.

### Issue: API key error

If API key is required for Prometheus, add to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'egress-guard'
    static_configs:
      - targets: ['egress-guard:8080']
    authorization:
      type: Bearer
      credentials: 'your-api-key-here'
```

---

## Useful Commands

```bash
# Start all services
docker compose up -d

# Watch logs
docker compose logs -f

# Stop services
docker compose down

# Stop services and delete data
docker compose down -v

# Restart a single service
docker compose restart prometheus

# Connect to a container
docker compose exec grafana /bin/sh
```

---

## Next Steps

1. **Alerting**: Define alert rules in Grafana
2. **Retention**: Adjust Prometheus data retention period
3. **Security**: Change Grafana passwords for production
4. **Backup**: Backup Grafana dashboards

---

## Resources

- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)
- [Docker Compose Reference](https://docs.docker.com/compose/)
