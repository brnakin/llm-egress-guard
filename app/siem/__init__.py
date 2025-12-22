"""
SIEM Integration Module for LLM Egress Guard

Provides connectors for sending security events to:
- Splunk (via HTTP Event Collector)
- Elasticsearch (via Bulk API)
- Generic Webhooks (HTTP POST)

Usage:
    from app.siem import SIEMManager, SIEMConfig

    # Configure via environment or code
    config = SIEMConfig(
        enabled=True,
        connector_type="splunk",
        splunk_url="https://splunk.example.com:8088",
        splunk_token="your-hec-token",
    )
    
    manager = SIEMManager(config)
    await manager.send_event(finding)
"""

from app.siem.config import SIEMConfig
from app.siem.manager import SIEMManager
from app.siem.connectors import (
    BaseSIEMConnector,
    SplunkConnector,
    ElasticsearchConnector,
    WebhookConnector,
)

__all__ = [
    "SIEMConfig",
    "SIEMManager",
    "BaseSIEMConnector",
    "SplunkConnector",
    "ElasticsearchConnector",
    "WebhookConnector",
]

