"""
SIEM Connectors

Implementations for different SIEM systems:
- Splunk (HTTP Event Collector)
- Elasticsearch (Bulk API)
- Webhook (Generic HTTP POST)
"""

from __future__ import annotations

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

import httpx
import structlog

from app.siem.config import SIEMConfig

logger = structlog.get_logger(__name__)


class SIEMEvent:
    """A security event to send to SIEM."""
    
    def __init__(
        self,
        event_type: str,
        rule_id: str,
        action: str,
        severity: str,
        request_id: str | None = None,
        tenant: str | None = None,
        risk_score: int = 0,
        snippet_hash: str | None = None,
        metadata: dict[str, Any] | None = None,
    ):
        self.timestamp = datetime.utcnow().isoformat() + "Z"
        self.event_type = event_type
        self.rule_id = rule_id
        self.action = action
        self.severity = severity
        self.request_id = request_id
        self.tenant = tenant
        self.risk_score = risk_score
        self.snippet_hash = snippet_hash
        self.metadata = metadata or {}
    
    def to_dict(self) -> dict[str, Any]:
        """Convert event to dictionary."""
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "rule_id": self.rule_id,
            "action": self.action,
            "severity": self.severity,
            "request_id": self.request_id,
            "tenant": self.tenant,
            "risk_score": self.risk_score,
            "snippet_hash": self.snippet_hash,
            **self.metadata,
        }


class BaseSIEMConnector(ABC):
    """Base class for SIEM connectors."""
    
    def __init__(self, config: SIEMConfig):
        self.config = config
        self._client: httpx.AsyncClient | None = None
    
    async def __aenter__(self):
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.disconnect()
    
    async def connect(self) -> None:
        """Initialize the HTTP client."""
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.timeout),
            verify=self._get_ssl_verify(),
        )
    
    async def disconnect(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    @abstractmethod
    def _get_ssl_verify(self) -> bool:
        """Get SSL verification setting."""
        pass
    
    @abstractmethod
    async def send_events(self, events: list[SIEMEvent]) -> bool:
        """Send events to the SIEM system."""
        pass
    
    async def send_event(self, event: SIEMEvent) -> bool:
        """Send a single event."""
        return await self.send_events([event])
    
    async def _retry_request(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> httpx.Response | None:
        """Execute request with retry logic."""
        last_error = None
        
        for attempt in range(self.config.retry_count + 1):
            try:
                if not self._client:
                    await self.connect()
                
                response = await self._client.request(method, url, **kwargs)
                
                if response.status_code < 400:
                    return response
                
                logger.warning(
                    "siem_request_failed",
                    status_code=response.status_code,
                    attempt=attempt + 1,
                    url=url,
                )
                
            except Exception as e:
                last_error = e
                logger.warning(
                    "siem_request_error",
                    error=str(e),
                    attempt=attempt + 1,
                    url=url,
                )
            
            if attempt < self.config.retry_count:
                await asyncio.sleep(self.config.retry_delay * (attempt + 1))
        
        logger.error(
            "siem_request_exhausted",
            url=url,
            retries=self.config.retry_count,
            last_error=str(last_error) if last_error else None,
        )
        return None


class SplunkConnector(BaseSIEMConnector):
    """
    Splunk HTTP Event Collector (HEC) connector.
    
    Sends events to Splunk's HEC endpoint.
    
    Configuration:
        SIEM_SPLUNK_URL: HEC URL (e.g., https://splunk:8088/services/collector/event)
        SIEM_SPLUNK_TOKEN: HEC token
        SIEM_SPLUNK_INDEX: Target index
        SIEM_SPLUNK_SOURCE: Event source
        SIEM_SPLUNK_SOURCETYPE: Source type
    """
    
    def _get_ssl_verify(self) -> bool:
        return self.config.splunk_verify_ssl
    
    def _get_headers(self) -> dict[str, str]:
        """Get request headers for Splunk HEC."""
        token = self.config.splunk_token.get_secret_value() if self.config.splunk_token else ""
        return {
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json",
        }
    
    def _format_event(self, event: SIEMEvent) -> dict[str, Any]:
        """Format event for Splunk HEC."""
        return {
            "time": datetime.fromisoformat(event.timestamp.replace("Z", "+00:00")).timestamp(),
            "host": "egress-guard",
            "source": self.config.splunk_source,
            "sourcetype": self.config.splunk_sourcetype,
            "index": self.config.splunk_index,
            "event": event.to_dict(),
        }
    
    async def send_events(self, events: list[SIEMEvent]) -> bool:
        """Send events to Splunk HEC."""
        if not events:
            return True
        
        if not self.config.splunk_url:
            logger.error("siem_splunk_no_url")
            return False
        
        # Format events for HEC (newline-delimited JSON)
        payload = "\n".join(
            json.dumps(self._format_event(e)) for e in events
        )
        
        # Ensure URL ends with correct path
        url = self.config.splunk_url.rstrip("/")
        if not url.endswith("/services/collector/event"):
            url = f"{url}/services/collector/event"
        
        response = await self._retry_request(
            "POST",
            url,
            content=payload,
            headers=self._get_headers(),
        )
        
        if response and response.status_code == 200:
            logger.info(
                "siem_splunk_sent",
                event_count=len(events),
            )
            return True
        
        return False


class ElasticsearchConnector(BaseSIEMConnector):
    """
    Elasticsearch Bulk API connector.
    
    Sends events to Elasticsearch using the Bulk API.
    
    Configuration:
        SIEM_ELASTIC_URL: Elasticsearch URL
        SIEM_ELASTIC_INDEX: Target index
        SIEM_ELASTIC_API_KEY: API key (preferred)
        SIEM_ELASTIC_USERNAME/PASSWORD: Basic auth (alternative)
    """
    
    def _get_ssl_verify(self) -> bool:
        return self.config.elastic_verify_ssl
    
    def _get_headers(self) -> dict[str, str]:
        """Get request headers for Elasticsearch."""
        headers = {"Content-Type": "application/x-ndjson"}
        
        if self.config.elastic_api_key:
            headers["Authorization"] = f"ApiKey {self.config.elastic_api_key.get_secret_value()}"
        
        return headers
    
    def _get_auth(self) -> tuple[str, str] | None:
        """Get basic auth credentials."""
        if self.config.elastic_username and self.config.elastic_password:
            return (
                self.config.elastic_username,
                self.config.elastic_password.get_secret_value(),
            )
        return None
    
    def _format_bulk_payload(self, events: list[SIEMEvent]) -> str:
        """Format events for Elasticsearch Bulk API."""
        lines = []
        index_name = f"{self.config.elastic_index}-{datetime.utcnow().strftime('%Y.%m.%d')}"
        
        for event in events:
            # Index action
            lines.append(json.dumps({"index": {"_index": index_name}}))
            # Document
            doc = event.to_dict()
            doc["@timestamp"] = doc.pop("timestamp")
            lines.append(json.dumps(doc))
        
        return "\n".join(lines) + "\n"
    
    async def send_events(self, events: list[SIEMEvent]) -> bool:
        """Send events to Elasticsearch."""
        if not events:
            return True
        
        if not self.config.elastic_url:
            logger.error("siem_elastic_no_url")
            return False
        
        url = f"{self.config.elastic_url.rstrip('/')}/_bulk"
        payload = self._format_bulk_payload(events)
        
        response = await self._retry_request(
            "POST",
            url,
            content=payload,
            headers=self._get_headers(),
            auth=self._get_auth(),
        )
        
        if response and response.status_code in (200, 201):
            result = response.json()
            if not result.get("errors"):
                logger.info(
                    "siem_elastic_sent",
                    event_count=len(events),
                )
                return True
            else:
                logger.warning(
                    "siem_elastic_partial_failure",
                    errors=result.get("items", []),
                )
        
        return False


class WebhookConnector(BaseSIEMConnector):
    """
    Generic Webhook connector.
    
    Sends events to any HTTP endpoint.
    
    Configuration:
        SIEM_WEBHOOK_URL: Target URL
        SIEM_WEBHOOK_METHOD: HTTP method (POST/PUT)
        SIEM_WEBHOOK_HEADERS: Additional headers (JSON string)
        SIEM_WEBHOOK_AUTH_HEADER: Authorization header value
    """
    
    def _get_ssl_verify(self) -> bool:
        return True  # Always verify for webhooks
    
    def _get_headers(self) -> dict[str, str]:
        """Get request headers for webhook."""
        headers = {"Content-Type": "application/json"}
        
        # Add custom headers
        if self.config.webhook_headers:
            try:
                custom_headers = json.loads(self.config.webhook_headers)
                headers.update(custom_headers)
            except json.JSONDecodeError:
                logger.warning("siem_webhook_invalid_headers")
        
        # Add auth header
        if self.config.webhook_auth_header:
            headers["Authorization"] = self.config.webhook_auth_header.get_secret_value()
        
        return headers
    
    async def send_events(self, events: list[SIEMEvent]) -> bool:
        """Send events to webhook."""
        if not events:
            return True
        
        if not self.config.webhook_url:
            logger.error("siem_webhook_no_url")
            return False
        
        # Send as array of events
        payload = {
            "source": "egress-guard",
            "event_count": len(events),
            "events": [e.to_dict() for e in events],
        }
        
        response = await self._retry_request(
            self.config.webhook_method,
            self.config.webhook_url,
            json=payload,
            headers=self._get_headers(),
        )
        
        if response and response.status_code < 400:
            logger.info(
                "siem_webhook_sent",
                event_count=len(events),
                status_code=response.status_code,
            )
            return True
        
        return False

