"""
SIEM Configuration

Supports configuration via environment variables or direct instantiation.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class ConnectorType(str, Enum):
    """Supported SIEM connector types."""

    SPLUNK = "splunk"
    ELASTICSEARCH = "elasticsearch"
    WEBHOOK = "webhook"
    NONE = "none"


class SIEMConfig(BaseSettings):
    """
    SIEM integration configuration.

    Environment Variables:
        SIEM_ENABLED: Enable SIEM integration (default: false)
        SIEM_CONNECTOR_TYPE: splunk | elasticsearch | webhook | none

        # Splunk
        SIEM_SPLUNK_URL: Splunk HEC URL (e.g., https://splunk:8088)
        SIEM_SPLUNK_TOKEN: Splunk HEC token
        SIEM_SPLUNK_INDEX: Target index (default: main)
        SIEM_SPLUNK_SOURCE: Event source (default: egress-guard)
        SIEM_SPLUNK_SOURCETYPE: Source type (default: _json)
        SIEM_SPLUNK_VERIFY_SSL: Verify SSL certificate (default: true)

        # Elasticsearch
        SIEM_ELASTIC_URL: Elasticsearch URL (e.g., https://elastic:9200)
        SIEM_ELASTIC_INDEX: Target index (default: egress-guard-events)
        SIEM_ELASTIC_API_KEY: API key for authentication
        SIEM_ELASTIC_USERNAME: Basic auth username
        SIEM_ELASTIC_PASSWORD: Basic auth password
        SIEM_ELASTIC_VERIFY_SSL: Verify SSL certificate (default: true)

        # Webhook
        SIEM_WEBHOOK_URL: Webhook endpoint URL
        SIEM_WEBHOOK_METHOD: HTTP method (default: POST)
        SIEM_WEBHOOK_HEADERS: JSON string of additional headers
        SIEM_WEBHOOK_AUTH_HEADER: Authorization header value

        # Common
        SIEM_BATCH_SIZE: Events to batch before sending (default: 10)
        SIEM_FLUSH_INTERVAL: Seconds between flushes (default: 5)
        SIEM_RETRY_COUNT: Number of retries on failure (default: 3)
        SIEM_RETRY_DELAY: Seconds between retries (default: 1)
        SIEM_TIMEOUT: Request timeout in seconds (default: 10)
    """

    # General
    enabled: bool = Field(default=False, alias="SIEM_ENABLED")
    connector_type: ConnectorType = Field(
        default=ConnectorType.NONE,
        alias="SIEM_CONNECTOR_TYPE",
    )

    # Splunk HEC
    splunk_url: str | None = Field(default=None, alias="SIEM_SPLUNK_URL")
    splunk_token: SecretStr | None = Field(default=None, alias="SIEM_SPLUNK_TOKEN")
    splunk_index: str = Field(default="main", alias="SIEM_SPLUNK_INDEX")
    splunk_source: str = Field(default="egress-guard", alias="SIEM_SPLUNK_SOURCE")
    splunk_sourcetype: str = Field(default="_json", alias="SIEM_SPLUNK_SOURCETYPE")
    splunk_verify_ssl: bool = Field(default=True, alias="SIEM_SPLUNK_VERIFY_SSL")

    # Elasticsearch
    elastic_url: str | None = Field(default=None, alias="SIEM_ELASTIC_URL")
    elastic_index: str = Field(default="egress-guard-events", alias="SIEM_ELASTIC_INDEX")
    elastic_api_key: SecretStr | None = Field(default=None, alias="SIEM_ELASTIC_API_KEY")
    elastic_username: str | None = Field(default=None, alias="SIEM_ELASTIC_USERNAME")
    elastic_password: SecretStr | None = Field(default=None, alias="SIEM_ELASTIC_PASSWORD")
    elastic_verify_ssl: bool = Field(default=True, alias="SIEM_ELASTIC_VERIFY_SSL")

    # Webhook
    webhook_url: str | None = Field(default=None, alias="SIEM_WEBHOOK_URL")
    webhook_method: Literal["POST", "PUT"] = Field(default="POST", alias="SIEM_WEBHOOK_METHOD")
    webhook_headers: str | None = Field(default=None, alias="SIEM_WEBHOOK_HEADERS")
    webhook_auth_header: SecretStr | None = Field(default=None, alias="SIEM_WEBHOOK_AUTH_HEADER")

    # Batching & Retry
    batch_size: int = Field(default=10, alias="SIEM_BATCH_SIZE", ge=1, le=1000)
    flush_interval: float = Field(default=5.0, alias="SIEM_FLUSH_INTERVAL", ge=0.1)
    retry_count: int = Field(default=3, alias="SIEM_RETRY_COUNT", ge=0, le=10)
    retry_delay: float = Field(default=1.0, alias="SIEM_RETRY_DELAY", ge=0.1)
    timeout: float = Field(default=10.0, alias="SIEM_TIMEOUT", ge=1.0)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    def validate_config(self) -> list[str]:
        """Validate configuration for the selected connector type."""
        errors = []

        if not self.enabled:
            return errors

        if self.connector_type == ConnectorType.SPLUNK:
            if not self.splunk_url:
                errors.append("SIEM_SPLUNK_URL is required for Splunk connector")
            if not self.splunk_token:
                errors.append("SIEM_SPLUNK_TOKEN is required for Splunk connector")

        elif self.connector_type == ConnectorType.ELASTICSEARCH:
            if not self.elastic_url:
                errors.append("SIEM_ELASTIC_URL is required for Elasticsearch connector")
            if not self.elastic_api_key and not (self.elastic_username and self.elastic_password):
                errors.append(
                    "SIEM_ELASTIC_API_KEY or username/password required for Elasticsearch"
                )

        elif self.connector_type == ConnectorType.WEBHOOK:
            if not self.webhook_url:
                errors.append("SIEM_WEBHOOK_URL is required for Webhook connector")

        return errors
