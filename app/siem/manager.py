"""
SIEM Manager

Manages event batching, queuing, and delivery to SIEM connectors.
Provides backpressure handling and async event processing.
"""

from __future__ import annotations

import asyncio
from collections import deque
from datetime import datetime
from typing import Any

import structlog

from app.siem.config import ConnectorType, SIEMConfig
from app.siem.connectors import (
    BaseSIEMConnector,
    ElasticsearchConnector,
    SIEMEvent,
    SplunkConnector,
    WebhookConnector,
)

logger = structlog.get_logger(__name__)


class SIEMMetrics:
    """Metrics for SIEM operations."""

    def __init__(self):
        self.events_queued = 0
        self.events_sent = 0
        self.events_failed = 0
        self.batches_sent = 0
        self.batches_failed = 0
        self.last_send_time: datetime | None = None
        self.last_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "events_queued": self.events_queued,
            "events_sent": self.events_sent,
            "events_failed": self.events_failed,
            "batches_sent": self.batches_sent,
            "batches_failed": self.batches_failed,
            "last_send_time": self.last_send_time.isoformat() if self.last_send_time else None,
            "last_error": self.last_error,
        }


class SIEMManager:
    """
    Manages SIEM event delivery with batching and async processing.

    Features:
    - Event batching (configurable batch size)
    - Periodic flushing (configurable interval)
    - Backpressure handling (queue size limit)
    - Multiple connector support
    - Metrics tracking

    Usage:
        config = SIEMConfig()
        manager = SIEMManager(config)
        await manager.start()

        # Queue events
        await manager.queue_event(event)

        # Graceful shutdown
        await manager.stop()
    """

    MAX_QUEUE_SIZE = 10000

    def __init__(self, config: SIEMConfig | None = None):
        self.config = config or SIEMConfig()
        self._queue: deque[SIEMEvent] = deque(maxlen=self.MAX_QUEUE_SIZE)
        self._connector: BaseSIEMConnector | None = None
        self._flush_task: asyncio.Task | None = None
        self._running = False
        self.metrics = SIEMMetrics()

    def _create_connector(self) -> BaseSIEMConnector | None:
        """Create the appropriate connector based on configuration."""
        if not self.config.enabled:
            return None

        connectors = {
            ConnectorType.SPLUNK: SplunkConnector,
            ConnectorType.ELASTICSEARCH: ElasticsearchConnector,
            ConnectorType.WEBHOOK: WebhookConnector,
        }

        connector_class = connectors.get(self.config.connector_type)
        if connector_class:
            return connector_class(self.config)

        return None

    async def start(self) -> None:
        """Start the SIEM manager and background flush task."""
        if not self.config.enabled:
            logger.info("siem_disabled")
            return

        # Validate configuration
        errors = self.config.validate_config()
        if errors:
            logger.error("siem_config_invalid", errors=errors)
            return

        # Create and connect the connector
        self._connector = self._create_connector()
        if self._connector:
            await self._connector.connect()

        # Start background flush task
        self._running = True
        self._flush_task = asyncio.create_task(self._flush_loop())

        logger.info(
            "siem_started",
            connector_type=self.config.connector_type.value,
            batch_size=self.config.batch_size,
            flush_interval=self.config.flush_interval,
        )

    async def stop(self) -> None:
        """Stop the SIEM manager gracefully."""
        self._running = False

        # Cancel flush task
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass

        # Flush remaining events
        await self._flush()

        # Disconnect connector
        if self._connector:
            await self._connector.disconnect()

        logger.info("siem_stopped", metrics=self.metrics.to_dict())

    async def queue_event(self, event: SIEMEvent) -> bool:
        """
        Queue an event for delivery.

        Returns True if queued, False if queue is full (backpressure).
        """
        if not self.config.enabled or not self._connector:
            return True  # Silently accept when disabled

        if len(self._queue) >= self.MAX_QUEUE_SIZE:
            logger.warning("siem_queue_full", queue_size=len(self._queue))
            return False

        self._queue.append(event)
        self.metrics.events_queued += 1

        # Flush if batch is full
        if len(self._queue) >= self.config.batch_size:
            asyncio.create_task(self._flush())

        return True

    def queue_finding(
        self,
        rule_id: str,
        action: str,
        severity: str,
        request_id: str | None = None,
        tenant: str | None = None,
        risk_score: int = 0,
        snippet_hash: str | None = None,
        blocked: bool = False,
        **metadata,
    ) -> bool:
        """
        Convenience method to queue a finding event.

        This is a sync wrapper that schedules the async queue_event.
        """
        event = SIEMEvent(
            event_type="finding",
            rule_id=rule_id,
            action=action,
            severity=severity,
            request_id=request_id,
            tenant=tenant,
            risk_score=risk_score,
            snippet_hash=snippet_hash,
            metadata={"blocked": blocked, **metadata},
        )

        # Use sync queue for now (called from sync context)
        if len(self._queue) >= self.MAX_QUEUE_SIZE:
            return False

        self._queue.append(event)
        self.metrics.events_queued += 1
        return True

    async def _flush(self) -> None:
        """Flush queued events to SIEM."""
        if not self._connector or not self._queue:
            return

        # Get batch of events
        batch: list[SIEMEvent] = []
        while self._queue and len(batch) < self.config.batch_size:
            batch.append(self._queue.popleft())

        if not batch:
            return

        # Send batch
        try:
            success = await self._connector.send_events(batch)

            if success:
                self.metrics.events_sent += len(batch)
                self.metrics.batches_sent += 1
                self.metrics.last_send_time = datetime.utcnow()
            else:
                self.metrics.events_failed += len(batch)
                self.metrics.batches_failed += 1
                self.metrics.last_error = "send_failed"

        except Exception as e:
            self.metrics.events_failed += len(batch)
            self.metrics.batches_failed += 1
            self.metrics.last_error = str(e)
            logger.error("siem_flush_error", error=str(e))

    async def _flush_loop(self) -> None:
        """Background task that periodically flushes events."""
        while self._running:
            try:
                await asyncio.sleep(self.config.flush_interval)
                await self._flush()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("siem_flush_loop_error", error=str(e))

    def get_metrics(self) -> dict[str, Any]:
        """Get current SIEM metrics."""
        return {
            **self.metrics.to_dict(),
            "queue_size": len(self._queue),
            "enabled": self.config.enabled,
            "connector_type": self.config.connector_type.value,
        }


# Singleton instance for global access
_manager: SIEMManager | None = None


def get_siem_manager() -> SIEMManager:
    """Get the global SIEM manager instance."""
    global _manager
    if _manager is None:
        _manager = SIEMManager()
    return _manager


async def init_siem_manager(config: SIEMConfig | None = None) -> SIEMManager:
    """Initialize and start the global SIEM manager."""
    global _manager
    _manager = SIEMManager(config)
    await _manager.start()
    return _manager


async def shutdown_siem_manager() -> None:
    """Shutdown the global SIEM manager."""
    global _manager
    if _manager:
        await _manager.stop()
        _manager = None




