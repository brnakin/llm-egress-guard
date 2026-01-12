"""FastAPI application entrypoint with security hardening."""

from __future__ import annotations

import asyncio
import logging
from typing import Annotated, Any

import structlog
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from app import metrics
from app.pipeline import GuardRequest, run_pipeline
from app.settings import Settings, get_settings

SettingsDep = Annotated[Settings, Depends(get_settings)]

# Security logger for auth/limit events
_security_logger = structlog.get_logger("security")


async def verify_api_key(
    request: Request,
    settings: SettingsDep,
    x_api_key: str | None = Header(default=None),
) -> None:
    """Simple API key gate for non-health endpoints."""
    if not settings.require_api_key:
        return
    if not settings.api_key:
        _security_logger.error(
            "auth_config_error",
            path=str(request.url.path),
            reason="api_key_not_configured",
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="API key not configured",
        )
    if x_api_key != settings.api_key:
        _security_logger.warning(
            "auth_failure",
            path=str(request.url.path),
            reason="invalid_api_key",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="unauthorized",
        )


def configure_logging(log_level: str) -> None:
    numeric_level = logging.getLevelName(log_level.upper())
    if isinstance(numeric_level, str):
        numeric_level = logging.INFO
    logging.basicConfig(level=numeric_level, format="%(message)s")
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        cache_logger_on_first_use=True,
    )


class GuardRequestModel(BaseModel):
    response: str
    policy_id: str = Field(default="default")
    metadata: dict[str, Any] = Field(default_factory=dict)


class GuardResponseModel(BaseModel):
    response: str
    findings: list[dict[str, Any]]
    blocked: bool
    risk_score: int
    policy_id: str
    latency_ms: float
    version: str


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    app = FastAPI(title="LLM Egress Guard", version=settings.model_version)
    guard_semaphore = asyncio.Semaphore(settings.max_concurrent_guard_requests)

    @app.middleware("http")
    async def enforce_limits(request: Request, call_next):
        if request.url.path == "/guard":
            limit = settings.max_request_size_bytes
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    size = int(content_length)
                    if size > limit:
                        _security_logger.warning(
                            "request_rejected",
                            path=str(request.url.path),
                            reason="body_too_large",
                            size=size,
                            limit=limit,
                        )
                        return Response(
                            content="request too large",
                            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            media_type="text/plain",
                        )
                except ValueError:
                    pass  # Ignore malformed header and fall through
        return await call_next(request)

    @app.get("/healthz", response_class=Response)
    async def healthz() -> Response:
        return Response(content="ok\n", media_type="text/plain")

    @app.post("/guard", response_model=GuardResponseModel)
    async def guard_endpoint(
        request: GuardRequestModel,
        settings: SettingsDep,
        _: None = Depends(verify_api_key),
    ) -> GuardResponseModel:
        async with guard_semaphore:
            try:
                result = await asyncio.wait_for(
                    asyncio.to_thread(
                        run_pipeline,
                        GuardRequest(
                            response=request.response,
                            policy_id=request.policy_id,
                            metadata=request.metadata,
                        ),
                        settings=settings,
                    ),
                    timeout=settings.request_timeout_seconds,
                )
                return GuardResponseModel(**result.asdict())
            except asyncio.TimeoutError:
                _security_logger.warning(
                    "request_timeout",
                    path="/guard",
                    timeout_seconds=settings.request_timeout_seconds,
                )
                raise HTTPException(
                    status_code=status.HTTP_408_REQUEST_TIMEOUT,
                    detail="request timeout",
                ) from None

    @app.get("/metrics")
    async def metrics_endpoint(
        settings: SettingsDep, _: None = Depends(verify_api_key)
    ) -> Response:
        if not settings.metrics_enabled:
            raise HTTPException(status_code=404, detail="metrics disabled")
        payload, content_type = metrics.render_metrics()
        return Response(content=payload, media_type=content_type)

    return app


app = create_app()
