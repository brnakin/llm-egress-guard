"""FastAPI application entrypoint."""

from __future__ import annotations

import logging
from typing import Annotated, Any

import structlog
from fastapi import Depends, FastAPI, HTTPException, Response
from pydantic import BaseModel, Field

from app import metrics
from app.pipeline import GuardRequest, run_pipeline
from app.settings import Settings, get_settings

SettingsDep = Annotated[Settings, Depends(get_settings)]


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

    @app.get("/healthz", response_class=Response)
    async def healthz() -> Response:
        return Response(content="ok\n", media_type="text/plain")

    @app.post("/guard", response_model=GuardResponseModel)
    async def guard_endpoint(
        request: GuardRequestModel,
        settings: SettingsDep,
    ) -> GuardResponseModel:
        result = run_pipeline(
            GuardRequest(
                response=request.response,
                policy_id=request.policy_id,
                metadata=request.metadata,
            ),
            settings=settings,
        )
        return GuardResponseModel(**result.asdict())

    @app.get("/metrics")
    async def metrics_endpoint(settings: SettingsDep) -> Response:
        if not settings.metrics_enabled:
            raise HTTPException(status_code=404, detail="metrics disabled")
        payload, content_type = metrics.render_metrics()
        return Response(content=payload, media_type=content_type)

    return app


app = create_app()
