"""HTTP transport using FastAPI (synchronous guard path)."""

from __future__ import annotations

import os

import uvicorn

from app.main import create_app

app = create_app()


if __name__ == "__main__":  # pragma: no cover - manual run helper
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8080"))
    reload = os.getenv("DEV_RELOAD", "false").lower() in {"1", "true", "yes"}
    uvicorn.run(
        "transports.http_fastapi_sync:app",
        host=host,
        port=port,
        reload=reload,
    )
