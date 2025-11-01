"""HTTP transport using FastAPI (synchronous guard path)."""

from __future__ import annotations

import uvicorn

from app.main import create_app

app = create_app()


if __name__ == "__main__":  # pragma: no cover - manual run helper
    uvicorn.run("transports.http_fastapi_sync:app", host="0.0.0.0", port=8080, reload=True)
