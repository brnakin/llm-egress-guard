"""AWS Lambda adapter placeholder."""

from __future__ import annotations

from typing import Any, Dict

from app.main import create_app

app = create_app()


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:  # pragma: no cover - stub
    del event, context
    raise NotImplementedError("Lambda adapter will be implemented in a future sprint.")
