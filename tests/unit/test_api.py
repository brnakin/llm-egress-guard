from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app


def get_client() -> TestClient:
    app = create_app()
    return TestClient(app)


def test_guard_masks_email() -> None:
    client = get_client()
    payload = {"response": "Reach out via jane.doe@example.com"}
    resp = client.post("/guard", json=payload)
    body = resp.json()

    assert resp.status_code == 200
    assert "example.com" in body["response"]
    assert "jane.doe@example.com" not in body["response"]
    assert any(f["rule_id"] == "PII-EMAIL" for f in body["findings"])


def test_guard_blocks_jwt_with_safe_message() -> None:
    client = get_client()
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    resp = client.post("/guard", json={"response": f"Token: {token}"})
    body = resp.json()

    assert body["blocked"] is True
    assert "blocked" in body["response"].lower()
    assert any(f["rule_id"] == "SECRET-JWT" for f in body["findings"])


def test_guard_delinks_risky_url() -> None:
    client = get_client()
    resp = client.post("/guard", json={"response": "Try https://bit.ly/abcd1234 now"})
    body = resp.json()

    assert body["blocked"] is False
    assert "[redacted-url]" in body["response"]
    assert any(f["rule_id"] == "URL-SHORTENER" for f in body["findings"])
