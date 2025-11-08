from app.pipeline import GuardRequest, run_pipeline
from app.settings import Settings


def test_ci_demo_block_secret() -> None:
    settings = Settings()
    result = run_pipeline(
        GuardRequest(response="sk-proj-1A2b3C4d5E6f7G8h9I0jK1lM2nOpQrStUvWxYz12345678"),
        settings=settings,
    )
    assert result.blocked is True
    assert any(f.rule_id == "SECRET-HIGH-ENTROPY" for f in result.findings)


def test_ci_demo_mask_pan() -> None:
    settings = Settings()
    result = run_pipeline(
        GuardRequest(response="Card 4111 1111 1111 1111 exp 09/27"),
        settings=settings,
    )
    assert result.blocked is True
    assert any(f.rule_id == "PII-PAN" for f in result.findings)
