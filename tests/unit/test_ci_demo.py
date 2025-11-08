from app.pipeline import GuardRequest, run_pipeline
from app.settings import Settings
from tests.regression.placeholders import get_placeholder


def test_ci_demo_block_secret() -> None:
    settings = Settings()
    response = get_placeholder("{{OPENAI_PROJECT_KEY}}")
    result = run_pipeline(GuardRequest(response=response), settings=settings)
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
