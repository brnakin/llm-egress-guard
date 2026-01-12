"""Application settings loaded from environment variables."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment-driven configuration with sensible defaults."""

    # Core settings
    policy_file: Path = Field(default=Path("config/policy.yaml"), alias="POLICY_FILE")
    log_level: str = Field(default="info", alias="LOG_LEVEL")
    metrics_enabled: bool = Field(default=True, alias="METRICS_ENABLED")
    model_version: str = Field(default="0.2.0", alias="MODEL_VERSION")

    # Feature flags
    feature_ml_preclf: bool = Field(default=True, alias="FEATURE_ML_PRECLF")
    feature_ml_validator: bool = Field(default=True, alias="FEATURE_ML_VALIDATOR")
    feature_context_parsing: bool = Field(default=True, alias="FEATURE_CONTEXT_PARSING")
    shadow_mode: bool = Field(default=False, alias="SHADOW_MODE")

    # Security & Auth (OWASP A01/A05)
    require_api_key: bool = Field(default=False, alias="REQUIRE_API_KEY")
    api_key: str | None = Field(default=None, alias="API_KEY")

    # DoS Protection (OWASP A11)
    max_concurrent_guard_requests: int = Field(default=10, alias="MAX_CONCURRENT_GUARD_REQUESTS")
    max_request_size_bytes: int = Field(default=524288, alias="MAX_REQUEST_SIZE_BYTES")  # 512KB
    request_timeout_seconds: float = Field(default=30.0, alias="REQUEST_TIMEOUT_SECONDS")

    # Model paths & integrity (OWASP A08)
    preclf_model_path: Path = Field(
        default=Path("models/preclf_v1.joblib"), alias="PRECLF_MODEL_PATH"
    )
    preclf_manifest_path: Path = Field(
        default=Path("models/preclf_v1.manifest.json"), alias="PRECLF_MANIFEST_PATH"
    )
    enforce_model_integrity: bool = Field(default=True, alias="ENFORCE_MODEL_INTEGRITY")

    # Policy downgrade controls (OWASP A04)
    allow_explain_only_bypass: bool = Field(default=False, alias="ALLOW_EXPLAIN_ONLY_BYPASS")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    @property
    def policy_path(self) -> Path:
        return self.policy_file


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()
