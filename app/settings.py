"""Application settings loaded from environment variables."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment-driven configuration with sensible defaults."""

    policy_file: Path = Field(default=Path("config/policy.yaml"), alias="POLICY_FILE")
    log_level: str = Field(default="info", alias="LOG_LEVEL")
    metrics_enabled: bool = Field(default=True, alias="METRICS_ENABLED")
    feature_ml_preclf: bool = Field(default=True, alias="FEATURE_ML_PRECLF")
    feature_ml_validator: bool = Field(default=False, alias="FEATURE_ML_VALIDATOR")
    feature_context_parsing: bool = Field(default=True, alias="FEATURE_CONTEXT_PARSING")
    preclf_model_path: Path = Field(
        default=Path("models/preclf_v1.joblib"), alias="PRECLF_MODEL_PATH"
    )
    shadow_mode: bool = Field(default=False, alias="SHADOW_MODE")
    model_version: str = Field(default="0.2.0", alias="MODEL_VERSION")

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
