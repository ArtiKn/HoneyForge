"""Control API settings (task 2.1)."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables or ``.env``."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    telemetry_path: str = "/assets/v2/init"

    app_name: str = "HoneyForge API"
    debug: bool = False
    database_url: str = Field(
        default="postgresql+asyncpg://honeyforge:honeyforge@localhost:5432/honeyforge",
        validation_alias="DATABASE_URL",
    )
    cors_origins: list[str] = ["https://localhost", "http://localhost"]
    agent_token: str = Field(default="change-me", validation_alias="AGENT_TOKEN")
    jwt_secret: str = Field(default="change-me", validation_alias="JWT_SECRET")
    access_token_expire_minutes: int = Field(
        default=480, validation_alias="ACCESS_TOKEN_EXPIRE_MINUTES"
    )
    operator_username: str = Field(default="operator", validation_alias="OPERATOR_USERNAME")
    operator_password: str = Field(
        default="change-me-in-production", validation_alias="OPERATOR_PASSWORD"
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


def validate_deployment_secrets(settings: Settings) -> None:
    """Refuse known placeholders before the service starts accepting traffic."""

    placeholders = {"", "change-me", "change-me-in-production"}
    if settings.jwt_secret in placeholders or len(settings.jwt_secret) < 24:
        raise RuntimeError(
            "JWT_SECRET must be a deployment-provided value of at least 24 characters"
        )
    if settings.operator_password in placeholders or len(settings.operator_password) < 12:
        raise RuntimeError(
            "OPERATOR_PASSWORD must be a deployment-provided value of at least 12 characters"
        )

