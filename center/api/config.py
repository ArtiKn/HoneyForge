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


@lru_cache
def get_settings() -> Settings:
    return Settings()

