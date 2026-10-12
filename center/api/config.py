"""Control API settings (task 2.1)."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", case_sensitive=False)

    telemetry_path: str = "/assets/v2/init"


settings = Settings()
