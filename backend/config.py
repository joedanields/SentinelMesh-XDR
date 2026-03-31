from functools import lru_cache
from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)

    # Application
    app_name: str = Field(default="SentinelMesh XDR")
    app_version: str = Field(default="1.0.0")
    debug: bool = Field(default=False)
    environment: str = Field(default="development")  # development | staging | production

    # Database
    database_url: str = Field(default="sqlite+aiosqlite:///./sentinelmesh.db")

    # Redis
    redis_url: str = Field(default="redis://localhost:6379/0")

    # Ollama (LLM inference)
    ollama_url: str = Field(default="http://localhost:11434")

    # JWT
    jwt_secret_key: str = Field(default="change-me-in-production-use-a-long-random-string")
    jwt_algorithm: str = Field(default="HS256")
    jwt_expire_minutes: int = Field(default=30)

    # Logging
    log_level: str = Field(default="INFO")
    log_file: str = Field(default="logs/sentinelmesh.log")

    # Rate limiting
    rate_limit_requests: int = Field(default=100)
    rate_limit_window: int = Field(default=60)

    # Ingestion
    max_log_batch_size: int = Field(default=1000)

    # CORS
    cors_origins: List[str] = Field(default=["http://localhost:3000", "http://localhost:5173"])
    cors_allow_credentials: bool = Field(default=True)

    # API
    api_prefix: str = Field(default="/api/v1")


@lru_cache()
def get_settings() -> Settings:
    return Settings()
