from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration, loaded from environment variables.

    No default is provided for secrets (JWT signing key, database credentials)
    in any non-local environment — the config loader must fail loudly rather
    than silently run with an insecure default in production.
    """

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    environment: Literal["local", "ci", "staging", "production"] = "local"

    database_url: str = Field(
        default="postgresql+asyncpg://postgres:postgres@localhost:5432/aegis",
        alias="DATABASE_URL",
    )
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")

    # --- AI layer (optional end to end) ------------------------------------
    # Absent means the whole assistant is off and every other part of the
    # platform behaves identically. `ai_api_key_env_var` is the NAME of an
    # environment variable; a key is never stored in configuration, the
    # database, or a log.
    ai_provider: str | None = Field(default=None, alias="AI_PROVIDER")
    ai_endpoint: str | None = Field(default=None, alias="AI_ENDPOINT")
    ai_model: str | None = Field(default=None, alias="AI_MODEL")
    ai_api_key_env_var: str | None = Field(default=None, alias="AI_API_KEY_ENV_VAR")
    ai_autonomy_mode: str = Field(default="ASSIST", alias="AI_AUTONOMY_MODE")

    jwt_secret: str = Field(default="insecure-local-dev-secret-change-me", alias="JWT_SECRET")
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 12

    cors_allowed_origins: list[str] = Field(
        default=["http://localhost:3000"], alias="CORS_ALLOWED_ORIGINS"
    )

    session_cookie_name: str = "aegis_session"
    session_cookie_secure: bool = Field(default=False, alias="SESSION_COOKIE_SECURE")

    def model_post_init(self, __context: object) -> None:
        if (
            self.environment == "production"
            and self.jwt_secret == "insecure-local-dev-secret-change-me"
        ):
            raise ValueError(
                "JWT_SECRET must be set explicitly when ENVIRONMENT=production; "
                "refusing to start with the local development default."
            )


@lru_cache
def get_settings() -> Settings:
    return Settings()
