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

    # Where evidence bundles and their hash-chained manifests are written
    # (docs/BUILD_SPEC.md §13). A path, not a URL: evidence never leaves the
    # deployment by default, and there is no public download URL for it.
    evidence_root: str = Field(default="var/evidence", alias="EVIDENCE_ROOT")

    # --- plugins (docs/BUILD_SPEC.md §16) ---------------------------------
    # Off unless an operator points at a configuration file that names the
    # packages allowed to load. `pip install` must not be what decides which
    # code runs inside the scope engine's process. `AEGIS_NO_PLUGINS=1` is the
    # `--no-plugins` switch: it wins over any configuration, so there is always
    # one thing to set when something has gone wrong.
    plugins_config: str | None = Field(default=None, alias="PLUGINS_CONFIG")
    no_plugins: bool = Field(default=False, alias="AEGIS_NO_PLUGINS")

    # --- outbound integrations (docs/BUILD_SPEC.md §27) ------------------
    # Which hosts a notification may reach, beyond the vendor hosts pinned in
    # `app/core/integrations/contract.py`. This lives in the environment, not
    # in the database, on purpose: an organization admin may choose which
    # Slack workspace to notify, but adding a brand-new outbound destination
    # is an operator decision. A generic webhook whose host is not listed here
    # is refused, so the database alone can never widen egress.
    notify_allowed_webhook_hosts: list[str] = Field(
        default_factory=list, alias="AEGIS_NOTIFY_ALLOWED_WEBHOOK_HOSTS"
    )
    notify_allowed_smtp_hosts: list[str] = Field(
        default_factory=list, alias="AEGIS_NOTIFY_ALLOWED_SMTP_HOSTS"
    )
    # Base URL used to build links back into the platform in a notification.
    # Absent means notifications carry no link rather than a guessed one.
    public_base_url: str | None = Field(default=None, alias="AEGIS_PUBLIC_BASE_URL")

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
