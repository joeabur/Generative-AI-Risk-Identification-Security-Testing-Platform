"""API key request/response shapes (docs/BUILD_SPEC.md §17.4)."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.api_key import ApiKeyScope
from app.models.organization import Role


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    # At least one scope. A key with no scopes would authenticate and be able
    # to do nothing, which is a confusing way to say "revoked".
    scopes: list[ApiKeyScope] = Field(min_length=1)
    expires_at: datetime | None = None


class ApiKeyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    key_id: str
    scopes: list[str]
    role: Role
    created_at: datetime
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked_at: datetime | None


class ApiKeyCreated(ApiKeyRead):
    """The one response that carries the secret.

    §17.4: shown once at creation and never again. There is no endpoint that
    returns it later, and no log line that contains it.
    """

    token: str
