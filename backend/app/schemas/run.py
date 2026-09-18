import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.assessment_run import RunEventKind, RunStatus


class RunCreate(BaseModel):
    target_id: uuid.UUID
    profile: str = Field(default="connectivity", max_length=50)
    safe_mode: bool = True
    # docs/BUILD_SPEC.md §14: the operator must affirm authorization, and who
    # affirmed it and when is stored with the run.
    authorization_confirmed: bool = False


class RunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    target_id: uuid.UUID
    status: RunStatus
    profile: str
    safe_mode: bool
    checks_total: int
    checks_completed: int
    requests_used: int
    requests_blocked: int
    authorization_digest: str | None
    roe_digest: str | None
    halted_reason: str | None
    error_message: str | None
    queued_at: datetime | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime


class RunEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    seq: int
    kind: RunEventKind
    message: str
    payload: dict[str, Any] | None
    occurred_at: datetime
