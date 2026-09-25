import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.ai_draft import DraftField


class DraftRequest(BaseModel):
    """Ask for a draft. Note there is no field for *which* value to set:
    the assistant proposes text, it never proposes a decision."""

    field: DraftField
    scan_result_id: uuid.UUID | None = None


class DraftRead(BaseModel):
    """A draft, always labelled as one.

    `accepted` is what separates a model's suggestion from the record: until
    a human sets it, this text appears in no report and no finding.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    run_id: uuid.UUID
    scan_result_id: uuid.UUID | None
    field: DraftField
    content: str
    provider: str
    model: str
    prompt_template_id: str
    prompt_template_version: str
    accepted_at: datetime | None
    created_at: datetime


class AssistantStatus(BaseModel):
    """Whether the AI layer is available, so a UI can say so plainly rather
    than offering a button that will fail."""

    configured: bool
    autonomy_mode: str
    provider: str | None = None
    model: str | None = None
    reason: str | None = Field(
        default=None,
        description="Why the assistant is unavailable, when it is.",
    )
