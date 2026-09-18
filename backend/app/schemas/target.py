import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.target import TargetEnvironment, TargetKind


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    environment: TargetEnvironment
    kind: TargetKind
    base_url: str = Field(min_length=1, max_length=2048)


class TargetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    environment: TargetEnvironment
    kind: TargetKind
    base_url: str
    has_authorization: bool
    has_rules_of_engagement: bool
    created_at: datetime
