import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.fields import Email


class AuthorizationGrant(BaseModel):
    authorized_by_name: str = Field(min_length=1, max_length=200)
    authorized_by_role: str = Field(min_length=1, max_length=100)
    authorized_by_email: Email
    reference: str = Field(min_length=1, max_length=500)
    valid_from: datetime
    valid_until: datetime

    @model_validator(mode="after")
    def _valid_until_after_valid_from(self) -> "AuthorizationGrant":
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be after valid_from")
        return self


class AuthorizationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_id: uuid.UUID
    authorized_by_name: str
    authorized_by_role: str
    authorized_by_email: str
    reference: str
    valid_from: datetime
    valid_until: datetime
    accepted_by_user_id: uuid.UUID
    accepted_at: datetime
