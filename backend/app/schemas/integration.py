"""Notification channel request/response shapes (docs/BUILD_SPEC.md §27).

`ChannelRead` carries `endpoint_env_var` and `endpoint_redacted` and never an
endpoint URL or a secret, because there is no endpoint that returns one. That
is not an oversight to be fixed later: the value is not in the database to
return.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.integrations.contract import ChannelKind, EventType
from app.core.integrations.policy import valid_env_var_name
from app.core.probes.models import Severity


class ChannelCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    kind: ChannelKind
    events: list[EventType] = Field(min_length=1)
    min_severity: Severity | None = None
    enabled: bool = True

    # Webhook kinds. The variable *name*; the value stays in the environment.
    endpoint_env_var: str | None = Field(default=None, max_length=128)
    signing_secret_env_var: str | None = Field(default=None, max_length=128)

    # Email.
    smtp_host: str | None = Field(default=None, max_length=255)
    smtp_port: int | None = Field(default=None, ge=1, le=65535)
    smtp_username: str | None = Field(default=None, max_length=255)
    smtp_password_env_var: str | None = Field(default=None, max_length=128)
    from_address: str | None = Field(default=None, max_length=320)
    recipients: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def check_kind_fields(self) -> "ChannelCreate":
        """Reject a channel that could never deliver, at creation time.

        A channel that fails only on its first real event is a channel nobody
        finds out about until the incident it was supposed to announce.
        """
        for name in (
            self.endpoint_env_var,
            self.signing_secret_env_var,
            self.smtp_password_env_var,
        ):
            if name is not None and not valid_env_var_name(name):
                raise ValueError(
                    f"{name!r} is not a valid environment variable name; a channel "
                    "references its secret by variable name, not by value"
                )

        if self.kind is ChannelKind.EMAIL_SMTP:
            if not self.smtp_host:
                raise ValueError("smtp_host is required for an email channel")
            if not self.from_address:
                raise ValueError("from_address is required for an email channel")
            if not self.recipients:
                raise ValueError("an email channel needs at least one recipient")
            if self.endpoint_env_var:
                raise ValueError("endpoint_env_var does not apply to an email channel")
        else:
            if not self.endpoint_env_var:
                raise ValueError(f"endpoint_env_var is required for a {self.kind.value} channel")
            if self.smtp_host or self.recipients:
                raise ValueError("SMTP fields do not apply to a webhook channel")
            if self.kind is ChannelKind.GENERIC_WEBHOOK and not self.signing_secret_env_var:
                raise ValueError(
                    "signing_secret_env_var is required for a generic webhook: a receiver "
                    "that cannot verify a signature cannot tell our POST from anyone else's"
                )
            if self.kind is not ChannelKind.GENERIC_WEBHOOK and self.signing_secret_env_var:
                raise ValueError(
                    f"a {self.kind.value} channel is not signed; the vendor does not verify one"
                )
        return self


class ChannelUpdate(BaseModel):
    """Only the fields it is safe to change in place.

    Not the kind and not the endpoint: changing where a channel points is
    creating a different channel, and doing it in place would leave the
    delivery history attached to a destination it never reached.
    """

    events: list[EventType] | None = Field(default=None, min_length=1)
    min_severity: Severity | None = None
    enabled: bool | None = None
    recipients: list[str] | None = None


class ChannelRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    kind: str
    events: list[str]
    min_severity: str | None
    enabled: bool
    endpoint_env_var: str | None
    #: Scheme, host and path shape. Never the token-bearing path itself.
    endpoint_redacted: str | None
    signing_secret_env_var: str | None
    smtp_host: str | None
    smtp_port: int | None
    smtp_username: str | None
    from_address: str | None
    recipients: list[str] | None
    created_at: datetime


class DeliveryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    channel_id: uuid.UUID
    event_type: str
    resource_type: str | None
    resource_id: str | None
    status: str
    attempts: int
    status_code: int | None
    last_error: str | None
    next_attempt_at: datetime | None
    delivered_at: datetime | None
    created_at: datetime


class ChannelTestResult(BaseModel):
    """Outcome of a deliberate test delivery.

    `detail` is the already-redacted delivery detail, so an operator can see
    *why* a channel is broken without the response body or the URL.
    """

    delivered: bool
    status_code: int | None
    detail: str
    delivery_id: uuid.UUID | None
