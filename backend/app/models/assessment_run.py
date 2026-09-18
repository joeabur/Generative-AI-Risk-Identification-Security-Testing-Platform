import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Identity,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.target import Target


class RunStatus(enum.StrEnum):
    """docs/BUILD_SPEC.md §15. `EXPIRED` is distinct from `CANCELLED`: it
    means the target's authorization window closed, which the scope engine
    detects mid-flight and halts on — not something an operator chose."""

    DRAFT = "draft"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


TERMINAL_STATUSES = frozenset(
    {RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELLED, RunStatus.EXPIRED}
)


class RunEventKind(enum.StrEnum):
    QUEUED = "queued"
    STARTED = "started"
    CHECK_STARTED = "check_started"
    CHECK_COMPLETED = "check_completed"
    REQUEST_BLOCKED = "request_blocked"
    HALTED = "halted"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AssessmentRun(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One execution against one target (docs/BUILD_SPEC.md §5).

    `authorization_digest` and `roe_digest` are captured when the run starts,
    not read live at report time: §5.2 requires the authorization record and
    Rules of Engagement to be hashed into every report, and an RoE edited
    after a run finished must not silently rewrite what that run was
    authorized to do.
    """

    __tablename__ = "assessment_runs"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[RunStatus] = mapped_column(
        Enum(RunStatus, name="run_status_enum"), nullable=False, default=RunStatus.DRAFT
    )
    profile: Mapped[str] = mapped_column(String(50), nullable=False, default="connectivity")
    safe_mode: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    authorization_confirmed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    authorization_confirmed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    queued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    checks_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    checks_completed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    requests_used: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    requests_blocked: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    authorization_digest: Mapped[str | None] = mapped_column(String(71), nullable=True)
    roe_digest: Mapped[str | None] = mapped_column(String(71), nullable=True)

    halted_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    celery_task_id: Mapped[str | None] = mapped_column(String(155), nullable=True)

    target: Mapped["Target"] = relationship()
    events: Mapped[list["RunEvent"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )


class RunEvent(UUIDPrimaryKeyMixin, Base):
    """Append-only progress log for a run.

    This is what the SSE stream serves, so progress shown in a browser is
    always a replay of something that actually happened rather than a
    client-side animation (docs/BUILD_SPEC.md §16: "Do not fake progress").
    """

    __tablename__ = "run_events"

    seq: Mapped[int] = mapped_column(BigInteger, Identity(), unique=True, nullable=False)
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment_runs.id", ondelete="CASCADE"), nullable=False
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    kind: Mapped[RunEventKind] = mapped_column(
        Enum(RunEventKind, name="run_event_kind_enum"), nullable=False
    )
    message: Mapped[str] = mapped_column(String(1000), nullable=False)
    payload: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    run: Mapped["AssessmentRun"] = relationship(back_populates="events")
