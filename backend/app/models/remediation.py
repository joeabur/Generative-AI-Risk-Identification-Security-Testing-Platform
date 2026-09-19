"""Remediation tasks (docs/BUILD_SPEC.md §5, §26 Phase 9).

**One source of truth, deliberately.** A task carries the *work* — who owns
it, when it is due, what was decided — and the finding carries the *security
state*. There is no second status column here, because two state machines
over the same fact drift, and when they disagree nobody can say which one the
report should believe. A board groups by the finding's status; this table says
whose desk each row is on.
"""

import uuid
from datetime import date, datetime
from typing import TYPE_CHECKING

from sqlalchemy import Date, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.finding import Finding


class RemediationTask(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "remediation_tasks"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    # One task per finding. Tracking the same weakness as two pieces of work
    # is how two people fix it twice and a third closes it while it is still
    # there; `unique=True` is what makes "the task for this finding" a
    # question with one answer.
    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    summary: Mapped[str] = mapped_column(String(300), nullable=False)
    # Nullable: unassigned is a real and useful state, and inventing an owner
    # to avoid a null makes the board lie about who is on the hook.
    assignee_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    finding: Mapped["Finding"] = relationship(back_populates="remediation_task")
