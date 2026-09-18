import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.target import Target


class Authorization(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """docs/BUILD_SPEC.md §5.2. One authorization record per target for
    Phase 2 (`target_id` is unique) — a full grant history/versioning model
    is deferred; granting a new one for the same target replaces the old
    one rather than layering, which is the simpler and safer default until
    there's a documented need for overlapping/historical grants.
    """

    __tablename__ = "authorizations"

    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    authorized_by_name: Mapped[str] = mapped_column(String(200), nullable=False)
    authorized_by_role: Mapped[str] = mapped_column(String(100), nullable=False)
    authorized_by_email: Mapped[str] = mapped_column(String(320), nullable=False)
    reference: Mapped[str] = mapped_column(String(500), nullable=False)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    accepted_by_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    accepted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    target: Mapped["Target"] = relationship(back_populates="authorization")
