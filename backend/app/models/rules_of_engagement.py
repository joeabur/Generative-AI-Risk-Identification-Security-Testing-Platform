import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.target import Target


class RulesOfEngagementRecord(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """docs/BUILD_SPEC.md §5.3. One RoE per target, replaced wholesale on
    update (no partial-field PATCH) so there is never a moment where the
    persisted RoE is a half-applied mix of old and new rules — the exact
    hazard the scope engine exists to prevent elsewhere.
    """

    __tablename__ = "rules_of_engagement"

    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    allowed_domains: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    excluded_domains: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    allowed_ip_ranges: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    allowed_paths: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    excluded_paths: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    allowed_methods: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    forbidden_headers: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    budgets: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    safe_mode: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    blackout_windows: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list
    )

    target: Mapped["Target"] = relationship(back_populates="rules_of_engagement")
