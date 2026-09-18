import uuid
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.target import Target


class ApiSpec(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """An uploaded API description for a target (docs/BUILD_SPEC.md §18.5).

    The raw document is stored **in the database**, not on the filesystem.
    §38 of the source spec asks for uploads to be stored outside executable
    paths with sanitized filenames and no path traversal; keeping the bytes
    in a column removes that entire class of problem rather than mitigating
    it, and makes the exact document that produced a given surface auditable
    alongside the findings derived from it. `original_filename` is retained
    as metadata only and is never used to build a path.
    """

    __tablename__ = "api_specs"

    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    openapi_version: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str | None] = mapped_column(String(300), nullable=True)
    api_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw_document: Mapped[str] = mapped_column(Text, nullable=False)
    uploaded_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    target: Mapped["Target"] = relationship(back_populates="api_spec")
