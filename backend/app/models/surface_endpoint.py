import enum
import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, Boolean, Enum, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.target import Target


class SurfaceSource(enum.StrEnum):
    OPENAPI = "openapi"
    DECLARED = "declared"


class SurfaceEndpoint(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One discovered, testable endpoint on a target (docs/BUILD_SPEC.md §18.5).

    `enabled` is what lets an operator take individual endpoints out of a
    run without editing the Rules of Engagement. It is a *convenience*
    filter layered on top of the scope engine, never a replacement for it:
    re-enabling an endpoint still cannot put an out-of-scope path in scope,
    because §6's checks run on every request regardless of what is stored
    here.
    """

    __tablename__ = "surface_endpoints"
    __table_args__ = (
        UniqueConstraint(
            "target_id", "method", "path", name="uq_surface_endpoint_target_method_path"
        ),
    )

    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    api_spec_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("api_specs.id", ondelete="CASCADE"), nullable=True
    )
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    operation_id: Mapped[str | None] = mapped_column(String(300), nullable=True)
    summary: Mapped[str | None] = mapped_column(String(500), nullable=True)
    parameters: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    request_body_content_types: Mapped[list[str]] = mapped_column(
        JSON, nullable=False, default=list
    )
    security_schemes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    requires_auth: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    source: Mapped[SurfaceSource] = mapped_column(
        Enum(SurfaceSource, name="surface_source_enum"), nullable=False
    )

    target: Mapped["Target"] = relationship(back_populates="surface_endpoints")
