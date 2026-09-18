import enum
import uuid
from typing import TYPE_CHECKING

from sqlalchemy import Enum, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.authorization import Authorization
    from app.models.rules_of_engagement import RulesOfEngagementRecord


class TargetEnvironment(enum.StrEnum):
    STAGING = "staging"
    TEST = "test"
    DEV = "dev"
    PRODUCTION = "production"


class TargetKind(enum.StrEnum):
    LLM_APP = "llm_app"
    AGENT = "agent"
    RAG = "rag"
    API = "api"
    MCP_SERVER = "mcp_server"
    MODEL_ENDPOINT = "model_endpoint"


class Target(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """The technical description of what is being tested
    (docs/BUILD_SPEC.md §5.1 "Target"/"Asset").

    Phase 2 keeps this to the fields the scope engine needs (a name and a
    base URL to seed scope checks against). The richer per-adapter
    configuration (`adapters: [...]` in §5.1 — chat_http templates, OpenAPI
    spec refs, credential references) lands with the adapter layer in
    Phase 3.
    """

    __tablename__ = "targets"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    environment: Mapped[TargetEnvironment] = mapped_column(
        Enum(TargetEnvironment, name="target_environment_enum"), nullable=False
    )
    kind: Mapped[TargetKind] = mapped_column(
        Enum(TargetKind, name="target_kind_enum"), nullable=False
    )
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    authorization: Mapped["Authorization | None"] = relationship(
        back_populates="target", uselist=False, cascade="all, delete-orphan"
    )
    rules_of_engagement: Mapped["RulesOfEngagementRecord | None"] = relationship(
        back_populates="target", uselist=False, cascade="all, delete-orphan"
    )
