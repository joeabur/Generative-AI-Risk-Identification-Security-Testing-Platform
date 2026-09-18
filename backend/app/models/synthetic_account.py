"""Authorized synthetic test accounts (docs/BUILD_SPEC.md §10).

This table holds the *description* of a test account and never the account's
credential. What is stored is the name of an environment variable the worker
reads at run time, so a dump of this database yields no way to authenticate
to anyone's API — §2's reference-only rule, enforced by there being no
column a secret could go in.
"""

import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.target import Target


class SyntheticAccount(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "synthetic_accounts"
    __table_args__ = (
        UniqueConstraint("target_id", "label", name="uq_synthetic_account_target_label"),
    )

    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    label: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # The NAME of an environment variable, never its value.
    credential_env_var: Mapped[str] = mapped_column(String(200), nullable=False)
    header_name: Mapped[str] = mapped_column(String(100), nullable=False, default="Authorization")
    value_template: Mapped[str] = mapped_column(
        String(200), nullable=False, default="Bearer {credential}"
    )
    # Real identifiers of objects this account owns, so a BOLA test can ask
    # about a real record without ever touching a stranger's data.
    owned_object_ids: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    is_privileged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    target: Mapped["Target"] = relationship(back_populates="synthetic_accounts")
