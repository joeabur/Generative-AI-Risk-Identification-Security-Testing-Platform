import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.user import User


class UserSession(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One issued JWT, tracked so "list my active sessions" and "revoke this
    one by name" are expressible (docs/security-review.md's gap: previously
    "this platform does not track which tokens exist, only which are dead").

    This is a record, not the authorization decision — revoking a session
    still means writing its `jti` to `app/core/revocation/`'s deny-list, the
    same as `/auth/logout` always has. Losing this table (a botched restore,
    a truncated table) makes past sessions invisible, but revokes nothing
    that was already revoked and un-revokes nothing: the deny-list and
    `User.tokens_valid_after` are what a request is actually checked against.
    """

    __tablename__ = "user_sessions"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    #: The JWT's own `jti` claim. Unique because a token is issued with a
    #: fresh one every time (`create_access_token`); a collision would mean
    #: two different tokens claiming to be the same session.
    jti: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    #: Set by `/auth/logout` (this session) or `/auth/logout-all` (every
    #: session) or `DELETE /auth/sessions/{id}` (one, by name). Null means
    #: still active as far as this table's record goes — the deny-list and
    #: `tokens_valid_after` remain the actual source of truth for a live
    #: request; this column exists so the listing endpoint does not have to
    #: ask the deny-list once per row to know what to show.
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: Best-effort context for the list an operator reads, not a security
    #: control — neither is verified, both are exactly what `/auth/login` or
    #: `/auth/register` saw on the request that created this row.
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)

    user: Mapped["User"] = relationship()
