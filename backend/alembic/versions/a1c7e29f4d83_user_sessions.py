"""user_sessions

Revision ID: a1c7e29f4d83
Revises: d4a91f3e0c5b
Create Date: 2026-09-25

Session visibility and revocation by name (docs/BUILD_SPEC.md §18,
docs/security-review.md). Previously this platform tracked only which
tokens were dead (the revocation deny-list), not which existed — "list my
active sessions" and "revoke this one" had nothing to query. This table is
that record; it is not itself the authorization decision, which stays with
`app/core/revocation/`'s deny-list and `users.tokens_valid_after`.
"""

import sqlalchemy as sa

from alembic import op

revision = "a1c7e29f4d83"
down_revision = "d4a91f3e0c5b"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "user_sessions",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("jti", sa.String(36), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ip_address", sa.String(64), nullable=True),
        sa.Column("user_agent", sa.String(255), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("jti", name="uq_user_sessions_jti"),
    )
    op.create_index("ix_user_sessions_user_id", "user_sessions", ["user_id"])
    op.create_index("ix_user_sessions_jti", "user_sessions", ["jti"])


def downgrade() -> None:
    op.drop_index("ix_user_sessions_jti", table_name="user_sessions")
    op.drop_index("ix_user_sessions_user_id", table_name="user_sessions")
    op.drop_table("user_sessions")
