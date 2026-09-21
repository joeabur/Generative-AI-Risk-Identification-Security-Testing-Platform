"""tokens_valid_after on users

Revision ID: d4a91f3e0c5b
Revises: b8e3f01c7d24
Create Date: 2026-09-21

Server-side JWT revocation (docs/BUILD_SPEC.md §18, docs/revocation.md). A
"log out everywhere" cutover is durable in Postgres rather than Redis-only,
because losing it to a Redis restart would silently undo a compromise
response — the case this column exists for. Nullable, no backfill needed:
absent means nothing has ever been revoked in bulk for that user, which is
true of every existing row.
"""

import sqlalchemy as sa

from alembic import op

revision = "d4a91f3e0c5b"
down_revision = "b8e3f01c7d24"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("tokens_valid_after", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("users", "tokens_valid_after")
