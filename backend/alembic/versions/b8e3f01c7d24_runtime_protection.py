"""runtime_protection declaration on targets

Revision ID: b8e3f01c7d24
Revises: f7a2d91b40c6
Create Date: 2026-09-20

Phase 18's extension point: what an operator CLAIMS is deployed in front of a
target. A claim, not a measurement — nothing on this platform tests runtime
protection, and each entry carries an `evidenced` field that says so.

`server_default='[]'` because `targets` is a populated table and the column is
NOT NULL: existing rows need a value at the moment the constraint lands. The
default is dropped afterwards so the application's own default is the only one,
rather than leaving two places that decide what an unset value means.
"""

import sqlalchemy as sa

from alembic import op

revision = "b8e3f01c7d24"
down_revision = "f7a2d91b40c6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "targets",
        sa.Column("runtime_protection", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.alter_column("targets", "runtime_protection", server_default=None)


def downgrade() -> None:
    op.drop_column("targets", "runtime_protection")
