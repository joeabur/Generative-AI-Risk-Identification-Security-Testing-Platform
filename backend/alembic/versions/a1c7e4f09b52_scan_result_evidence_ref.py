"""scan result evidence ref

Records where a result's evidence bundle was stored (docs/BUILD_SPEC.md §13).
Nullable by design: a design-review or "not tested" result has no exchange
behind it, and a placeholder digest would point at a bundle that does not
exist.

Revision ID: a1c7e4f09b52
Revises: 7fb3c0b81e34
Create Date: 2026-09-19 07:05:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "a1c7e4f09b52"
down_revision: str | None = "7fb3c0b81e34"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scan_results", sa.Column("evidence_ref", sa.String(length=80), nullable=True))


def downgrade() -> None:
    op.drop_column("scan_results", "evidence_ref")
