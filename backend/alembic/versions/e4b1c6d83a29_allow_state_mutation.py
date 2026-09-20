"""rules of engagement: allow_state_mutation

Revision ID: e4b1c6d83a29
Revises: c93f2a7e15b8
Create Date: 2026-09-20

Separate from `safe_mode` on purpose (docs/BUILD_SPEC.md §5.2
`behaviour.allow_state_mutation`): safe mode bounds how a probe behaves, this
decides whether state-changing tooling may run at all. The DAST engine reads it
to pick which Nuclei templates and which ZAP mode are permitted.

NOT NULL on a populated table, so it needs a `server_default` for the backfill
and then the default dropped — existing rows become `false`, which is the
conservative reading of a grant that never mentioned state mutation.
"""

import sqlalchemy as sa

from alembic import op

revision = "e4b1c6d83a29"
down_revision = "c93f2a7e15b8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "rules_of_engagement",
        sa.Column(
            "allow_state_mutation",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    # The column keeps its server default: a row inserted by an older code path
    # should still default to "may not change state", which is the safe reading.


def downgrade() -> None:
    op.drop_column("rules_of_engagement", "allow_state_mutation")
