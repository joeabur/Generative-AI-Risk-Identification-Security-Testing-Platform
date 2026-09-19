"""remediation tasks and retest results

Phase 9 (docs/BUILD_SPEC.md §26). Three things land here:

* `remediation_tasks` — assignment and scheduling for a finding. No status
  column: the finding's own lifecycle is the single source of truth for
  security state, and two state machines over one fact drift.
* `retest_results` — the verdict a retest reached per finding, with the
  before and after evidence digests. This table exists to record an
  *absence*, which an ordinary scan cannot express.
* `assessment_runs.kind` and its retest columns — a retest is a run, so it
  reuses the authorization gate, the scope engine, the budgets and the
  evidence path rather than re-earning them.

Revision ID: 24731f9e68f9
Revises: a1c7e4f09b52
Create Date: 2026-09-19 07:22:38.959558
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "24731f9e68f9"
down_revision: str | None = "a1c7e4f09b52"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "remediation_tasks",
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("summary", sa.String(length=300), nullable=False),
        sa.Column("assignee_user_id", sa.UUID(), nullable=True),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_by_user_id", sa.UUID(), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["assignee_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("finding_id", name="uq_remediation_tasks_finding_id"),
    )
    op.create_table(
        "retest_results",
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("run_id", sa.UUID(), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("fingerprint", sa.String(length=80), nullable=False),
        sa.Column(
            "verdict",
            sa.Enum("REPRODUCED", "NOT_REPRODUCED", "NOT_TESTED", name="retest_verdict_enum"),
            nullable=False,
        ),
        sa.Column("before_evidence_ref", sa.String(length=80), nullable=True),
        sa.Column("after_evidence_ref", sa.String(length=80), nullable=True),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["run_id"], ["assessment_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    # `create_table` creates an ENUM type it needs; `add_column` does not, so
    # the type is created explicitly here or the ALTER fails with
    # "type run_kind_enum does not exist".
    sa.Enum("ASSESSMENT", "RETEST", name="run_kind_enum").create(op.get_bind(), checkfirst=True)

    # Existing rows are all assessments, and the JSON column needs a default
    # for the same reason: a NOT NULL column added to a populated table has to
    # say what the existing rows hold. The default is then dropped so the
    # application, not the database, decides for new rows.
    op.add_column(
        "assessment_runs",
        sa.Column(
            "kind",
            postgresql.ENUM("ASSESSMENT", "RETEST", name="run_kind_enum", create_type=False),
            nullable=False,
            server_default="ASSESSMENT",
        ),
    )
    op.alter_column("assessment_runs", "kind", server_default=None)
    op.add_column("assessment_runs", sa.Column("retest_of_run_id", sa.UUID(), nullable=True))
    op.add_column(
        "assessment_runs",
        sa.Column("retest_baseline", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.alter_column("assessment_runs", "retest_baseline", server_default=None)
    op.add_column(
        "assessment_runs",
        sa.Column("probes_executed", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.alter_column("assessment_runs", "probes_executed", server_default=None)
    op.create_foreign_key(
        "fk_assessment_runs_retest_of_run_id",
        "assessment_runs",
        "assessment_runs",
        ["retest_of_run_id"],
        ["id"],
        ondelete="SET NULL",
    )

    op.add_column("findings", sa.Column("retest_result", sa.String(length=30), nullable=True))
    op.add_column("findings", sa.Column("last_retest_run_id", sa.UUID(), nullable=True))
    op.create_foreign_key(
        "fk_findings_last_retest_run_id",
        "findings",
        "assessment_runs",
        ["last_retest_run_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_findings_last_retest_run_id", "findings", type_="foreignkey")
    op.drop_column("findings", "last_retest_run_id")
    op.drop_column("findings", "retest_result")

    op.drop_constraint("fk_assessment_runs_retest_of_run_id", "assessment_runs", type_="foreignkey")
    op.drop_column("assessment_runs", "probes_executed")
    op.drop_column("assessment_runs", "retest_baseline")
    op.drop_column("assessment_runs", "retest_of_run_id")
    op.drop_column("assessment_runs", "kind")

    op.drop_table("retest_results")
    op.drop_table("remediation_tasks")

    # drop_table and drop_column leave the Postgres ENUM types behind, so a
    # downgrade followed by an upgrade would fail with "type already exists".
    sa.Enum(name="retest_verdict_enum").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="run_kind_enum").drop(op.get_bind(), checkfirst=True)
