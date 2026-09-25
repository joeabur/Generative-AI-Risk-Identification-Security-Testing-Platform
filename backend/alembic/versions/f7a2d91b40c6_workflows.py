"""workflows and workflow runs

Revision ID: f7a2d91b40c6
Revises: e4b1c6d83a29
Create Date: 2026-09-20

Persisted in the existing database rather than in a workflow product: what is
stored is a trigger, a derived plan, five stage records and a gate decision, and
a second state store holding that would be a second source of truth about what
ran.
"""

import sqlalchemy as sa

from alembic import op

revision = "f7a2d91b40c6"
down_revision = "e4b1c6d83a29"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "workflows",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "target_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("targets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("trigger_kind", sa.String(32), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("gate_config", sa.JSON(), nullable=True),
        sa.Column(
            "created_by_user_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("organization_id", "name", name="uq_workflow_org_name"),
    )
    op.create_index("ix_workflows_organization_id", "workflows", ["organization_id"])

    op.create_table(
        "workflow_runs",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "workflow_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("workflows.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "assessment_run_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assessment_runs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("trigger", sa.JSON(), nullable=False),
        sa.Column("plan", sa.JSON(), nullable=False),
        sa.Column("plan_digest", sa.String(80), nullable=False, server_default=""),
        sa.Column("stages", sa.JSON(), nullable=False),
        sa.Column("evidence_refs", sa.JSON(), nullable=False),
        sa.Column("gate_passed", sa.Boolean(), nullable=True),
        sa.Column("gate_exit_code", sa.Integer(), nullable=True),
        sa.Column("gate_reasons", sa.JSON(), nullable=False),
        sa.Column("gate_counts", sa.JSON(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("detail", sa.String(500), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_workflow_runs_workflow_id", "workflow_runs", ["workflow_id"])
    # "Did the plan change between these two commits?" is the question the
    # digest exists for, so it is the column that gets an index.
    op.create_index("ix_workflow_runs_plan_digest", "workflow_runs", ["plan_digest"])


def downgrade() -> None:
    op.drop_index("ix_workflow_runs_plan_digest", table_name="workflow_runs")
    op.drop_index("ix_workflow_runs_workflow_id", table_name="workflow_runs")
    op.drop_table("workflow_runs")
    op.drop_index("ix_workflows_organization_id", table_name="workflows")
    op.drop_table("workflows")
