"""code host connections and pull request posts

Revision ID: c93f2a7e15b8
Revises: a1c7f4d92b30
Create Date: 2026-09-20

`vcs_connections` has no token column, by design: a connection names the
environment variable holding its token (docs/BUILD_SPEC.md §5), so the schema
cannot hold a credential that grants access to a customer's source.
"""

import sqlalchemy as sa

from alembic import op

revision = "c93f2a7e15b8"
down_revision = "a1c7f4d92b30"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vcs_connections",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("api_host", sa.String(255), nullable=True),
        sa.Column("token_env_var", sa.String(128), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
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
        sa.UniqueConstraint("organization_id", "name", name="uq_vcs_connection_org_name"),
    )
    op.create_index("ix_vcs_connections_organization_id", "vcs_connections", ["organization_id"])

    op.create_table(
        "pull_request_posts",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "connection_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("vcs_connections.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "assessment_run_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assessment_runs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("repo_slug", sa.String(255), nullable=False),
        sa.Column("pull_number", sa.Integer(), nullable=False),
        sa.Column("head_sha", sa.String(64), nullable=False),
        sa.Column("conclusion", sa.String(20), nullable=False, server_default="neutral"),
        sa.Column("check_run_id", sa.Integer(), nullable=True),
        sa.Column("check_run_url", sa.String(500), nullable=True),
        sa.Column("annotations_posted", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("annotations_dropped", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("posted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("detail", sa.String(500), nullable=True),
        sa.Column("fingerprints", sa.JSON(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_pull_request_posts_connection_id", "pull_request_posts", ["connection_id"])
    # "What did we say on this pull request?" is the question this table is
    # read by, so that is the index it gets.
    op.create_index(
        "ix_pull_request_posts_repo_pull",
        "pull_request_posts",
        ["organization_id", "repo_slug", "pull_number"],
    )


def downgrade() -> None:
    op.drop_index("ix_pull_request_posts_repo_pull", table_name="pull_request_posts")
    op.drop_index("ix_pull_request_posts_connection_id", table_name="pull_request_posts")
    op.drop_table("pull_request_posts")
    op.drop_index("ix_vcs_connections_organization_id", table_name="vcs_connections")
    op.drop_table("vcs_connections")
