"""notification channels and deliveries

Revision ID: a1c7f4d92b30
Revises: c5e81a0d4f37
Create Date: 2026-09-20

Note the columns that do *not* exist: there is no endpoint URL, no webhook
token and no SMTP password. A channel stores the *name* of the environment
variable holding its credential (docs/BUILD_SPEC.md §5), so this schema cannot
hold a secret even if a future caller tried to put one there.

Statuses are plain `VARCHAR` rather than a Postgres ENUM, deliberately: adding
a delivery status later is then a code change instead of a migration that has
to `ALTER TYPE` on a live table.
"""

import sqlalchemy as sa

from alembic import op

revision = "a1c7f4d92b30"
down_revision = "c5e81a0d4f37"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "notification_channels",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("endpoint_env_var", sa.String(128), nullable=True),
        sa.Column("endpoint_redacted", sa.String(300), nullable=True),
        sa.Column("signing_secret_env_var", sa.String(128), nullable=True),
        sa.Column("smtp_host", sa.String(255), nullable=True),
        sa.Column("smtp_port", sa.Integer(), nullable=True),
        sa.Column("smtp_username", sa.String(255), nullable=True),
        sa.Column("smtp_password_env_var", sa.String(128), nullable=True),
        sa.Column("from_address", sa.String(320), nullable=True),
        sa.Column("recipients", sa.JSON(), nullable=True),
        sa.Column("events", sa.JSON(), nullable=False),
        sa.Column("min_severity", sa.String(20), nullable=True),
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
        sa.UniqueConstraint("organization_id", "name", name="uq_channel_org_name"),
    )
    op.create_index(
        "ix_notification_channels_organization_id",
        "notification_channels",
        ["organization_id"],
    )

    op.create_table(
        "notification_deliveries",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "channel_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("notification_channels.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("resource_type", sa.String(64), nullable=True),
        sa.Column("resource_id", sa.String(100), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("last_error", sa.String(500), nullable=True),
        sa.Column("event_json", sa.JSON(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index(
        "ix_notification_deliveries_channel_id", "notification_deliveries", ["channel_id"]
    )
    # The retry sweep's query: due work, oldest first. Partial on the two
    # statuses that can be retried, so dead-lettered rows never enter the index.
    op.create_index(
        "ix_notification_deliveries_due",
        "notification_deliveries",
        ["next_attempt_at"],
        postgresql_where=sa.text("status IN ('pending', 'failed')"),
    )


def downgrade() -> None:
    op.drop_index("ix_notification_deliveries_due", table_name="notification_deliveries")
    op.drop_index("ix_notification_deliveries_channel_id", table_name="notification_deliveries")
    op.drop_table("notification_deliveries")
    op.drop_index("ix_notification_channels_organization_id", table_name="notification_channels")
    op.drop_table("notification_channels")
