"""Privacy Test (F7): grupos de scans y artefactos (captura del banner)

Revision ID: 0006
Revises: 0005
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "test_groups",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("url", sa.Text(), nullable=False),
        # {scenarios: [...], profiles: [...], runs: n}
        sa.Column("config", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.add_column(
        "jobs",
        sa.Column("group_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("test_groups.id", ondelete="CASCADE"), nullable=True),
    )
    op.create_index("ix_jobs_group_id", "jobs", ["group_id"], postgresql_where=sa.text("group_id IS NOT NULL"))
    op.create_table(
        "scan_artifacts",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("mime", sa.Text(), nullable=False),
        sa.Column("data", sa.LargeBinary(), nullable=False),
        sa.UniqueConstraint("job_id", "kind", name="uq_scan_artifacts_job_kind"),
        sa.CheckConstraint("mime IN ('image/jpeg', 'image/png')", name="scan_artifacts_mime_check"),
    )


def downgrade() -> None:
    op.drop_table("scan_artifacts")
    op.drop_index("ix_jobs_group_id", table_name="jobs")
    op.drop_column("jobs", "group_id")
    op.drop_table("test_groups")
