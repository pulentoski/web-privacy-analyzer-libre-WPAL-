"""destinos por IP (proxy), CNAME y archivos de reporte (F8)

Revision ID: 0007
Revises: 0006
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Captura: a qué IP conectó realmente el proxy para cada host del scan. ip '' = no conectó.
    op.create_table(
        "scan_destinations",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("host", sa.Text(), nullable=False),
        sa.Column("ip", sa.Text(), nullable=False),
        sa.Column("connections", sa.Integer(), nullable=False),
        sa.UniqueConstraint("job_id", "host", "ip", name="uq_scan_destinations"),
    )
    # Cadena CNAME de los subdominios propios del sitio (resuelta una vez, bajo demanda).
    op.create_table(
        "scan_cnames",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("host", sa.Text(), nullable=False),
        # [] = sin CNAME; status: resolved | error | skipped
        sa.Column("chain", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("job_id", "host", name="uq_scan_cnames"),
    )
    # Reportes exportados: instantánea JSON, HTML autocontenido y PDF (lo renderiza el worker).
    op.create_table(
        "report_files",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("subject_type", sa.Text(), nullable=False),
        sa.Column("subject_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("reveal", sa.Boolean(), nullable=False),
        sa.Column("sha256", sa.Text(), nullable=False),  # del JSON del reporte
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("data", sa.LargeBinary(), nullable=True),
        sa.Column("render_info", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("subject_type", "subject_id", "kind", "reveal", name="uq_report_files"),
        sa.CheckConstraint("subject_type IN ('scan', 'group')", name="report_files_subject_check"),
        sa.CheckConstraint("kind IN ('json', 'html', 'pdf')", name="report_files_kind_check"),
        sa.CheckConstraint("status IN ('pending', 'rendering', 'ready', 'failed')", name="report_files_status_check"),
    )
    op.create_index("ix_report_files_pending", "report_files", ["created_at"], postgresql_where=sa.text("status = 'pending'"))


def downgrade() -> None:
    op.drop_table("report_files")
    op.drop_table("scan_cnames")
    op.drop_table("scan_destinations")
