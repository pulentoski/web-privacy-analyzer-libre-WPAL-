"""tablas de análisis (F3) y estado del análisis en jobs

Revision ID: 0003
Revises: 0002
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

LEVELS = "('EVIDENCIA', 'INFERENCIA', 'POSIBLE', 'DESCONOCIDO')"


def _job_id(primary_key: bool = False) -> sa.Column:
    return sa.Column(
        "job_id",
        postgresql.UUID(as_uuid=True),
        sa.ForeignKey("jobs.id", ondelete="CASCADE"),
        nullable=False,
        primary_key=primary_key,
    )


def _request_id() -> sa.Column:
    return sa.Column(
        "request_id", sa.BigInteger(), sa.ForeignKey("scan_requests.id", ondelete="CASCADE"), nullable=False
    )


def upgrade() -> None:
    # NULL = sin captura que analizar.
    op.add_column("jobs", sa.Column("analysis_status", sa.String(16), nullable=True))
    op.add_column("jobs", sa.Column("analysis_locked_until", sa.DateTime(timezone=True), nullable=True))
    op.create_check_constraint(
        "jobs_analysis_status_check",
        "jobs",
        "analysis_status IS NULL OR analysis_status IN ('queued', 'running', 'completed', 'failed')",
    )
    op.create_index(
        "ix_jobs_analysis_queued", "jobs", ["updated_at"], postgresql_where=sa.text("analysis_status = 'queued'")
    )
    # Los scans de F2 ya tienen captura: quedan encolados para su primer análisis.
    op.execute(
        "UPDATE jobs SET analysis_status = 'queued' "
        "WHERE EXISTS (SELECT 1 FROM scan_requests WHERE scan_requests.job_id = jobs.id)"
    )

    op.create_table(
        "request_analysis",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        _job_id(),
        _request_id(),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("band", sa.Text(), nullable=False),
        sa.Column("category", sa.Text(), nullable=False),
        sa.Column("mechanism", sa.Text(), nullable=False),
        # "no_disponible" si el dominio no está en el mapa de entidades.
        sa.Column("entity", sa.Text(), nullable=False),
        sa.Column("list_matches", postgresql.JSONB(), nullable=False),
        # [{signal, weight, level, evidence_ref, detail}]
        sa.Column("reasons", postgresql.JSONB(), nullable=False),
        sa.Column("analyzer_version", sa.Text(), nullable=False),
        sa.UniqueConstraint("request_id", name="uq_request_analysis_request"),
        sa.CheckConstraint("score BETWEEN 0 AND 100", name="request_analysis_score_check"),
    )
    op.create_index("ix_request_analysis_job_band", "request_analysis", ["job_id", "band"])

    op.create_table(
        "parameters",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        _job_id(),
        _request_id(),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("value_truncated", sa.Boolean(), nullable=False),
        sa.Column("category", sa.Text(), nullable=True),
        sa.Column("shapes", postgresql.JSONB(), nullable=False),
        sa.Column("length", sa.Integer(), nullable=False),
        sa.Column("entropy", sa.Float(), nullable=False),
        sa.Column("identifier_like", sa.Boolean(), nullable=False),
        sa.Column("encoding_chain", postgresql.JSONB(), nullable=False),
    )
    op.create_index("ix_parameters_job_request", "parameters", ["job_id", "request_id"])

    op.create_table(
        "decoded_values",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        _job_id(),
        _request_id(),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        # El valor tal como se capturó: nunca se modifica.
        sa.Column("raw_value", sa.Text(), nullable=False),
        sa.Column("decoded_value", sa.Text(), nullable=False),
        sa.Column("decoded_truncated", sa.Boolean(), nullable=False),
        sa.Column("encoding_chain", postgresql.JSONB(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
    )
    op.create_index("ix_decoded_values_job_request", "decoded_values", ["job_id", "request_id"])

    op.create_table(
        "findings",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        _job_id(),
        sa.Column("type", sa.Text(), nullable=False),
        sa.Column("level", sa.Text(), nullable=False),
        sa.Column("claim", sa.Text(), nullable=False),
        # ids de scan_requests. Nunca vacío (regla 1 de CLAUDE.md).
        sa.Column("evidence_refs", postgresql.JSONB(), nullable=False),
        sa.Column("details", postgresql.JSONB(), nullable=False),
        sa.Column("analyzer_version", sa.Text(), nullable=False),
        sa.CheckConstraint(f"level IN {LEVELS}", name="findings_level_check"),
        sa.CheckConstraint("jsonb_array_length(evidence_refs) > 0", name="findings_evidence_refs_check"),
    )
    op.create_index("ix_findings_job_id", "findings", ["job_id"])

    op.create_table(
        "site_analysis",
        _job_id(primary_key=True),
        sa.Column("analyzer_version", sa.Text(), nullable=False),
        sa.Column("lists_version", sa.Text(), nullable=False),
        sa.Column("lists", postgresql.JSONB(), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("band", sa.Text(), nullable=False),
        sa.Column("breakdown", postgresql.JSONB(), nullable=False),
        sa.Column("data_categories", postgresql.JSONB(), nullable=False),
        sa.Column("mechanisms", postgresql.JSONB(), nullable=False),
        sa.Column("summary", postgresql.JSONB(), nullable=False),
        # true = se alcanzó el límite de tiempo y parte de las requests se puntuó sin parámetros.
        sa.Column("partial", sa.Boolean(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("analyzed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("score BETWEEN 0 AND 100", name="site_analysis_score_check"),
    )


def downgrade() -> None:
    for table in ("site_analysis", "findings", "decoded_values", "parameters", "request_analysis"):
        op.drop_table(table)
    op.drop_index("ix_jobs_analysis_queued", table_name="jobs")
    op.drop_constraint("jobs_analysis_status_check", "jobs")
    op.drop_column("jobs", "analysis_locked_until")
    op.drop_column("jobs", "analysis_status")
