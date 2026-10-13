"""instrumentación de fingerprinting (F4) y Referer por request

Revision ID: 0004
Revises: 0003
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def _id() -> sa.Column:
    return sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True)


def _job_id() -> sa.Column:
    return sa.Column(
        "job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False
    )


def upgrade() -> None:
    # Captura: llamadas a APIs agregadas por (api, script, frame). La escribe el worker al navegar.
    op.create_table(
        "fp_api_calls",
        _id(),
        _job_id(),
        sa.Column("api", sa.Text(), nullable=False),
        # '' = no se pudo atribuir a un script (código inline evaluado, eval...).
        sa.Column("script_url", sa.Text(), nullable=False),
        sa.Column("frame_url", sa.Text(), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        # {value} | {reads: [{kind, sha256, length, ...}]} | {distinct_fonts}. Nunca contenido de canvas/audio.
        sa.Column("details", postgresql.JSONB(), nullable=False),
    )
    op.create_index("ix_fp_api_calls_job_id", "fp_api_calls", ["job_id"])

    # Análisis: se regeneran en cada (re)análisis.
    op.create_table(
        "fp_findings",
        _id(),
        _job_id(),
        sa.Column("script_url", sa.Text(), nullable=False),
        sa.Column("heuristic", sa.Text(), nullable=False),
        sa.Column("level", sa.Text(), nullable=False),
        sa.Column("claim", sa.Text(), nullable=False),
        # ids de fp_api_calls (la llamada) e ids de scan_requests (la request). Al menos uno no vacío.
        sa.Column("call_refs", postgresql.JSONB(), nullable=False),
        sa.Column("request_refs", postgresql.JSONB(), nullable=False),
        sa.Column("details", postgresql.JSONB(), nullable=False),
        sa.Column("analyzer_version", sa.Text(), nullable=False),
        sa.CheckConstraint(
            "level IN ('EVIDENCIA', 'INFERENCIA', 'POSIBLE', 'DESCONOCIDO')", name="fp_findings_level_check"
        ),
        sa.CheckConstraint(
            "jsonb_array_length(call_refs) + jsonb_array_length(request_refs) > 0", name="fp_findings_refs_check"
        ),
    )
    op.create_index("ix_fp_findings_job_id", "fp_findings", ["job_id"])

    op.create_table(
        "fp_attributes",
        _id(),
        _job_id(),
        sa.Column("attribute", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("value", sa.Text(), nullable=True),
        sa.Column("scripts", postgresql.JSONB(), nullable=False),
        sa.Column("call_refs", postgresql.JSONB(), nullable=False),
        sa.Column("request_refs", postgresql.JSONB(), nullable=False),
        sa.UniqueConstraint("job_id", "attribute", name="uq_fp_attributes_job_attribute"),
        sa.CheckConstraint(
            "status IN ('NO_DISPONIBLE', 'DISPONIBLE', 'UTILIZADO', 'OBSERVADO')", name="fp_attributes_status_check"
        ),
    )

    # full_url | origin_only | absent; NULL = request first-party o análisis anterior a F4.
    op.add_column("request_analysis", sa.Column("referer", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("request_analysis", "referer")
    op.drop_table("fp_attributes")
    op.drop_table("fp_findings")
    op.drop_table("fp_api_calls")
