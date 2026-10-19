"""Comparación de visitas (v1.5.2, docs/adr/040)

`visit_comparisons`: una comparación reproducible de tres visitas a la misma URL (perfil A limpio, perfil A persistente
tras un intervalo, perfil B limpio de control). Cada visita es un job normal con `comparison_id`.
`state` lo escribe el worker: condiciones de cada visita, horas de cierre y apertura del navegador, huellas sha256 de las
cookies persistentes (nunca sus valores) y la verificación del estado de los perfiles.

`jobs.not_before`: el job no se toma antes de esa hora. Solo lo usan las visitas 2 y 3 (la 2 espera el intervalo); en
las filas existentes queda NULL y la cola funciona igual que antes.

Revision ID: 0016
Revises: 0015
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "visit_comparisons",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("original_url", sa.Text(), nullable=True),
        # {interval_s: n}
        sa.Column("config", postgresql.JSONB(), nullable=False),
        sa.Column("state", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.add_column(
        "jobs",
        sa.Column("comparison_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("visit_comparisons.id", ondelete="CASCADE"), nullable=True),
    )
    op.add_column("jobs", sa.Column("not_before", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_jobs_comparison_id", "jobs", ["comparison_id"], postgresql_where=sa.text("comparison_id IS NOT NULL"))


def downgrade() -> None:
    op.drop_index("ix_jobs_comparison_id", table_name="jobs")
    op.drop_column("jobs", "not_before")
    op.drop_column("jobs", "comparison_id")
    op.drop_table("visit_comparisons")
