"""Importar HAR (v1.3, docs/adr/025)

`har_imports`: entradas del HAR ya validadas y depuradas (sin valores de Cookie, Set-Cookie ni
Authorization), a la espera de que el worker las convierta en captura. El worker borra la fila al
cerrar el job; el archivo original nunca se guarda.

Revision ID: 0013
Revises: 0012
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "har_imports",
        sa.Column("job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("jobs.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("har_imports")
