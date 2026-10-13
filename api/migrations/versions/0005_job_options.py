"""opciones por scan

Revision ID: 0005
Revises: 0004
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # {"fp_instrumentation": bool}. NULL = valores por defecto del worker.
    op.add_column("jobs", sa.Column("options", postgresql.JSONB(), nullable=True))


def downgrade() -> None:
    op.drop_column("jobs", "options")
