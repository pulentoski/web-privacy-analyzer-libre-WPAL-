"""progreso real del scan (F10)

jobs.progress lo escribe el worker mientras el scan corre: etapa, requests capturadas hasta
el momento, cuándo empezó la captura y el máximo configurado (SCAN_TIMEOUT_S).

Revision ID: 0009
Revises: 0008
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # {"stage": "opening|capturing|analyzing|building|failed", "requests": n, "max_s": n, "capture_started_at": iso}
    op.add_column("jobs", sa.Column("progress", postgresql.JSONB(), nullable=True))


def downgrade() -> None:
    op.drop_column("jobs", "progress")
