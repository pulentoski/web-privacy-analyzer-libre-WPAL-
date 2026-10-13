"""Registro de interacción de la captura interactiva (v1.4.2, docs/adr/030)

`interactive_sessions.interactions`: lista de [epoch_ms, tipo] con la hora de cada clic, desplazamiento y
tecla del usuario, que anota el relé VNC de la api. Solo hora y tipo: nunca la tecla, el texto ni la posición.

Revision ID: 0015
Revises: 0014
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("interactive_sessions", sa.Column("interactions", postgresql.JSONB(), nullable=True))


def downgrade() -> None:
    op.drop_column("interactive_sessions", "interactions")
