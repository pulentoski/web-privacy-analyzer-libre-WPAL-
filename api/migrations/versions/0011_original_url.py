"""URL original de cada scan y de cada grupo (v1.2)

Si la URL que se pegó traía parámetros de seguimiento (gclid, fbclid, utm_*…), por defecto se
escanea la URL limpia. Se guardan las dos: `url` es la escaneada y `original_url` la recibida.
NULL en las filas anteriores a v1.2 (se escaneó tal cual se recibió).

Revision ID: 0011
Revises: 0010
"""
import sqlalchemy as sa
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("jobs", sa.Column("original_url", sa.Text(), nullable=True))
    op.add_column("test_groups", sa.Column("original_url", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("test_groups", "original_url")
    op.drop_column("jobs", "original_url")
