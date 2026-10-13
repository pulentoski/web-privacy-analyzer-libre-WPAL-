"""Clasificación por organización de cada request (v1.2.1)

propio (mismo dominio) · misma organización (otro dominio del mismo dueño según el mapa de
entidades) · tercero (otra organización o desconocida). Solo los de otra organización cuentan
como "terceros" en el resumen, el índice de exposición, el Panel y los reportes.

NULL en las filas anteriores a v1.2.1; al reanalizar (scripts/reanalyze.sh) se rellena. Las
consultas que distinguen terceros tratan NULL como "tercero si third_party, propio si no".

Revision ID: 0012
Revises: 0011
"""
import sqlalchemy as sa
from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("request_analysis", sa.Column("party", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("request_analysis", "party")
