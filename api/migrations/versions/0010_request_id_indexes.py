"""índices por request_id en parameters y decoded_values (F10)

Ambas tablas apuntan a scan_requests con ON DELETE CASCADE pero no tenían índice por esa
columna: borrar una request recorría la tabla entera. Borrar todo el historial (244 scans,
40 000 requests) tardaba 28 s, casi el tiempo de espera del proxy. También acelera el
detalle de una request y la purga por retención.

Revision ID: 0010
Revises: 0009
"""
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("ix_parameters_request_id", "parameters", ["request_id"])
    op.create_index("ix_decoded_values_request_id", "decoded_values", ["request_id"])


def downgrade() -> None:
    op.drop_index("ix_decoded_values_request_id", table_name="decoded_values")
    op.drop_index("ix_parameters_request_id", table_name="parameters")
