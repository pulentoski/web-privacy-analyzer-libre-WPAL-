"""Captura interactiva e indicador de recursos (v1.4, docs/adr/029)

`interactive_sessions`: una fila por captura interactiva. El índice único parcial garantiza una
sola sesión viva a la vez. Del token de acceso al relé VNC solo se guarda el hash; la contraseña
de un solo uso del VNC y su dirección se borran al terminar la sesión.

`service_resources`: última muestra de contadores de cgroup de los servicios que no pueden
responderle a la api por red (worker y egress-proxy). Dato efímero: una fila por servicio.

Revision ID: 0014
Revises: 0013
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "interactive_sessions",
        sa.Column("job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("jobs.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("vnc_password", sa.Text()),
        sa.Column("vnc_host", sa.Text()),
        sa.Column("vnc_port", sa.Integer()),
        sa.Column("state", sa.String(16), server_default="starting", nullable=False),
        sa.Column("stop_requested", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("ready_at", sa.DateTime(timezone=True)),
        sa.Column("last_input_at", sa.DateTime(timezone=True)),
        sa.Column("ended_at", sa.DateTime(timezone=True)),
        sa.Column("end_reason", sa.String(32)),
        sa.Column("idle_s", sa.Integer()),
        sa.Column("max_s", sa.Integer()),
    )
    # Una sesión a la vez: no puede haber dos filas sin `ended_at`.
    op.execute("CREATE UNIQUE INDEX interactive_sessions_one_active ON interactive_sessions ((true)) WHERE ended_at IS NULL")
    op.create_table(
        "service_resources",
        sa.Column("service", sa.Text(), primary_key=True),
        sa.Column("sample", postgresql.JSONB(), nullable=False),
        sa.Column("reported_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("service_resources")
    op.drop_table("interactive_sessions")
