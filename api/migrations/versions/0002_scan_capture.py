"""tablas de captura de tráfico (F2)

Revision ID: 0002
Revises: 0001
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def _job_id() -> sa.Column:
    return sa.Column(
        "job_id",
        postgresql.UUID(as_uuid=True),
        sa.ForeignKey("jobs.id", ondelete="CASCADE"),
        nullable=False,
    )


def _ts() -> sa.Column:
    return sa.Column("ts", sa.DateTime(timezone=True), nullable=False)


def upgrade() -> None:
    op.create_table(
        "scan_requests",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        _job_id(),
        sa.Column("seq", sa.Integer(), nullable=False),
        _ts(),
        sa.Column("method", sa.Text(), nullable=True),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("url_truncated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("scheme", sa.Text(), nullable=True),
        sa.Column("host", sa.Text(), nullable=True),
        sa.Column("path", sa.Text(), nullable=True),
        # Lista cruda [[nombre, valor|null], ...]: conserva orden y duplicados.
        sa.Column("query_params", postgresql.JSONB(), nullable=False),
        sa.Column("resource_type", sa.Text(), nullable=True),
        sa.Column("frame_url", sa.Text(), nullable=True),
        sa.Column("is_navigation", sa.Boolean(), nullable=False),
        sa.Column("initiator", postgresql.JSONB(), nullable=True),
        sa.Column("request_headers", postgresql.JSONB(), nullable=False),
        sa.Column("post_data", sa.Text(), nullable=True),
        sa.Column("post_data_encoding", sa.Text(), nullable=True),
        sa.Column("post_data_sha256", sa.Text(), nullable=True),
        sa.Column("post_data_size", sa.Integer(), nullable=True),
        sa.Column("post_data_truncated", sa.Boolean(), nullable=True),
        sa.Column("post_data_source", sa.Text(), nullable=True),
        sa.Column("response_status", sa.Integer(), nullable=True),
        sa.Column("response_headers", postgresql.JSONB(), nullable=True),
        sa.Column("mime_type", sa.Text(), nullable=True),
        sa.Column("sizes", postgresql.JSONB(), nullable=True),
        sa.Column("timing", postgresql.JSONB(), nullable=True),
        sa.Column("failure_text", sa.Text(), nullable=True),
        sa.Column("blocked_by_proxy", sa.Boolean(), nullable=False),
        # NULL = no se pudo determinar (URL sin host).
        sa.Column("third_party", sa.Boolean(), nullable=True),
        sa.Column("registrable_domain", sa.Text(), nullable=True),
        sa.Column("redirected_from_seq", sa.Integer(), nullable=True),
        sa.UniqueConstraint("job_id", "seq", name="uq_scan_requests_job_seq"),
        sa.CheckConstraint(
            "post_data_encoding IS NULL OR post_data_encoding IN ('utf8', 'base64')",
            name="scan_requests_post_data_encoding_check",
        ),
    )
    op.create_index("ix_scan_requests_job_resource_type", "scan_requests", ["job_id", "resource_type"])

    op.create_table(
        "scan_redirects",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        _job_id(),
        sa.Column("chain_index", sa.Integer(), nullable=False),
        sa.Column("hop_index", sa.Integer(), nullable=False),
        sa.Column("request_seq", sa.Integer(), nullable=False),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("status", sa.Integer(), nullable=True),
        sa.UniqueConstraint("job_id", "chain_index", "hop_index", name="uq_scan_redirects_hop"),
    )

    op.create_table(
        "scan_websockets",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        _job_id(),
        sa.Column("seq", sa.Integer(), nullable=False),
        _ts(),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("host", sa.Text(), nullable=True),
        sa.Column("third_party", sa.Boolean(), nullable=True),
        sa.Column("frames_sent", sa.Integer(), nullable=False),
        sa.Column("frames_received", sa.Integer(), nullable=False),
        # true = hubo más frames de los que se guardaron.
        sa.Column("frames_truncated", sa.Boolean(), nullable=False),
        sa.Column("closed", sa.Boolean(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.UniqueConstraint("job_id", "seq", name="uq_scan_websockets_job_seq"),
    )

    op.create_table(
        "scan_ws_frames",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        _job_id(),
        sa.Column("websocket_seq", sa.Integer(), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        _ts(),
        sa.Column("direction", sa.Text(), nullable=False),
        sa.Column("opcode", sa.Text(), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("payload_encoding", sa.Text(), nullable=False),
        sa.Column("payload_size", sa.Integer(), nullable=False),
        sa.Column("payload_sha256", sa.Text(), nullable=False),
        sa.Column("payload_truncated", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(
            ["job_id", "websocket_seq"],
            ["scan_websockets.job_id", "scan_websockets.seq"],
            ondelete="CASCADE",
            name="fk_scan_ws_frames_websocket",
        ),
        sa.UniqueConstraint("job_id", "websocket_seq", "seq", name="uq_scan_ws_frames_seq"),
        sa.CheckConstraint("direction IN ('sent', 'received')", name="scan_ws_frames_direction_check"),
    )

    op.create_table(
        "scan_cookies",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        _job_id(),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("domain", sa.Text(), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        # Epoch en segundos; -1 = cookie de sesión.
        sa.Column("expires", sa.Float(), nullable=True),
        sa.Column("http_only", sa.Boolean(), nullable=False),
        sa.Column("secure", sa.Boolean(), nullable=False),
        sa.Column("same_site", sa.Text(), nullable=True),
        sa.Column("third_party", sa.Boolean(), nullable=True),
    )
    op.create_index("ix_scan_cookies_job_id", "scan_cookies", ["job_id"])

    op.create_table(
        "scan_storage",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        _job_id(),
        sa.Column("origin", sa.Text(), nullable=False),
        sa.Column("storage_type", sa.Text(), nullable=False),
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("value_truncated", sa.Boolean(), nullable=False),
        sa.CheckConstraint("storage_type IN ('local', 'session')", name="scan_storage_type_check"),
    )
    op.create_index("ix_scan_storage_job_id", "scan_storage", ["job_id"])


def downgrade() -> None:
    op.drop_table("scan_storage")
    op.drop_table("scan_cookies")
    op.drop_table("scan_ws_frames")
    op.drop_table("scan_websockets")
    op.drop_table("scan_redirects")
    op.drop_table("scan_requests")
