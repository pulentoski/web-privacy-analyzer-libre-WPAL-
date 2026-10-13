import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    url: Mapped[str] = mapped_column(Text)
    # URL tal como se recibió; `url` es la escaneada (sin parámetros de seguimiento, v1.2). NULL = igual.
    original_url: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), server_default="queued")
    attempts: Mapped[int] = mapped_column(Integer, server_default="0")
    max_attempts: Mapped[int] = mapped_column(Integer, server_default="3")
    locked_by: Mapped[str | None] = mapped_column(Text)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    result: Mapped[dict | None] = mapped_column(JSONB)
    error: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # NULL = sin captura que analizar. queued | running | completed | failed.
    analysis_status: Mapped[str | None] = mapped_column(String(16))
    # {"fp_instrumentation": bool}; NULL = valores por defecto del worker.
    options: Mapped[dict | None] = mapped_column(JSONB)
    # Progreso que publica el worker mientras el scan corre (F10); NULL = aún en cola.
    progress: Mapped[dict | None] = mapped_column(JSONB)


class HarImport(Base):
    """Entradas depuradas de un HAR importado, hasta que el worker las convierte en captura (v1.3)."""

    __tablename__ = "har_imports"

    job_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="CASCADE"), primary_key=True)
    payload: Mapped[dict] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class InteractiveSession(Base):
    """Captura interactiva (v1.4): el usuario navega en el Chromium del worker. Una viva a la vez."""

    __tablename__ = "interactive_sessions"

    job_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="CASCADE"), primary_key=True)
    # sha256 del token que autoriza el relé VNC; el token solo lo tiene el navegador que inició la sesión.
    token_hash: Mapped[str] = mapped_column(Text)
    # Contraseña de un solo uso y dirección del VNC en la red interna; NULL al terminar.
    vnc_password: Mapped[str | None] = mapped_column(Text)
    vnc_host: Mapped[str | None] = mapped_column(Text)
    vnc_port: Mapped[int | None] = mapped_column(Integer)
    # starting | ready | ended
    state: Mapped[str] = mapped_column(String(16), server_default="starting")
    stop_requested: Mapped[bool] = mapped_column(Boolean, server_default="false")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    ready_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_input_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    end_reason: Mapped[str | None] = mapped_column(String(32))
    # Límites que aplica el worker (los informa al quedar lista).
    idle_s: Mapped[int | None] = mapped_column(Integer)
    max_s: Mapped[int | None] = mapped_column(Integer)
    # [[epoch_ms, "click" | "scroll" | "key"], ...]: hora y tipo de cada interacción del usuario (v1.4.2). Nunca qué se tecleó.
    interactions: Mapped[list | None] = mapped_column(JSONB)


class WorkerHeartbeat(Base):
    __tablename__ = "worker_heartbeats"

    worker_id: Mapped[str] = mapped_column(Text, primary_key=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ScanRequest(Base):
    """Una request capturada por el worker. La escribe el worker; la api solo lee."""

    __tablename__ = "scan_requests"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    job_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="CASCADE"))
    seq: Mapped[int] = mapped_column(Integer)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    method: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(Text)
    url_truncated: Mapped[bool] = mapped_column(Boolean)
    scheme: Mapped[str | None] = mapped_column(Text)
    host: Mapped[str | None] = mapped_column(Text)
    path: Mapped[str | None] = mapped_column(Text)
    query_params: Mapped[list] = mapped_column(JSONB)
    resource_type: Mapped[str | None] = mapped_column(Text)
    frame_url: Mapped[str | None] = mapped_column(Text)
    is_navigation: Mapped[bool] = mapped_column(Boolean)
    initiator: Mapped[dict | None] = mapped_column(JSONB)
    request_headers: Mapped[list] = mapped_column(JSONB)
    post_data: Mapped[str | None] = mapped_column(Text)
    post_data_encoding: Mapped[str | None] = mapped_column(Text)
    post_data_sha256: Mapped[str | None] = mapped_column(Text)
    post_data_size: Mapped[int | None] = mapped_column(Integer)
    post_data_truncated: Mapped[bool | None] = mapped_column(Boolean)
    post_data_source: Mapped[str | None] = mapped_column(Text)
    response_status: Mapped[int | None] = mapped_column(Integer)
    response_headers: Mapped[list | None] = mapped_column(JSONB)
    mime_type: Mapped[str | None] = mapped_column(Text)
    sizes: Mapped[dict | None] = mapped_column(JSONB)
    timing: Mapped[dict | None] = mapped_column(JSONB)
    failure_text: Mapped[str | None] = mapped_column(Text)
    blocked_by_proxy: Mapped[bool] = mapped_column(Boolean)
    third_party: Mapped[bool | None] = mapped_column(Boolean)
    registrable_domain: Mapped[str | None] = mapped_column(Text)
    redirected_from_seq: Mapped[int | None] = mapped_column(Integer)


class ScanRedirect(Base):
    __tablename__ = "scan_redirects"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    job_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="CASCADE"))
    chain_index: Mapped[int] = mapped_column(Integer)
    hop_index: Mapped[int] = mapped_column(Integer)
    request_seq: Mapped[int] = mapped_column(Integer)
    url: Mapped[str | None] = mapped_column(Text)
    status: Mapped[int | None] = mapped_column(Integer)


class RequestAnalysis(Base):
    """Resultado del analizador para una request. Lo escribe el worker."""

    __tablename__ = "request_analysis"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    job_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="CASCADE"))
    request_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("scan_requests.id", ondelete="CASCADE"))
    score: Mapped[int] = mapped_column(Integer)
    band: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(Text)
    mechanism: Mapped[str] = mapped_column(Text)
    entity: Mapped[str] = mapped_column(Text)
    list_matches: Mapped[list] = mapped_column(JSONB)
    reasons: Mapped[list] = mapped_column(JSONB)
    analyzer_version: Mapped[str] = mapped_column(Text)
    referer: Mapped[str | None] = mapped_column(Text)
    # propio | same_org | third_party (NULL en filas anteriores a v1.2.1). Solo third_party cuenta
    # como "tercero" en el resumen, el índice de exposición, el Panel y los reportes.
    party: Mapped[str | None] = mapped_column(Text)
