"""Captura interactiva (v1.4, docs/adr/029): el usuario navega en el Chromium del worker.

La api crea la sesión (un job con `source = interactive`), la detiene y hace de relé entre el
WebSocket de noVNC (navegador del usuario → nginx en 127.0.0.1 → api) y el servidor VNC del
worker, que solo escucha en la red `internal` de Docker. Para llegar a la pantalla hacen falta
las tres cosas: estar en el equipo (el frontend solo publica en loopback), el token de la sesión
(solo lo recibe quien la inició; aquí se guarda su hash) y la contraseña VNC de un solo uso.

Deshabilitada en modo demo: con el frontend publicado en la red local, nadie debe poder manejar
un navegador dentro del equipo.
"""

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import time
import uuid
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field, StrictBool
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db import SessionLocal, get_session
from app.errors import AppError
from app.models import InteractiveSession, Job
from app.ratelimit import client_ip, scan_limiter
from app.security.url_validator import MAX_URL_LENGTH, UrlValidationError, validate_url
from app.url_cleaning import clean_url

router = APIRouter(tags=["interactive"])
logger = logging.getLogger(__name__)

SOURCE = "interactive"
VNC_PORT = 5900
# Mensajes RFB del cliente que son entrada del usuario: tecla, puntero, portapapeles.
INPUT_MESSAGES = frozenset({4, 5, 6})
INPUT_TOUCH_EVERY_S = 5.0
INTERACTION_FLUSH_S = 1.0
MAX_FRAME_BYTES = 1 << 20
WARNING = (
    "Lo que escriba en el navegador (búsquedas, formularios) y las cookies de la sesión quedan guardados en la captura. "
    "Las contraseñas y otros campos de credenciales se enmascaran antes de guardar, pero las cookies de una sesión iniciada no. "
    "No inicie sesión con cuentas reales si va a compartir el reporte."
)

EXPIRE_SQL = """
UPDATE interactive_sessions s
   SET state = 'ended', ended_at = now(), end_reason = 'worker_lost', vnc_password = NULL, vnc_host = NULL, vnc_port = NULL
 WHERE s.ended_at IS NULL
   AND (EXISTS (SELECT 1 FROM jobs j WHERE j.id = s.job_id AND j.status NOT IN ('queued', 'running'))
        OR (s.state = 'starting' AND s.created_at < now() - make_interval(secs => :timeout)
            AND EXISTS (SELECT 1 FROM jobs j WHERE j.id = s.job_id AND j.status = 'queued')))
RETURNING s.job_id
"""
FAIL_QUEUED_SQL = """
UPDATE jobs SET status = 'failed', finished_at = now(), updated_at = now(),
       error = jsonb_build_object('error_code', 'INTERACTIVE_NOT_STARTED', 'message', 'El worker no tomó la captura interactiva.', 'stage', 'interactive')
 WHERE id = ANY(:ids) AND status = 'queued'
"""
ACTIVE_SQL = """
SELECT s.job_id, s.state, s.stop_requested, s.created_at, s.ready_at, s.idle_s, s.max_s, j.url,
       (j.progress->>'requests')::int AS requests,
       extract(epoch FROM now() - coalesce(s.last_input_at, s.ready_at, s.created_at)) AS idle_for_s,
       extract(epoch FROM now() - coalesce(s.ready_at, s.created_at)) AS age_s
  FROM interactive_sessions s JOIN jobs j ON j.id = s.job_id
 WHERE s.ended_at IS NULL
"""


class InteractiveBody(BaseModel):
    model_config = {"extra": "forbid"}

    url: str = Field(min_length=1, max_length=MAX_URL_LENGTH)
    clean_url: StrictBool = True


def _require_enabled() -> None:
    if get_settings().demo:
        raise AppError("INTERACTIVE_DISABLED", "En modo demo no hay captura interactiva.", stage="interactive", status_code=403)


async def expire_stale(session: AsyncSession) -> None:
    """Sesiones cuyo job ya terminó o que el worker nunca tomó: se cierran para liberar el turno."""
    ids = [row[0] for row in (await session.execute(text(EXPIRE_SQL), {"timeout": get_settings().interactive_start_timeout_s})).all()]
    if ids:
        await session.execute(text(FAIL_QUEUED_SQL), {"ids": ids})
        logger.warning("interactive_expired", extra={"sessions": len(ids)})
    await session.commit()


async def active_session(session: AsyncSession) -> dict | None:
    await expire_stale(session)
    row = (await session.execute(text(ACTIVE_SQL))).mappings().one_or_none()
    if row is None:
        return None
    ready = row["state"] == "ready"
    return {
        "job_id": str(row["job_id"]),
        "state": "stopping" if row["stop_requested"] else row["state"],
        "url": row["url"],
        "created_at": row["created_at"],
        "ready_at": row["ready_at"],
        "requests": row["requests"],
        # Límites que aplica el worker; None hasta que la sesión queda lista.
        "idle_limit_s": row["idle_s"],
        "max_duration_s": row["max_s"],
        "idle_remaining_s": max(0, round(row["idle_s"] - float(row["idle_for_s"]))) if ready and row["idle_s"] else None,
        "remaining_s": max(0, round(row["max_s"] - float(row["age_s"]))) if ready and row["max_s"] else None,
    }


@router.get("/api/interactive")
async def status(session: AsyncSession = Depends(get_session)) -> dict:
    enabled = not get_settings().demo
    return {"enabled": enabled, "session": await active_session(session) if enabled else None, "warning": WARNING}


@router.post("/api/interactive", status_code=201)
async def start(body: InteractiveBody, request: Request, session: AsyncSession = Depends(get_session)) -> dict:
    _require_enabled()
    settings = get_settings()
    original = body.url.strip()
    target = clean_url(original)[0] if body.clean_url else original
    try:
        # Misma capa 1 que un scan. La que garantiza es el proxy, en cada conexión del navegador.
        validated = await validate_url(target, allow_fixtures=settings.allow_fixtures)
    except UrlValidationError as exc:
        raise AppError(exc.code, exc.message, stage="url_validation", status_code=400) from exc
    retry_after = scan_limiter.check(client_ip(request), settings.scan_rate_limit, settings.scan_rate_window_s)
    if retry_after is not None:
        raise AppError("RATE_LIMITED", f"Demasiados scans desde esta dirección. Máximo {settings.scan_rate_limit} cada {settings.scan_rate_window_s} segundos.",
                       stage="rate_limit", status_code=429,
                       details={"limit": settings.scan_rate_limit, "window_s": settings.scan_rate_window_s, "retry_after_s": round(retry_after, 1)})
    await expire_stale(session)
    token, password = secrets.token_urlsafe(32), secrets.token_hex(4)
    # max_attempts = 1: una sesión interrumpida no se repite sola (lo que navegó el usuario ya no existe).
    job = Job(url=validated.url, original_url=original, options={"source": SOURCE}, max_attempts=1)
    session.add(job)
    try:
        await session.flush()
        session.add(InteractiveSession(job_id=job.id, token_hash=hashlib.sha256(token.encode()).hexdigest(), vnc_password=password))
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise AppError("INTERACTIVE_BUSY", "Ya hay una captura interactiva en curso. Deténgala antes de iniciar otra.",
                       stage="interactive", status_code=409) from exc
    # El token y la contraseña se entregan una sola vez, a quien inició la sesión.
    return {"job_id": str(job.id), "state": "starting", "url": job.url, "token": token, "vnc_password": password, "warning": WARNING}


@router.post("/api/interactive/{job_id}/stop")
async def stop(job_id: uuid.UUID, session: AsyncSession = Depends(get_session)) -> dict:
    _require_enabled()
    await expire_stale(session)
    updated = await session.execute(
        text("UPDATE interactive_sessions SET stop_requested = true WHERE job_id = :job_id AND ended_at IS NULL RETURNING state"), {"job_id": job_id}
    )
    row = updated.first()
    await session.commit()
    if row is None:
        if await session.get(Job, job_id) is None:
            raise AppError("JOB_NOT_FOUND", "El job no existe.", stage="interactive", status_code=404)
        # Ya había terminado (inactividad, duración máxima…): el scan está o estará en su página.
        return {"job_id": str(job_id), "state": "ended"}
    return {"job_id": str(job_id), "state": "stopping"}


# --- relé VNC ---

_relays: dict[uuid.UUID, asyncio.Task] = {}


def _same_origin(websocket: WebSocket) -> bool:
    """Un navegador siempre manda Origin: debe ser el propio frontend (evita el secuestro entre sitios)."""
    origin = websocket.headers.get("origin")
    if origin is None:
        return True  # cliente que no es un navegador; igual necesita el token
    try:
        return urlsplit(origin).netloc.lower() == (websocket.headers.get("host") or "").lower() != ""
    except ValueError:
        return False


async def _vnc_target(job_id: uuid.UUID, token: str) -> tuple[str, int] | None:
    async with SessionLocal() as session:
        row = await session.get(InteractiveSession, job_id)
    if row is None or row.ended_at is not None or row.state != "ready" or not row.vnc_host:
        return None
    if not hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(), row.token_hash):
        return None
    # La dirección la escribió el worker: aun así solo se conecta a la red interna de Docker y al puerto del VNC.
    try:
        address = ipaddress.ip_address(row.vnc_host)
    except ValueError:
        return None
    if row.vnc_port != VNC_PORT or not any(address in network for network in get_settings().docker_networks):
        return None
    return str(address), VNC_PORT


# Largo de cada mensaje RFB del cliente (RFC 6143 §7.5); -1 = variable.
RFB_LENGTHS = {0: 20, 2: -1, 3: 10, 4: 8, 5: 6, 6: -1}
MAX_INTERACTIONS = 3000
COALESCE_MS = 300


class InteractionLog:
    """Hora y tipo de cada clic, desplazamiento y tecla del usuario, leídos de los mensajes RFB que pasan por el relé.

    Solo eso: de una tecla no se mira cuál es; de un clic, ni la posición. Sirve para correlacionar la
    interacción con los envíos del sitio en los segundos siguientes (docs/adr/030).
    """

    def __init__(self) -> None:
        self.pending: list[list] = []
        self.total = 0
        self._buttons = 0
        self._last: dict[str, float] = {}

    def _add(self, kind: str, now_ms: float) -> None:
        if self.total >= MAX_INTERACTIONS or now_ms - self._last.get(kind, 0.0) < COALESCE_MS:
            return
        self._last[kind] = now_ms
        self.total += 1
        self.pending.append([round(now_ms), kind])

    def feed(self, data: bytes, now_ms: float) -> bool:
        """Procesa un frame del cliente. Devuelve True si traía entrada del usuario (teclado o puntero)."""
        offset, user_input = 0, False
        while offset < len(data):
            kind = data[offset]
            length = RFB_LENGTHS.get(kind)
            if length is None:
                break  # extensión que no se interpreta: el resto del frame se reenvía sin mirar
            if kind == 2:
                length = 4 + 4 * int.from_bytes(data[offset + 2:offset + 4], "big") if offset + 4 <= len(data) else len(data)
            elif kind == 6:
                length = 8 + int.from_bytes(data[offset + 4:offset + 8], "big") if offset + 8 <= len(data) else len(data)
            if offset + length > len(data):
                break
            if kind == 4:
                user_input = True
                if data[offset + 1]:  # tecla presionada; el keysym (bytes 4-7) no se lee
                    self._add("key", now_ms)
            elif kind == 5:
                user_input = True
                buttons = data[offset + 1]
                pressed = buttons & ~self._buttons
                if pressed & 0b00000111:
                    self._add("click", now_ms)
                if pressed & 0b01111000:  # rueda: arriba, abajo, izquierda, derecha
                    self._add("scroll", now_ms)
                self._buttons = buttons
            offset += length
        return user_input

    def take(self) -> list[list]:
        taken, self.pending = self.pending, []
        return taken


async def _touch(job_id: uuid.UUID, interactions: list | None = None) -> bool:
    if interactions:
        async with SessionLocal() as session:
            await session.execute(
                text("UPDATE interactive_sessions SET interactions = coalesce(interactions, '[]'::jsonb) || CAST(:new AS jsonb) WHERE job_id = :job_id"),
                {"job_id": job_id, "new": json.dumps(interactions)},
            )
            await session.commit()
    async with SessionLocal() as session:
        result = await session.execute(
            text("UPDATE interactive_sessions SET last_input_at = now() WHERE job_id = :job_id AND ended_at IS NULL"), {"job_id": job_id}
        )
        await session.commit()
        return result.rowcount == 1


@router.websocket("/api/interactive/{job_id}/ws")
async def relay(websocket: WebSocket, job_id: uuid.UUID, token: str = "") -> None:
    if get_settings().demo or not _same_origin(websocket) or not 16 <= len(token) <= 128:
        await websocket.close(code=1008)
        return
    target = await _vnc_target(job_id, token)
    if target is None:
        await websocket.close(code=1008)
        return
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(*target), 5)
    except (OSError, asyncio.TimeoutError):
        await websocket.close(code=1011)
        return
    offered = websocket.scope.get("subprotocols") or []
    await websocket.accept(subprotocol="binary" if "binary" in offered else None)
    # Una sola vista: una conexión nueva (p. ej. al recargar la página) reemplaza a la anterior.
    previous = _relays.get(job_id)
    if previous is not None:
        previous.cancel()
    _relays[job_id] = asyncio.current_task()

    async def to_browser() -> None:
        while True:
            data = await reader.read(65536)
            if not data:
                return
            await websocket.send_bytes(data)

    log = InteractionLog()

    async def to_vnc() -> None:
        last_touch = last_flush = 0.0
        while True:
            data = await websocket.receive_bytes()
            if len(data) > MAX_FRAME_BYTES:
                return
            writer.write(data)
            await writer.drain()
            user_input = log.feed(data, time.time() * 1000)
            now = time.monotonic()
            if user_input and now - last_touch >= INPUT_TOUCH_EVERY_S:
                last_touch = last_flush = now
                if not await _touch(job_id, log.take()):
                    return  # la sesión terminó
            elif log.pending and now - last_flush >= INTERACTION_FLUSH_S:
                last_flush = now
                await _touch(job_id, log.take())

    pumps = [asyncio.create_task(to_browser()), asyncio.create_task(to_vnc())]
    try:
        await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for pump in pumps:
            pump.cancel()
        results = await asyncio.gather(*pumps, return_exceptions=True)
        if any(isinstance(item, Exception) and not isinstance(item, (WebSocketDisconnect, OSError)) for item in results):
            logger.warning("interactive_relay_error", extra={"job_id": str(job_id)})
        writer.close()
        if log.pending:
            try:
                await _touch(job_id, log.take())
            except Exception:  # la sesión ya no existe: no hay dónde anotarlo
                pass
        if _relays.get(job_id) is asyncio.current_task():
            del _relays[job_id]
        try:
            await websocket.close()
        except RuntimeError:
            pass  # ya estaba cerrado
