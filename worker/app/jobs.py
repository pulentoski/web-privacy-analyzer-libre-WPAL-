"""Cola de jobs sobre Postgres: claim con FOR UPDATE SKIP LOCKED + lease."""

import json
import logging

import asyncpg

logger = logging.getLogger(__name__)

CLAIM_SQL = """
UPDATE jobs
   SET status = 'running',
       attempts = attempts + 1,
       locked_by = $1,
       locked_until = now() + make_interval(secs => $2),
       started_at = now(),
       progress = '{"stage": "opening"}'::jsonb,
       updated_at = now()
 WHERE id = (
        SELECT id FROM jobs
         WHERE status = 'queued'
           -- Las capturas interactivas tienen su propio turno (una a la vez) y no ocupan el de los scans.
           AND (coalesce(options->>'source', '') = 'interactive') = $3
         ORDER BY created_at
         FOR UPDATE SKIP LOCKED
         LIMIT 1)
RETURNING id, url, attempts, options
"""

# El filtro por locked_by y attempts evita que un worker lento pise un job que el
# reaper ya reencoló y otro worker volvió a tomar.
FINISH_SQL = """
UPDATE jobs
   SET status = $2,
       result = $3::jsonb,
       error = $4::jsonb,
       analysis_status = $7,
       progress = coalesce(progress, '{}'::jsonb) || $8::jsonb,
       locked_by = NULL,
       locked_until = NULL,
       finished_at = now(),
       updated_at = now()
 WHERE id = $1 AND status = 'running' AND locked_by = $5 AND attempts = $6
"""

RELEASE_SQL = """
UPDATE jobs
   SET status = 'queued', locked_by = NULL, locked_until = NULL, updated_at = now()
 WHERE id = $1 AND status = 'running' AND locked_by = $2 AND attempts = $3
"""

RENEW_SQL = """
UPDATE jobs SET locked_until = now() + make_interval(secs => $4)
 WHERE id = $1 AND status = 'running' AND locked_by = $2 AND attempts = $3
"""

REAP_REQUEUE_SQL = """
UPDATE jobs
   SET status = 'queued', locked_by = NULL, locked_until = NULL, updated_at = now()
 WHERE status = 'running' AND locked_until < now() AND attempts < max_attempts
RETURNING id, attempts, locked_until
"""

REAP_FAIL_SQL = """
UPDATE jobs
   SET status = 'failed',
       error = $1::jsonb,
       locked_by = NULL,
       locked_until = NULL,
       finished_at = now(),
       updated_at = now()
 WHERE status = 'running' AND locked_until < now() AND attempts >= max_attempts
RETURNING id, attempts
"""

HEARTBEAT_SQL = """
INSERT INTO worker_heartbeats (worker_id, last_seen) VALUES ($1, now())
ON CONFLICT (worker_id) DO UPDATE SET last_seen = EXCLUDED.last_seen
"""

INSERT_REQUEST_SQL = """
INSERT INTO scan_requests (
    job_id, seq, ts, method, url, url_truncated, scheme, host, path, query_params, resource_type,
    frame_url, is_navigation, initiator, request_headers, post_data, post_data_encoding,
    post_data_sha256, post_data_size, post_data_truncated, post_data_source, response_status,
    response_headers, mime_type, sizes, timing, failure_text, blocked_by_proxy, third_party,
    registrable_domain, redirected_from_seq)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12, $13, $14::jsonb, $15::jsonb, $16, $17,
        $18, $19, $20, $21, $22, $23::jsonb, $24, $25::jsonb, $26::jsonb, $27, $28, $29, $30, $31)
"""

INSERT_REDIRECT_SQL = """
INSERT INTO scan_redirects (job_id, chain_index, hop_index, request_seq, url, status)
VALUES ($1, $2, $3, $4, $5, $6)
"""

INSERT_WEBSOCKET_SQL = """
INSERT INTO scan_websockets (
    job_id, seq, ts, url, host, third_party, frames_sent, frames_received, frames_truncated, closed, error)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
"""

INSERT_WS_FRAME_SQL = """
INSERT INTO scan_ws_frames (
    job_id, websocket_seq, seq, ts, direction, opcode, payload, payload_encoding, payload_size,
    payload_sha256, payload_truncated)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
"""

INSERT_COOKIE_SQL = """
INSERT INTO scan_cookies (job_id, name, value, domain, path, expires, http_only, secure, same_site, third_party)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
"""

INSERT_FP_CALL_SQL = """
INSERT INTO fp_api_calls (job_id, api, script_url, frame_url, count, details)
VALUES ($1, $2, $3, $4, $5, $6::jsonb)
"""

INSERT_STORAGE_SQL = """
INSERT INTO scan_storage (job_id, origin, storage_type, key, value, value_truncated)
VALUES ($1, $2, $3, $4, $5, $6)
"""


async def claim(pool: asyncpg.Pool, worker_id: str, lease_s: int, *, interactive: bool = False) -> asyncpg.Record | None:
    return await pool.fetchrow(CLAIM_SQL, worker_id, float(lease_s), interactive)


async def renew_lease(pool, job, worker_id: str, lease_s: float) -> None:
    """Una captura interactiva dura más que el lease de un scan: se renueva mientras siga viva."""
    await pool.execute(RENEW_SQL, job["id"], worker_id, job["attempts"], float(lease_s))


def job_options(job) -> dict:
    """Opciones del scan validadas (vienen de la api, pero no por eso se usan a ciegas)."""
    raw = job["options"] if "options" in job.keys() else None
    try:
        options = json.loads(raw) if isinstance(raw, str) else (raw or {})
    except ValueError:
        return {}
    out = {}
    if not isinstance(options, dict):
        return out
    if isinstance(options.get("fp_instrumentation"), bool):
        out["fp_instrumentation"] = options["fp_instrumentation"]
    # Privacy Test (F7): escenario de consentimiento, perfil y sondeo de atributos.
    if options.get("scenario") in ("sin_interaccion", "aceptar", "rechazar"):
        out["scenario"] = options["scenario"]
    if isinstance(options.get("profile"), str) and len(options["profile"]) <= 64:
        out["profile_name"] = options["profile"]
    if options.get("probe") is True:
        out["probe"] = True
    return out


def job_source(job) -> str:
    """scan (navegar con el worker) | har_import (captura del navegador del usuario, ya guardada) |
    interactive (el usuario navega en el Chromium del worker; v1.4)."""
    raw = job["options"] if "options" in job.keys() else None
    try:
        options = json.loads(raw) if isinstance(raw, str) else (raw or {})
    except ValueError:
        return "scan"
    source = options.get("source") if isinstance(options, dict) else None
    return source if source in ("har_import", "interactive") else "scan"


async def load_har_import(pool, job_id):
    """Entradas depuradas que dejó la api. None si no están (el job falla con HAR_INVALID)."""
    payload = await pool.fetchval("SELECT payload FROM har_imports WHERE job_id = $1", job_id)
    return json.loads(payload) if isinstance(payload, str) else payload


def capture_summary(capture: dict) -> dict:
    """Resumen que viaja en jobs.result; el detalle va a las tablas scan_*."""
    return {
        "total_requests": len(capture["requests"]),
        "truncated": capture["truncated"],
        "end_reason": capture["end_reason"],
        "duration_ms": capture["duration_ms"],
        "websockets": len(capture["websockets"]),
        "cookies": len(capture["cookies"]),
        "storage_items": len(capture["storage"]),
        "service_workers": capture["service_workers"],
        "first_party_domains": capture["first_party_domains"],
        "fingerprinting": _fingerprinting_summary(capture.get("fingerprinting")),
    }


def _fingerprinting_summary(fingerprinting: dict | None) -> dict | None:
    """None = el scan corrió sin instrumentación (no es lo mismo que "sin llamadas")."""
    if fingerprinting is None:
        return None
    return {
        "api_calls": len(fingerprinting["calls"]),
        "available": fingerprinting["available"],
        "truncated": fingerprinting["truncated"],
        "messages": fingerprinting["messages"],
        "rejected": fingerprinting["rejected"],
    }


def _json(value) -> str | None:
    return json.dumps(value) if value is not None else None


async def _insert_capture(conn, job_id, capture: dict) -> None:
    await conn.executemany(
        INSERT_REQUEST_SQL,
        [
            (
                job_id, r["seq"], r["ts"], r["method"], r["url"], r["url_truncated"], r["scheme"], r["host"],
                r["path"], _json(r["query_params"]), r["resource_type"], r["frame_url"], r["is_navigation"],
                _json(r["initiator"]), _json(r["request_headers"]),
                r["post_data"]["data"] if r["post_data"] else None,
                r["post_data"]["encoding"] if r["post_data"] else None,
                r["post_data"]["sha256"] if r["post_data"] else None,
                r["post_data"]["size"] if r["post_data"] else None,
                r["post_data"]["truncated"] if r["post_data"] else None,
                r["post_data_source"], r["response_status"], _json(r["response_headers"]), r["mime_type"],
                _json(r["sizes"]), _json(r["timing"]), r["failure_text"], r["blocked_by_proxy"], r["third_party"],
                r["registrable_domain"], r["redirected_from_seq"],
            )
            for r in capture["requests"]
        ],
    )
    await conn.executemany(
        INSERT_REDIRECT_SQL,
        [
            (job_id, chain_index, hop_index, hop["request_seq"], hop["url"], hop["status"])
            for chain_index, chain in enumerate(capture["redirects"])
            for hop_index, hop in enumerate(chain)
        ],
    )
    await conn.executemany(
        INSERT_WEBSOCKET_SQL,
        [
            (
                job_id, w["seq"], w["ts"], w["url"], w["host"], w["third_party"], w["frames_sent"],
                w["frames_received"], w["frames_truncated"], w["closed"], w["error"],
            )
            for w in capture["websockets"]
        ],
    )
    await conn.executemany(
        INSERT_WS_FRAME_SQL,
        [
            (
                job_id, w["seq"], f["seq"], f["ts"], f["direction"], f["opcode"], f["data"], f["encoding"],
                f["size"], f["sha256"], f["truncated"],
            )
            for w in capture["websockets"]
            for f in w["frames"]
        ],
    )
    await conn.executemany(
        INSERT_COOKIE_SQL,
        [
            (
                job_id, c["name"], c["value"], c["domain"], c["path"], c["expires"], c["http_only"], c["secure"],
                c["same_site"], c["third_party"],
            )
            for c in capture["cookies"]
        ],
    )
    await conn.executemany(
        "INSERT INTO scan_destinations (job_id, host, ip, connections) VALUES ($1, $2, $3, $4)",
        [(job_id, d["host"], d["ip"] or "", d["connections"]) for d in capture.get("destinations") or []],
    )
    await conn.executemany(
        "INSERT INTO scan_artifacts (job_id, kind, mime, data) VALUES ($1, $2, $3, $4)",
        [(job_id, a["kind"], a["mime"], a["data"]) for a in capture.get("artifacts") or []],
    )
    await conn.executemany(
        INSERT_FP_CALL_SQL,
        [
            (job_id, c["api"], c["script_url"], c["frame_url"], c["count"], _json(c["details"]))
            for c in (capture.get("fingerprinting") or {}).get("calls", [])
        ],
    )
    await conn.executemany(
        INSERT_STORAGE_SQL,
        [
            (job_id, s["origin"], s["storage_type"], s["key"], s["value"], s["value_truncated"])
            for s in capture["storage"]
        ],
    )


async def finish(
    pool, job, worker_id: str, *, result: dict | None = None, error: dict | None = None, capture: dict | None = None,
    progress: dict | None = None,
) -> bool:
    """Cierra el job y guarda su captura en la misma transacción.

    Devuelve False (sin guardar nada) si el lease venció y el job ya no es de este worker.
    """
    status = "completed" if error is None else "failed"
    async with pool.acquire() as conn:
        async with conn.transaction():
            outcome = await conn.execute(
                FINISH_SQL,
                job["id"],
                status,
                _json(result),
                _json(error),
                worker_id,
                job["attempts"],
                # Con captura guardada, el análisis queda encolado (lo toma analysis_loop).
                "queued" if capture is not None else None,
                # Último progreso publicado: el contador final de la captura (F10).
                _json(progress or {}),
            )
            if outcome != "UPDATE 1":
                return False
            if capture is not None:
                await _insert_capture(conn, job["id"], capture)
            # Staging de un HAR importado: ya está en scan_requests (o el job falló); no se conserva.
            await conn.execute("DELETE FROM har_imports WHERE job_id = $1", job["id"])
    return True


async def release(pool, job, worker_id: str) -> None:
    await pool.execute(RELEASE_SQL, job["id"], worker_id, job["attempts"])


async def reap(pool) -> None:
    for row in await pool.fetch(REAP_REQUEUE_SQL):
        logger.warning(
            "reaper_requeued_job",
            extra={"job_id": str(row["id"]), "attempts": row["attempts"]},
        )
    error = {
        "error_code": "LEASE_EXPIRED",
        "message": "El job agotó sus intentos sin terminar.",
        "stage": "worker",
    }
    for row in await pool.fetch(REAP_FAIL_SQL, json.dumps(error)):
        logger.error("reaper_failed_job", extra={"job_id": str(row["id"]), "attempts": row["attempts"]})


async def heartbeat(pool, worker_id: str) -> None:
    await pool.execute(HEARTBEAT_SQL, worker_id)
