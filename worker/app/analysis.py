"""Puente entre la base de datos y el analizador puro (app/analyzer).

Lee la captura de las tablas scan_*, ejecuta analyze() y reemplaza el análisis
anterior del job. No navega: re-analizar un scan no genera tráfico.
"""

import asyncio
import concurrent.futures
import json
import logging
import pathlib
from urllib.parse import urlsplit

from app import jobs, progress
from app.analyzer import ANALYZER_VERSION
from app.analyzer.config import load_config
from app.analyzer.engine import analyze
from app.analyzer.lists import FilterLists
from app.config import settings

logger = logging.getLogger(__name__)

# Un único hilo: los motores de `adblock` solo pueden usarse desde el hilo que los creó,
# y el análisis es CPU puro que no debe bloquear el event loop (heartbeat, scans).
_executor = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="analyzer")
_resources = None

CLAIM_SQL = """
UPDATE jobs
   SET analysis_status = 'running', analysis_locked_until = now() + make_interval(secs => $1), updated_at = now(),
       progress = coalesce(progress, '{}'::jsonb) || '{"stage": "analyzing"}'::jsonb
 WHERE id = (
        SELECT id FROM jobs
         WHERE analysis_status = 'queued'
         ORDER BY updated_at
         FOR UPDATE SKIP LOCKED
         LIMIT 1)
RETURNING id, url, result, finished_at, status, options
"""

REAP_SQL = """
UPDATE jobs SET analysis_status = 'queued', analysis_locked_until = NULL, updated_at = now()
 WHERE analysis_status = 'running' AND analysis_locked_until < now()
RETURNING id
"""

REQUESTS_SQL = """
SELECT id, seq, method, url, host, resource_type, is_navigation, query_params, request_headers,
       response_headers, post_data, post_data_encoding, post_data_size, sizes, mime_type, third_party,
       registrable_domain, response_status, initiator->>'script_url' AS initiator_script, ts, failure_text, frame_url,
       redirected_from_seq
  FROM scan_requests WHERE job_id = $1 ORDER BY seq
"""

ANALYSIS_TABLES = (
    "request_analysis", "parameters", "decoded_values", "findings", "site_analysis", "fp_findings", "fp_attributes",
)


def _load_resources():
    global _resources
    if _resources is None:
        data_dir = pathlib.Path(settings.data_dir)
        lists = FilterLists(data_dir, allow_fixtures=settings.allow_fixtures, license_profile=settings.license_profile)
        _resources = (lists, load_config(data_dir, allow_fixtures=settings.allow_fixtures,
                                         license_profile=settings.license_profile,
                                         blocking_min_requests=settings.blocking_min_requests))
        logger.info(
            "analyzer_resources_loaded",
            extra={"lists_version": lists.version, "lists": [source["id"] for source in lists.sources],
                   "license_profile": lists.license_profile, "excluded": [source["id"] for source in lists.excluded]},
        )
    return _resources


def _analyze_in_thread(capture: dict) -> dict:
    lists, config = _load_resources()
    return analyze(capture, lists, config)


def _safe(value):
    """Postgres no admite NUL en text ni en jsonb; un valor decodificado sí puede traerlo."""
    if isinstance(value, str):
        return value.replace("\x00", "").encode("utf-8", "replace").decode("utf-8")
    if isinstance(value, list):
        return [_safe(item) for item in value]
    if isinstance(value, dict):
        return {_safe(key) if isinstance(key, str) else key: _safe(item) for key, item in value.items()}
    return value


def _json(value) -> str:
    return json.dumps(_safe(value))


HISTORY_SQL = """
SELECT j.url, s.summary->>'requests' AS requests, s.summary->>'trackers' AS trackers
  FROM jobs j JOIN site_analysis s ON s.job_id = j.id
 WHERE j.status = 'completed' AND j.id <> $1
   AND j.created_at < (SELECT created_at FROM jobs WHERE id = $1)
   -- Las visitas de una comparación (v1.5.2) no son scans sueltos: no entran en el historial de un sitio.
   AND j.comparison_id IS NULL
   AND COALESCE((s.summary->'blocking'->>'blocked')::boolean, false) = false
 ORDER BY j.created_at DESC LIMIT 300
"""
MAX_HISTORY = 10


def _site(url: str | None) -> str | None:
    try:
        return (urlsplit(url or "").hostname or "").rstrip(".").lower().removeprefix("www.") or None
    except ValueError:
        return None


async def site_history(conn, job_id, url: str) -> list[dict]:
    """requests/trackers de los scans anteriores del mismo host (más reciente primero)."""
    site = _site(url)
    if site is None:
        return []
    found = []
    for row in await conn.fetch(HISTORY_SQL, job_id):
        if _site(row["url"]) != site or not (row["requests"] or "").isdigit() or not (row["trackers"] or "").isdigit():
            continue
        found.append({"requests": int(row["requests"]), "trackers": int(row["trackers"])})
        if len(found) >= MAX_HISTORY:
            break
    return found


async def load_capture(conn, job_id, url: str, result, finished_at=None) -> dict:
    result = json.loads(result) if isinstance(result, str) else (result or {})
    requests = []
    for row in await conn.fetch(REQUESTS_SQL, job_id):
        post_data = None
        if row["post_data"] is not None:
            post_data = {"data": row["post_data"], "encoding": row["post_data_encoding"], "size": row["post_data_size"]}
        requests.append(
            {
                "request_id": row["id"],
                "seq": row["seq"],
                "method": row["method"],
                "url": row["url"],
                "host": row["host"],
                "resource_type": row["resource_type"],
                "is_navigation": row["is_navigation"],
                "query_params": json.loads(row["query_params"]),
                "request_headers": json.loads(row["request_headers"]),
                "response_headers": json.loads(row["response_headers"]) if row["response_headers"] else None,
                "post_data": post_data,
                "sizes": json.loads(row["sizes"]) if row["sizes"] else None,
                "mime_type": row["mime_type"],
                "third_party": row["third_party"],
                "registrable_domain": row["registrable_domain"],
                "response_status": row["response_status"],
                "initiator_script": row["initiator_script"],
                "ts": row["ts"].timestamp() if row["ts"] is not None else None,
                "failure_text": row["failure_text"],
                "frame_url": row["frame_url"],
                # v1.4.9: salto 3xx anterior de la cadena de redirección (sincronización por redirección).
                "redirected_from_seq": row["redirected_from_seq"],
            }
        )
    # None = scan sin instrumentación (anterior a F4 o desactivada): no se inventa "sin llamadas".
    meta = (result.get("capture") or {}).get("fingerprinting")
    fingerprinting = None
    if meta is not None:
        calls = await conn.fetch(
            "SELECT id, api, script_url, frame_url, count, details FROM fp_api_calls WHERE job_id = $1 ORDER BY id", job_id
        )
        fingerprinting = {
            "calls": [
                {"call_id": row["id"], "api": row["api"], "script_url": row["script_url"], "frame_url": row["frame_url"],
                 "count": row["count"], "details": json.loads(row["details"])}
                for row in calls
            ],
            "available": meta.get("available") or [],
            "truncated": bool(meta.get("truncated")),
            "error_frame_messages": meta.get("error_frame_messages") or 0,
        }
    return {
        "start_url": url,
        # Scans anteriores del mismo sitio no marcados: referencia de la anomalía de rastreo (v1.3.1).
        "history": await site_history(conn, job_id, url),
        "page_url": result.get("final_url") or url,
        "fingerprinting": fingerprinting,
        "tcf": result.get("tcf"),
        "consent": result.get("consent"),
        # Señales de bloqueo antibot (point 3).
        "title": result.get("title"),
        # Meta description y keywords (v1.4.8). None = scan anterior o no se pudo leer.
        "page_meta": result.get("page_meta") if isinstance(result.get("page_meta"), dict) else None,
        # scan (navegador del worker) | har_import (captura del navegador real del usuario).
        "source": result.get("source") or "scan",
        # Captura interactiva (v1.4.2): hora y tipo de cada interacción del usuario. None = no se registró.
        "interactions": (result.get("interactive") or {}).get("interactions") if isinstance(result.get("interactive"), dict) else None,
        # v1.4.10: páginas visitadas de la captura interactiva (URL de navegaciones sin request propia; linker _gl).
        "timeline": (result.get("interactive") or {}).get("timeline") if isinstance(result.get("interactive"), dict) else None,
        "http_status": result.get("http_status"),
        # Scan parcial (v1.4.8): goto agotó el tiempo con respuestas ya recibidas. None = navegación completa.
        "partial_navigation": result.get("partial"),
        "requests": requests,
        # Fin de la visita: referencia para saber cuánto le queda a cada cookie.
        "visit_ts": finished_at.timestamp() if finished_at is not None else None,
        "cookies": [dict(row) for row in await conn.fetch("SELECT name, value, domain, expires, third_party FROM scan_cookies WHERE job_id = $1", job_id)],
        "storage": [dict(row) for row in await conn.fetch("SELECT storage_type, key, value, origin FROM scan_storage WHERE job_id = $1", job_id)],
        "websockets": [dict(row) for row in await conn.fetch("SELECT url, third_party FROM scan_websockets WHERE job_id = $1", job_id)],
    }


async def save_analysis(conn, job_id, analysis: dict) -> None:
    """Reemplaza el análisis del job. Todo o nada."""
    version = analysis["analyzer_version"]
    async with conn.transaction():
        for table in ANALYSIS_TABLES:
            await conn.execute(f"DELETE FROM {table} WHERE job_id = $1", job_id)
        await conn.executemany(
            "INSERT INTO request_analysis (job_id, request_id, score, band, category, mechanism, entity,"
            " list_matches, reasons, analyzer_version, referer, party)"
            " VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10, $11, $12)",
            [
                (job_id, r["request_id"], r["score"], r["band"], r["category"], r["mechanism"], r["entity"],
                 _json(r["list_matches"]), _json(r["reasons"]), version, r["referer"], r.get("party"))
                for r in analysis["requests"]
            ],
        )
        await conn.executemany(
            "INSERT INTO parameters (job_id, request_id, source, name, value, value_truncated, category, shapes,"
            " length, entropy, identifier_like, encoding_chain)"
            " VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11, $12::jsonb)",
            [
                (job_id, p["request_id"], p["source"], _safe(p["name"]), _safe(p["value"]), p["value_truncated"],
                 p["category"], _json(p["shapes"]), p["length"], p["entropy"], p["identifier_like"],
                 _json(p["encoding_chain"]))
                for p in analysis["parameters"]
            ],
        )
        await conn.executemany(
            "INSERT INTO decoded_values (job_id, request_id, source, name, path, raw_value, decoded_value,"
            " decoded_truncated, encoding_chain, confidence) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10)",
            [
                # raw_value se guarda tal cual llegó de la captura: nunca se transforma.
                (job_id, d["request_id"], d["source"], _safe(d["name"]), _safe(d["path"]), d["raw_value"],
                 _safe(d["decoded_value"]), d["decoded_truncated"], _json(d["encoding_chain"]), d["confidence"])
                for d in analysis["decoded_values"]
            ],
        )
        await conn.executemany(
            "INSERT INTO findings (job_id, type, level, claim, evidence_refs, details, analyzer_version)"
            " VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7)",
            [
                (job_id, f["type"], f["level"], _safe(f["claim"]), _json(f["evidence_refs"]), _json(f["details"]), version)
                for f in analysis["findings"]
            ],
        )
        fingerprinting = analysis["fingerprinting"]
        await conn.executemany(
            "INSERT INTO fp_findings (job_id, script_url, heuristic, level, claim, call_refs, request_refs, details,"
            " analyzer_version) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8::jsonb, $9)",
            [
                (job_id, _safe(f["script_url"]), f["heuristic"], f["level"], _safe(f["claim"]), _json(f["call_refs"]),
                 _json(f["request_refs"]), _json(f["details"]), version)
                for f in fingerprinting["findings"]
            ],
        )
        await conn.executemany(
            "INSERT INTO fp_attributes (job_id, attribute, status, value, scripts, call_refs, request_refs)"
            " VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb)",
            [
                (job_id, a["attribute"], a["status"], _safe(a["value"]), _json(a["scripts"]), _json(a["call_refs"]),
                 _json(a["request_refs"]))
                for a in fingerprinting["attributes"]
            ],
        )
        site = analysis["site"]
        await conn.execute(
            "INSERT INTO site_analysis (job_id, analyzer_version, lists_version, lists, score, band, breakdown,"
            " data_categories, mechanisms, summary, partial, duration_ms)"
            " VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7::jsonb, $8::jsonb, $9::jsonb, $10::jsonb, $11, $12)",
            job_id, version, analysis["lists_version"], _json(analysis["lists"]), site["score"], site["band"],
            _json(site["breakdown"]), _json(site["data_categories"]), _json(site["mechanisms"]), _json(site["summary"]),
            analysis["partial"], analysis["duration_ms"],
        )
        await conn.execute(
            "UPDATE jobs SET analysis_status = 'completed', analysis_locked_until = NULL, updated_at = now() WHERE id = $1",
            job_id,
        )


async def run_analysis(pool, job) -> None:
    job_id = job["id"]
    loop = asyncio.get_running_loop()
    try:
        async with pool.acquire() as conn:
            capture = await load_capture(conn, job_id, job["url"], job["result"], job["finished_at"])
        # Navegación fallida (timeout, error de red): lo guardado no es una medición (docs/adr/035).
        capture["navigation_failed"] = job.get("status") == "failed"
        if capture["source"] == "scan":
            # Un job fallido no tiene result: el origen (p. ej. captura interactiva) sale de sus opciones.
            capture["source"] = jobs.job_source(job)
        analysis = await loop.run_in_executor(_executor, _analyze_in_thread, capture)
        # Etapa "generando resultado": el análisis terminó y se está guardando.
        await progress.set_stage(pool, job_id, "building")
        async with pool.acquire() as conn:
            await save_analysis(conn, job_id, analysis)
    except Exception:
        logger.exception("analysis_failed", extra={"job_id": str(job_id)})
        await pool.execute(
            "UPDATE jobs SET analysis_status = 'failed', analysis_locked_until = NULL, updated_at = now() WHERE id = $1",
            job_id,
        )
        return
    logger.info(
        "analysis_finished",
        extra={
            "job_id": str(job_id),
            "analyzer_version": ANALYZER_VERSION,
            "requests": len(analysis["requests"]),
            "trackers": analysis["site"]["summary"]["trackers"],
            "findings": len(analysis["findings"]),
            "site_score": analysis["site"]["score"],
            "partial": analysis["partial"],
            "duration_ms": analysis["duration_ms"],
        },
    )


async def analysis_loop(pool) -> None:
    """Toma jobs con analysis_status='queued' (tras cada captura o por /reanalyze)."""
    try:
        # Cargar las listas tarda unos segundos: mejor al arrancar que en el primer análisis.
        await asyncio.get_running_loop().run_in_executor(_executor, _load_resources)
    except Exception:
        logger.exception("analyzer_resources_failed")
    while True:
        try:
            for row in await pool.fetch(REAP_SQL):
                logger.warning("analysis_requeued", extra={"job_id": str(row["id"])})
            job = await pool.fetchrow(CLAIM_SQL, float(settings.analysis_lease_s))
        except Exception as exc:
            logger.error("analysis_claim_failed", extra={"error_type": type(exc).__name__, "error": str(exc)})
            job = None
        if job is None:
            await asyncio.sleep(settings.poll_interval_s)
            continue
        await run_analysis(pool, job)
