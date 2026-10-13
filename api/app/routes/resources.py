"""Indicador de recursos (v1.4): CPU y RAM del stack, scans activos y captura interactiva.

Cada servicio lee sus propios contadores de cgroup v2 (`/sys/fs/cgroup`, solo lectura) y la api
los agrega; nadie monta el socket de Docker:
  - api: lee sus archivos;
  - db: PostgreSQL lee los suyos (`pg_read_file`) en la misma consulta que cuenta los scans;
  - frontend: un bucle de shell deja su muestra en un archivo que nginx sirve en un puerto interno;
  - worker y egress-proxy: el worker publica ambas en `service_resources` (no tiene listeners y
    la api no comparte red con el proxy).
El uso de CPU es la diferencia entre dos muestras del mismo servicio; sin muestra anterior, o
con una muestra vieja, el dato es "no_disponible": no se estima.
"""

import asyncio
import json
import logging
import pathlib
import time
import urllib.request
from datetime import datetime, timezone

from fastapi import APIRouter
from sqlalchemy import text

from app.config import get_settings
from app.db import SessionLocal

router = APIRouter(tags=["resources"])
logger = logging.getLogger(__name__)

UNKNOWN = "no_disponible"
CGROUP = pathlib.Path("/sys/fs/cgroup")
SERVICES = ("frontend", "api", "worker", "db", "egress-proxy")
SAMPLE_KEYS = ("ts", "cpu_usage_usec", "memory_current", "memory_inactive_file", "memory_max", "cpu_quota_usec", "cpu_period_usec", "pids_current", "pids_max")
# Varias pestañas abiertas no multiplican el costo: la respuesta se reutiliza durante este tiempo.
CACHE_S = 1.0
MAX_CPU_WINDOW_S = 120.0

DB_SQL = """
SELECT pg_read_file('/sys/fs/cgroup/cpu.stat', 0, 8192) AS cpu_stat,
       pg_read_file('/sys/fs/cgroup/memory.current', 0, 64) AS memory_current,
       pg_read_file('/sys/fs/cgroup/memory.stat', 0, 16384) AS memory_stat,
       pg_read_file('/sys/fs/cgroup/memory.max', 0, 64) AS memory_max,
       pg_read_file('/sys/fs/cgroup/cpu.max', 0, 64) AS cpu_max,
       pg_read_file('/sys/fs/cgroup/pids.current', 0, 64) AS pids_current,
       pg_read_file('/sys/fs/cgroup/pids.max', 0, 64) AS pids_max,
       (SELECT count(*) FROM jobs WHERE status = 'running' AND coalesce(options->>'source', '') <> 'interactive') AS running,
       (SELECT count(*) FROM jobs WHERE status = 'queued' AND coalesce(options->>'source', '') <> 'interactive') AS queued,
       (SELECT count(*) FROM jobs WHERE analysis_status IN ('queued', 'running')) AS analyzing,
       (SELECT job_id FROM interactive_sessions WHERE ended_at IS NULL LIMIT 1) AS interactive_job,
       EXISTS (SELECT 1 FROM worker_heartbeats WHERE last_seen > now() - make_interval(secs => :heartbeat_age)) AS worker_alive,
       (SELECT jsonb_object_agg(service, sample) FROM service_resources
         WHERE reported_at > now() - make_interval(secs => :max_age)) AS reported
"""


def _limit(value: str) -> int | None:
    value = (value or "").strip()
    return int(value) if value.isdigit() else None


def _stat(content: str, key: str) -> int | None:
    for line in (content or "").splitlines():
        name, _, value = line.partition(" ")
        if name == key and value.strip().isdigit():
            return int(value)
    return None


def parse_sample(files: dict, ts: float) -> dict:
    """Muestra a partir del contenido de los archivos de cgroup v2. "max" (sin límite) = None."""
    quota, _, period = (files.get("cpu_max") or "").strip().partition(" ")
    return {
        "ts": ts,
        "cpu_usage_usec": _stat(files.get("cpu_stat"), "usage_usec"),
        "memory_current": _limit(files.get("memory_current")),
        "memory_inactive_file": _stat(files.get("memory_stat"), "inactive_file"),
        "memory_max": _limit(files.get("memory_max")),
        "cpu_quota_usec": _limit(quota),
        "cpu_period_usec": _limit(period),
        "pids_current": _limit(files.get("pids_current")),
        "pids_max": _limit(files.get("pids_max")),
    }


def clean_sample(raw: object) -> dict | None:
    """Muestra que llega de otro servicio: solo las claves conocidas y solo números no negativos."""
    if not isinstance(raw, dict):
        return None
    out = {}
    for key in SAMPLE_KEYS:
        value = raw.get(key)
        if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value < 2**62):
            return None
        out[key] = value
    return out if out["ts"] is not None else None


def own_sample() -> dict:
    names = {"cpu_stat": "cpu.stat", "memory_current": "memory.current", "memory_stat": "memory.stat", "memory_max": "memory.max",
             "cpu_max": "cpu.max", "pids_current": "pids.current", "pids_max": "pids.max"}
    return parse_sample({key: (CGROUP / name).read_text(encoding="ascii") for key, name in names.items()}, time.time())


def _fetch_frontend(url: str) -> dict | None:
    with urllib.request.urlopen(url, timeout=1.5) as response:  # noqa: S310 - URL fija de configuración
        return clean_sample(json.loads(response.read(4096)))


class Aggregator:
    """Guarda las dos últimas muestras distintas de cada servicio para calcular el uso de CPU."""

    def __init__(self) -> None:
        self._last: dict[str, dict] = {}
        self._previous: dict[str, dict] = {}

    def add(self, service: str, sample: dict) -> None:
        last = self._last.get(service)
        if last is not None and last["ts"] == sample["ts"]:
            return
        if last is not None:
            self._previous[service] = last
        self._last[service] = sample

    def describe(self, service: str, fresh: bool, alert_percent: float) -> dict:
        sample = self._last.get(service) if fresh else None
        if sample is None or sample.get("memory_current") is None:
            return {"service": service, "status": UNKNOWN, "cpu_percent": None, "cpu_limit_percent": None, "memory_bytes": None,
                    "memory_limit_bytes": None, "memory_percent": None, "pids": None, "pids_limit": None, "alert": False}
        previous = self._previous.get(service)
        cpu = None
        if previous is not None and sample["cpu_usage_usec"] is not None and previous.get("cpu_usage_usec") is not None:
            elapsed = sample["ts"] - previous["ts"]
            used = sample["cpu_usage_usec"] - previous["cpu_usage_usec"]
            if 0 < elapsed <= MAX_CPU_WINDOW_S and used >= 0:
                # 100 % = un núcleo completo (misma convención que `docker stats`).
                cpu = round(used / (elapsed * 1_000_000) * 100, 1)
        memory = max(0, sample["memory_current"] - (sample.get("memory_inactive_file") or 0))
        limit = sample.get("memory_max")
        percent = round(memory / limit * 100, 1) if limit else None
        quota, period = sample.get("cpu_quota_usec"), sample.get("cpu_period_usec")
        return {
            "service": service, "status": "ok", "cpu_percent": cpu,
            "cpu_limit_percent": round(quota / period * 100, 1) if quota and period else None,
            # Como `docker stats`: memoria en uso sin la caché de archivos inactiva.
            "memory_bytes": memory, "memory_limit_bytes": limit, "memory_percent": percent,
            "pids": sample.get("pids_current"), "pids_limit": sample.get("pids_max"),
            "alert": percent is not None and percent > alert_percent,
        }


aggregator = Aggregator()
_cache: dict = {"at": 0.0, "body": None}
_lock = asyncio.Lock()


async def _collect() -> dict:
    settings = get_settings()
    fresh = set()
    try:
        aggregator.add("api", own_sample())
        fresh.add("api")
    except (OSError, ValueError) as exc:
        logger.warning("resources_own_failed", extra={"error_type": type(exc).__name__})

    async def database():
        async with SessionLocal() as session:
            return (await session.execute(text(DB_SQL), {"max_age": settings.resources_max_age_s, "heartbeat_age": settings.worker_heartbeat_max_age_s})).mappings().one()

    row, frontend = await asyncio.gather(
        asyncio.wait_for(database(), 3), asyncio.wait_for(asyncio.to_thread(_fetch_frontend, settings.frontend_resources_url), 3),
        return_exceptions=True,
    )
    scans = {"running": None, "queued": None, "analyzing": None}
    interactive = {"active": None, "job_id": None}
    # Bloque de estado del indicador (v1.4.2): mismos criterios que /health. None = no se pudo consultar.
    status = {"database": False, "worker": None}
    if isinstance(row, BaseException):
        logger.warning("resources_db_failed", extra={"error_type": type(row).__name__})
    else:
        aggregator.add("db", parse_sample(row, time.time()))
        fresh.add("db")
        status = {"database": True, "worker": bool(row["worker_alive"])}
        scans = {"running": row["running"], "queued": row["queued"], "analyzing": row["analyzing"]}
        interactive = {"active": row["interactive_job"] is not None, "job_id": str(row["interactive_job"]) if row["interactive_job"] else None}
        for service, raw in (row["reported"] or {}).items():
            sample = clean_sample(raw)
            if service in ("worker", "egress-proxy") and sample is not None:
                aggregator.add(service, sample)
                fresh.add(service)
    if isinstance(frontend, dict):
        aggregator.add("frontend", frontend)
        fresh.add("frontend")

    alert_percent = settings.resources_memory_alert_percent
    services = [aggregator.describe(service, service in fresh, alert_percent) for service in SERVICES]
    known = [item for item in services if item["status"] == "ok"]
    cpu_known = [item["cpu_percent"] for item in known if item["cpu_percent"] is not None]
    limits = [item["memory_limit_bytes"] for item in known]
    memory_total = sum(item["memory_bytes"] for item in known)
    memory_limit = sum(limits) if known and all(limits) else None
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "totals": {
            # Suma de lo que se pudo medir; `services_reporting` dice de cuántos servicios.
            "cpu_percent": round(sum(cpu_known), 1) if cpu_known else None,
            "memory_bytes": memory_total if known else None,
            "memory_limit_bytes": memory_limit,
            "memory_percent": round(memory_total / memory_limit * 100, 1) if memory_limit else None,
            "services_reporting": len(known), "services_total": len(SERVICES),
        },
        "status": {**status, "stack": "ok" if status["database"] and status["worker"] and len(known) == len(SERVICES) else "degradado"},
        "scans": scans,
        "interactive": interactive,
        "services": services,
        "memory_alert_percent": alert_percent,
        "alerts": [{"service": item["service"], "memory_percent": item["memory_percent"]} for item in services if item["alert"]],
        "refresh_s": 5,
    }


@router.get("/api/resources")
async def resources() -> dict:
    async with _lock:
        now = time.monotonic()
        if _cache["body"] is None or now - _cache["at"] >= CACHE_S:
            _cache["body"] = await _collect()
            _cache["at"] = time.monotonic()
        return _cache["body"]
