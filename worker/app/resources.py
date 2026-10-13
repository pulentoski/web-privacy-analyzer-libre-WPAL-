"""Indicador de recursos (v1.4): el worker publica sus propios contadores de cgroup v2.

Cada servicio lee SU cgroup (`/sys/fs/cgroup`, solo lectura, visible dentro del contenedor);
nadie monta el socket de Docker. El worker no tiene listeners, así que deja su muestra en la
tabla `service_resources`; de paso reenvía la del egress-proxy, que la escribe en el volumen
`scanlog` (la api no comparte red con el proxy).
"""

import asyncio
import json
import logging
import pathlib
import time

from app.config import settings

logger = logging.getLogger(__name__)

CGROUP = pathlib.Path("/sys/fs/cgroup")
PROXY_SAMPLE = "resources-egress-proxy.json"
SAMPLE_KEYS = ("ts", "cpu_usage_usec", "memory_current", "memory_inactive_file", "memory_max", "cpu_quota_usec", "cpu_period_usec", "pids_current", "pids_max")

UPSERT_SQL = """
INSERT INTO service_resources (service, sample, reported_at) VALUES ($1, $2::jsonb, now())
ON CONFLICT (service) DO UPDATE SET sample = EXCLUDED.sample, reported_at = EXCLUDED.reported_at
"""


def _read(name: str) -> str:
    return (CGROUP / name).read_text(encoding="ascii")


def _limit(value: str) -> int | None:
    """"max" (sin límite) = None; nunca se inventa un límite."""
    value = value.strip()
    return int(value) if value.isdigit() else None


def _stat(content: str, key: str) -> int | None:
    for line in content.splitlines():
        name, _, value = line.partition(" ")
        if name == key and value.strip().isdigit():
            return int(value)
    return None


def read_sample() -> dict:
    quota, _, period = _read("cpu.max").strip().partition(" ")
    return {
        "ts": time.time(),
        "cpu_usage_usec": _stat(_read("cpu.stat"), "usage_usec"),
        "memory_current": int(_read("memory.current")),
        "memory_inactive_file": _stat(_read("memory.stat"), "inactive_file"),
        "memory_max": _limit(_read("memory.max")),
        "cpu_quota_usec": _limit(quota),
        "cpu_period_usec": _limit(period),
        "pids_current": int(_read("pids.current")),
        "pids_max": _limit(_read("pids.max")),
    }


def clean_sample(raw: object) -> dict | None:
    """Muestra escrita por otro servicio: solo las claves conocidas y solo números."""
    if not isinstance(raw, dict):
        return None
    out = {}
    for key in SAMPLE_KEYS:
        value = raw.get(key)
        if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value < 2**62):
            return None
        out[key] = value
    return out if out["ts"] is not None else None


def read_proxy_sample() -> dict | None:
    try:
        return clean_sample(json.loads((pathlib.Path(settings.scanlog_dir) / PROXY_SAMPLE).read_text(encoding="ascii")))
    except (OSError, ValueError):
        return None


async def _publish(pool, service: str, sample: dict) -> None:
    async with pool.acquire() as conn:
        async with conn.transaction():
            # Dato efímero: no vale un fsync por muestra (igual que el progreso de un scan).
            await conn.execute("SET LOCAL synchronous_commit TO OFF")
            await conn.execute(UPSERT_SQL, service, json.dumps(sample))


async def resources_loop(pool) -> None:
    last_proxy_ts = None
    while True:
        try:
            await _publish(pool, "worker", read_sample())
            proxy = read_proxy_sample()
            if proxy is not None and proxy["ts"] != last_proxy_ts:
                await _publish(pool, "egress-proxy", proxy)
                last_proxy_ts = proxy["ts"]
        except Exception as exc:  # el indicador nunca tumba al worker
            logger.warning("resources_publish_failed", extra={"error_type": type(exc).__name__})
        await asyncio.sleep(settings.resources_interval_s)
