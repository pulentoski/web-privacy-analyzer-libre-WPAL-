"""Lee del log del proxy a qué IP se conectó realmente cada host de un scan (docs/adr/016).

El worker no resuelve DNS: lo hace el proxy. Cada navegador se autentica con un usuario
"scan-<id>", así que las líneas de un scan se distinguen de las de otro aunque corran a la vez.
"""

import asyncio
import ipaddress
import json
import logging
import pathlib

from app.config import settings

logger = logging.getLogger(__name__)

MAX_HOSTS = 2000
MAX_IPS_PER_HOST = 20


def read_destinations(proxy_user: str) -> list[dict]:
    """[{host, ip, connections}] del scan. ip es None si el proxy denegó o no llegó a conectar."""
    needle = f'"user":"{proxy_user}"'
    seen: dict[tuple[str, str | None], int] = {}
    directory = pathlib.Path(settings.scanlog_dir)
    # El archivo actual y las generaciones rotadas (access.jsonl.0 ... .4).
    for path in sorted(directory.glob("access.jsonl*")) if directory.is_dir() else []:
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    if needle not in line:
                        continue
                    try:
                        entry = json.loads(line)
                    except ValueError:
                        continue
                    if entry.get("user") != proxy_user or not isinstance(entry.get("host"), str):
                        continue
                    ip = entry.get("dst_ip")
                    try:
                        ip = str(ipaddress.ip_address(ip))
                    except ValueError:
                        ip = None
                    key = (entry["host"].lower()[:255], ip)
                    if key in seen or len(seen) < MAX_HOSTS * 2:
                        seen[key] = seen.get(key, 0) + 1
        except OSError as exc:
            # Sin el log no hay IPs de destino: que no pase inadvertido.
            logger.warning("scanlog_unreadable", extra={"file": path.name, "error_type": type(exc).__name__})
            continue
    per_host: dict[str, int] = {}
    out = []
    for (host, ip), count in sorted(seen.items(), key=lambda item: (item[0][0], item[0][1] or "")):
        per_host[host] = per_host.get(host, 0) + 1
        if per_host[host] <= MAX_IPS_PER_HOST and len(out) < MAX_HOSTS * 2:
            out.append({"host": host, "ip": ip, "connections": count})
    return out


async def read_destinations_when_flushed(proxy_user: str, expect_hosts: bool) -> list[dict]:
    """Squid escribe la línea de un túnel al cerrarse: se espera un momento tras cerrar el navegador."""
    for delay in (0.3, 0.7, 1.5):
        await asyncio.sleep(delay)
        destinations = read_destinations(proxy_user)
        if destinations or not expect_hosts:
            return destinations
    return read_destinations(proxy_user)
