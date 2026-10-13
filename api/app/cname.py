"""Resolución de cadenas CNAME para detectar "CNAME cloaking" (F8, docs/adr/017).

Superficie mínima a propósito:
- solo se resuelven hostnames que YA están en la captura de un scan (first-party); ningún
  endpoint acepta un hostname como entrada;
- solo se hace una consulta DNS con el resolvedor del sistema: nunca una conexión al
  destino, así que no es una vía de SSRF;
- sintaxis estricta, tope de hostnames por scan, timeout, caché y rate limit global.
"""

import asyncio
import re
import socket
import time

HOSTNAME = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
MAX_HOSTS_PER_SCAN = 30
TIMEOUT_S = 3.0
CACHE_TTL_S = 3600
RATE_LIMIT = 120  # consultas DNS por minuto, en todo el proceso
MAX_CHAIN = 8


class NotInCapture(ValueError):
    """Se pidió resolver un hostname que no pertenece a la captura del scan."""


class CnameResolver:
    def __init__(self, test_dns: dict[str, list[str]] | None = None) -> None:
        self._test_dns = {host.lower(): [str(item).lower() for item in chain] for host, chain in (test_dns or {}).items()}
        self._cache: dict[str, tuple[float, str, list[str]]] = {}
        self._calls: list[float] = []

    def _allowed_by_rate(self) -> bool:
        now = time.monotonic()
        self._calls = [t for t in self._calls if now - t < 60]
        if len(self._calls) >= RATE_LIMIT:
            return False
        self._calls.append(now)
        return True

    @staticmethod
    def _lookup(host: str) -> list[str]:
        canonical, aliases, _ = socket.gethostbyname_ex(host)
        names = [name.rstrip(".").lower() for name in [*aliases, canonical]]
        chain = [name for name in dict.fromkeys(names) if name != host]
        return chain[:MAX_CHAIN]

    async def resolve(self, host: str, capture_hosts: set[str]) -> tuple[str, list[str]]:
        """(status, cadena). status: resolved | error | skipped. Lanza NotInCapture si el host no es del scan."""
        host = (host or "").rstrip(".").lower()
        if host not in capture_hosts:
            raise NotInCapture(host[:80])
        if not HOSTNAME.match(host):
            return "skipped", []  # IPs, nombres de una etiqueta o con caracteres no válidos
        if host in self._test_dns:
            return "resolved", self._test_dns[host]
        cached = self._cache.get(host)
        if cached and time.monotonic() - cached[0] < CACHE_TTL_S:
            return cached[1], cached[2]
        if not self._allowed_by_rate():
            return "skipped", []
        try:
            chain = await asyncio.wait_for(asyncio.to_thread(self._lookup, host), TIMEOUT_S)
            status = "resolved"
        except (OSError, asyncio.TimeoutError, UnicodeError):
            status, chain = "error", []
        self._cache[host] = (time.monotonic(), status, chain)
        if len(self._cache) > 5000:
            self._cache.pop(next(iter(self._cache)))
        return status, chain

    async def resolve_all(self, hosts: list[str], capture_hosts: set[str]) -> dict[str, tuple[str, list[str]]]:
        selected = sorted(set(hosts))[:MAX_HOSTS_PER_SCAN]
        results = await asyncio.gather(*(self.resolve(host, capture_hosts) for host in selected))
        return dict(zip(selected, results))


def cloaking_target(chain: list[str], site_domain: str, targets: dict[str, str]) -> tuple[str, str, str] | None:
    """(nombre del CNAME, dominio del tercero, organización) si la cadena sale del sitio hacia un tracker conocido."""
    for name in chain:
        if name == site_domain or name.endswith("." + site_domain):
            continue
        for target, organization in targets.items():
            if name == target or name.endswith("." + target):
                return name, target, organization
    return None
