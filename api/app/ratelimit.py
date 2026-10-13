"""Rate limit en memoria para POST /api/scans (un solo proceso de api).

La IP del cliente es la del socket. X-Forwarded-For solo se cree si quien conecta
es un proxy declarado en TRUSTED_PROXIES (el nginx del frontend): cualquier otro
cliente podría inventarla para saltarse el límite.
"""

import ipaddress
import time
from collections import defaultdict, deque

from fastapi import Request

from app.config import get_settings

MAX_TRACKED_CLIENTS = 10_000


def _parse(value: str | None):
    try:
        return ipaddress.ip_address((value or "").strip())
    except ValueError:
        return None


def client_ip(request: Request) -> str:
    peer = request.client.host if request.client else ""
    peer_ip = _parse(peer)
    trusted = get_settings().trusted_proxy_networks
    if peer_ip is not None and any(peer_ip in network for network in trusted):
        # nginx sobrescribe la cabecera con la IP real del cliente (no la concatena).
        forwarded = _parse(request.headers.get("x-forwarded-for", "").split(",")[-1])
        if forwarded is not None:
            return str(forwarded)
    return peer or "desconocida"


class SlidingWindowLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str, limit: int, window_s: float) -> float | None:
        """None si se permite (y cuenta la request); si no, segundos hasta poder reintentar."""
        now = time.monotonic()
        hits = self._hits[key]
        while hits and now - hits[0] >= window_s:
            hits.popleft()
        if len(hits) >= limit:
            return max(0.0, window_s - (now - hits[0]))
        hits.append(now)
        if len(self._hits) > MAX_TRACKED_CLIENTS:
            for stale in [k for k, v in self._hits.items() if not v or now - v[-1] >= window_s]:
                del self._hits[stale]
        return None

    def check_many(self, key: str, count: int, limit: int, window_s: float) -> float | None:
        """Como check(), pero para `count` requests a la vez: o caben todas o no se cuenta ninguna."""
        now = time.monotonic()
        hits = self._hits[key]
        while hits and now - hits[0] >= window_s:
            hits.popleft()
        if len(hits) + count > limit:
            # Si el pedido supera el límite por sí solo, esperar no lo arregla: se informa la ventana completa.
            return float(window_s) if count > limit or not hits else max(0.0, window_s - (now - hits[0]))
        hits.extend([now] * count)
        return None

    def reset(self) -> None:
        self._hits.clear()


scan_limiter = SlidingWindowLimiter()
