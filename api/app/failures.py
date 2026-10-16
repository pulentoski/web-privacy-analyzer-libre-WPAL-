"""Scans fallidos y parciales (v1.4.8, docs/adr/035): un scan fallido no es una medición.

Los datos vienen del worker (jobs.error, jobs.result), que a su vez los tomó del navegador: no confiables.
"""

import re

NET_ERROR_RE = re.compile(r"net::ERR_[A-Z0-9_]{1,60}")


def net_error(error: object) -> str | None:
    """Código net::ERR_* real del navegador. None = no hubo (p. ej. tiempo agotado sin respuesta).

    Los jobs anteriores a v1.4.8 no guardan `net_error`: se busca en el mensaje.
    """
    if not isinstance(error, dict):
        return None
    for value in (error.get("net_error"), error.get("message")):
        match = NET_ERROR_RE.search(value) if isinstance(value, str) else None
        if match:
            return match.group(0)
    return None


def failure(status: str | None, error: object) -> dict | None:
    """Resumen del fallo de un scan para la interfaz y los reportes. None si el scan no falló."""
    if status != "failed":
        return None
    error = error if isinstance(error, dict) else {}
    code = error.get("error_code")
    message = error.get("message")
    return {
        "error_code": code[:64] if isinstance(code, str) else "no_disponible",
        "net_error": net_error(error),
        "message": message[:300] if isinstance(message, str) else "no_disponible",
    }


def partial_navigation(result: object) -> dict | None:
    """Scan parcial: goto agotó el tiempo con respuestas ya recibidas. None = navegación completa."""
    partial = (result or {}).get("partial") if isinstance(result, dict) else None
    if not isinstance(partial, dict):
        return None
    ints = {key: partial.get(key) if isinstance(partial.get(key), int) and not isinstance(partial.get(key), bool) else None
            for key in ("requests", "responses")}
    message = partial.get("message")
    return {
        "reason": "navigation_timeout",
        "net_error": net_error(partial),
        **ints,
        "message": message[:300] if isinstance(message, str) else "La navegación no terminó a tiempo; se analiza lo capturado.",
    }
