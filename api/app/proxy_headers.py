"""Cabeceras del navegador con el egress-proxy (v1.5.3, docs/adr/041).

Proxy-Authorization lleva el usuario del scan y PROXY_SCAN_SECRET en base64; Proxy-Connection es del salto al proxy. No
son del sitio analizado: el worker ya no las guarda y la migración 0017 las quitó de las capturas anteriores. La api las
filtra igual en toda salida (detalle de request, HAR, comparación) por si llegan de otra fuente.
"""

PROXY_HEADERS = frozenset({"proxy-authorization", "proxy-connection"})


def is_proxy_header(name: object) -> bool:
    return isinstance(name, str) and name.strip().lower() in PROXY_HEADERS


def without_proxy_headers(headers):
    """La lista de cabeceras sin las del proxy (lo que no es lista se devuelve igual)."""
    if not isinstance(headers, list):
        return headers
    return [header for header in headers if not (isinstance(header, dict) and is_proxy_header(header.get("name")))]
