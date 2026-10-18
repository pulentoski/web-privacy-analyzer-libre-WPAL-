"""País de la IP de salida de los scans (v1.5.0, docs/adr/038).

Una consulta por scan a un servicio de IP pública (EGRESS_IP_SERVICE_URL), a través del mismo egress-proxy
pero con un usuario de proxy propio: no es tráfico del navegador ni entra en las conexiones del scan. La IP
se geolocaliza con la base DB-IP Lite del proyecto y se descarta: no se guarda, no se devuelve y no se
escribe en los logs. Si algo falla, el país es «desconocido». Nunca se infiere del idioma ni de la zona
horaria del navegador.
"""

import asyncio
import ipaddress
import json
import logging
import pathlib
import urllib.error
import urllib.request
import uuid
from urllib.parse import urlsplit

import maxminddb

from app.config import settings

logger = logging.getLogger(__name__)

UNKNOWN = "desconocido"
TIMEOUT_S = 5.0
MAX_BODY_BYTES = 64
SOURCE_NAME = "DB-IP Lite"


def _unknown(reason: str) -> dict:
    return {"status": UNKNOWN, "country_code": None, "country": UNKNOWN, "source": None, "reason": reason}


def _opener(proxy_url: str, secret: str):
    # Usuario de proxy aparte (scan-<uuid> nuevo): la consulta no queda asociada a las conexiones del scan.
    user = f"scan-{uuid.uuid4()}"
    proxy = proxy_url.replace("://", f"://{user}:{secret}@", 1)
    return urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))


def _fetch_ip(service_url: str, proxy_url: str, secret: str) -> str:
    """Texto que devuelve el servicio (debería ser solo una IP). Lanza si la consulta falla."""
    with _opener(proxy_url, secret).open(urllib.request.Request(service_url, method="GET"), timeout=TIMEOUT_S) as response:
        if response.status != 200:
            raise OSError(f"HTTP {response.status}")
        return response.read(MAX_BODY_BYTES + 1).decode("ascii", "strict")


def _edition(directory: pathlib.Path) -> str | None:
    try:
        manifest = json.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
        return next((item.get("edition") for item in manifest["sources"] if item.get("id") == "country"), None)
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _geolocate(ip: str, directory: pathlib.Path) -> dict:
    path = directory / "dbip-country-lite.mmdb"
    try:
        with maxminddb.open_database(str(path)) as reader:
            record = reader.get(ip)
    except (OSError, ValueError, maxminddb.InvalidDatabaseError):
        return _unknown("La base DB-IP de países no está disponible.")
    country = (record or {}).get("country") if isinstance(record, dict) else None
    code = country.get("iso_code") if isinstance(country, dict) else None
    if not isinstance(code, str) or len(code) != 2:
        return _unknown("La base DB-IP no tiene país para la IP de salida.")
    names = country.get("names") if isinstance(country.get("names"), dict) else {}
    name = names.get("es") or names.get("en") or code
    edition = _edition(directory)
    return {"status": "ok", "country_code": code.upper(), "country": str(name)[:80],
            "source": f"{SOURCE_NAME} {edition}" if edition else SOURCE_NAME, "reason": None}


def lookup_country(service_url: str | None = None, *, proxy_url: str | None = None, secret: str | None = None,
                   ipdb_dir: str | pathlib.Path | None = None) -> dict:
    """País de la IP de salida. Nunca lanza y nunca devuelve la IP."""
    service_url = settings.egress_ip_service_url if service_url is None else service_url
    if not service_url:
        return _unknown("EGRESS_IP_SERVICE_URL está vacío: no se consultó la IP de salida.")
    if urlsplit(service_url).scheme not in ("http", "https"):
        return _unknown("EGRESS_IP_SERVICE_URL no es una URL http(s).")
    try:
        body = _fetch_ip(service_url, proxy_url or settings.egress_proxy_url,
                         secret if secret is not None else settings.proxy_scan_secret.get_secret_value())
    except (OSError, ValueError, urllib.error.URLError) as exc:
        # Solo el tipo de error: el mensaje podría traer la respuesta del servicio.
        logger.warning("egress_ip_query_failed", extra={"error_type": type(exc).__name__})
        return _unknown("La consulta de la IP de salida falló.")
    if len(body) > MAX_BODY_BYTES:
        return _unknown("El servicio de IP pública no devolvió una IP.")
    try:
        ip = ipaddress.ip_address(body.strip())
    except ValueError:
        return _unknown("El servicio de IP pública no devolvió una IP.")
    if not ip.is_global:
        return _unknown("El servicio de IP pública devolvió una IP no pública.")
    directory = pathlib.Path(ipdb_dir) if ipdb_dir is not None else pathlib.Path(settings.data_dir) / "ipdb"
    result = _geolocate(str(ip), directory)
    del ip, body  # la IP no sale de esta función
    return result


async def lookup_country_async(service_url: str | None = None) -> dict:
    """lookup_country en un hilo: la consulta no bloquea el scan."""
    try:
        return await asyncio.to_thread(lookup_country, service_url)
    except Exception:  # nunca tumba el scan
        logger.exception("egress_country_failed")
        return _unknown("La consulta de la IP de salida falló.")
