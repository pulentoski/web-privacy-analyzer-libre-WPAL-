"""Inteligencia de IP offline: país y sistema autónomo desde DB-IP Lite (CC BY 4.0).

Módulo reutilizable (lo usará también F8). No consulta ningún servicio externo.
Reglas: una IP privada o reservada no tiene ubicación ("no aplica"), un dato que
falta es "no_disponible", y nunca se da más precisión que el país: la
geolocalización por IP es aproximada.
"""

import ipaddress
import json
import logging
import pathlib
import threading

import maxminddb

logger = logging.getLogger(__name__)

UNAVAILABLE = "no_disponible"
ATTRIBUTION = "IP Geolocation by DB-IP"
ATTRIBUTION_URL = "https://db-ip.com"

_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def classify(ip) -> str:
    """public | private | loopback | link_local | cgnat | reserved."""
    if ip.is_unspecified or ip.is_multicast:
        return "reserved"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.version == 4 and ip in _CGNAT:
        return "cgnat"
    if ip.is_private:
        return "private"
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return "reserved"
    return "public"


class IpIntel:
    def __init__(self, directory: str | pathlib.Path) -> None:
        self._directory = pathlib.Path(directory)
        self._lock = threading.Lock()
        self._readers: dict[str, object] | None = None
        self.edition: str | None = None

    def _load(self) -> dict:
        with self._lock:
            if self._readers is None:
                readers = {}
                for kind in ("country", "asn"):
                    path = self._directory / f"dbip-{kind}-lite.mmdb"
                    try:
                        readers[kind] = maxminddb.open_database(str(path))
                    except (OSError, maxminddb.InvalidDatabaseError) as exc:
                        logger.warning("ipdb_unavailable", extra={"kind": kind, "error_type": type(exc).__name__})
                try:
                    manifest = json.loads((self._directory / "MANIFEST.json").read_text(encoding="utf-8"))
                    self.edition = manifest["sources"][0].get("edition")
                except (OSError, ValueError, KeyError, IndexError):
                    self.edition = None
                self._readers = readers
            return self._readers

    def lookup(self, value: str) -> dict:
        """Lo que se puede decir de una IP sin salir a internet. Nunca lanza."""
        try:
            ip = ipaddress.ip_address((value or "").strip())
        except ValueError:
            return {"kind": "invalid", "applies": False, "note": "No es una dirección IP válida."}
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        kind = classify(ip)
        if kind != "public":
            notes = {
                "private": "no aplica (red privada)",
                "loopback": "no aplica (el propio equipo)",
                "link_local": "no aplica (dirección de enlace local)",
                "cgnat": "no aplica (rango compartido del proveedor, CGNAT)",
                "reserved": "no aplica (dirección reservada)",
            }
            return {"kind": kind, "applies": False, "note": notes[kind]}
        readers = self._load()
        country_code = country_name = asn = organization = UNAVAILABLE
        try:
            record = readers["country"].get(str(ip)) if "country" in readers else None
            if isinstance(record, dict):
                country = record.get("country") or {}
                country_code = country.get("iso_code") or UNAVAILABLE
                names = country.get("names") or {}
                country_name = names.get("es") or names.get("en") or UNAVAILABLE
            record = readers["asn"].get(str(ip)) if "asn" in readers else None
            if isinstance(record, dict):
                number = record.get("autonomous_system_number")
                asn = f"AS{number}" if isinstance(number, int) else UNAVAILABLE
                organization = record.get("autonomous_system_organization") or UNAVAILABLE
        except (ValueError, maxminddb.InvalidDatabaseError):
            pass
        return {
            "kind": "public",
            "applies": True,
            "country_code": country_code,
            "country": country_name,
            "asn": asn,
            "organization": organization,
            "precision": "país (aproximado); no se estima ciudad ni coordenadas",
            "source": f"DB-IP Lite {self.edition or UNAVAILABLE}",
            "attribution": ATTRIBUTION,
            "attribution_url": ATTRIBUTION_URL,
        }
