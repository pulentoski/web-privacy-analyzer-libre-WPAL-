"""Capa 1 de la defensa SSRF (SPEC §Seguridad).

Rechaza temprano las URLs que apuntan a destinos prohibidos. NO es la capa que
garantiza: entre esta validación y la conexión real el DNS puede cambiar
(rebinding). La garantía la da el egress-proxy, que valida la IP resuelta en
cada conexión.
"""

import asyncio
import ipaddress
import re
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = {"http": 80, "https": 443}
ALLOWED_PORTS = {80, 443}
DNS_TIMEOUT_S = 5.0

FORBIDDEN_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
    )
)
FORBIDDEN_HOSTNAMES = {"localhost", "db", "api", "worker", "egress-proxy", "frontend"}
FORBIDDEN_SUFFIXES = (".localhost", ".local", ".internal")
# Sitio de fixtures de los tests de captura (docs/adr/003). Solo se aceptan con
# allow_fixtures=True, por HTTP y puerto 80; el proxy los limita a la IP del contenedor.
FIXTURE_HOSTS = frozenset({"site.fixtures.test", "tracker-a.fixtures.test", "cdn-b.fixtures.test"})

_IPV4_PART = re.compile(r"^(0[xX][0-9a-fA-F]*|[0-9]+)$")
_HOST_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

Resolver = Callable[[str], Awaitable[list[str]]]


class UrlValidationError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ValidatedUrl:
    url: str
    scheme: str
    host: str
    port: int
    resolved_ips: tuple[str, ...]


async def system_resolver(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return [info[4][0] for info in infos]


def is_forbidden_ip(ip: ipaddress.IPv4Address) -> bool:
    return any(ip in net for net in FORBIDDEN_NETWORKS)


def _parse_ipv4_number(part: str) -> int:
    if part.lower().startswith("0x"):
        return int(part[2:] or "0", 16)
    if len(part) > 1 and part.startswith("0"):
        return int(part, 8)
    return int(part)


def parse_legacy_ipv4(host: str) -> ipaddress.IPv4Address | None:
    """Interpreta un host como lo hace un navegador (parser IPv4 de WHATWG).

    Cubre las formas no canónicas (127.1, 2130706433, 0x7f000001, 0177.0.0.1).
    Devuelve None si el host no es numérico; lanza si es numérico pero inválido.
    """
    parts = host.split(".")
    if parts[-1] == "" and len(parts) > 1:
        parts = parts[:-1]
    if not _IPV4_PART.match(parts[-1]):
        return None
    invalid = UrlValidationError("INVALID_URL", "El host es numérico pero no es una IPv4 válida.")
    if len(parts) > 4 or not all(_IPV4_PART.match(p) for p in parts):
        raise invalid
    try:
        numbers = [_parse_ipv4_number(p) for p in parts]
    except ValueError as exc:
        raise invalid from exc
    if any(n > 255 for n in numbers[:-1]) or numbers[-1] >= 256 ** (5 - len(numbers)):
        raise invalid
    value = numbers[-1]
    for index, number in enumerate(numbers[:-1]):
        value += number * 256 ** (3 - index)
    return ipaddress.IPv4Address(value)


def _check_hostname(host: str) -> None:
    forbidden = UrlValidationError("HOST_FORBIDDEN", "El host apunta a un destino interno no permitido.")
    if host in FORBIDDEN_HOSTNAMES or host.endswith(FORBIDDEN_SUFFIXES):
        raise forbidden
    labels = host.split(".")
    if len(labels) < 2:
        # Los nombres de una sola etiqueta solo resuelven dentro de la red local/Docker.
        raise forbidden
    if len(host) > 253 or not all(_HOST_LABEL.match(label) for label in labels):
        raise UrlValidationError("INVALID_URL", "El nombre de host no es válido.")


async def validate_url(
    raw_url: str, resolver: Resolver | None = None, *, allow_fixtures: bool = False
) -> ValidatedUrl:
    """Valida una URL inicial o un salto de redirect. Lanza UrlValidationError."""
    # El resolutor por defecto se busca en cada llamada: los tests lo sustituyen para no
    # depender del DNS externo (un fallo de DNS es un 400 legítimo, pero no lo que prueban).
    resolver = resolver or system_resolver
    if not isinstance(raw_url, str) or not raw_url or len(raw_url) > MAX_URL_LENGTH:
        raise UrlValidationError("INVALID_URL", "La URL está vacía o es demasiado larga.")
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F or ch == "\\" for ch in raw_url):
        raise UrlValidationError("INVALID_URL", "La URL contiene caracteres no permitidos.")
    try:
        parts = urlsplit(raw_url)
        port = parts.port
        host = parts.hostname
    except ValueError as exc:
        raise UrlValidationError("INVALID_URL", "La URL no se pudo interpretar.") from exc

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UrlValidationError("SCHEME_NOT_ALLOWED", "Solo se permiten URLs http y https.")
    if not host:
        raise UrlValidationError("INVALID_URL", "La URL no tiene host.")
    if "@" in parts.netloc:
        raise UrlValidationError("CREDENTIALS_NOT_ALLOWED", "No se permiten credenciales en la URL.")
    port = port if port is not None else ALLOWED_SCHEMES[scheme]
    if port not in ALLOWED_PORTS:
        raise UrlValidationError("PORT_NOT_ALLOWED", "Solo se permiten los puertos 80 y 443.")
    if ":" in host:
        raise UrlValidationError("IPV6_NOT_SUPPORTED", "IPv6 está deshabilitado.")

    try:
        host = host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise UrlValidationError("INVALID_URL", "El nombre de host no es válido.") from exc
    if not host:
        raise UrlValidationError("INVALID_URL", "La URL no tiene host.")

    if allow_fixtures and host in FIXTURE_HOSTS and scheme == "http" and port == 80:
        # No resuelven desde la api (viven en la red egress): la capa 2 decide.
        return ValidatedUrl(url=raw_url, scheme=scheme, host=host, port=port, resolved_ips=())

    literal = parse_legacy_ipv4(host)
    if literal is not None:
        if is_forbidden_ip(literal):
            raise UrlValidationError("IP_FORBIDDEN", "La IP de destino está en un rango prohibido.")
        resolved = (str(literal),)
    else:
        _check_hostname(host)
        try:
            answers = await asyncio.wait_for(resolver(host), timeout=DNS_TIMEOUT_S)
        except (OSError, asyncio.TimeoutError) as exc:
            raise UrlValidationError("DNS_RESOLUTION_FAILED", "No se pudo resolver el host.") from exc
        ipv4 = []
        for answer in answers:
            ip = ipaddress.ip_address(answer)
            if isinstance(ip, ipaddress.IPv6Address):
                if ip.ipv4_mapped is None:
                    continue  # IPv6 deshabilitado: el proxy nunca conectará por IPv6.
                ip = ip.ipv4_mapped
            ipv4.append(ip)
        if not ipv4:
            raise UrlValidationError("DNS_RESOLUTION_FAILED", "El host no tiene direcciones IPv4.")
        # Basta UNA dirección prohibida para rechazar: el proxy podría elegir cualquiera.
        if any(is_forbidden_ip(ip) for ip in ipv4):
            raise UrlValidationError("IP_FORBIDDEN", "El host resuelve a una IP en un rango prohibido.")
        resolved = tuple(dict.fromkeys(str(ip) for ip in ipv4))

    return ValidatedUrl(url=raw_url, scheme=scheme, host=host, port=port, resolved_ips=resolved)
