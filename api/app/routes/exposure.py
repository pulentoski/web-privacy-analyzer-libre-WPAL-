"""Mi exposición (F6): qué revela el navegador de quien visita la página.

Principio (docs/adr/011): por defecto el servidor no guarda NADA de estos
endpoints. No hay tabla, y el log de acceso solo registra método, ruta y estado
(nunca query, cuerpo, IP ni cabeceras del visitante).
"""

import hmac
import ipaddress
import pathlib
import uuid
from functools import lru_cache

import yaml

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db import get_session
from app.errors import AppError
from app.attribute_usage import API_ATTRIBUTE, UNKNOWN, party, read_rows, sent_rows  # noqa: F401
from app.exposure_room import ATTRIBUTES, is_hash, room
from app.ipintel import IpIntel, classify
from app.ratelimit import SlidingWindowLimiter, client_ip
from app.testscans import TEST_HOSTS, TEST_SUFFIXES, is_test_scan  # noqa: F401

router = APIRouter(prefix="/api/exposure")
compare_limiter = SlidingWindowLimiter()
_intel: IpIntel | None = None

# Cabeceras que se le devuelven al visitante (las que el navegador manda sin JavaScript).
HEADERS = (
    "user-agent", "accept-language", "accept-encoding", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "dnt", "sec-gpc", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-user",
)
MAX_HEADER_CHARS = 1024

IP_LABELS = {
    "public": "IP pública observada por este servidor",
    "private": "IP privada (misma red local)",
    "loopback": "Acceso local: el servidor ve la dirección de loopback (mismo equipo que el servidor). "
    "Desde otro equipo o desde internet se vería la IP real.",
    "link_local": "IP observada por este servidor (enlace local)",
    "cgnat": "IP observada por este servidor (rango compartido del proveedor, no es su IP pública)",
    "reserved": "IP observada por este servidor (dirección reservada)",
}
LEVELS = ("alto", "medio", "bajo")


def _network_label(network) -> str:
    """172.30.0.0/16 -> "172.30.x" (así se nombra la red en la interfaz)."""
    if network.version == 4 and network.prefixlen in (8, 16, 24):
        octets = str(network.network_address).split(".")[: network.prefixlen // 8]
        return ".".join(octets) + ".x"
    return str(network)


def access_of(ip, kind: str) -> tuple[str, str]:
    """(access, label). access: local | lan | public | other.

    "local" = la IP observada es de la red interna de Docker o loopback: quien visita está en el
    mismo equipo que el servidor y esa dirección NO es la suya. Nunca se presenta como su IP.
    """
    if ip is not None and kind != "loopback":
        for network in get_settings().docker_networks:
            if ip.version == network.version and ip in network:
                return "local", (
                    f"Acceso local: el servidor ve la red interna de Docker ({_network_label(network)}). "
                    "Desde otro equipo o desde internet se vería la IP real."
                )
    label = IP_LABELS.get(kind, "IP observada por este servidor")
    return {"loopback": "local", "private": "lan", "public": "public"}.get(kind, "other"), label


@lru_cache
def identifiability() -> dict:
    """data/identifiability.yaml: nivel cualitativo por atributo, con su justificación. Se valida al cargar."""
    data = yaml.safe_load((pathlib.Path(get_settings().data_dir) / "identifiability.yaml").read_text(encoding="utf-8"))
    if set(data.get("levels", {})) != set(LEVELS):
        raise ValueError("identifiability.yaml: los niveles deben ser alto, medio y bajo")
    for section in ("attributes", "headers", "connection"):
        for name, entry in (data.get(section) or {}).items():
            if entry.get("level") not in LEVELS or not str(entry.get("rationale") or "").strip():
                raise ValueError(f"identifiability.yaml: {section}.{name} necesita level y rationale")
    return data


def intel() -> IpIntel:
    global _intel
    if _intel is None:
        _intel = IpIntel(get_settings().ipdb_dir)
    return _intel


def no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


@router.get("/server")
async def server_view(request: Request, response: Response) -> dict:
    """Lo que llegó en ESTA request. Se devuelve al visitante y se olvida."""
    no_store(response)
    peer = request.client.host if request.client else ""
    observed = client_ip(request)
    try:
        ip = ipaddress.ip_address(observed)
        kind = classify(ip)
    except ValueError:
        ip, kind = None, "unknown"
    access, label = access_of(ip, kind)
    headers = {}
    for name in HEADERS:
        value = request.headers.get(name)
        # None = el navegador no la envió (no es lo mismo que vacía).
        headers[name] = value[:MAX_HEADER_CHARS] if isinstance(value, str) else None
    return {
        "ip": {
            "observed": observed,
            "kind": kind,
            # local = red interna de Docker o loopback: no es la IP de quien visita.
            "access": access,
            "label": label,
            "is_public": kind == "public",
            "source": "x-forwarded-for (proxy de confianza)" if observed != peer else "conexión directa",
        },
        "ip_intel": intel().lookup(observed),
        "headers": headers,
        "note": "Esto se envía en cada visita aunque JavaScript esté apagado.",
        "stored": False,
    }


@router.get("/identifiability")
async def identifiability_levels() -> dict:
    """Nivel de identificabilidad por atributo (estimación cualitativa). Texto fijo del proyecto."""
    return identifiability()


class LookupBody(BaseModel):
    model_config = {"extra": "forbid"}
    ip: str = Field(min_length=2, max_length=45)


@router.post("/ip-lookup")
async def ip_lookup(body: LookupBody, response: Response) -> dict:
    """País y ASN de una IP con la base offline. La IP viaja en el cuerpo (no queda en ningún log)."""
    no_store(response)
    result = intel().lookup(body.ip)
    if result["kind"] == "invalid":
        raise AppError("INVALID_IP", "No es una dirección IP válida.", stage="exposure", status_code=400)
    return {"ip_intel": result, "stored": False}


class CompareBody(BaseModel):
    model_config = {"extra": "forbid"}
    consent: bool
    combined: str = Field(min_length=64, max_length=64)
    attributes: dict[str, str] = Field(max_length=len(ATTRIBUTES))
    participant: str | None = Field(default=None, min_length=32, max_length=32)


def _room_info() -> dict:
    settings = get_settings()
    return {
        "participants": room.count(settings.exposure_ttl_s),
        "capacity": settings.exposure_max_participants,
        "ttl_s": settings.exposure_ttl_s,
        "salt": room.salt,
        "attributes": list(ATTRIBUTES),
        "purge_enabled": bool(settings.exposure_presenter_token.get_secret_value()),
    }


@router.get("/room")
async def room_info(response: Response) -> dict:
    no_store(response)
    return _room_info()


@router.post("/compare")
async def compare(body: CompareBody, request: Request, response: Response) -> dict:
    """Opt-in: recibe SOLO hashes y dice cuántos participantes comparten cada uno."""
    no_store(response)
    settings = get_settings()
    if body.consent is not True:
        raise AppError("CONSENT_REQUIRED", "La comparación requiere su consentimiento explícito.", stage="exposure", status_code=400)
    # Solo hashes: cualquier valor que no lo sea (un dato en claro) invalida el envío completo.
    if not is_hash(body.combined) or not body.attributes:
        raise AppError("HASHES_ONLY", "Solo se aceptan hashes sha256 en hexadecimal.", stage="exposure", status_code=400)
    for name, value in body.attributes.items():
        if name not in ATTRIBUTES or not is_hash(value):
            raise AppError("HASHES_ONLY", "Solo se aceptan hashes sha256 de atributos conocidos.", stage="exposure", status_code=400)
    retry_after = compare_limiter.check(client_ip(request), settings.exposure_rate_limit, settings.exposure_rate_window_s)
    if retry_after is not None:
        raise AppError(
            "RATE_LIMITED", "Demasiados envíos desde esta dirección. Espere un momento.", stage="rate_limit",
            status_code=429, details={"retry_after_s": round(retry_after, 1)},
        )
    participant, problem = room.submit(
        body.combined, body.attributes, body.participant, settings.exposure_ttl_s, settings.exposure_max_participants
    )
    if problem == "full":
        raise AppError(
            "ROOM_FULL", "El grupo alcanzó el máximo de participantes.", stage="exposure", status_code=429,
            details={"capacity": settings.exposure_max_participants},
        )
    return {"participant": participant, **room.compare(participant), "ttl_s": settings.exposure_ttl_s}


@router.post("/purge")
async def purge(request: Request, response: Response) -> dict:
    """Borra el grupo. Solo el administrador (token en X-Presenter-Token)."""
    no_store(response)
    expected = get_settings().exposure_presenter_token.get_secret_value()
    provided = request.headers.get("x-presenter-token", "")
    if not expected:
        raise AppError("PURGE_DISABLED", "La purga remota no está configurada (EXPOSURE_PRESENTER_TOKEN).", stage="exposure", status_code=403)
    if not hmac.compare_digest(provided.encode(), expected.encode()):
        raise AppError("FORBIDDEN", "Token de administrador incorrecto.", stage="exposure", status_code=403)
    return {"purged": room.purge(), "participants": 0}


@router.get("/scan-usage")
async def scan_usage(job_id: uuid.UUID | None = None, session: AsyncSession = Depends(get_session)) -> dict:
    """Quién leyó y a quién se le envió cada atributo en los scans guardados (datos de F4).

    - "read": organización (o dominio) del SCRIPT que leyó el atributo.
    - "sent": organización (o dominio) que RECIBIÓ el valor en una request (exfiltración con evidencia).
    Usa datos de los sitios escaneados; nada del visitante.
    - Con `job_id`: solo ese scan («Comparar con un scan» de Mi exposición).
    - Sin `job_id`: la suma de todos los scans guardados, sin los del sitio de fixtures ni los
      creados por tests (`is_test_scan`).
    """
    usage: dict[str, dict] = {}
    scope = [job_id] if job_id is not None else None

    def add(row: dict, kind: str) -> None:
        label, is_entity = party(row["entity"], row["domain"])
        if not label:
            return  # sin organización ni dominio conocidos no se nombra a nadie
        if scope is None and is_test_scan(row["site"]):
            return
        bucket = usage.setdefault(row["attribute"], {"read": {}, "sent": {}})[kind]
        item = bucket.setdefault(label, {"label": label, "is_entity": is_entity, "scans": set(), "last_scan_at": None, "example": None})
        item["scans"].add(str(row["job_id"]))
        created_at = row["created_at"]
        if created_at is not None and (item["last_scan_at"] is None or created_at > item["last_scan_at"]):
            item["last_scan_at"] = created_at
        if item["example"] is None:
            item["example"] = {"job_id": str(row["job_id"]), "site": row["site"], "call_ref": row["call_ref"],
                               "request_ref": row.get("request_ref")}

    for row in await read_rows(session, scope):
        add(row, "read")
    for row in await sent_rows(session, scope):
        add(row, "sent")

    def top(bucket: dict) -> list[dict]:
        items = [
            {**item, "scans": len(item["scans"]), "last_scan_at": item["last_scan_at"].isoformat() if item["last_scan_at"] else None}
            for item in bucket.values()
        ]
        return sorted(items, key=lambda item: (-item["scans"], item["label"]))[:10]

    return {
        "job_id": str(job_id) if job_id else None,
        "attributes": {name: {"read": top(entry["read"]), "sent": top(entry["sent"])} for name, entry in usage.items()},
        "note": "Solo refleja los scans guardados en esta instalación; no dice qué hacen esos scripts en otros sitios.",
        "excludes": None if job_id else "scans del sitio de fixtures y scans creados por tests",
    }
