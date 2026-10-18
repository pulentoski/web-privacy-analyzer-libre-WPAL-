"""Panel de inicio (v1.2): lo que muestran, en conjunto, los scans guardados.

Base de cálculo: el scan analizado MÁS RECIENTE de cada sitio (un sitio = el host de la URL,
sin «www.»). Así un sitio escaneado diez veces no pesa diez veces, y «presente en k de N
sitios» significa siempre lo mismo. No entran los scans del sitio de fixtures ni los creados
por tests (`is_test_scan`).
"""

import uuid
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.attribute_usage import UNKNOWN, party, read_rows, sent_rows
from app.config import get_settings
from app.db import get_session
from app.measurement import mixed_protocols, protocol_version
from app.service_types import service_types
from app.testscans import is_test_scan

router = APIRouter(prefix="/api/panel")
MAX_SCANS = 2000
TOP_ORGANIZATIONS = 10
TOP_ATTRIBUTES = 8
TOP_SITES = 15
BASIS = "Scan analizado más reciente de cada sitio. Sin scans de fixtures ni de tests."


def site_key(url: str | None) -> str | None:
    try:
        host = (urlsplit(url or "").hostname or "").rstrip(".").lower()
    except ValueError:
        return None
    return host.removeprefix("www.") or None


@router.get("")
async def get_panel(include_tests: bool = False, session: AsyncSession = Depends(get_session)) -> dict:
    # `include_tests` solo vale en el stack de pruebas (ALLOW_FIXTURES=1): las suites E2E necesitan
    # ver en el Panel los scans del sitio de fixtures. En una instalación normal se ignora.
    include_tests = include_tests and get_settings().allow_fixtures
    rows = (
        await session.execute(
            text(
                "SELECT j.id, j.url, j.created_at, j.result -> 'measurement' AS measurement, s.score, s.band, s.summary "
                "FROM jobs j JOIN site_analysis s ON s.job_id = j.id "
                "WHERE j.status = 'completed' ORDER BY j.created_at DESC LIMIT :limit"
            ),
            {"limit": MAX_SCANS},
        )
    ).mappings().all()
    latest: dict[str, dict] = {}
    scans = 0
    for row in rows:
        key = site_key(row["url"])
        if key is None or (is_test_scan(row["url"]) and not include_tests):
            continue
        scans += 1
        latest.setdefault(key, dict(row))  # las filas vienen de la más nueva a la más antigua
    sites = len(latest)
    by_job = {entry["id"]: key for key, entry in latest.items()}
    ids: list[uuid.UUID] = list(by_job)

    organizations: dict[str, dict] = {}
    requests = 0
    for key, entry in latest.items():
        summary = entry["summary"] or {}
        requests += int(summary.get("requests") or 0)
        for item in summary.get("entities") or []:
            name = item.get("entity")
            if not name or name == UNKNOWN:
                continue
            org = organizations.setdefault(name, {"entity": name, "sites": set(), "requests": 0})
            org["sites"].add(key)
            org["requests"] += int(item.get("requests") or 0)

    def attribute_ranking(usage_rows: list[dict]) -> list[dict]:
        table: dict[str, dict] = {}
        for row in usage_rows:
            key = by_job.get(row["job_id"])
            if key is None:
                continue
            entry = table.setdefault(row["attribute"], {"attribute": row["attribute"], "sites": set(), "organizations": {}})
            entry["sites"].add(key)
            label, is_entity = party(row["entity"], row["domain"])
            if label:
                entry["organizations"].setdefault(label, set()).add(key)
        ranked = sorted(table.values(), key=lambda entry: (-len(entry["sites"]), entry["attribute"]))[:TOP_ATTRIBUTES]
        return [
            {
                "attribute": entry["attribute"], "sites": len(entry["sites"]), "of": sites,
                "organizations": [name for name, _ in sorted(entry["organizations"].items(), key=lambda kv: (-len(kv[1]), kv[0]))[:3]],
            }
            for entry in ranked
        ]

    read = attribute_ranking(await read_rows(session, ids)) if ids else []
    sent = attribute_ranking(await sent_rows(session, ids)) if ids else []

    def is_blocked(entry: dict) -> bool:
        # "Visita posiblemente bloqueada" (point 3): se excluye del ranking por no ser representativa.
        return bool(((entry["summary"] or {}).get("blocking") or {}).get("blocked"))

    def source_of(entry: dict) -> str:
        return (entry["summary"] or {}).get("source") or "scan"

    def is_partial(entry: dict) -> bool:
        # Fuera del ranking por índice (se listan aparte, marcadas): captura HAR importada (v1.3.1: sin cookies ni
        # fingerprinting, índice parcial) y captura interactiva (v1.4.1: su índice suma toda una sesión de navegación).
        return source_of(entry) in ("har_import", "interactive")

    resolver = service_types()
    # El ranking omite los scans marcados como posiblemente bloqueados y las capturas HAR (índice parcial).
    ranking = sorted(
        ((key, entry) for key, entry in latest.items() if not is_blocked(entry) and not is_partial(entry)),
        key=lambda kv: (-(kv[1]["score"] or 0), kv[0]),
    )[:TOP_SITES]
    blocked_sites = sorted(key for key, entry in latest.items() if is_blocked(entry))
    partial_sites = sorted(
        ({"site": key, "job_id": str(entry["id"]), "site_exposure_score": entry["score"], "band": entry["band"], "source": source_of(entry)}
         for key, entry in latest.items() if is_partial(entry) and not is_blocked(entry)),
        key=lambda item: item["site"],
    )
    # v1.5.0: el índice depende de cómo se visitó cada sitio. Si el ranking junta scans con distinto protocolo de
    # visita (o scans anteriores a v1.5.0, sin protocolo), se avisa.
    protocols = mixed_protocols([protocol_version({"measurement": entry["measurement"]}) for _, entry in ranking])
    return {
        "basis": BASIS,
        "ranking_protocols": protocols,
        "level": "EVIDENCIA",
        "totals": {"sites": sites, "scans": scans, "requests": requests, "organizations": len(organizations),
                   "blocked_sites": len(blocked_sites), "partial_sites": len(partial_sites)},
        "organizations": [
            {"entity": org["entity"], "sites": len(org["sites"]), "of": sites, "requests": org["requests"],
             # Giro del servicio (point 5): contexto, no evidencia del uso concreto.
             "service_label": (resolver.of(entity=org["entity"]) or {}).get("label")}
            for org in sorted(organizations.values(), key=lambda org: (-len(org["sites"]), -org["requests"], org["entity"]))[:TOP_ORGANIZATIONS]
        ],
        "attributes": {"read": read, "sent": sent},
        # Sitios excluidos del ranking por detección antibot; se listan para que no parezcan ausentes.
        "blocked_sites": blocked_sites,
        # Sitios cuyo scan más reciente es un HAR importado o una captura interactiva: fuera del ranking, marcados con su origen.
        "partial_sites": partial_sites,
        "ranking": [
            {
                "site": key, "job_id": str(entry["id"]), "url": entry["url"], "site_exposure_score": entry["score"], "band": entry["band"],
                "trackers": (entry["summary"] or {}).get("trackers"), "third_party_domains": (entry["summary"] or {}).get("third_party_domains"),
                "created_at": entry["created_at"],
                "protocol_version": protocol_version({"measurement": entry["measurement"]}),
            }
            for key, entry in ranking
        ],
    }
