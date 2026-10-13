"""Atributos del navegador leídos y enviados en los scans (datos de F4).

- leído: un script llamó a la API que lo expone (fp_attributes OBSERVADO o UTILIZADO);
- enviado: el valor leído apareció en una request (hallazgo `exfiltration` con EVIDENCIA).

Lo usan «Mi exposición» (comparar con un scan), la pestaña Fingerprinting y el Panel. Todo
sale de los sitios escaneados: nada del navegador del visitante.
"""

import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

UNKNOWN = "no_disponible"
MAX_ROWS = 5000
# API instrumentada -> atributo de fp_attributes (los mismos nombres que usa el catálogo de la interfaz).
API_ATTRIBUTE = {
    "canvas.toDataURL": "canvas", "canvas.toBlob": "canvas", "canvas.getImageData": "canvas",
    "webgl.UNMASKED_VENDOR_WEBGL": "webgl_vendor", "webgl.UNMASKED_RENDERER_WEBGL": "webgl_renderer",
    "audio.getChannelData": "audio", "navigator.userAgent": "user_agent", "navigator.platform": "platform",
    "navigator.hardwareConcurrency": "hardware_concurrency", "navigator.deviceMemory": "device_memory",
    "navigator.languages": "languages", "intl.timeZone": "timezone",
    "screen.width": "screen", "screen.height": "screen", "screen.availWidth": "screen", "screen.availHeight": "screen",
    "screen.colorDepth": "screen", "screen.pixelDepth": "screen", "window.devicePixelRatio": "screen",
}


async def read_rows(session: AsyncSession, job_ids: list[uuid.UUID] | None = None) -> list[dict]:
    """Una fila por (scan, atributo, script que lo leyó), con la organización y el dominio del script."""
    scope = "AND a.job_id = ANY(:ids)" if job_ids is not None else ""
    rows = await session.execute(
        text(
            "WITH used AS ("
            " SELECT a.job_id, a.attribute, a.status, s.script AS script_url, a.call_refs"
            " FROM fp_attributes a CROSS JOIN LATERAL jsonb_array_elements_text(a.scripts) AS s(script)"
            f" WHERE a.status IN ('UTILIZADO', 'OBSERVADO') {scope})"
            " SELECT u.attribute, u.status, u.job_id, u.script_url, j.url AS site, j.created_at AS created_at,"
            " (u.call_refs->>0)::bigint AS call_ref,"
            " (SELECT ra.entity FROM scan_requests r JOIN request_analysis ra ON ra.request_id = r.id"
            "   WHERE r.job_id = u.job_id AND r.url = u.script_url LIMIT 1) AS entity,"
            " (SELECT r.registrable_domain FROM scan_requests r WHERE r.job_id = u.job_id AND r.url = u.script_url LIMIT 1) AS domain"
            f" FROM used u JOIN jobs j ON j.id = u.job_id ORDER BY j.created_at DESC, u.attribute, u.script_url LIMIT {MAX_ROWS}"
        ),
        {"ids": job_ids} if job_ids is not None else {},
    )
    return [dict(row) for row in rows.mappings()]


async def sent_rows(session: AsyncSession, job_ids: list[uuid.UUID] | None = None) -> list[dict]:
    """Una fila por exfiltración con evidencia: atributo, a qué dominio y organización llegó y en qué request."""
    scope = "AND f.job_id = ANY(:ids)" if job_ids is not None else ""
    rows = await session.execute(
        text(
            "SELECT f.job_id, j.url AS site, j.created_at AS created_at, f.details->>'api' AS api, f.details->>'domain' AS domain,"
            " (f.request_refs->>0)::bigint AS request_ref, (f.call_refs->>0)::bigint AS call_ref,"
            " (SELECT ra.entity FROM request_analysis ra WHERE ra.request_id = (f.request_refs->>0)::bigint) AS entity"
            " FROM fp_findings f JOIN jobs j ON j.id = f.job_id"
            f" WHERE f.heuristic = 'exfiltration' AND f.level = 'EVIDENCIA' {scope} ORDER BY j.created_at DESC, f.id LIMIT {MAX_ROWS}"
        ),
        {"ids": job_ids} if job_ids is not None else {},
    )
    out = []
    for row in rows.mappings():
        attribute = API_ATTRIBUTE.get(row["api"])
        if attribute:
            out.append({**dict(row), "attribute": attribute})
    return out


def party(entity: str | None, domain: str | None) -> tuple[str | None, bool]:
    """(nombre a mostrar, es una organización conocida). Sin organización se nombra el dominio."""
    known = entity if entity and entity != UNKNOWN else None
    return known or domain, known is not None


async def scan_table(session: AsyncSession, job_id: uuid.UUID, inline_owners: dict[str, str] | None = None) -> list[dict]:
    """Tabla de la pestaña Fingerprinting: atributo · leído por (script y organización) · enviado a.

    `inline_owners` (v1.4.2): «(inline o eval en <documento>)» → organización u host de ese documento.
    """
    table: dict[str, dict] = {}
    for row in await read_rows(session, [job_id]):
        entry = table.setdefault(row["attribute"], {"attribute": row["attribute"], "status": row["status"], "read_by": [], "sent_to": []})
        label, is_entity = party(row["entity"], row["domain"])
        owner = (inline_owners or {}).get(row["script_url"]) if not is_entity else None
        if owner:
            # Código inline o eval: es del documento donde corrió; se nombra a su dueño (o su host).
            label, is_entity = owner, True
        entry["read_by"].append({
            "script_url": row["script_url"], "organization": label or UNKNOWN, "is_entity": is_entity,
            "domain": row["domain"] or UNKNOWN, "call_ref": row["call_ref"],
        })
    for row in await sent_rows(session, [job_id]):
        entry = table.setdefault(row["attribute"], {"attribute": row["attribute"], "status": "UTILIZADO", "read_by": [], "sent_to": []})
        label, is_entity = party(row["entity"], row["domain"])
        if not label or any(item["organization"] == label and item["domain"] == (row["domain"] or UNKNOWN) for item in entry["sent_to"]):
            continue
        entry["sent_to"].append({
            "organization": label, "is_entity": is_entity, "domain": row["domain"] or UNKNOWN,
            "request_ref": row["request_ref"], "level": "EVIDENCIA",
        })
    return sorted(table.values(), key=lambda entry: (not entry["sent_to"], entry["attribute"]))
