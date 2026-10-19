"""Reporte exportable en HTML autocontenido (F8, docs/adr/018).

Dos niveles en un mismo documento: un resumen ejecutivo en lenguaje simple y un anexo
técnico con la evidencia. Funciones puras: reciben el JSON del reporte (ya enmascarado
o no) y devuelven texto. Todo dato capturado se escapa; el documento no lleva scripts,
ni enlaces, ni recursos externos.
"""

import base64
import html
from datetime import datetime, timezone
import pathlib
from dataclasses import dataclass
from urllib.parse import urlsplit

from app import brands

UNKNOWN = "no_disponible"
# request_analysis.party → etiqueta. «Tercero» es siempre otra organización.
# Captura HAR importada: su índice no es comparable con el de un scan (v1.3.1).
PARTIAL_INDEX_LABEL = "índice parcial (sin cookies ni fingerprinting)"
PARTY_LABELS = {"first_party": "propio", "same_org": "misma organización", "third_party": "tercero"}
PROFILE_LABELS = {"no_comercial": "no comercial", "comercial": "comercial"}
MAX_ROWS = 200
MAX_REFS = 12
BRAND_NAME_MAX = 80
LOGO_MAX_BYTES = 300_000
# Solo formatos de mapa de bits reconocidos por su firma: un SVG puede llevar contenido activo.
LOGO_SIGNATURES = ((b"\x89PNG\r\n\x1a\n", "image/png"), (b"\xff\xd8\xff", "image/jpeg"))

CSS = """
*{box-sizing:border-box}
body{font-family:Arial,Helvetica,sans-serif;color:#1a1a1a;font-size:11pt;line-height:1.45;margin:0;padding:24px;max-width:960px;margin-inline:auto}
h1{font-size:20pt;margin:0 0 4px}
h2{font-size:15pt;margin:28px 0 8px;border-bottom:2px solid #1a1a1a;padding-bottom:3px}
h3{font-size:12pt;margin:18px 0 6px}
p{margin:6px 0}
table{border-collapse:collapse;width:100%;margin:6px 0 12px;font-size:9pt}
th,td{border:1px solid #999;padding:3px 5px;text-align:left;vertical-align:top;overflow-wrap:anywhere;word-break:break-word}
th{background:#eee}
thead{display:table-header-group}
tr{page-break-inside:avoid}
.brand{display:flex;align-items:center;gap:12px;border-bottom:1px solid #999;padding-bottom:8px;margin-bottom:12px}
.brand img{max-height:48px;max-width:180px}
.brand .name{font-size:13pt;font-weight:bold}
.meta{font-size:9.5pt;color:#333}
.mono{font-family:"Courier New",monospace;font-size:8.5pt;overflow-wrap:anywhere;word-break:break-all}
.lvl{display:inline-block;border:1px solid #000;border-radius:3px;padding:0 4px;font-size:8pt;font-weight:bold;white-space:nowrap}
.lvl-EVIDENCIA{background:#d1fae5}.lvl-INFERENCIA{background:#fef3c7}.lvl-POSIBLE{background:#e0e7ff}.lvl-DESCONOCIDO{background:#e5e7eb}
.box{border:1px solid #999;background:#f6f6f6;padding:8px 10px;margin:10px 0}
.legal{border:2px solid #1a1a1a;padding:8px 10px;margin:14px 0;font-weight:bold}
.annex{page-break-before:always}
.small{font-size:8.5pt;color:#333}
.step{border:1px solid #999;border-left:5px solid #1a1a1a;padding:6px 10px;margin:8px 0;page-break-inside:avoid}
.step h4{font-size:11.5pt;margin:0 0 3px}
.step .tech{font-size:8.5pt;color:#333;font-weight:normal}
.step p{margin:3px 0}
ul,ol{margin:6px 0 6px 22px;padding:0}
li{margin:3px 0}
"""


@dataclass(frozen=True)
class Brand:
    name: str = ""
    logo_data_uri: str = ""


def load_brand(name: str, directory: str) -> Brand:
    """Marca opcional: nombre por variable de entorno o `nombre.txt`; logo `logo.png`/`logo.jpg`.

    El directorio vive fuera del repo. Si falta todo, el encabezado queda neutro.
    """
    base = pathlib.Path(directory) if directory else None
    brand_name = (name or "").strip()
    if not brand_name and base is not None:
        try:
            brand_name = (base / "nombre.txt").read_text(encoding="utf-8").strip().splitlines()[0].strip()
        except (OSError, UnicodeDecodeError, IndexError):
            brand_name = ""
    logo = ""
    for filename in ("logo.png", "logo.jpg") if base is not None else ():
        try:
            data = (base / filename).read_bytes()
        except OSError:
            continue
        mime = next((mime for signature, mime in LOGO_SIGNATURES if data.startswith(signature)), None)
        if mime and len(data) <= LOGO_MAX_BYTES:
            logo = f"data:{mime};base64,{base64.b64encode(data).decode('ascii')}"
            break
    if not brand_name and not logo:
        # Sin marca configurada: la del proyecto (v1.2). REPORT_BRAND_NAME / REPORT_BRAND_DIR la reemplazan.
        return default_brand()
    return Brand(name=brand_name[:BRAND_NAME_MAX], logo_data_uri=logo)


DEFAULT_BRAND_NAME = "Web Privacy & Tracker Analyzer"
DEFAULT_LOGO_PATH = pathlib.Path(__file__).parent / "assets" / "logo-report.png"


def default_brand() -> Brand:
    """Logo del proyecto (128 px, incrustado como data URI: el reporte sigue siendo autocontenido)."""
    try:
        data = DEFAULT_LOGO_PATH.read_bytes()
    except OSError:
        return Brand(name=DEFAULT_BRAND_NAME)
    if not data.startswith(b"\x89PNG") or len(data) > LOGO_MAX_BYTES:
        return Brand(name=DEFAULT_BRAND_NAME)
    return Brand(name=DEFAULT_BRAND_NAME, logo_data_uri=f"data:image/png;base64,{base64.b64encode(data).decode('ascii')}")


def e(value) -> str:
    if value is None:
        return UNKNOWN
    return html.escape(str(value), quote=True)


def _host(url) -> str | None:
    """Host de una URL (también enmascarada: el host se conserva siempre)."""
    try:
        return urlsplit(url).hostname if isinstance(url, str) else None
    except ValueError:
        return None


def when(value) -> str:
    """Fecha ISO del reporte en formato legible (al segundo). Si no es UTC, se deja tal cual."""
    if not isinstance(value, str) or len(value) < 19:
        return e(value)
    if value.endswith("+00:00") or value.endswith("Z"):
        return e(value[:19].replace("T", " ") + " UTC")
    return e(value)


def level(value) -> str:
    name = value if value in ("EVIDENCIA", "INFERENCIA", "POSIBLE", "DESCONOCIDO") else "DESCONOCIDO"
    return f'<span class="lvl lvl-{name}">{name}</span>'


def refs(values, label: str = "request") -> str:
    values = [value for value in (values or []) if value is not None]
    if not values:
        return ""
    shown = ", ".join(f"#{e(value)}" for value in values[:MAX_REFS])
    more = f" y {len(values) - MAX_REFS} más" if len(values) > MAX_REFS else ""
    return f"{label}: {shown}{more}"


def evidence_refs(value) -> str:
    """Referencias de un hallazgo: lista de ids de request, o {calls, requests} en fingerprinting."""
    if isinstance(value, dict):
        parts = [refs(value.get("requests")), refs(value.get("calls"), "llamada")]
        return "; ".join(part for part in parts if part) or "sin referencias"
    return refs(value) or "sin referencias"


def table(headers: list[str], rows: list[list[str]], total: int | None = None) -> str:
    """`rows` ya viene escapado celda a celda."""
    if not rows:
        return '<p class="small">Sin elementos.</p>'
    head = "".join(f"<th>{e(header)}</th>" for header in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows[:MAX_ROWS])
    total = len(rows) if total is None else total
    note = f'<p class="small">Se muestran {min(len(rows), MAX_ROWS)} de {total}. El JSON del reporte contiene el resto.</p>' if total > MAX_ROWS else ""
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>{note}"


def items(values: list[str], ordered: bool = False) -> str:
    tag = "ol" if ordered else "ul"
    return f"<{tag}>" + "".join(f"<li>{value}</li>" for value in values) + f"</{tag}>"


def plural(count: int, singular: str, plural_form: str) -> str:
    return f"{count} {singular if count == 1 else plural_form}"


def _document(title: str, body: str) -> str:
    # La política va dentro del archivo: aunque se abra desde el disco, no puede cargar nada externo.
    return (
        '<!doctype html>\n<html lang="es"><head><meta charset="utf-8">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; img-src data:">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{e(title)}</title><style>{CSS}</style></head><body>{body}</body></html>\n"
    )


def _header(brand: Brand, title: str, lines: list[str]) -> str:
    out = ""
    if brand.name or brand.logo_data_uri:
        logo = f'<img src="{brand.logo_data_uri}" alt="">' if brand.logo_data_uri else ""
        out += f'<div class="brand">{logo}<span class="name">{e(brand.name) if brand.name else ""}</span></div>'
    out += f"<h1>{e(title)}</h1>"
    out += "".join(f'<p class="meta">{line}</p>' for line in lines if line)
    return out


def _masking_note(report: dict) -> str:
    if report.get("masked"):
        return ('<p class="small">Los valores que podrían ser identificadores aparecen enmascarados: se muestra un prefijo y '
                "el largo del valor, no el valor completo.</p>")
    return ('<p class="small"><strong>Este reporte muestra los valores completos</strong> por decisión explícita de quien lo '
            "exportó. Trátelo como un documento sensible.</p>")


def _legend(levels: dict) -> str:
    rows = [[level(name), e(text)] for name, text in (levels or {}).items()]
    return "<h3>Leyenda de niveles de evidencia</h3>" + table(["Nivel", "Qué significa"], rows)


def _versions(versions: dict) -> str:
    labels = {"analyzer": "Analizador", "lists": "Listas de filtros", "ip_database": "Base de IP", "cmp_list": "Lista de CMP (IAB)",
              "license_profile": "Perfil de licencias"}
    rows = [[e(labels.get(key, key)), f'<span class="mono">{e(value)}</span>'] for key, value in (versions or {}).items()]
    return "<h3>Versiones</h3>" + table(["Componente", "Versión"], rows)


MODE_LABELS = {"headful": "con ventana (headful, sobre display virtual)", "headless": "headless", "no_aplica": "no aplica"}
STAGE_LABELS = {"carga": "Carga", "espera": "Espera", "scroll": "Scroll hasta el final", "cierre": "Cierre de la pestaña"}


def _planned(planned: dict) -> str:
    parts = []
    if "duration_s" in planned:
        parts.append(f"{planned['duration_s']:g} s")
    if "max_s" in planned:
        parts.append(f"máx. {planned['max_s']:g} s, un paso cada {planned.get('step_interval_ms', 0):g} ms")
    if "observe_s" in planned:
        parts.append(f"{planned['observe_s']:g} s de observación tras cerrar")
    return ", ".join(parts) or "hasta load + red en calma"


def _conditions_line(measurement: dict) -> str:
    """Una línea del encabezado: navegador, modo, protocolo y país de la IP de salida."""
    if not measurement:
        return ""
    conditions = measurement.get("conditions") or {}
    browser = conditions.get("browser") or {}
    browser_text = " ".join(str(part) for part in (browser.get("name"), browser.get("version")) if part) or None
    country = conditions.get("egress_country") or {}
    protocol = measurement.get("protocol_version")
    return (f'Navegador {e(browser_text)} ({e(MODE_LABELS.get(conditions.get("browser_mode"), conditions.get("browser_mode")))}) · '
            f'protocolo de visita {e(protocol) if protocol is not None else "no aplica"} · '
            f'país de la IP de salida: {e(country.get("country_code")) if country.get("status") == "ok" else "desconocido"}')


def _measurement(measurement: dict) -> str:
    """Condiciones de la medición, protocolo de visita y cobertura por contexto (v1.5.0)."""
    if not measurement:
        return ""
    conditions = measurement.get("conditions") or {}
    browser = conditions.get("browser") or {}
    country = conditions.get("egress_country") or {}
    country_text = (f'{e(country.get("country"))} ({e(country.get("country_code"))}) · {e(country.get("source"))}'
                    if country.get("status") == "ok" else f'desconocido — {e(country.get("reason"))}')
    lists = ", ".join(f'{e(item.get("id"))} {e(item.get("version"))}' for item in conditions.get("lists") or [])
    out = '<h3 id="condiciones">Condiciones de la medición</h3>' + table(["Condición", "Valor"], [
        ["Navegador", e(" ".join(str(part) for part in (browser.get("name"), browser.get("version")) if part) or None)],
        ["Modo", e(MODE_LABELS.get(conditions.get("browser_mode"), conditions.get("browser_mode")))],
        ["Fecha y hora de la visita", when(conditions.get("measured_at"))],
        ["Analizador", f'<span class="mono">{e(conditions.get("analyzer_version"))}</span>'],
        ["Listas", f'<span class="mono">{e(conditions.get("lists_version"))}</span>' + (f" ({lists})" if lists else "")],
        ["País de la IP de salida", country_text],
    ])
    out += ('<p class="small">El país sale de la IP de salida del analizador, consultada una vez por scan a través del '
            "egress-proxy y geolocalizada con DB-IP Lite; la IP no se guarda. Nunca se deduce del idioma ni de la zona "
            "horaria del navegador.</p>")
    protocol = measurement.get("visit_protocol") or {}
    out += '<h3 id="protocolo">Protocolo de visita</h3>'
    if not protocol.get("applies"):
        out += f'<p>{e(protocol.get("note"))}</p>'
    else:
        out += f'<p>Protocolo de visita {e(protocol.get("protocol_version"))}: carga → espera → scroll hasta el final → espera → cierre de la pestaña.</p>'
        rows = []
        for stage in protocol.get("stages") or []:
            detail = e(stage.get("reason_text"))
            if stage.get("includes"):
                detail += " (" + e("; ".join(stage["includes"])) + ")"
            rows.append([e(stage.get("order")), e(STAGE_LABELS.get(stage.get("name"), stage.get("name"))), e(_planned(stage.get("planned") or {})),
                         "sí" if stage.get("completed") else "<strong>no</strong>", when(stage.get("started_at")) if stage.get("started_at") else "—",
                         when(stage.get("ended_at")) if stage.get("ended_at") else "—", detail, e(stage.get("requests"))])
        out += table(["#", "Etapa", "Previsto", "Completada", "Inicio", "Fin", "Motivo", "Requests"], rows)
        sends = protocol.get("closing_sends") or []
        out += "<p>Envíos observados durante el cierre de la pestaña:</p>" + table(["Request", "Método", "Host", "Ruta", "Tipo"], [
            [e(item.get("seq")), e(item.get("method")), f'<span class="mono">{e(item.get("host"))}</span>',
             f'<span class="mono">{e(item.get("path"))}</span>', e(item.get("resource_type"))] for item in sends
        ])
    out += f'<p class="small">{e(protocol.get("closing_notice"))}</p>'
    coverage = measurement.get("coverage") or {}
    out += '<h3 id="cobertura">Cobertura por contexto</h3>'
    out += table(["Contexto", "Instrumentación instalada", "APIs observadas", "Tráfico capturado"], [
        [e(row.get("label")), "sí" if row.get("instrumentation") else "no",
         e(", ".join(row.get("apis_observed") or []) or "ninguna"), "sí" if row.get("traffic_captured") else "no"]
        for row in coverage.get("contexts") or []
    ])
    out += (f'<p class="small">Resultado de la auditoría reproducible <span class="mono">{e(coverage.get("audited_with"))}</span> '
            f'(APIs de prueba: {e(", ".join(coverage.get("probe_apis") or []))}). Lo no cubierto figura en «Limitaciones».</p>')
    return out


def _attributions(attributions: list) -> str:
    rows = [
        [e(item.get("source")), e(item.get("text")), e(item.get("license")) + (" · uso no comercial" if item.get("noncommercial") else ""),
         f'<span class="mono">{e(item.get("url"))}</span>']
        for item in attributions or []
    ]
    return "<h3>Atribuciones</h3>" + table(["Fuente", "Atribución", "Licencia", "Dirección"], rows)


def _footer(report: dict, sha256: str) -> str:
    return (
        f'<div class="legal">{e(report.get("legal_notice"))}</div>'
        '<div class="box"><strong>Integridad.</strong> sha256 del JSON de este reporte:<br>'
        f'<span class="mono" data-sha256="{e(sha256)}">{e(sha256)}</span><br>'
        '<span class="small">Este documento se generó a partir de ese JSON, que puede descargarse junto con él para comprobarlo.</span></div>'
    )


# --- Reporte de un scan ---


def _import_info(report: dict) -> dict | None:
    """Captura importada (HAR): de dónde salió, qué se descartó y qué no pudo medirse. None si es un scan."""
    scan = report.get("scan") or {}
    if scan.get("source") != "har_import":
        return None
    meta = scan.get("import") or {}
    removed = meta.get("sensitive_removed") or {}
    blocked = (report.get("capture") or {}).get("blocked_by_client", 0)
    summary = "Captura importada: navegador real del usuario (archivo HAR). No incluye instrumentación de fingerprinting."
    if blocked:
        summary += f" {plural(blocked, 'request fue bloqueada', 'requests fueron bloqueadas')} por una extensión del navegador."
    load = meta.get("load") or {}
    details = [
        "Captura importada: navegador real del usuario. El archivo HAR lo generó el usuario con las herramientas de su navegador; no hubo navegación automatizada.",
        f"Carga analizada: {e(load.get('started_at') or UNKNOWN)} ({e(meta.get('entries_load', UNKNOWN))} requests de {e(meta.get('entries_total', UNKNOWN))} entradas del archivo; "
        f"{e(meta.get('loads_in_file', UNKNOWN))} carga(s) en el archivo).",
        f"Requests bloqueadas por una extensión del navegador (net::ERR_BLOCKED_BY_CLIENT): {blocked}. Se cuentan aparte: no llegaron a salir.",
        f"Cabeceras sensibles descartadas antes de guardar (solo se conserva nombre y largo): Cookie {e(removed.get('cookie', 0))}, "
        f"Set-Cookie {e(removed.get('set_cookie', 0))}, Authorization {e(removed.get('authorization', 0))}; cookies registradas en el HAR: {e(removed.get('cookie_objects', 0))}.",
        "Sin instrumentación de fingerprinting: un HAR solo registra tráfico de red, no las lecturas de APIs del navegador. Tampoco trae snapshot de cookies ni de storage.",
    ]
    return {"summary": summary, "details": details}


INTERACTIVE_END = {
    "user_stop": "la detuvo el usuario", "idle_timeout": "se cerró por inactividad", "max_duration": "alcanzó la duración máxima",
    "max_requests": "alcanzó el máximo de requests", "window_closed": "el usuario cerró la ventana", "browser_closed": "el navegador se cerró",
}


def _masked_note(masked) -> str:
    if masked is None:
        return "Captura anterior a v1.4.1: los campos de contraseña NO se enmascararon; los cuerpos guardados pueden contener credenciales."
    if not masked:
        return "No se detectaron campos de contraseña ni credenciales en los cuerpos enviados (no cubre la URL ni WebSocket)."
    names = sorted({str(item.get("name")) for item in masked})
    return (f"{plural(len(masked), 'valor de credencial fue enmascarado', 'valores de credenciales fueron enmascarados')} antes de guardar "
            f"(solo se registró nombre y largo): {', '.join(e(name) for name in names[:20])}.")


def _interactive_info(report: dict) -> dict | None:
    """Captura interactiva (v1.4): quién navegó, páginas visitadas y aviso sobre lo escrito. None si no lo es."""
    scan = report.get("scan") or {}
    if scan.get("source") != "interactive":
        return None
    meta = scan.get("interactive") or {}
    timeline = meta.get("timeline") or []
    ended = INTERACTIVE_END.get(meta.get("end_reason"), "terminó")
    return {
        "summary": (f"Captura interactiva: una persona navegó en el navegador del analizador ({plural(len(timeline), 'página visitada', 'páginas visitadas')}); "
                    f"la sesión {ended}. Las cifras corresponden a toda la sesión y no son comparables con las de una visita automática."),
        "details": [
            "Captura interactiva: una persona navegó libremente en el Chromium del analizador, visto por VNC; se registraron las requests de toda la sesión, "
            "con la misma instrumentación y el mismo proxy de salida que un scan.",
            "Lo que la persona escribió (búsquedas, formularios) y las cookies de la sesión forman parte de la captura.",
            _masked_note(meta.get("masked_fields")),
        ],
        "timeline": timeline, "truncated": bool(meta.get("timeline_truncated")),
    }


def _interactive_section(report: dict) -> str:
    info = _interactive_info(report)
    if info is None:
        return ""
    rows = [[e(when(entry.get("ts"))), e(entry.get("tab")), f'<span class="mono">{e(entry.get("url"))}</span>', e(entry.get("title") or "no_disponible")]
            for entry in info["timeline"]]
    out = "<h3>Captura interactiva: páginas visitadas</h3>"
    out += "<p>Orden en que se cargaron las páginas durante la sesión. Las direcciones y los títulos provienen de los sitios visitados y se muestran como texto.</p>"
    out += table(["Hora", "Pestaña", "Dirección", "Título"], rows) if rows else "<p>No se registraron páginas.</p>"
    if info["truncated"]:
        out += "<p>La línea de tiempo se cortó al llegar a su máximo de entradas.</p>"
    return out


INTERACTION_KINDS = {"click": "clic", "scroll": "desplazamiento", "key": "tecla"}


def _interaction_section(report: dict) -> str:
    """Registro de interacción (v1.4.2): correlación entre la interacción del usuario y los envíos, y datos de interacción en payloads."""
    data = ((report.get("site") or {}).get("summary") or {}).get("interaction")
    if not isinstance(data, dict):
        return ""
    out = "<h3>Registro de interacción</h3>"
    payloads = data.get("payloads") or []
    if payloads:
        out += "<p>Parámetros con nombre de dato de interacción (Inferencia: el nombre no prueba el contenido).</p>"
        out += table(["Dominio", "Dato", "Parámetros", "Requests"],
                     [[f'<span class="mono">{e(item.get("domain"))}</span>', e(item.get("label")),
                       f'<span class="mono">{e(", ".join(str(name) for name in item.get("parameters") or []))}</span>', e(item.get("requests"))]
                      for item in payloads[:40]], total=len(payloads))
    if data.get("recording_domains"):
        out += "<p>Servicios de grabación de sesión contactados (Inferencia): " + e(", ".join(str(d) for d in data["recording_domains"])) + ".</p>"
    if not data.get("available"):
        return out + "<p>Esta captura no registró la interacción del usuario (solo las capturas interactivas desde v1.4.2 lo hacen): no se puede correlacionar con los envíos.</p>"
    kinds = data.get("interactions") or {}
    out += (f"<p>Interacciones del usuario registradas (solo hora y tipo; nunca qué se tecleó ni dónde se hizo clic): "
            f"{e(kinds.get('click', 0))} clics, {e(kinds.get('scroll', 0))} desplazamientos, {e(kinds.get('key', 0))} teclas. "
            f"Ventana de correlación: {e(data.get('window_s'))} s.</p>")
    flagged = [item for item in data.get("organizations") or [] if item.get("flagged")]
    if flagged:
        out += table(["Organización", "Interacciones seguidas de envío", "Envíos", "Esperados por ritmo normal"],
                     [[e(item.get("organization")), e(item.get("interactions")), e(item.get("requests")), e(item.get("expected"))] for item in flagged])
    else:
        out += "<p>Ninguna organización recibió envíos tras la interacción por encima de su ritmo normal en la sesión.</p>"
    rows = []
    for entry in (data.get("timeline") or [])[:60]:
        stamp = datetime.fromtimestamp(entry["ts"], timezone.utc).strftime("%H:%M:%S") if isinstance(entry.get("ts"), (int, float)) else UNKNOWN
        sends = ", ".join(f"{send.get('organization')} ({send.get('requests')})" for send in entry.get("sends") or [])
        rows.append([e(stamp + " UTC"), e(INTERACTION_KINDS.get(entry.get("kind"), entry.get("kind"))),
                     "abrió otra página" if entry.get("navigation") else e(sends or "sin envíos")])
    if rows:
        out += "<p>Línea de tiempo (primeras interacciones) y envíos a otras organizaciones en la ventana siguiente:</p>"
        out += table(["Hora", "Interacción", "Envíos en la ventana"], rows, total=len(data.get("timeline") or []))
    return out


def executive_summary(report: dict) -> dict:
    """Qué se encontró, por qué importa y 3–5 recomendaciones, en lenguaje simple y trato de usted.

    Cada frase sale de un dato del reporte; no se añade nada que el anexo no respalde.
    """
    capture = report.get("capture") or {}
    site = report.get("site") or {}
    trackers = report.get("trackers") or []
    destinations = report.get("destinations") or {}
    fingerprinting = report.get("fingerprinting") or {}
    consent = report.get("consent") or {}
    third_domains = [domain for domain in destinations.get("domains") or [] if domain.get("third_party")]
    named = [group["entity"] for group in trackers if group.get("entity") not in (None, UNKNOWN)]
    tracker_requests = sum(group.get("request_count", 0) for group in trackers)
    countries = destinations.get("countries") or []
    fp_scripts = [script for script in fingerprinting.get("scripts") or [] if script.get("fingerprinting_inferred")]
    exfiltrations = fingerprinting.get("exfiltrations") or []
    cloaking = (destinations.get("cname_cloaking") or {}).get("findings") or []
    url_leaks = [finding for finding in report.get("findings") or [] if finding.get("type") in ("url_leak", "referer_leak")]
    tcf = consent.get("tcf") or {}
    consent_mode = consent.get("consent_mode")

    scan = report.get("scan") or {}
    if scan.get("failure"):
        # v1.4.8 (docs/adr/035): sin medición no hay índice ni «no se observó»: solo el motivo del fallo.
        return {"found": [no_measurement_text(scan["failure"])], "why": [], "recommendations": []}
    blocking = (site.get("summary") or {}).get("blocking") or {}
    found = []
    if scan.get("partial_navigation"):
        found.append(f"{PARTIAL_SCAN_LABEL}: {scan['partial_navigation'].get('message')}")
    if blocking.get("blocked"):
        found.append(BLOCKING_BANNER)
    elif blocking.get("partial"):
        found.append(PARTIAL_BLOCK_BANNER + " El resto de la página cargó; el resultado se considera representativo.")
    elif blocking.get("possible_variant"):
        found.append(f"Posible: {blocking['possible_variant'].get('text')}")
    imported = _import_info(report) or _interactive_info(report)
    scan_source = (report.get("scan") or {}).get("source")
    if imported:
        found.append(imported["summary"])
    found.append(
        f"{'Durante la sesión' if scan_source in ('interactive', 'har_import') else 'Durante la carga de la página'}, el sitio realizó {plural(capture.get('total_requests', 0), 'request', 'requests')}, "
        f"de las cuales {capture.get('third_party', 0)} se dirigieron a terceros (organizaciones distintas del sitio), "
        f"distribuidas en {plural(len(third_domains), 'dominio de terceros', 'dominios de terceros')}."
    )
    if tracker_requests:
        names = ", ".join(named[:5]) + (" y otras" if len(named) > 5 else "")
        found.append(
            f"{plural(tracker_requests, 'de esas requests presenta', 'de esas requests presentan')} señales de seguimiento"
            + (f", asociadas a {plural(len(named), 'organización identificada', 'organizaciones identificadas')}: {names}." if named else ".")
        )
    else:
        found.append("No se observaron requests con señales suficientes de seguimiento en esta visita.")
    services = third_party_services(report)
    if services and services["items"]:
        kinds = list(dict.fromkeys(str(item["service_label"]).split(" (")[0] for item in services["items"] if item.get("service_label")))
        found.append(
            f"Servicios de terceros sin señales de rastreo: {plural(services.get('requests', 0), 'request se dirigió', 'requests se dirigieron')} a "
            f"{plural(services.get('organizations', 0), 'organización', 'organizaciones')} que prestan servicios a la página"
            + (f" ({', '.join(kinds[:6])}{' y otros' if len(kinds) > 6 else ''})" if kinds else "")
            + ". No muestran señales de rastreo, pero reciben la dirección IP y el navegador de cada visitante."
        )
    # Otro dominio del mismo dueño (CDN propio, dominios del grupo): se informa aparte, no es tercero.
    same_org_domains = [domain for domain in destinations.get("domains") or [] if domain.get("party") == "same_org"]
    if capture.get("same_org"):
        found.append(
            f"Otras {plural(capture['same_org'], 'request se dirigió', 'requests se dirigieron')} a "
            f"{plural(len(same_org_domains), 'dominio', 'dominios')} de la misma organización que el sitio; no se cuentan como terceros."
        )
    telemetry = (site.get("summary") or {}).get("first_party_telemetry") or {}
    if telemetry.get("requests") or telemetry.get("scripts"):
        found.append(
            f"Telemetría propia: {plural(telemetry.get('requests', 0), 'request de eventos se envió', 'requests de eventos se enviaron')} al propio sitio "
            f"o a su misma organización ({plural(telemetry.get('endpoints', 0), 'endpoint', 'endpoints')}); scripts de analítica propia cargados: "
            f"{telemetry.get('scripts', 0)}. No son terceros, pero sí un método de recolección."
        )
    note = blocking.get("note") if not blocking.get("blocked") else None
    if note:
        found.append("Rastreo de terceros bajo; telemetría propia detectada: la visita no se considera bloqueada.")
    if countries:
        listed = ", ".join(f"{country.get('country')} ({country.get('domains')})" for country in countries[:6])
        found.append(f"Geolocalización aproximada de los servidores de destino, según su dirección IP: {listed}.")
    if fp_scripts or exfiltrations:
        text = f"{plural(len(fp_scripts), 'script de la página presenta', 'scripts de la página presentan')} un uso de APIs compatible con fingerprinting, el reconocimiento del dispositivo sin cookies (inferencia)"
        if exfiltrations:
            text += f", y en {plural(len(exfiltrations), 'caso', 'casos')} se observó la exfiltración de un atributo: un valor leído del navegador se transmitió en una request"
        found.append(text + ".")
    if tcf.get("present"):
        found.append(
            f"El sitio utiliza una plataforma de gestión del consentimiento (CMP) que implementa el estándar TCF "
            f"(plataforma: {tcf.get('cmp_name') or UNKNOWN})."
        )
    else:
        found.append("No se detectó una plataforma de gestión del consentimiento (CMP) que implemente el estándar TCF.")
    if consent_mode:
        found.append(f"{plural(consent_mode.get('requests', 0), 'request a Google transmitió', 'requests a Google transmitieron')} un estado de consentimiento (Google Consent Mode).")
    # Conclusión de consentimiento en lenguaje técnico, por plantilla (point 6).
    for conclusion in consent.get("conclusions") or []:
        if conclusion.get("text"):
            found.append(conclusion["text"])
    if cloaking:
        found.append(f"{plural(len(cloaking), 'subdominio del sitio es', 'subdominios del sitio son')} un alias DNS (CNAME) de un servicio de terceros (CNAME cloaking).")
    if url_leaks:
        found.append("Fuga de URL: la URL de la página visitada se transmitió a terceros.")
    if (report.get("scan") or {}).get("source") == "har_import":
        # v1.3.1: un HAR no trae cookies ni fingerprinting; su índice no es comparable con el de un scan.
        found.append(
            f"{PARTIAL_INDEX_LABEL.capitalize()}: {site.get('exposure_score')} de 99 (banda «{site.get('band')}»). "
            "Un HAR solo registra tráfico de red: este valor no es comparable con el índice de un scan."
        )
    else:
        found.append(
            f"Índice de exposición estimado: {site.get('exposure_score')} de 99 (banda «{site.get('band')}»)"
            + (f"; {score_levels_text(by_level)}" if (by_level := (site.get("summary") or {}).get("score_by_level")) else "")
            + ". Es una estimación para comparar visitas, no una calificación oficial."
        )
    found.extend(client_hints_sentences((site.get("summary") or {}).get("client_hints")))

    why = []
    if tracker_requests or third_domains:
        why.append("Cada tercero que su sitio carga recibe, como mínimo, la dirección IP del visitante y la cabecera User-Agent. El responsable del sitio responde por el comportamiento de este, aunque el código pertenezca a otra organización.")
    if tracker_requests:
        why.append("Las herramientas de medición y publicidad pueden combinar la visita a su sitio con visitas a otros sitios. Conviene mantener identificadas las que están activas y su finalidad.")
    if countries:
        why.append("El país del servidor es solo una aproximación a partir de su IP: orienta sobre el proveedor implicado, pero no permite afirmar dónde se almacenan los datos.")
    if fp_scripts or exfiltrations:
        why.append("El fingerprinting no depende de cookies y el visitante dispone de pocos medios para detectarlo o desactivarlo; su uso requiere una decisión explícita del administrador del sitio.")
    if not why:
        why.append("Un sitio con pocas requests a terceros expone menos a sus visitantes y tiene menos dependencias que mantener.")
    why.append("Este análisis corresponde a una sola visita automatizada: el comportamiento del sitio puede variar con otros visitantes o en otro momento.")

    recommendations = []
    if tracker_requests or third_domains:
        recommendations.append("Revise con el equipo de mantenimiento del sitio la lista de terceros del anexo y retire los que no reconozca o ya no utilice.")
    if tracker_requests:
        recommendations.append("Verifique en qué momento se activa cada herramienta de medición o publicidad (antes o después de la elección del visitante en el aviso de consentimiento) y contrástelo con la configuración prevista.")
    if url_leaks:
        recommendations.append("Configure la cabecera Referrer-Policy del sitio para que los terceros reciban solo el origen y no la URL completa de cada página.")
    if fp_scripts or exfiltrations:
        recommendations.append("Consulte al proveedor de los scripts señalados en la sección de fingerprinting la finalidad de la lectura de esos atributos y si puede desactivarse.")
    if cloaking:
        recommendations.append("Revise los subdominios que apuntan a terceros: el navegador los trata como parte de su sitio y pueden recibir sus cookies.")
    for fallback in (
        "Mantenga un inventario de los servicios de terceros del sitio: responsable de la integración, finalidad y responsable de su revisión.",
        "Repita este análisis después de cada cambio importante del sitio y compare los resultados.",
        "Si necesita saber si su sitio cumple una norma específica, consulte a un profesional: este documento no lo evalúa.",
    ):
        if len(recommendations) >= 5:
            break
        recommendations.append(fallback)
    return {"found": found, "why": why, "recommendations": recommendations[:5]}


def _story_summary(story: dict) -> str:
    """Hallazgos por grupo en el resumen: grupos fijos, cada uno con su frase técnica, conteo y nivel."""
    out = ""
    for step in story.get("steps") or []:
        count = "" if step.get("fixed") else f' · {plural(step.get("count") or 0, "hallazgo", "hallazgos")}'
        levels = " ".join(f"{level(name)} {e(total)}" for name, total in (step.get("levels") or {}).items())
        out += f'<div class="step"><h4>{e(step.get("number"))}. {e(step.get("title"))} <span class="tech">({e(step.get("technical"))}{count})</span></h4>'
        for sentence in step.get("sentences") or []:
            badge = level(sentence.get("level")) + " " if sentence.get("level") else ""
            out += f"<p>{badge}{e(sentence.get('text'))}</p>"
        if levels:
            out += f'<p class="small">Hallazgos por nivel: {levels}</p>'
        out += "</div>"
    return out


def _story_annex(story: dict) -> str:
    """Detalle de cada grupo: la frase técnica, el hallazgo que la respalda y su evidencia."""
    rows = []
    for step in story.get("steps") or []:
        for item in step.get("items") or []:
            rows.append([f'{e(step.get("number"))}. {e(step.get("title"))}', level(item.get("level")), e(item.get("plain")), e(item.get("claim")),
                         evidence_refs(item.get("evidence_refs"))])
    return table(["Grupo", "Nivel", "Descripción", "Detalle técnico", "Referencias de evidencia"], rows)


def _ip_cell(domain: dict) -> tuple[str, str, str]:
    """(IPs, red, país) de un dominio, o "no_disponible" con su motivo."""
    ips = domain.get("ips") or []
    if not ips:
        reason = f'{UNKNOWN}: {e(domain.get("ip_reason") or "sin motivo registrado")}'
        return reason, UNKNOWN, UNKNOWN
    addresses, networks, countries = [], [], []
    for ip in ips:
        addresses.append(f'<span class="mono">{e(ip.get("ip"))}</span>')
        if ip.get("applies"):
            networks.append(f'{e(ip.get("asn"))} {e(ip.get("organization"))}')
            countries.append(f'{e(ip.get("country"))} ({e(ip.get("country_code"))})')
        else:
            networks.append(e(ip.get("note") or UNKNOWN))
            countries.append(e(ip.get("note") or UNKNOWN))
    unique = lambda values: "<br>".join(dict.fromkeys(values))  # noqa: E731
    return "<br>".join(addresses), unique(networks), unique(countries)


BLOCKING_BANNER = ("Resultado posiblemente no representativo: el sitio pudo detectar el navegador "
                   "automatizado.")


# v1.3.2: firma antibot en un componente con rastreo normal; aviso informativo.
PARTIAL_BLOCK_BANNER = "Bloqueo parcial: un componente mostró verificación antibot."


def score_levels_text(by_level: dict) -> str:
    """v1.4.9: «Evidencia X + Inferencia Y» (puntos del índice que se sostienen solo con evidencia, y el resto)."""
    return f"Evidencia {by_level.get('EVIDENCIA', 0):g} + Inferencia {by_level.get('INFERENCIA', 0):g}"


def client_hints_sentences(client_hints: dict | None) -> list[str]:
    """Client Hints (v1.4.9): la solicitud se dice como solicitud; el envío solo si se observó la cabecera."""
    if not isinstance(client_hints, dict):
        return []
    out = []
    for item in client_hints.get("requests") or []:
        text = (f"Solicitud de Client Hints: {item.get('organization')} pidió {', '.join(item.get('hints') or [])}. "
                f"{client_hints.get('request_text') or ''}").strip()
        if item.get("sent") == "confirmado":
            text += f" Envío confirmado: {', '.join(item.get('sent_hints') or [])} aparecen en requests posteriores a esa organización."
        out.append(text)
    for organization in sorted({item.get("organization") for item in client_hints.get("sends") or []} - {None}):
        hints = sorted({hint for item in client_hints.get("sends") or [] if item.get("organization") == organization for hint in item.get("hints") or []})
        out.append(f"Envío de Client Hints: el navegador envió a {organization} {', '.join(hints)}.")
    delegation = client_hints.get("delegation") or {}
    if out and delegation.get("label"):
        out.append(f"Delegación de Client Hints por el sitio: {delegation['label']}"
                   + (f" ({'; '.join(delegation.get('evidence') or [])})" if delegation.get("evidence") else "") + "."
                   + (f" {delegation['note']}" if delegation.get("note") else ""))
    if out:
        out.extend(client_hints.get("notes") or [])
    return out


NO_MEASUREMENT_LABEL = "Sin medición"
PARTIAL_SCAN_LABEL = "Scan parcial"


def no_measurement_text(failure: dict) -> str:
    """Frase de un scan fallido (v1.4.8): el motivo y el código net::ERR_* real, si el navegador dio uno."""
    net = failure.get("net_error") or "el navegador no informó un código net::ERR_*"
    return (f"{NO_MEASUREMENT_LABEL}: la navegación falló ({failure.get('error_code')}; {net}). Lo capturado no "
            "permite calcular el índice de exposición ni afirmar que no se observó nada.")


def _blocking_banner(report: dict) -> str:
    """Aviso de visita posiblemente bloqueada (point 3), de bloqueo parcial, de versión distinta (v1.4.8) o de
    scan fallido o parcial. Vacío si no hay nada que avisar."""
    scan = report.get("scan") or {}
    if scan.get("failure"):
        return f'<div class="legal"><strong>{e(no_measurement_text(scan["failure"]))}</strong></div>'
    out = ""
    if scan.get("partial_navigation"):
        out = f'<div class="legal"><strong>{e(PARTIAL_SCAN_LABEL)}:</strong> {e(scan["partial_navigation"].get("message"))}</div>'
    return out + _blocking_notice(report)


def _blocking_notice(report: dict) -> str:
    blocking = ((report.get("site") or {}).get("summary") or {}).get("blocking") or {}
    variant = blocking.get("possible_variant")
    if not blocking.get("blocked") and not blocking.get("partial") and variant:
        reasons = items([e(signal.get("detail")) for signal in variant.get("signals") or []])
        return (f'<div class="legal">{level(variant.get("level"))} {e(variant.get("text"))} '
                f"El scan sigue en el ranking del Panel.{reasons}</div>")
    if not blocking.get("blocked") and blocking.get("partial"):
        reasons = items([e(signal.get("detail")) for signal in blocking.get("signals") or []])
        return f'<div class="legal"><strong>{e(PARTIAL_BLOCK_BANNER)}</strong> Aviso informativo.{reasons}</div>'
    if not blocking.get("blocked"):
        return ""
    reasons = items([e(signal.get("detail")) for signal in blocking.get("signals") or []])
    return (f'<div class="legal"><strong>{e(BLOCKING_BANNER)}</strong> '
            "Por eso este scan se excluye del ranking comparativo del Panel.</div>" + reasons)


def _consent_conclusions(consent: dict) -> str:
    """Conclusiones de consentimiento en lenguaje técnico, por plantilla, con su nivel (point 6)."""
    conclusions = consent.get("conclusions") or []
    if not conclusions:
        return ""
    return "".join(f"<p>{level(item.get('level'))} {e(item.get('text'))}</p>" for item in conclusions)


TELEMETRY_KINDS = {"path": "ruta de eventos", "status_204": "respuesta 204 con datos", "known": "analítica propia conocida",
                   "script": "script de analítica propia"}


def _telemetry_section(report: dict) -> str:
    """Telemetría propia (v1.3.4): eventos al propio sitio o a su misma organización. Vacío si no se midió o no hubo."""
    telemetry = ((report.get("site") or {}).get("summary") or {}).get("first_party_telemetry") or {}
    rows = [*(telemetry.get("endpoint_list") or []), *(telemetry.get("script_list") or [])]
    if not rows:
        return ""
    out = "<h3>Telemetría propia (no son terceros)</h3>"
    out += (f'<p class="small">{level("INFERENCIA")} {e(telemetry.get("requests", 0))} requests de eventos hacia {e(telemetry.get("endpoints", 0))} '
            f'endpoints del propio sitio o de su misma organización, y {e(telemetry.get("scripts", 0))} scripts de analítica propia. Se reconocen por la ruta, '
            "por respuestas 204 a envíos con datos y por nombres conocidos: es una inferencia a partir del patrón. Se cuentan aparte de los "
            "terceros y tienen su propio componente en el índice de exposición.</p>")
    out += table(["Host", "Ruta", "Tipo", "Requests"], [
        [f'<span class="mono">{e(row.get("host"))}</span>', f'<span class="mono">{e(row.get("path"))}</span>',
         e(TELEMETRY_KINDS.get(row.get("kind"), "otro")) + (f' · {e(row.get("name"))}' if row.get("name") else ""), e(row.get("requests"))]
        for row in rows
    ])
    return out


def third_party_services(report: dict) -> dict | None:
    """Servicios de terceros sin señales de rastreo (v1.4.5), o None si el análisis es anterior (no se inventa «0»)."""
    services = ((report.get("site") or {}).get("summary") or {}).get("third_party_services")
    return services if isinstance(services, dict) and isinstance(services.get("items"), list) else None


def _third_party_services_section(report: dict) -> str:
    """Terceros contactados SIN señales de rastreo: organización, giro y requests. Se muestra siempre que se midió."""
    services = third_party_services(report)
    if services is None:
        return ""
    out = "<h3>Servicios de terceros sin señales de rastreo</h3>"
    out += (f'<p class="small">{level(services.get("level"))} Requests a otras organizaciones que no alcanzaron la banda de '
            "rastreador: mapas, fuentes, librerías, antibot, clima, redes sociales y similares. Que no muestren señales de rastreo no "
            "significa que no reciban datos: cada una recibe al menos la dirección IP y el navegador del visitante. El tipo de servicio "
            f'es contexto ({e(str(services.get("service_level") or "INFERENCIA").capitalize())}), no evidencia del uso concreto.</p>')
    if not services["items"]:
        return out + "<p>En esta visita no hubo requests a terceros sin señales de rastreo.</p>"
    out += table(["Organización", "Tipo de servicio (contexto)", "Dominios", "Requests", "Referencias de evidencia"], [
        [(e(item.get("organization")) if item.get("organization") not in (None, UNKNOWN) else "no disponible")
         + (" <em>(también en rastreadores)</em>" if item.get("in_trackers") else ""),
         e(item.get("service_label") or "tipo no identificado"),
         "<br>".join(f'<span class="mono">{e(host)}</span>' for host in item.get("hosts") or item.get("domains") or []),
         e(item.get("requests")), refs(item.get("evidence_refs") or [])]
        for item in services["items"]
    ])
    if services.get("truncated"):
        out += '<p class="small">La lista se truncó por volumen.</p>'
    return out


def _error_frames_note(report: dict) -> str:
    """Un iframe que no cargó muestra la página de error de Chromium: su código no es del sitio y no se cuenta (v1.4.5)."""
    frames = ((report.get("site") or {}).get("summary") or {}).get("error_frames") or {}
    if not frames.get("observed"):
        return ""
    return ('<p class="small">Un recuadro (iframe) de la página no cargó. Lo que ejecutó en su lugar la página de error del '
            "navegador no pertenece al sitio y no se cuenta.</p>")


def _same_org_section(report: dict) -> str:
    """Recursos de la MISMA organización del sitio (point 1 y 2): informativo, no son terceros."""
    summary = (report.get("site") or {}).get("summary") or {}
    parties = summary.get("parties") or {}
    same_org_domains = parties.get("same_org_domains") or []
    same_org = summary.get("same_org") or {}
    if not same_org_domains and not same_org.get("url_recipients") and not same_org.get("referer_full_url_recipients"):
        return ""
    out = "<h3>Recursos de la misma organización (no son terceros)</h3>"
    out += ('<p class="small">Dominios de otra dirección pero del mismo dueño que el sitio, según el mapa '
            "de entidades. No cuentan como terceros ni entran en el índice de exposición.</p>")
    if same_org_domains:
        out += table(["Dominio de la misma organización"], [[f'<span class="mono">{e(domain)}</span>'] for domain in same_org_domains])
    if same_org.get("url_recipients"):
        out += ("<p>La URL de la página se envió a dominios de la misma organización (dato informativo, "
                "no es fuga a terceros): " + e(", ".join(same_org["url_recipients"])) + ".</p>")
    if same_org.get("referer_full_url_recipients"):
        out += ("<p>La cabecera Referer con la URL completa llegó a dominios de la misma organización "
                "(dato informativo, no es fuga a terceros): " + e(", ".join(same_org["referer_full_url_recipients"])) + ".</p>")
    return out


def _consent_section(consent: dict) -> str:
    out = "<h3>Consentimiento: TCF y Consent Mode</h3>"
    out += _consent_conclusions(consent)
    tcf = consent.get("tcf")
    if not tcf or not tcf.get("present"):
        out += "<p>TCF: la página no expone la interfaz <span class=\"mono\">__tcfapi</span>. No se detectó una plataforma de consentimiento TCF.</p>"
    else:
        labels = [
            ("cmp_name", "Plataforma (CMP)"), ("cmp_id", "Identificador de CMP"), ("cmp_version", "Versión de la CMP"),
            ("gdpr_applies", "gdprApplies"), ("cmp_status", "cmpStatus"), ("display_status", "displayStatus"),
            ("event_status", "eventStatus"), ("has_tc_string", "Hay cadena de consentimiento (no se guarda)"),
            ("purposes_granted", "Propósitos con consentimiento"), ("purposes_total", "Propósitos declarados"),
        ]
        def show(value):
            return {True: "sí", False: "no", None: UNKNOWN}.get(value, value) if isinstance(value, (bool, type(None))) else value
        rows = [[e(label), e(show(tcf.get(key)))] for key, label in labels if key in tcf]
        out += f"<p>{level('EVIDENCIA')} Estado que la propia plataforma declara por la interfaz TCF:</p>" + table(["Campo", "Valor declarado"], rows)
    mode = consent.get("consent_mode")
    if not mode:
        out += "<p>Google Consent Mode: no se observaron parámetros <span class=\"mono\">gcs</span> ni <span class=\"mono\">gcd</span> en las comunicaciones con Google.</p>"
    else:
        out += (f"<p>{level('EVIDENCIA')} Google Consent Mode: {e(mode.get('requests'))} comunicaciones con Google llevaron el estado de consentimiento.</p>")
        out += table(["Estado enviado", "Requests"], [[f'<span class="mono">{e(key)}</span>', e(value)] for key, value in (mode.get("states") or {}).items()])
        rows = [[e(signal), "; ".join(f"{e(state)}: {e(count)}" for state, count in (states or {}).items())] for signal, states in (mode.get("by_signal") or {}).items()]
        out += table(["Señal", "Estados decodificados (requests)"], rows)
        out += '<p class="small">Fuente del dato: ' + "; ".join(f"{e(key)} ({e(value)})" for key, value in (mode.get("sources") or {}).items()) + ". <span class=\"mono\">gcd</span> se decodifica con una tabla no oficial.</p>"
    # v1.4.10: `banner_interaction`; un reporte anterior trae `user_interaction`.
    pressed = consent.get("banner_interaction", consent.get("user_interaction"))
    out += f"<p class=\"small\">Interacción con el aviso de consentimiento durante el scan: {'sí' if pressed else 'no'}. Lo anterior describe lo declarado y lo enviado; no evalúa si es correcto.</p>"
    return out


def render_scan_report(report: dict, sha256: str, brand: Brand | None = None) -> str:
    brand = brand or Brand()
    scan = report.get("scan") or {}
    analysis = report.get("analysis") or {}
    destinations = report.get("destinations") or {}
    fingerprinting = report.get("fingerprinting") or {}
    summary = executive_summary(report)

    body = _header(brand, "Reporte de privacidad del sitio web", [
        f'Sitio analizado: <span class="mono">{e(scan.get("url"))}</span>',
        f'Fecha del análisis: {when(scan.get("finished_at") or scan.get("started_at"))} · Reporte generado: {when(report.get("generated_at"))}',
        f'Analizador {e(analysis.get("analyzer_version"))} · listas {e((report.get("versions") or {}).get("lists"))} · {e((report.get("versions") or {}).get("ip_database"))}',
        _conditions_line(report.get("measurement") or {}),
        f'Perfil de licencias de las fuentes: <strong>{e(PROFILE_LABELS.get(report.get("license_profile"), report.get("license_profile")))}</strong>',
    ])
    body += f'<div class="legal">{e(report.get("legal_notice"))}</div>'
    body += _blocking_banner(report)

    body += '<section id="resumen"><h2>Resumen ejecutivo</h2>'
    body += "<p>Síntesis de los resultados para el responsable del sitio. El detalle técnico y la evidencia figuran en el anexo.</p>"
    body += "<h3>Resultados</h3>" + items([e(text) for text in summary["found"]])
    story = report.get("story") or {}
    if story.get("steps"):
        body += '<h3 id="grupos">Hallazgos por grupo</h3>'
        body += ("<p>Los hallazgos se clasifican en ocho grupos técnicos. Cada frase indica su nivel de evidencia; "
                 "un grupo sin hallazgos se indica como tal.</p>")
        body += _story_summary(story)
    body += "<h3>Relevancia</h3>" + items([e(text) for text in summary["why"]])
    body += "<h3>Recomendaciones</h3>" + items([e(text) for text in summary["recommendations"]], ordered=True)
    body += "</section>"

    body += '<section id="anexo" class="annex"><h2>Anexo técnico</h2>'
    body += "<h3>Metodología</h3>" + items([
        *((_import_info(report) or _interactive_info(report) or {}).get("details") or
          ["Un navegador Chromium automatizado visitó la URL indicada una vez, desde la red del analizador, y se registraron sus requests."]),
        "Cada request se clasificó con listas públicas de filtros y con heurísticas; cada señal queda como razón con su nivel de evidencia.",
        "La dirección IP de cada destino es la que usó el proxy de salida al conectar; red y país se estiman con una base offline.",
        "El estado de consentimiento es el que declara la plataforma del sitio (TCF) o el que se transmite en las requests (Consent Mode).",
        f'Datos de la visita: dirección final <span class="mono">{e(scan.get("final_url"))}</span>, estado HTTP {e(scan.get("http_status"))}, '
        f'{e((report.get("capture") or {}).get("total_requests"))} requests'
        + (" (captura truncada por límite)" if (report.get("capture") or {}).get("capture_truncated") else "")
        + (" · análisis parcial" if analysis.get("partial") else "") + ".",
    ])
    body += _interactive_section(report)
    body += _interaction_section(report)
    body += _masking_note(report)
    body += _legend(report.get("evidence_levels"))

    if story.get("steps"):
        body += "<h3>Hallazgos por grupo: detalle y evidencia</h3>"
        body += _story_annex(story)

    body += "<h3>Hallazgos</h3>"
    body += table(["Nivel", "Hallazgo", "Tipo", "Referencias de evidencia"], [
        [level(finding.get("level")), e(finding.get("claim")), e(finding.get("type")), evidence_refs(finding.get("evidence_refs"))]
        for finding in report.get("findings") or []
    ])

    body += "<h3>Terceros con señales de seguimiento, por organización</h3>"
    body += ('<p class="small">Solo organizaciones distintas a la del sitio. Los recursos de la misma '
             "organización (p. ej. su CDN) no cuentan como terceros; se indican aparte, más abajo. El "
             "«giro» describe a qué se dedica normalmente el servicio (contexto, no evidencia del uso concreto).</p>")
    body += table(["Organización", "Giro (contexto)", "Dominios", "Requests", "Banda máxima", "Categorías", "Referencias de evidencia"], [
        [e(brands.group_label(group.get("entity"), group.get("domains") or [])), e(group.get("service_label") or "tipo no identificado"),
         "<br>".join(f'<span class="mono">{e(domain)}</span>' for domain in group.get("domains") or []), e(group.get("request_count")),
         f'{e(group.get("max_band"))} ({e(group.get("max_score"))})', e(", ".join(group.get("categories") or [])),
         refs([request.get("request_id") for request in group.get("requests") or []])]
        for group in report.get("trackers") or []
    ])
    body += _third_party_services_section(report)
    body += _same_org_section(report)
    body += _telemetry_section(report)

    tracker_requests = [
        [f'#{e(request.get("request_id"))}', e(brands.label(group.get("entity"), _host(request.get("url")))), f'<span class="mono">{e(request.get("url"))}</span>',
         f'{e(request.get("band"))} ({e(request.get("score"))})', e(request.get("mechanism")), e(request.get("category"))]
        for group in report.get("trackers") or [] for request in group.get("requests") or []
    ]
    body += "<h3>Requests con señales de seguimiento</h3>"
    body += ('<p class="small">Dirección de cada request tal como salió del navegador'
             + (", con los valores de sus parámetros enmascarados" if report.get("masked") else ", con sus valores completos") + ".</p>")
    body += table(["Request", "Organización", "Dirección", "Banda (score)", "Mecanismo", "Categoría"], tracker_requests)

    body += "<h3>Destinos por país</h3>"
    body += f'<p class="small">{e(destinations.get("location_note"))}</p>'
    body += table(["País", "Dominios", "De terceros", "Ejemplos"], [
        [f'{e(country.get("country"))} ({e(country.get("country_code"))})', e(country.get("domains")), e(country.get("third_party_domains")),
         e(", ".join(country.get("examples") or []))]
        for country in destinations.get("countries") or []
    ])
    body += "<h3>Destinos por dominio: organización, dirección IP, red y país</h3>"
    domain_rows = []
    for domain in destinations.get("domains") or []:
        addresses, networks, countries = _ip_cell(domain)
        domain_rows.append([
            f'<span class="mono">{e(domain.get("domain"))}</span>', PARTY_LABELS.get(domain.get("party")) or ("tercero" if domain.get("third_party") else "propio"), e(domain.get("requests")),
            e(brands.label(domain.get("entity"), domain.get("domain"))) + (" <strong>(difiere de la red)</strong>" if domain.get("sources_differ") else ""), addresses, networks, countries,
        ])
    body += table(["Dominio", "Tipo", "Requests", "Dueño del dominio", "IP observada", "Red de la IP (ASN)", "País de la IP"], domain_rows)
    body += '<p class="small">«Dueño del dominio» y «red de la IP» vienen de fuentes distintas y no se arbitran: cuando difieren, se muestran ambas.</p>'

    cloaking = destinations.get("cname_cloaking") or {}
    body += "<h3>CNAME cloaking</h3>"
    body += f'<p class="small">{e(cloaking.get("note"))} Subdominios propios en la captura: {e(cloaking.get("first_party_subdomains"))}; resueltos: {e(cloaking.get("checked_hosts"))}.</p>'
    body += table(["Nivel", "Hallazgo", "Cadena CNAME", "Inferencia", "Referencias de evidencia"], [
        [level(finding.get("level")), e(finding.get("claim")), f'<span class="mono">{e(" → ".join(finding.get("cname_chain") or []))}</span>',
         f'{level(finding.get("inference_level"))} {e(finding.get("inference"))}', evidence_refs(finding.get("evidence_refs"))]
        for finding in cloaking.get("findings") or []
    ])

    body += "<h3>Fingerprinting</h3>"
    body += _error_frames_note(report)
    if not fingerprinting.get("instrumented"):
        if (report.get("scan") or {}).get("source") == "har_import":
            body += "<p>Captura importada (HAR): un HAR solo registra tráfico de red, sin instrumentación de fingerprinting.</p>"
        body += "<p>Este scan se hizo sin instrumentación: no se midió el uso de APIs de fingerprinting. La ausencia de filas no significa ausencia de fingerprinting.</p>"
    else:
        heuristics = [
            [level(item.get("level")), e(item.get("claim")), f'<span class="mono">{e(script.get("script_url"))}</span>', e(script.get("entity")), evidence_refs(item.get("evidence_refs"))]
            for script in fingerprinting.get("scripts") or [] for item in script.get("heuristics") or []
        ]
        body += "<p>Patrones de uso de APIs por script. «Fingerprinting» es siempre una inferencia; la llamada observada es la evidencia.</p>"
        body += table(["Nivel", "Hallazgo", "Script", "Organización", "Referencias de evidencia"], heuristics)
        body += "<p>Valores leídos del navegador que aparecieron en una comunicación:</p>"
        body += table(["Nivel", "Hallazgo", "Script", "Referencias de evidencia"], [
            [level(item.get("level")), e(item.get("claim")), f'<span class="mono">{e(item.get("script_url"))}</span>', evidence_refs(item.get("evidence_refs"))]
            for item in fingerprinting.get("exfiltrations") or []
        ])

    body += _consent_section(report.get("consent") or {})
    body += _measurement(report.get("measurement") or {})
    body += "<h3>Limitaciones</h3>" + items([e(text) for text in report.get("limitations") or []])
    body += _versions({**(report.get("versions") or {}), "license_profile": PROFILE_LABELS.get(report.get("license_profile"), report.get("license_profile"))})
    body += _attributions(report.get("attributions"))
    body += _footer(report, sha256) + "</section>"
    return _document(f"Reporte de privacidad — {scan.get('url')}", body)


# --- Reporte de un grupo de Privacy Test ---

SCENARIO_LABELS = {"sin_interaccion": "sin interacción", "aceptar": "aceptar", "rechazar": "rechazar"}


def _stat(value: dict | None) -> str:
    if not value:
        return UNKNOWN
    return f'{e(value.get("median"))} (rango {e(value.get("min"))}–{e(value.get("max"))})'


def _cell_label(cell: dict) -> str:
    return f'{SCENARIO_LABELS.get(cell.get("scenario"), cell.get("scenario") or "sin escenario")} · {cell.get("profile")}'


def group_summary(report: dict) -> dict:
    group = report.get("group") or {}
    result = report.get("result") or {}
    config = group.get("config") or {}
    progress = group.get("progress") or {}
    consent = result.get("consent") or {}
    consent_findings = consent.get("findings") or {}
    persistent = result.get("persistent_ids") or {}
    profiles = result.get("profiles") or {}
    differences = result.get("tracker_differences") or []
    pre = (consent_findings.get("pre_consent") or {}).get("items") or []
    post_reject = (consent_findings.get("post_reject") or {}).get("items") or []

    found = [
        f"Se visitó su sitio {plural(progress.get('total', 0), 'vez', 'veces')} ({progress.get('failed', 0)} fallidas), combinando "
        f"{plural(len(config.get('scenarios') or []), 'escenario de consentimiento', 'escenarios de consentimiento')}, "
        f"{plural(len(config.get('profiles') or []), 'perfil de navegador', 'perfiles de navegador')} y {plural(config.get('runs', 0), 'corrida', 'corridas')} de cada combinación.",
    ]
    if consent and not consent.get("not_applicable"):
        found.append(f"Se reconoció un banner de consentimiento ({consent.get('cmp') or UNKNOWN}).")
        found.append(f"Antes de cualquier elección del visitante se observaron {plural(len(pre), 'recurso con señales de seguimiento', 'recursos con señales de seguimiento')}.")
        if (consent_findings.get("post_reject") or {}).get("runs"):
            found.append(f"Después de pulsar «rechazar» se observaron {plural(len(post_reject), 'recurso con señales de seguimiento', 'recursos con señales de seguimiento')}.")
    else:
        found.append("No se reconoció un banner de consentimiento de una plataforma conocida: los escenarios de aceptar y rechazar no aplican.")
    if differences:
        found.append(f"{plural(len(differences), 'dominio de seguimiento apareció', 'dominios de seguimiento aparecieron')} en unas combinaciones y no en otras.")
    if persistent.get("total"):
        found.append(f"{plural(persistent['total'], 'valor con forma de identificador se repitió', 'valores con forma de identificador se repitieron')} entre visitas que partían sin cookies.")
    if profiles:
        found.append("Cambiar el perfil del navegador modificó algunos atributos visibles; la dirección IP fue la misma en todas las visitas.")

    why = [
        "Comparar varias visitas muestra qué hace su sitio según lo que elige el visitante, en lugar de una sola fotografía.",
        "Las cifras varían entre visitas: por eso se informan mediana y rango, y cada dominio con «apareció en k de N».",
    ]
    if persistent.get("total"):
        why.append("Un valor que se repite sin cookies previas puede servir para reconocer al mismo visitante; también puede ser una clave fija del sitio. El anexo distingue lo observado de lo inferido.")

    recommendations = []
    if pre:
        recommendations.append("Revise con quien mantiene su sitio qué herramientas se activan antes de que el visitante elija, y decida si eso es lo que usted espera.")
    if post_reject:
        recommendations.append("Pida revisar la configuración del banner: se observaron recursos de seguimiento después de «rechazar» (detalle en el anexo).")
    if persistent.get("total"):
        recommendations.append("Pregunte a los proveedores de los dominios listados en «valores repetidos» qué representa cada valor.")
    for fallback in (
        "Repita esta prueba con más corridas si necesita más certeza: con pocas, una diferencia puede ser variación normal.",
        "Mantenga un inventario de los servicios externos de su sitio y de cuándo se activa cada uno.",
        "Si necesita saber si su sitio cumple una norma específica, consulte a un profesional: este documento no lo evalúa.",
    ):
        if len(recommendations) >= 5:
            break
        recommendations.append(fallback)
    return {"found": found, "why": why, "recommendations": recommendations[:5]}


def _evidence(entries: list) -> str:
    shown = ", ".join(f'scan {e(str(item.get("job_id"))[:8])} #{e(item.get("request_id"))}' for item in (entries or [])[:6])
    return shown or "sin referencias"


def render_group_report(report: dict, sha256: str, brand: Brand | None = None) -> str:
    brand = brand or Brand()
    group = report.get("group") or {}
    result = report.get("result") or {}
    config = group.get("config") or {}
    summary = group_summary(report)
    cells = result.get("cells") or []

    body = _header(brand, "Reporte de análisis con opciones avanzadas (grupo de scans)", [
        f'Sitio analizado: <span class="mono">{e(group.get("url"))}</span>',
        f'Fecha del test: {when(group.get("created_at"))} · Reporte generado: {when(report.get("generated_at"))}',
        f'Escenarios: {e(", ".join(SCENARIO_LABELS.get(name, name) for name in config.get("scenarios") or []))} · '
        f'perfiles: {e(", ".join(config.get("profiles") or []))} · corridas: {e(config.get("runs"))}',
    ])
    body += f'<div class="legal">{e(report.get("legal_notice"))}</div>'
    body += '<section id="resumen"><h2>Resumen ejecutivo</h2>'
    body += "<p>Síntesis de los resultados para el responsable del sitio. El detalle técnico y la evidencia figuran en el anexo.</p>"
    conclusion = result.get("conclusion") or {}
    if conclusion.get("text"):
        # Conclusión de una línea (v1.2), por plantilla y con su nivel de evidencia.
        body += f'<p><strong>{e(conclusion["text"])}</strong> ({e(conclusion.get("level"))})</p>'
    body += "<h3>Resultados</h3>" + items([e(text) for text in summary["found"]])
    body += "<h3>Relevancia</h3>" + items([e(text) for text in summary["why"]])
    body += "<h3>Recomendaciones</h3>" + items([e(text) for text in summary["recommendations"]], ordered=True)
    body += "</section>"

    body += '<section id="anexo" class="annex"><h2>Anexo técnico</h2>'
    body += "<h3>Metodología</h3>" + items([
        "Cada combinación de escenario de consentimiento y perfil se visitó en corridas independientes, con un contexto de navegador nuevo (sin cookies ni almacenamiento previos).",
        "Los escenarios «aceptar» y «rechazar» solo se ejecutan con plataformas de consentimiento reconocidas; nunca se adivina un botón.",
        "Los perfiles cambian lo que el navegador dice ser. No cambian la dirección IP, y este reporte no afirma anonimato.",
        "Toda comparación usa agregados de varias corridas: mediana, rango y «apareció en k de N».",
    ])
    body += _masking_note(report) + _legend(report.get("evidence_levels"))

    body += "<h3>Scans del grupo</h3>"
    body += table(["Scan", "Escenario", "Perfil", "Corrida", "Estado", "Exposición (0–99)", "Banda"], [
        [f'<span class="mono">{e(scan.get("job_id"))}</span>', e(SCENARIO_LABELS.get(scan.get("scenario"), scan.get("scenario"))), e(scan.get("profile")), e(scan.get("run")),
         e(scan.get("status")), e(scan.get("exposure_score")), e(scan.get("band"))]
        for scan in report.get("scans") or []
    ])

    body += "<h3>Agregados por combinación (mediana y rango)</h3>"
    body += table(["Combinación", "Corridas completas", "Requests", "Dominios de terceros", "Requests con señales de seguimiento"], [
        [e(_cell_label(cell)), f'{e(cell.get("completed"))} de {e(cell.get("runs"))}', _stat(cell.get("requests")), _stat(cell.get("third_party_domains")), _stat(cell.get("tracker_requests"))]
        for cell in cells
    ])
    body += "<h3>Dominios de seguimiento por combinación</h3>"
    body += table(["Combinación", "Dominio", "Organización", "Apareció en"], [
        [e(_cell_label(cell)), f'<span class="mono">{e(domain.get("domain"))}</span>', e(domain.get("entity")), f'{e(domain.get("appeared"))} de {e(domain.get("of"))}']
        for cell in cells for domain in cell.get("tracker_domains") or []
    ])
    differences = result.get("tracker_differences") or []
    if differences:
        body += "<h3>Dominios cuya presencia difiere entre combinaciones</h3>"
        body += table(["Dominio", "Organización"] + [_cell_label(cell) for cell in cells], [
            [f'<span class="mono">{e(row.get("domain"))}</span>', e(row.get("entity"))]
            + [f'{e((row.get("by_cell") or {}).get(cell["key"], {}).get("appeared"))} de {e((row.get("by_cell") or {}).get(cell["key"], {}).get("of"))}' for cell in cells]
            for row in differences
        ])

    consent = result.get("consent")
    body += "<h3>Consentimiento</h3>"
    if not consent:
        body += "<p>Ninguna corrida registró información de consentimiento.</p>"
    else:
        body += (f'<p>Plataforma reconocida: {e(consent.get("cmp"))}. Banner detectado en {e(consent.get("banner_detected_runs"))} de {e(consent.get("runs"))} corridas.'
                 + (" Los escenarios de aceptar y rechazar no aplican (no_aplicable)." if consent.get("not_applicable") else "") + "</p>")
        body += table(["Scan", "Escenario", "Corrida", "Resultado", "Verificado", "Motivo"], [
            [f'<span class="mono">{e(str(item.get("job_id"))[:8])}</span>', e(SCENARIO_LABELS.get(item.get("scenario"), item.get("scenario"))), e(item.get("run")), e(item.get("status")),
             e({True: "sí", False: "no"}.get(item.get("verified"), UNKNOWN)), e(item.get("reason") or "")]
            for item in consent.get("scenarios") or []
        ])
        for key in ("pre_consent", "post_reject", "only_after_accept"):
            finding = (consent.get("findings") or {}).get(key) or {}
            body += f'<p>{level(finding.get("level"))} {e(finding.get("claim"))} Corridas consideradas: {e(finding.get("runs"))}.</p>'
            body += table(["Recurso", "Organización", "Apareció en", "Referencias de evidencia"], [
                [f'<span class="mono">{e(item.get("resource"))}</span>', e(item.get("entity")), f'{e(item.get("runs"))} de {e(item.get("of"))}', _evidence(item.get("evidence"))]
                for item in finding.get("items") or []
            ])
        body += f'<p class="small">{e(consent.get("note"))}</p>'

    profiles = result.get("profiles")
    body += "<h3>Perfiles: qué cambió y qué sigue observable</h3>"
    if not profiles:
        body += "<p>No hay datos de perfiles en este grupo.</p>"
    else:
        names = [profile.get("name") for profile in profiles.get("profiles") or [] if profile.get("name") != "real"]
        body += f'<p>{level("EVIDENCIA")} Valores observados en el navegador en cada perfil. Estado respecto del navegador real del worker.</p>'
        body += table(["Atributo", "Navegador real"] + names, [
            [e(row.get("label")), f'<span class="mono">{e(row.get("real"))}</span>']
            + [f'<span class="mono">{e((row.get("values") or {}).get(name))}</span><br>{e((row.get("status") or {}).get(name))}'
               + (" · sigue sirviendo para reconocer el equipo" if name in (row.get("potentially_identifying") or []) else "") for name in names]
            for row in profiles.get("attributes") or []
        ])
        inconsistencies = []
        for name, entries in (profiles.get("inconsistencies") or {}).items():
            for entry in entries or []:
                if isinstance(entry, dict):
                    inconsistencies.append([
                        e(name), f'{level(entry.get("level"))} {e(entry.get("title") or entry.get("rule"))}: <span class="mono">{e(entry.get("observed"))}</span>',
                        f'{level(entry.get("inference_level"))} {e(entry.get("inference"))}',
                    ])
        if inconsistencies:
            body += "<p>Inconsistencias detectadas en los perfiles:</p>" + table(["Perfil", "Valores observados", "Inferencia"], inconsistencies)
        body += f'<p class="small">{e(profiles.get("ip_note"))}</p>'

    persistent = result.get("persistent_ids") or {}
    body += "<h3>Valores repetidos entre corridas limpias</h3>"
    body += table(["Nivel", "Hallazgo", "Inferencia sobre su origen", "Referencias de evidencia"], [
        [level(item.get("level")), e(item.get("claim")), f'{level(item.get("inference_level"))} {e(item.get("inference"))}', _evidence(item.get("evidence"))]
        for item in persistent.get("items") or []
    ], total=persistent.get("total"))
    body += f'<p class="small">{e(persistent.get("note"))}</p>'

    body += "<h3>Limitaciones</h3>" + items([e(text) for text in report.get("limitations") or []])
    body += _versions(report.get("versions")) + _attributions(report.get("attributions"))
    body += _footer(report, sha256) + "</section>"
    return _document(f"Reporte de análisis con opciones avanzadas — {group.get('url')}", body)
