"""analyze(): captura -> análisis. Función pura: sin red, sin DB, sin estado global.

Contrato de la captura (lo produce app/analysis.py desde las tablas scan_*):
  page_url, start_url, first_party_domains, visit_ts (epoch del fin de la visita, o None),
  requests[]: request_id, seq, url, host, method, resource_type, is_navigation,
              query_params, request_headers, response_headers, post_data
              {data, encoding, size}, sizes, mime_type, third_party,
              registrable_domain
  cookies[]: name, value, domain, expires, third_party · storage[]: storage_type, key, value, origin
  websockets[]: url, third_party
"""

import math
import statistics
import time
import unicodedata
from collections import Counter, defaultdict
from urllib.parse import urlsplit

from app.analyzer import ANALYZER_VERSION
from app.analyzer import consent_mode
from app.analyzer.config import AnalyzerConfig
from app.analyzer.fingerprinting import analyze_fingerprinting
from app.analyzer.lists import UNKNOWN_ENTITY
from app.analyzer.parameters import Param, extract, is_identifier_like, shannon_entropy, value_shapes

DEFAULT_DEADLINE_S = 25.0
MIN_SHARED_VALUE_CHARS = 12
MAX_FINDINGS = 500
MAX_REFS = 50
MAX_STORED_VALUE_CHARS = 2048
PIXEL_MAX_BODY_BYTES = 200
# Cookie "persistente": su vencimiento está a más de un día de la visita (-1 o None = de sesión).
PERSISTENT_COOKIE_MIN_S = 86_400
MAX_EXCLUDED_EXAMPLES = 5
STATIC_TYPES = frozenset({"stylesheet", "font", "image", "script", "media"})
# Fuentes que se describen pero no participan en el cruce de valores entre requests.
VALUE_SOURCES_EXCLUDED = frozenset({"cookie", "set_cookie", "referer"})
DATA_CATEGORIES = ("DEVICE", "IDENTIFIERS", "BEHAVIOR", "NETWORK", "LOCATION", "ADVERTISING", "SESSION")


def prepare_capture(capture: dict, *, start_url: str, page_url: str | None, result: dict | None = None) -> dict:
    """Adapta una captura en memoria (NetworkMonitor.finalize) al contrato de analyze()."""
    prepared = dict(capture)
    prepared["start_url"] = start_url
    prepared["tcf"] = (result or {}).get("tcf")
    prepared["consent"] = (result or {}).get("consent")
    # Señales de bloqueo antibot (point 3): título y estado HTTP de la navegación.
    prepared["title"] = (result or {}).get("title")
    prepared["http_status"] = (result or {}).get("http_status")
    prepared["page_url"] = page_url or start_url
    # Captura interactiva (v1.4.2): hora y tipo de cada clic, desplazamiento y tecla del usuario. None = no se registró.
    prepared["interactions"] = ((result or {}).get("interactive") or {}).get("interactions")
    stamps = [request["ts"].timestamp() for request in capture["requests"] if hasattr(request.get("ts"), "timestamp")]
    prepared["visit_ts"] = max(stamps) if stamps else None
    prepared["requests"] = [{**request, "request_id": request.get("request_id", request["seq"])} for request in capture["requests"]]
    fingerprinting = capture.get("fingerprinting")
    if fingerprinting:
        prepared["fingerprinting"] = {
            **fingerprinting,
            "calls": [{**call, "call_id": call.get("call_id", index)} for index, call in enumerate(fingerprinting["calls"])],
        }
    return prepared


def _host(url: str | None) -> str | None:
    try:
        return urlsplit(url or "").hostname
    except ValueError:
        return None


def _strip_accents(text: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c))


class _SafeDict(dict):
    def __missing__(self, key):  # una variable sin dato queda visible, no rompe la plantilla
        return "{" + key + "}"


def _conclusion(templates: dict, key: str, **values) -> dict:
    """Conclusión por plantilla (point 6): {type, level, text}. Sin juicio legal."""
    spec = (templates or {}).get(key) or {}
    text = str(spec.get("text") or "")
    return {"type": key, "level": spec.get("level") or "EVIDENCIA", "text": text.format_map(_SafeDict(values))}


def _page_needles(*urls: str | None) -> list[str]:
    """Formas de la URL de la página que se buscan dentro de los valores (sin query ni fragmento)."""
    needles = []
    for url in urls:
        try:
            parts = urlsplit(url or "")
        except ValueError:
            continue
        if parts.scheme in ("http", "https") and parts.hostname:
            needle = f"{parts.scheme}://{parts.netloc}{parts.path}".rstrip("/")
            if needle not in needles:
                needles.append(needle)
    return needles


def _referer_exposure(request: dict) -> str:
    """Qué reveló la cabecera Referer que EFECTIVAMENTE se envió: full_url | origin_only | absent.

    No se deduce de la Referrer-Policy: se mira la cabecera capturada, que ya es su resultado.
    """
    value = next(
        (h.get("value") for h in request.get("request_headers") or []
         if isinstance(h, dict) and str(h.get("name", "")).lower() == "referer" and isinstance(h.get("value"), str)),
        None,
    )
    if not value:
        return "absent"
    try:
        parts = urlsplit(value)
    except ValueError:
        return "origin_only"
    return "full_url" if parts.path not in ("", "/") or parts.query else "origin_only"


def _preview(value: str) -> str:
    """Muestra parcial de un valor para un claim: suficiente para reconocerlo, no para reusarlo."""
    return value if len(value) <= 8 else f"{value[:6]}…({len(value)} caracteres)"


def _mechanism(request: dict) -> str:
    resource_type = request.get("resource_type")
    if resource_type in ("ping", "beacon"):
        return "beacon"
    if resource_type == "image":
        body_size = (request.get("sizes") or {}).get("responseBodySize")
        tiny = isinstance(body_size, int) and 0 <= body_size <= PIXEL_MAX_BODY_BYTES
        return "pixel" if tiny and request.get("query_params") else "image"
    if resource_type in ("fetch", "xhr"):
        return "fetch/xhr"
    if resource_type == "script":
        return "script"
    if resource_type == "document":
        return "document" if request.get("is_navigation") and request.get("seq") == 0 else "iframe"
    if resource_type in ("stylesheet", "font", "media"):
        return "static"
    return "other"


def _has_header(headers: list | None, name: str) -> bool:
    return any(isinstance(h, dict) and str(h.get("name", "")).lower() == name for h in headers or [])


def analyze(capture: dict, lists, config: AnalyzerConfig, *, deadline_s: float = DEFAULT_DEADLINE_S) -> dict:
    started = time.monotonic()
    weights = config.scoring["signals"]
    requests = capture["requests"]
    by_id = {request["request_id"]: request for request in requests}
    page_url = capture.get("page_url") or capture.get("start_url")
    source_host = _host(page_url)
    partial = False

    # --- 0. clasificación por organización (v1.2.1, points 1 y 2) ---
    # propio (mismo dominio) · misma organización (otro dominio del mismo dueño según el mapa de
    # entidades) · tercero (otra organización o desconocida). Solo los de otra organización cuentan
    # como "terceros" en el resumen, el índice de exposición, el Panel y los reportes.
    def _org(domain: str | None) -> str | None:
        entity = lists.entity(domain)
        return None if entity == UNKNOWN_ENTITY else entity

    first_party_domains = {
        request.get("registrable_domain")
        for request in requests
        if not request.get("third_party") and request.get("registrable_domain")
    }
    site_orgs = {org for domain in first_party_domains if (org := _org(domain))}

    def party_of(request: dict) -> str:
        if not request.get("third_party"):
            return "first_party"
        org = _org(request.get("registrable_domain"))
        return "same_org" if org is not None and org in site_orgs else "third_party"

    party_by_id = {request["request_id"]: party_of(request) for request in requests}
    external_ids = {request_id for request_id, party in party_by_id.items() if party == "third_party"}
    same_org_ids = {request_id for request_id, party in party_by_id.items() if party == "same_org"}

    # --- 1. parámetros y decodificación ---
    params: list[Param] = []
    decoded_rows: list[dict] = []
    params_by_request: dict[int, list[Param]] = defaultdict(list)
    decoded_by_request: dict[int, list[dict]] = defaultdict(list)
    for request in requests:
        if time.monotonic() - started > deadline_s:
            partial = True  # límite de tiempo: el resto se puntúa sin parámetros
            break
        request_params, request_decoded = extract(request, config.names)
        params += request_params
        decoded_rows += request_decoded
        params_by_request[request["request_id"]] = request_params
        decoded_by_request[request["request_id"]] = request_decoded

    value_params = [p for p in params if p.source not in VALUE_SOURCES_EXCLUDED]

    # --- 2. señales observables entre requests ---
    # 2a. mismo valor con forma de identificador enviado a dominios registrables distintos
    # IDs de cuenta del sitio (pixel, contenedor, ID de medición): iguales para todo visitante.
    # Se informan aparte y no cuentan ni como sincronización ni como identificador persistente.
    account_ids, account_values = config.account_ids.detect(requests, params_by_request)
    shared: dict[str, dict[str, set[int]]] = defaultdict(lambda: defaultdict(set))
    shared_names: dict[str, set[str]] = defaultdict(set)
    for param in value_params:
        domain = by_id[param.request_id].get("registrable_domain")
        if param.value in account_values:
            continue
        if domain and param.identifier_like and len(param.value) >= MIN_SHARED_VALUE_CHARS:
            shared[param.value][domain].add(param.request_id)
            shared_names[param.value].add(param.name)

    def owner(domain: str) -> str:
        """Organización dueña del dominio; si no se conoce, el dominio cuenta como dueño propio."""
        entity = lists.entity(domain)
        return domain if entity == UNKNOWN_ENTITY else f"entidad:{entity}"

    # Dominios distintos de UNA misma organización (google.com / doubleclick.net) no son
    # sincronización entre partes: se exige que el valor llegue a dos dueños distintos.
    candidates = {
        value: domains for value, domains in shared.items() if len({owner(domain) for domain in domains}) >= 2
    }
    # Versiones de software, trozos del User-Agent y constantes del sitio llegan iguales a todo
    # el mundo: que dos organizaciones los reciban no les permite reconocer a nadie. Se
    # descartan, y queda constancia de cuántos y por qué (data/shared_constants.yaml).
    environment = config.shared_constants.environment(capture)
    synced, excluded = {}, []
    for value, domains in candidates.items():
        why = config.shared_constants.classify(value, shared_names[value], environment)
        if why is None:
            synced[value] = domains
        else:
            excluded.append({"reason": why, "preview": _preview(value), "domains": len(domains)})
    sync_by_request: dict[int, str] = {}
    for value, domains in synced.items():
        for request_ids in domains.values():
            for request_id in request_ids:
                sync_by_request.setdefault(request_id, value)

    # 2b. valor igual al de una cookie o un ítem de storage del snapshot
    stored: dict[str, str] = {}
    for cookie in capture.get("cookies") or []:
        stored.setdefault(cookie.get("value") or "", f"la cookie «{cookie.get('name')}»")
    for item in capture.get("storage") or []:
        kind = "localStorage" if item.get("storage_type") == "local" else "sessionStorage"
        stored.setdefault(item.get("value") or "", f"el ítem «{item.get('key')}» de {kind}")
    stored = {
        value: label
        for value, label in stored.items()
        if len(value) >= MIN_SHARED_VALUE_CHARS
        and value not in account_values
        and is_identifier_like(value, value_shapes(value), shannon_entropy(value))
    }
    # Un valor igual a una cookie/storage enviado a la MISMA organización no es persistencia hacia
    # un tercero (point 2): solo cuenta cuando el destino es de otra organización.
    persistent_by_request: dict[int, Param] = {}
    for param in value_params:
        if param.value in stored and param.request_id in external_ids:
            persistent_by_request.setdefault(param.request_id, param)

    # 2c. valor que contiene la URL de la página. Hacia un tercero = fuga; hacia la misma
    # organización (point 2) = dato informativo, no hallazgo de fuga.
    needles = _page_needles(page_url, capture.get("start_url"))
    leak_by_request: dict[int, Param] = {}
    same_org_leak_by_request: dict[int, Param] = {}
    for param in value_params:
        party = party_by_id.get(param.request_id)
        target = leak_by_request if party == "third_party" else same_org_leak_by_request if party == "same_org" else None
        if target is None or param.request_id in target:
            continue
        if any(len(param.value) >= len(needle) and needle in param.value for needle in needles):
            target[param.request_id] = param

    # 2d. cabecera Referer: se mide para todo destino externo (tercero o misma organización).
    referer_by_request = {
        request["request_id"]: _referer_exposure(request) for request in requests if request.get("third_party")
    }

    # 2e. fingerprinting: llamadas a APIs instrumentadas y valores leídos que salen en requests
    fingerprint = analyze_fingerprinting(
        capture.get("fingerprinting"), value_params, by_id, config.scoring["fingerprinting"],
        benign=config.benign_libraries, interaction=config.interaction,
    )
    fp_scripts = fingerprint["fp_scripts"]

    # --- 3. clasificación y score por request ---
    analyzed = []
    list_hits: dict[tuple[str, str], list] = defaultdict(list)
    for request in requests:
        request_id = request["request_id"]
        third_party = bool(request.get("third_party"))
        party = party_by_id[request_id]
        external = party == "third_party"  # tercero de OTRA organización
        domain = request.get("registrable_domain")
        own_params = [p for p in params_by_request.get(request_id, []) if p.source not in VALUE_SOURCES_EXCLUDED]
        mechanism = _mechanism(request)
        reasons = []

        def reason(signal: str, detail: str, **data) -> None:
            # `data`: los mismos hechos del detalle, sueltos, para las frases técnicas de la interfaz.
            spec = weights[signal]
            entry = {"signal": signal, "weight": spec["weight"], "level": spec["level"], "evidence_ref": request_id, "detail": detail}
            if data:
                entry["data"] = data
            reasons.append(entry)

        matches = lists.match(request, source_host)
        if matches:
            best = max(matches, key=lambda match: weights.get(f"list_{match['list']}", {"weight": 0})["weight"])
            if f"list_{best['list']}" in weights:
                reason(f"list_{best['list']}", f"La URL coincide con la regla «{best['rule']}» de la lista {best['list']}.", list=best["list"])
            for match in matches:
                list_hits[(match["list"], domain or "")].append((request_id, match["rule"]))
        if external:
            reason("third_party", f"El dominio {domain} es de otra organización, distinta a la del sitio analizado.")
        if request_id in sync_by_request:
            value = sync_by_request[request_id]
            others = sorted(d for d in synced[value] if d != domain)
            reason("id_sync", f"El valor {_preview(value)} también se envió a: {', '.join(others[:5])}.",
                   other_domains=others[:5], other_entities=sorted({lists.entity(other) for other in others} - {UNKNOWN_ENTITY})[:5])
        if request_id in persistent_by_request:
            param = persistent_by_request[request_id]
            reason("persistent_id", f"El parámetro «{param.name}» lleva el mismo valor que {stored[param.value]} del navegador.",
                   parameter=param.name, stored_in=stored[param.value])
        if request_id in leak_by_request:
            reason("url_leak", f"El parámetro «{leak_by_request[request_id].name}» contiene la URL de la página.",
                   parameter=leak_by_request[request_id].name)
        if external and referer_by_request.get(request_id) == "full_url":
            reason("referer_full_url", "La cabecera Referer llevó a un tercero la URL completa de la página (ruta y parámetros).")
        if request_id in fingerprint["exfiltration_by_request"]:
            hit = fingerprint["exfiltration_by_request"][request_id][0]
            reason("fp_exfiltration", f"El parámetro «{hit['parameter']}» contiene un valor leído con {hit['api']} ({hit['form']}).",
                   parameter=hit["parameter"], api=hit["api"], form=hit["form"])
        initiator_script = request.get("initiator_script") or (request.get("initiator") or {}).get("script_url")
        if request.get("url") in fp_scripts:
            reason("fp_script", "Este recurso es un script con un patrón de uso compatible con fingerprinting.")
        elif initiator_script in fp_scripts:
            reason("fp_script_initiator", f"La inició {initiator_script}, un script con un patrón compatible con fingerprinting.")
        if external and _has_header(request.get("response_headers"), "set-cookie"):
            reason("third_party_set_cookie", "La respuesta de un tercero incluye Set-Cookie.")
        identifier = next((p for p in own_params if p.category == "identity" and p.identifier_like), None)
        if identifier:
            reason(
                "identifier_param",
                f"El parámetro «{identifier.name}» tiene nombre típico de identificador y un valor con forma de identificador.",
                parameter=identifier.name,
            )
        token = next(
            (p for p in own_params if "jwt" in p.shapes or (p.category == "session" and p.identifier_like)), None
        )
        if token and external:
            reason("session_token_third_party", f"El parámetro «{token.name}» tiene forma de token de sesión o JWT.", parameter=token.name)
        if mechanism in ("pixel", "beacon"):
            reason(
                f"mechanism_{mechanism}",
                "Imagen mínima con parámetros." if mechanism == "pixel" else "Enviada con sendBeacon/ping.",
            )
        body = request.get("post_data")
        if external and isinstance(body, dict):
            encoded = body.get("encoding") == "base64" or any(
                row["source"] == "post_body" and row["encoding_chain"][0] in ("base64", "hex")
                for row in decoded_by_request.get(request_id, [])
            )
            if encoded:
                reason("encoded_payload_third_party", "El cuerpo viaja codificado (no es texto ni JSON directo).")
        if request.get("resource_type") in STATIC_TYPES and not request.get("query_params") and not body:
            if party == "first_party":
                reason("first_party_static", "Asset estático del propio sitio, sin parámetros.")
            elif external and not matches and not _has_header(request.get("request_headers"), "cookie") and not _has_header(
                request.get("response_headers"), "set-cookie"
            ):
                reason("third_party_static_clean", "Asset estático de terceros sin parámetros, cookies ni cuerpo.")
            # party == "same_org": asset estático de la misma organización, sin señal.

        score = max(0, min(100, sum(item["weight"] for item in reasons)))
        if domain in config.domain_categories:
            category = config.domain_categories[domain]
        elif matches:
            category = config.scoring["list_categories"].get(matches[0]["list"], "third-party")
        elif request_id in sync_by_request and external:
            category = "cross-site"
        elif external:
            category = "third-party"
        elif party == "same_org":
            category = "same-org"
        elif mechanism == "beacon":
            category = "telemetry"
        else:
            category = "first-party"
        analyzed.append(
            {
                "request_id": request_id,
                "seq": request["seq"],
                "score": score,
                "band": config.band(score),
                "category": category,
                "mechanism": mechanism,
                "entity": lists.entity(domain),
                "registrable_domain": domain,
                "third_party": third_party,
                "party": party,
                "referer": referer_by_request.get(request_id),
                "list_matches": matches,
                "reasons": reasons,
            }
        )

    # --- 4. hallazgos ---
    findings: list[dict] = []

    def finding(kind: str, level: str, claim: str, refs, details: dict | None = None) -> None:
        refs = sorted(set(refs))[:MAX_REFS]
        if refs and len(findings) < MAX_FINDINGS:  # ningún hallazgo sin evidencia
            findings.append({"type": kind, "level": level, "claim": claim, "evidence_refs": refs, "details": details or {}})

    for value, domains in synced.items():
        refs = [request_id for request_ids in domains.values() for request_id in request_ids]
        finding(
            "id_sync",
            "EVIDENCIA",
            f"El mismo valor ({_preview(value)}) se envió en requests a {len(domains)} dominios registrables "
            f"distintos, de {len({owner(domain) for domain in domains})} organizaciones: {', '.join(sorted(domains)[:10])}.",
            refs,
            {"domains": sorted(domains), "owners": len({owner(domain) for domain in domains}), "value_length": len(value), "value_shapes": list(value_shapes(value))},
        )
    persistent_groups: dict[tuple[str, str], list[int]] = defaultdict(list)
    for request_id, param in persistent_by_request.items():
        persistent_groups[(param.value, by_id[request_id].get("registrable_domain") or "")].append(request_id)
    for (value, domain), refs in persistent_groups.items():
        finding(
            "persistent_id",
            "EVIDENCIA",
            f"Un valor enviado a {domain} ({_preview(value)}) coincide con el valor de {stored[value]} del navegador.",
            refs,
            {"domain": domain, "stored_in": stored[value]},
        )
    leak_groups: dict[tuple[str, str], list[int]] = defaultdict(list)
    for request_id, param in leak_by_request.items():
        leak_groups[(by_id[request_id].get("registrable_domain") or "", param.name)].append(request_id)
    for (domain, name), refs in leak_groups.items():
        finding(
            "url_leak",
            "EVIDENCIA",
            f"La URL de la página analizada se envió a {domain} dentro del parámetro «{name}».",
            refs,
            {"domain": domain, "parameter": name},
        )
    referer_groups: dict[str, list[int]] = defaultdict(list)
    same_org_referer: set[str] = set()
    for request_id, exposure in referer_by_request.items():
        if exposure != "full_url":
            continue
        domain = by_id[request_id].get("registrable_domain") or ""
        if request_id in external_ids:
            referer_groups[domain].append(request_id)
        elif request_id in same_org_ids:
            same_org_referer.add(domain)
    for domain, refs in referer_groups.items():
        finding(
            "referer_leak",
            "EVIDENCIA",
            f"La cabecera Referer enviada a {domain} contiene la URL completa de la página, con ruta y parámetros.",
            refs,
            {"domain": domain, "exposure": "full_url"},
        )
    for (list_id, domain), hits in list_hits.items():
        finding(
            "list_match",
            "EVIDENCIA",
            f"{len(hits)} request(s) a {domain} coinciden con reglas de la lista {list_id} (p. ej. «{hits[0][1]}»).",
            [request_id for request_id, _ in hits],
            {"list": list_id, "domain": domain},
        )
    # Telemetría propia (v1.3.4): eventos enviados al propio sitio o a su misma organización.
    telemetry = config.first_party_telemetry.detect(requests, party_by_id)
    if telemetry["requests"]:
        finding(
            "first_party_telemetry",
            "INFERENCIA",
            f"{telemetry['requests']} request(s) al propio sitio o a su misma organización tienen el patrón de un envío de eventos "
            f"(rutas de medición o respuestas 204), hacia {telemetry['endpoints']} endpoint(s): {', '.join(telemetry['hosts'][:6])}.",
            [rid for rid in telemetry["request_ids"] if (config.first_party_telemetry.classify(by_id[rid], party_by_id.get(rid)) or {}).get("kind") != "script"],
            {"requests": telemetry["requests"], "endpoints": telemetry["endpoints"], "hosts": telemetry["hosts"][:10]},
        )
    if telemetry["scripts"]:
        names = sorted({entry["name"] for entry in telemetry["script_list"] if entry.get("name")})
        finding(
            "first_party_analytics_script",
            "EVIDENCIA",
            f"La página cargó {telemetry['scripts']} script(s) de analítica o publicidad propia conocidos: {', '.join(names[:6])}.",
            [rid for rid in telemetry["request_ids"] if (config.first_party_telemetry.classify(by_id[rid], party_by_id.get(rid)) or {}).get("kind") == "script"],
            {"scripts": telemetry["scripts"], "names": names[:10]},
        )
    # Fuga de búsqueda (v1.3): el texto buscado viaja a un host distinto del de la página.
    search_leaks = config.har_signals.search_leaks(params_by_request, by_id, source_host, party_by_id)
    for leak in search_leaks:
        where = {"first_party": "otro host del propio sitio", "same_org": "dominio de la misma organización"}.get(leak["party"], "tercero")
        finding(
            "search_leak",
            "EVIDENCIA",
            f"El término de búsqueda «{leak['term']}» se envió a {leak['host']} ({where}) en el parámetro «{leak['parameter']}»."
            # Telemetría de la caja de búsqueda: el texto puede ser el que el sitio propone, no uno escrito.
            + (" Es el texto que mostraba el buscador: no se determina si lo escribió el usuario o lo propuso el sitio." if leak["rule"] == "contexto" else ""),
            leak["request_ids"],
            {"domain": leak["domain"], "host": leak["host"], "term": leak["term"], "parameter": leak["parameter"],
             "party": leak["party"], "rule": leak["rule"]},
        )
    # Ola de sincronización (v1.3): ráfaga de requests de sync hacia varias organizaciones.
    sync_wave = config.har_signals.sync_wave(requests, party_by_id, owner)
    if sync_wave["detected"]:
        finding(
            "sync_wave",
            "EVIDENCIA",
            f"Ola de sincronización: {sync_wave['requests']} requests de sincronización a {len(sync_wave['domains'])} dominios de "
            f"{sync_wave['organizations']} organizaciones en {sync_wave['duration_ms']} ms"
            + (f", iniciada por {sync_wave['initiator']} (primera request de la ola)." if sync_wave["initiator"] else "."),
            sync_wave["request_ids"],
            {"domain": sync_wave["initiator"], "initiator": sync_wave["initiator"], "requests": sync_wave["requests"],
             "organizations": sync_wave["organizations"], "domains": sync_wave["domains"], "duration_ms": sync_wave["duration_ms"]},
        )
    cookie_groups: dict[str, list[int]] = defaultdict(list)
    identifier_groups: dict[tuple[str, str], list[int]] = defaultdict(list)
    token_groups: dict[tuple[str, str], list[int]] = defaultdict(list)
    email_groups: dict[str, list[int]] = defaultdict(list)
    opaque_groups: dict[str, list[int]] = defaultdict(list)
    for item in analyzed:
        domain = item["registrable_domain"] or ""
        for entry in item["reasons"]:
            if entry["signal"] == "third_party_set_cookie":
                cookie_groups[domain].append(item["request_id"])
        request = by_id[item["request_id"]]
        body = request.get("post_data")
        if item["third_party"] and isinstance(body, dict):
            undecoded = not decoded_by_request.get(item["request_id"]) and (body.get("size") or 0) >= 64
            form = "x-www-form-urlencoded" in str(request.get("request_headers")).lower()
            if body.get("encoding") == "base64" or (undecoded and not form):
                opaque_groups[domain].append(item["request_id"])
    for param in value_params:
        domain = by_id[param.request_id].get("registrable_domain") or ""
        if param.category == "identity" and param.identifier_like:
            identifier_groups[(domain, param.name)].append(param.request_id)
        if by_id[param.request_id].get("third_party"):
            if "jwt" in param.shapes or (param.category == "session" and param.identifier_like):
                token_groups[(domain, param.name)].append(param.request_id)
            if "email" in param.shapes:
                email_groups[domain].append(param.request_id)
    for domain, refs in cookie_groups.items():
        finding("third_party_set_cookie", "EVIDENCIA", f"{domain} (tercero) respondió con cabeceras Set-Cookie.", refs, {"domain": domain})
    _persistent_cookie_findings(capture, requests, params, lists, finding)
    for (domain, name), refs in identifier_groups.items():
        finding(
            "identifier_param",
            "INFERENCIA",
            f"El parámetro «{name}» enviado a {domain} tiene nombre típico de identificador y un valor con forma de "
            "identificador. El nombre no prueba qué contiene.",
            refs,
            {"domain": domain, "parameter": name},
        )
    for (domain, name), refs in token_groups.items():
        finding(
            "session_token_third_party",
            "INFERENCIA",
            f"El parámetro «{name}» enviado a {domain} (tercero) tiene forma de token de sesión o JWT.",
            refs,
            {"domain": domain, "parameter": name},
        )
    for domain, refs in email_groups.items():
        finding(
            "email_shape",
            "POSIBLE",
            f"Un valor enviado a {domain} tiene forma de dirección de correo. No se sabe a quién corresponde ni si es real.",
            refs,
            {"domain": domain},
        )
    for domain, refs in opaque_groups.items():
        finding(
            "opaque_payload",
            "DESCONOCIDO",
            f"Se envió a {domain} un cuerpo cuyo contenido no se pudo interpretar (binario o con codificación no reconocida).",
            refs,
            {"domain": domain},
        )

    # --- 4a. v1.4.2: rastreo del lado del servidor y registro de interacción (docs/adr/030) ---
    server_side = config.server_side.detect(requests, params_by_request, party_by_id)
    for item in server_side:
        finding(
            "server_side_meta",
            "INFERENCIA",
            f"El host {item['host']} (nube genérica, sin dueño identificable) recibió {', '.join(item['signals'][:6])}: es compatible con un "
            "servidor de Conversions API de Meta (rastreo del lado del servidor). El reenvío a Meta ocurriría entre servidores y no es observable.",
            item["request_ids"],
            {"domain": item["domain"], "host": item["host"], "signals": item["signals"]},
        )
    interaction_payloads = config.interaction.payloads(requests, params_by_request, party_by_id, VALUE_SOURCES_EXCLUDED)
    for item in interaction_payloads:
        finding(
            "interaction_payload",
            "INFERENCIA",
            f"{len(item['request_ids'])} request(s) a {item['domain']} llevan parámetros con nombre de {item['label']} "
            f"({', '.join('«' + name + '»' for name in item['parameters'][:6])}). El nombre no prueba qué contiene el valor.",
            item["request_ids"],
            {"domain": item["domain"], "category": item["category"], "label": item["label"], "parameters": item["parameters"], "party": item["party"]},
        )
    recording: dict[str, list[int]] = defaultdict(list)
    for request in requests:
        if party_by_id[request["request_id"]] != "third_party":
            continue
        domain = request.get("registrable_domain")
        service = config.service_types.of(entity=lists.entity(domain), domain=domain, host=request.get("host"))
        if service and service["type"] == "session_recording":
            recording[domain or ""].append(request["request_id"])
    for domain, refs in recording.items():
        finding(
            "session_recording",
            "INFERENCIA",
            f"Se enviaron {len(refs)} request(s) a {domain}, un servicio de grabación de sesión (registra clics, movimiento del mouse y "
            "desplazamiento). Es compatible con que esta sesión se esté grabando; el contenido de la grabación no se observa.",
            refs,
            {"domain": domain, "requests": len(refs)},
        )

    def organization_of(request: dict) -> str:
        entity = lists.entity(request.get("registrable_domain"))
        return (request.get("registrable_domain") or request.get("host") or UNKNOWN_ENTITY) if entity == UNKNOWN_ENTITY else entity

    interaction = config.interaction.correlate(capture.get("interactions"), requests, party_by_id, organization_of)
    for item in interaction.get("organizations") or []:
        if not item["flagged"]:
            continue
        finding(
            "interaction_sent",
            "EVIDENCIA",
            f"Tras {item['interactions']} de {interaction['total']} interacciones del usuario (clics, desplazamientos o teclas) se enviaron "
            f"{item['requests']} request(s) a {', '.join(item['domains'][:4]) or item['organization']} dentro de los {interaction['window_s']:g} s siguientes; "
            f"por el ritmo normal de la sesión se esperaban {item['expected']:g}. Lo observado es la secuencia temporal: no se registró qué se tecleó ni dónde se hizo clic.",
            item["request_ids"],
            {"domain": (item["domains"] or [None])[0], "organization": item["organization"], "interactions": item["interactions"],
             "requests": item["requests"], "expected": item["expected"], "kinds": item["kinds"], "party": item["party"]},
        )

    # --- 4b. consentimiento declarado por la página y por las requests (F8) ---
    consent_summary = _consent_findings(capture, requests, value_params, by_id, config, finding)

    # --- 5. sitio ---
    # Terceros = dominios de OTRA organización (point 1). La misma organización se cuenta aparte y
    # no entra en el índice de exposición, el resumen ni los reportes.
    tracker_bands = set(config.tracker_bands)
    trackers = [item for item in analyzed if item["band"] in tracker_bands]
    third_party_domains = {item["registrable_domain"] for item in analyzed if item["party"] == "third_party" and item["registrable_domain"]}
    same_org_domains = {item["registrable_domain"] for item in analyzed if item["party"] == "same_org" and item["registrable_domain"]}
    counts = {
        "tracker_domains": len({t["registrable_domain"] for t in trackers if t["party"] == "third_party" and t["registrable_domain"]}),
        "id_sync": len(synced),
        "url_leak_recipients": len({domain for domain, _ in leak_groups} | set(referer_groups)),
        "stored_items": len(capture.get("cookies") or []) + len(capture.get("storage") or []),
        "fp_scripts": len(fp_scripts),
        "fp_exfiltration": len({f["details"]["api"] for f in fingerprint["findings"] if f["heuristic"] == "exfiltration"}),
        "persistent_id_recipients": len({domain for _, domain in persistent_groups}),
        "third_party_domains": len(third_party_domains),
        # Telemetría propia (v1.3.4): endpoints de eventos distintos + scripts de analítica propia.
        "first_party_telemetry": telemetry["endpoints"] + telemetry["scripts"],
    }
    # Asintótica: cada componente tiende a su tope sin alcanzarlo, y la suma nunca llega a 100.
    breakdown = []
    for component, spec in config.scoring["site_exposure"].items():
        count = counts.get(component, 0)
        breakdown.append(
            {"component": component, "count": count, "cap": spec["cap"], "k": spec["k"],
             "points": round(spec["cap"] * (1 - math.exp(-count / spec["k"])), 2)}
        )
    site_score = max(0, min(99, math.floor(sum(item["points"] for item in breakdown))))

    # "Rastreadores" = organizaciones de terceros (otra organización). El giro (point 5) es contexto.
    entities: dict[str, dict] = {}
    server_side_domains = {item["domain"] for item in server_side if item["domain"]}
    for tracker in trackers:
        if tracker["party"] != "third_party":
            continue
        entry = entities.setdefault(tracker["entity"], {"entity": tracker["entity"], "domains": set(), "requests": 0, "max_score": 0, "urls": []})
        entry["domains"].add(tracker["registrable_domain"] or "")
        if len(entry["urls"]) < 200:
            entry["urls"].append(by_id[tracker["request_id"]].get("url") or "")
        entry["requests"] += 1
        entry["max_score"] = max(entry["max_score"], tracker["score"])
    for entry in entities.values():
        domain = next(iter(sorted(entry["domains"])), None)
        service = config.service_types.of(entity=entry["entity"], domain=domain, urls=entry.pop("urls"))
        if service is None and entry["domains"] & server_side_domains:
            service = {"type": "server_side_meta", "label": config.server_side.meta_label}
        entry["service_type"] = service["type"] if service else None
        entry["service_label"] = service["label"] if service else None
    mechanisms = Counter(item["mechanism"] for item in analyzed)
    mechanisms.update({"websocket": len(capture.get("websockets") or []), "cookie": len(capture.get("cookies") or []),
                       "storage": len(capture.get("storage") or [])})
    trackers_external = [item for item in trackers if item["party"] == "third_party"]
    blocking = _blocking(capture, requests, config.blocking, trackers=len(trackers_external),
                         telemetry=telemetry, telemetry_min=config.first_party_telemetry.min_requests_for_note)

    return {
        "analyzer_version": ANALYZER_VERSION,
        "lists_version": lists.version,
        "lists": lists.sources,
        "partial": partial,
        "requests": analyzed,
        "parameters": [
            {
                "request_id": p.request_id,
                "source": p.source,
                "name": p.name,
                "value": p.value[:MAX_STORED_VALUE_CHARS],
                "value_truncated": len(p.value) > MAX_STORED_VALUE_CHARS,
                "category": p.category,
                "shapes": list(p.shapes),
                "length": p.length,
                "entropy": p.entropy,
                "identifier_like": p.identifier_like,
                "encoding_chain": list(p.encoding_chain),
            }
            for p in params
        ],
        "decoded_values": decoded_rows,
        "findings": findings,
        "fingerprinting": {
            "instrumented": fingerprint["instrumented"],
            "truncated": fingerprint["truncated"],
            "scripts": fingerprint["scripts"],
            "findings": fingerprint["findings"],
            "attributes": fingerprint["attributes"],
        },
        "site": {
            "score": site_score,
            "band": config.band(site_score),
            "breakdown": breakdown,
            "data_categories": _data_categories(
                analyzed, params, by_id, leak_by_request, persistent_by_request, sync_by_request, third_party_domains,
                referer_by_request, fingerprint,
            ),
            "mechanisms": {name: count for name, count in sorted(mechanisms.items()) if count},
            "summary": {
                "requests": len(analyzed),
                "trackers": len(trackers_external),
                "third_party_domains": len(third_party_domains),
                "same_org_domains": len(same_org_domains),
                # Clasificación por organización (point 1): los dominios de cada tipo.
                "parties": {
                    "first_party_domains": sorted(d for d in first_party_domains if d),
                    "same_org_domains": sorted(d for d in same_org_domains if d),
                    "third_party_domains": sorted(d for d in third_party_domains if d),
                },
                # Fugas hacia la MISMA organización (point 2): informativo, no es hallazgo de fuga.
                "same_org": {
                    "url_recipients": sorted({by_id[rid].get("registrable_domain") for rid in same_org_leak_by_request if by_id[rid].get("registrable_domain")}),
                    "referer_full_url_recipients": sorted(same_org_referer),
                },
                # Marca de "visita posiblemente bloqueada" (point 3): banner y exclusión del ranking del Panel.
                "blocking": blocking,
                # Telemetría propia (v1.3.4): no son terceros; conteo aparte.
                "first_party_telemetry": {key: value for key, value in telemetry.items() if key != "request_ids"},
                # v1.3: ola de sincronización y términos de búsqueda enviados fuera del host de la página.
                "sync_wave": {key: value for key, value in sync_wave.items() if key != "request_ids"},
                "search_leaks": [{key: leak[key] for key in ("host", "domain", "term", "parameter", "party")} for leak in search_leaks[:20]],
                # Requests que el navegador del usuario canceló por una extensión (solo capturas HAR).
                "blocked_by_client": sum(1 for request in requests if "ERR_BLOCKED_BY_CLIENT" in (request.get("failure_text") or "")),
                "source": capture.get("source") or "scan",
                # v1.4.2: hosts de nube con señales de eventos de Meta (inferencia) y registro de interacción.
                "server_side": [{key: item[key] for key in ("host", "domain", "signals", "label")} | {"requests": len(item["request_ids"])} for item in server_side],
                "interaction": {
                    **{key: value for key, value in interaction.items() if key != "organizations"},
                    "organizations": [{key: value for key, value in item.items() if key != "request_ids"} for item in (interaction.get("organizations") or [])[:30]],
                    "payloads": [{key: item[key] for key in ("domain", "party", "category", "label", "parameters")} | {"requests": len(item["request_ids"])}
                                 for item in interaction_payloads[:60]],
                    "listener_scripts": len([f for f in fingerprint["findings"] if f["heuristic"] == "interaction_listener"]),
                    "recording_domains": sorted(recording),
                },
                "referer": dict(Counter(referer_by_request.values())),
                "consent": consent_summary,
                # Valores que llegaron a varias organizaciones pero no son identificadores
                # (versiones, User-Agent, constantes): no cuentan como sincronización.
                "shared_values_excluded": {
                    "total": len(excluded),
                    "by_reason": dict(Counter(item["reason"].split(":", 1)[0] for item in excluded)),
                    "examples": sorted(excluded, key=lambda item: (-item["domains"], item["preview"]))[:MAX_EXCLUDED_EXAMPLES],
                },
                # IDs de cuenta del sitio: excluidos de persistencia y de sincronización (v1.2).
                "account_ids": account_ids,
                # Con qué perfil de licencias se cargaron las fuentes de este análisis (docs/adr/019).
                "license_profile": getattr(lists, "license_profile", "no_comercial"),
                "fingerprinting_scripts": sorted(fp_scripts),
                "bands": dict(Counter(item["band"] for item in analyzed)),
                "categories": dict(Counter(item["category"] for item in analyzed)),
                "findings": dict(Counter(item["level"] for item in findings)),
                "entities": sorted(
                    ({**entry, "domains": sorted(entry["domains"])} for entry in entities.values()),
                    key=lambda entry: (-entry["requests"], entry["entity"]),
                ),
                # Giro de cada organización de terceros presente (point 5): contexto, no evidencia.
                "service_types": {
                    entry["entity"]: {"type": entry["service_type"], "label": entry["service_label"]}
                    for entry in entities.values() if entry.get("service_label")
                },
            },
        },
        "duration_ms": round((time.monotonic() - started) * 1000),
    }


def _blocking(capture: dict, requests: list, config: dict, *, trackers: int | None = None,
              telemetry: dict | None = None, telemetry_min: int = 3) -> dict:
    """Señales de que el sitio detectó el navegador automatizado (point 3). Sin esto, blocked=False."""
    min_requests = config.get("min_requests", 20)
    bad_statuses = set(config.get("bad_statuses") or [])
    keywords = [_strip_accents(str(k).lower()) for k in config.get("title_keywords") or []]
    title = _strip_accents(str(capture.get("title") or "").lower())
    http_status = capture.get("http_status")
    signals = []
    if capture.get("source") == "har_import":
        # Captura del navegador real del usuario: la alerta de navegador automatizado no aplica.
        return {"blocked": False, "signals": [], "requests": len(requests), "http_status": http_status, "min_requests": min_requests}
    if len(requests) < min_requests:
        signals.append({"signal": "few_requests",
                        "detail": f"Se capturaron {len(requests)} request(s), menos del umbral de {min_requests}."})
    matched = next((k for k in keywords if k and k in title), None)
    if matched:
        signals.append({"signal": "challenge_text", "detail": f"El título de la página contiene «{matched}»."})
    statuses = {http_status} | {r.get("response_status") for r in requests if r.get("is_navigation")}
    bad_seen = sorted(s for s in statuses if isinstance(s, int) and s in bad_statuses)
    if bad_seen:
        signals.append({"signal": "http_status", "detail": f"La navegación respondió con estado {', '.join(map(str, bad_seen))}."})
    anomaly = _tracker_anomaly(len(requests), trackers, capture.get("history"), config.get("tracker_anomaly") or {})
    signature = _challenge_signature(requests, config)
    note = None
    own = (telemetry or {}).get("requests") or 0
    # v1.3.4: poco rastreo de terceros no basta si el sitio mide con infraestructura propia. Con título
    # normal, sin firma antibot y sin otra señal, queda una nota informativa en vez de la marca.
    if anomaly and not signals and not signature and title.strip() and own >= telemetry_min:
        note = {"signal": "low_third_party_tracking",
                "detail": f"Rastreo de terceros bajo; telemetría propia detectada ({own} requests de eventos al propio sitio o a su "
                          f"misma organización, y {trackers} de rastreo de terceros en {len(requests)} requests)."}
    elif anomaly:
        signals.append(anomaly)
    partial = None
    if signature:
        detail = (f"Se cargó un documento o frame cuya dirección contiene «{signature[0]}», "
                  f"firma habitual de una pantalla de verificación antibot ({signature[1]}).")
        # v1.3.2: la firma sola no basta. Si la página principal cargó y el rastreo es normal, el
        # desafío afectó a un componente (p. ej. un bloque de recomendaciones): aviso informativo.
        if not signals and _normal_tracking(len(requests), trackers, config.get("challenge_partial") or {}) \
                and not _is_challenge_page(capture, signature[0], config):
            partial = {"signal": "challenge_component",
                       "detail": f"{detail} El resto de la página cargó: {trackers} de {len(requests)} requests fueron de rastreo."}
        else:
            signals.append({"signal": "challenge_url", "detail": detail})
    return {"blocked": bool(signals), "partial": partial is not None, "signals": signals or ([partial] if partial else []),
            # Nota informativa (no marca ni excluye del ranking); None si no aplica o si la visita quedó marcada.
            "note": note if not signals else None,
            "requests": len(requests), "http_status": http_status, "min_requests": min_requests}


def _normal_tracking(total: int, trackers: int | None, rule: dict) -> bool:
    """Rastreo suficiente para descartar que la visita entera fue desafiada (umbrales en YAML)."""
    if trackers is None or not total:
        return False
    return trackers >= rule.get("min_trackers", 10) and trackers / total >= rule.get("min_tracker_ratio", 0.05)


def _is_challenge_page(capture: dict, signature: str, config: dict) -> bool:
    """La propia página (no un componente) es la pantalla de verificación."""
    ignored = [str(s).lower() for s in config.get("challenge_url_ignore") or [] if s]
    for url in (capture.get("page_url"), capture.get("start_url")):
        lowered = str(url or "").lower()
        if signature in lowered and not any(item in lowered for item in ignored):
            return True
    return False


def _challenge_signature(requests: list, config: dict) -> tuple[str, str] | None:
    """Primera firma de desafío antibot en la URL de un documento o frame: (firma, host). Solo texto."""
    signatures = [str(s).lower() for s in config.get("challenge_url_signatures") or [] if s]
    ignored = [str(s).lower() for s in config.get("challenge_url_ignore") or [] if s]
    if not signatures:
        return None
    seen = set()
    for request in requests:
        candidates = [request.get("frame_url")]
        if request.get("resource_type") == "document" or request.get("is_navigation"):
            candidates.append(request.get("url"))
        for url in candidates:
            if not url or url in seen:
                continue
            seen.add(url)
            lowered = str(url).lower()
            if any(item in lowered for item in ignored):
                continue
            matched = next((s for s in signatures if s in lowered), None)
            if matched:
                return matched, (urlsplit(str(url)).hostname or "host no_disponible")[:120]
    return None


def _tracker_anomaly(total: int, trackers: int | None, history, config: dict) -> dict | None:
    """Rastreo muy por debajo de lo esperado para el total de requests (v1.3.1). None = sin señal."""
    if trackers is None or not config:
        return None
    rule = config.get("history") or {}
    previous = [item for item in (history or []) if (item.get("requests") or 0) > 0 and item.get("trackers") is not None]
    previous = previous[: int(rule.get("max_scans", 5))]
    if previous:
        baseline = statistics.median(item["trackers"] for item in previous)
        ratio = statistics.median(item["trackers"] / item["requests"] for item in previous)
        expected = ratio * total
        # Un historial con poco rastreo no sirve de referencia: se aplica el umbral sin historial.
        if baseline >= rule.get("min_baseline_trackers", 10):
            if total >= rule.get("min_requests", 30) and trackers < rule.get("max_fraction_of_expected", 0.25) * expected:
                return {"signal": "tracker_anomaly_history",
                        "detail": f"Se observaron {trackers} request(s) de rastreo en {total} requests; por "
                                  f"{len(previous)} scan(s) anterior(es) del mismo sitio se esperaban cerca de {round(expected)}."}
            return None
    rule = config.get("no_history") or {}
    if (rule and total >= rule.get("min_requests", 100) and trackers >= rule.get("min_trackers", 1)
            and trackers / total <= rule.get("max_tracker_ratio", 0.015)):
        return {"signal": "tracker_anomaly",
                "detail": f"Solo {trackers} de {total} requests fueron de rastreo, muy poco para una página de ese tamaño "
                          "(no hay scans anteriores del sitio para comparar)."}
    return None


def _persistent_cookie_findings(capture, requests, params, lists, finding) -> None:
    """Cookies que siguen en el navegador después de la visita (vencen a más de un día).

    Lo observado es la cookie y su fecha de vencimiento (EVIDENCIA). Para qué se usa no se
    afirma. Evidencia: las requests que la fijaron (Set-Cookie) o la enviaron (Cookie); si
    la creó un script y nunca viajó, la primera request de la visita.
    """
    cookies = [cookie for cookie in capture.get("cookies") or [] if isinstance(cookie.get("expires"), (int, float))]
    if not cookies or not requests:
        return
    # El "ahora" de la visita sale de la captura, no del reloj: re-analizar da el mismo resultado.
    visit = capture.get("visit_ts")
    by_name: dict[str, list[int]] = defaultdict(list)
    for param in params:
        if param.source in ("cookie", "set_cookie"):
            by_name[param.name].append(param.request_id)
    # Dominio registrable de la cookie: el de alguna request de la captura que lo contenga.
    registrable = sorted({request["registrable_domain"] for request in requests if request.get("registrable_domain")}, key=len, reverse=True)
    groups: dict[str, dict] = {}
    for cookie in cookies:
        remaining = cookie["expires"] - visit if isinstance(visit, (int, float)) else None
        if cookie["expires"] <= 0 or remaining is None or remaining < PERSISTENT_COOKIE_MIN_S:
            continue
        host = str(cookie.get("domain") or "").lstrip(".").lower()
        domain = next((known for known in registrable if host == known or host.endswith("." + known)), host)
        group = groups.setdefault(domain, {"names": [], "max_days": 0, "third_party": bool(cookie.get("third_party")), "refs": []})
        group["names"].append(str(cookie.get("name") or ""))
        group["max_days"] = max(group["max_days"], int(remaining // 86_400))
        group["refs"] += by_name.get(cookie.get("name") or "", [])
    for domain, group in sorted(groups.items()):
        count = len(group["names"])
        finding(
            "persistent_cookie",
            "EVIDENCIA",
            f"Tras la visita quedaron en el navegador {count} cookie(s) de {domain} que no se borran al cerrarlo: "
            f"la que más dura vence en {group['max_days']} día(s).",
            group["refs"] or [requests[0]["request_id"]],
            {"domain": domain, "entity": lists.entity(domain), "cookies": count, "max_days": group["max_days"],
             "names": sorted(group["names"])[:10], "third_party": group["third_party"]},
        )


def _consent_findings(capture, requests, value_params, by_id, config, finding) -> dict:
    """TCF (lo que declara la página) y Consent Mode (lo que viaja a Google). Sin juicio legal."""
    first_ref = [requests[0]["request_id"]] if requests else []
    interaction = (capture.get("consent") or {}).get("interaction_seq")
    summary = {"tcf": None, "consent_mode": None, "user_interaction": interaction is not None}
    # Conclusiones por plantilla, con su nivel (point 6): se muestran en Resumen, Hallazgos y reportes.
    conclusions: list[dict] = []
    templates = config.consent_conclusions

    tcf = capture.get("tcf")
    if isinstance(tcf, dict) and tcf.get("present"):
        ping, data = tcf.get("ping") or {}, tcf.get("tc_data") or {}
        cmp_id = ping.get("cmp_id") if ping.get("cmp_id") is not None else data.get("cmp_id")
        name = (config.cmp_names or {}).get(cmp_id) if isinstance(cmp_id, int) else None
        label = f"{name} (cmpId {cmp_id})" if name else f"CMP {cmp_id}" if cmp_id is not None else "CMP no identificado"
        gdpr = ping.get("gdpr_applies") if ping.get("gdpr_applies") is not None else data.get("gdpr_applies")
        summary["tcf"] = {
            "present": True, "cmp_id": cmp_id, "cmp_name": name or "no_disponible", "cmp_version": ping.get("cmp_version") or data.get("cmp_version"),
            "cmp_status": ping.get("cmp_status") or data.get("cmp_status"), "display_status": ping.get("display_status"),
            "gdpr_applies": gdpr, "event_status": data.get("event_status"), "has_tc_string": data.get("has_tc_string"),
            "purposes_granted": data.get("purposes_granted"), "purposes_total": data.get("purposes_total"),
        }
        claim = f"El sitio tiene una plataforma de consentimiento TCF ({label}) y declara gdprApplies={str(gdpr).lower() if gdpr is not None else 'no informado'} para esta visita"
        if gdpr is False:
            claim += ": según la propia plataforma, no aplica solicitar consentimiento a este visitante"
        if ping.get("display_status") in ("hidden", "disabled"):
            claim += f"; la plataforma informa que su interfaz no se mostró (displayStatus={ping['display_status']})"
        elif ping.get("display_status") == "visible":
            claim += "; la plataforma informa que su interfaz estaba visible"
        finding("tcf_state", "EVIDENCIA", claim + ".", first_ref, summary["tcf"])
        # Plataforma presente pero que no se muestra en esta visita (point 6).
        if gdpr is False and ping.get("display_status") in ("hidden", "disabled"):
            conclusions.append(_conclusion(templates, "tcf_present_not_shown", cmp=label))
    elif isinstance(tcf, dict) and tcf.get("present") is False:
        summary["tcf"] = {"present": False}

    entries = consent_mode.detect(value_params, by_id, set(config.google_domains))
    if entries:
        states: dict[str, list[int]] = defaultdict(list)
        for entry in entries:
            key = entry["gcs"]["raw"] if entry["gcs"] else f"gcd:{entry['gcd']['raw']}"
            states[key].append(entry["request_id"])
        by_signal = {
            signal: dict(Counter(consent_mode.state_of(entry, signal) or "no_definido" for entry in entries))
            for signal in ("ad_storage", "analytics_storage")
        }
        summary["consent_mode"] = {
            "requests": len(entries), "states": {key: len(refs) for key, refs in states.items()}, "by_signal": by_signal,
            "sources": {"gcs": sum(1 for e in entries if e["gcs"]), "gcd_only": sum(1 for e in entries if not e["gcs"])},
        }
        for key, refs in states.items():
            entry = next(e for e in entries if (e["gcs"]["raw"] if e["gcs"] else f"gcd:{e['gcd']['raw']}") == key)
            ad, analytics = consent_mode.state_of(entry, "ad_storage"), consent_mode.state_of(entry, "analytics_storage")
            source = "gcs" if entry["gcs"] else "gcd (formato no oficial)"
            finding(
                "consent_mode_state", "EVIDENCIA",
                f"{len(refs)} request(s) a Google llevan el parámetro {source}={key.replace('gcd:', '')}: ad_storage={ad}, analytics_storage={analytics}.",
                refs, {"raw": key, "ad_storage": ad, "analytics_storage": analytics, "source": source},
            )
        # Antes de cualquier interacción: todo el scan si no hubo clic, o lo anterior al clic.
        before = [e for e in entries if interaction is None or e["seq"] < interaction]
        granted_nouns, granted_raw = [], None
        for signal, noun in (("ad_storage", "publicidad"), ("analytics_storage", "analítica")):
            granted = [e for e in before if consent_mode.state_of(e, signal) == "granted" and e["gcs"]]
            if granted:
                granted_nouns.append(noun)
                granted_raw = granted_raw or granted[0]["gcs"]["raw"]
                moment = "sin interacción del usuario" if interaction is None else "antes de cualquier interacción del usuario"
                finding(
                    "consent_mode_granted_without_interaction", "EVIDENCIA",
                    f"Se enviaron datos a Google con {signal}=granted {moment} ({len(granted)} request(s); almacenamiento de {noun}).",
                    [e["request_id"] for e in granted], {"signal": signal, "requests": len(granted)},
                )
        if granted_nouns:
            conclusions.append(_conclusion(
                templates, "consent_mode_granted_without_interaction", ambito=" y ".join(granted_nouns), raw=granted_raw))
        else:
            # gcs enviado pero sin declarar estado (G1--): todas las señales "no_definido".
            undefined = next(
                (e for e in entries if e["gcs"]
                 and consent_mode.state_of(e, "ad_storage") == "no_definido"
                 and consent_mode.state_of(e, "analytics_storage") == "no_definido"),
                None,
            )
            if undefined:
                conclusions.append(_conclusion(templates, "consent_mode_undefined", raw=undefined["gcs"]["raw"]))
    summary["conclusions"] = conclusions
    return summary


def _data_categories(
    analyzed, params, by_id, leaks, persistent, synced, third_party_domains, referers, fingerprint
) -> list[dict]:
    """Qué tipos de datos expone el sitio a terceros. status: observado | inferido | potencial."""
    items: list[dict] = []

    def add(category: str, status: str, item: str, refs) -> None:
        refs = sorted(set(refs))[:MAX_REFS]
        if refs:
            items.append({"category": category, "status": status, "item": item, "evidence_refs": refs})

    third_party = [item["request_id"] for item in analyzed if item["third_party"]]
    with_header = lambda name: [  # noqa: E731
        request_id for request_id in third_party if _has_header(by_id[request_id].get("request_headers"), name)
    ]
    add("NETWORK", "observado", f"Se abrieron conexiones a {len(third_party_domains)} dominio(s) de terceros; toda conexión expone la IP de origen.", third_party)
    add("LOCATION", "potencial", "La IP de origen permite a esos terceros una geolocalización aproximada.", third_party)
    add("DEVICE", "observado", "La cabecera User-Agent se envió a terceros.", with_header("user-agent"))
    add("BEHAVIOR", "observado", "La cabecera Referer llevó a terceros la URL completa de la página.",
        [request_id for request_id, exposure in referers.items() if exposure == "full_url"])
    add("BEHAVIOR", "observado", "La cabecera Referer llevó a terceros solo el origen del sitio.",
        [request_id for request_id, exposure in referers.items() if exposure == "origin_only"])
    exfiltrated = [ref for f in fingerprint["findings"] if f["heuristic"] == "exfiltration" for ref in f["request_refs"]]
    add("DEVICE", "observado", "Valores del dispositivo leídos por scripts (GPU, user agent, canvas...) aparecen en requests salientes.",
        exfiltrated)
    add("BEHAVIOR", "observado", "La URL de la página se envió a terceros dentro de parámetros.", leaks)
    add("IDENTIFIERS", "observado", "Se envió a terceros un valor igual al de una cookie o ítem de storage.", persistent)
    add("IDENTIFIERS", "observado", "El mismo valor con forma de identificador se envió a varios dominios.", synced)
    by_category: dict[str, list[int]] = defaultdict(list)
    for param in params:
        if param.source in VALUE_SOURCES_EXCLUDED or not by_id[param.request_id].get("third_party"):
            continue
        if param.category == "identity" and param.identifier_like:
            by_category["IDENTIFIERS"].append(param.request_id)
        elif param.category in ("device", "location", "advertising", "session") and param.value:
            by_category[param.category.upper()].append(param.request_id)
    labels = {
        "IDENTIFIERS": "Parámetros con nombre y forma de identificador enviados a terceros.",
        "DEVICE": "Parámetros con nombre de dato del dispositivo (pantalla, idioma, plataforma...) enviados a terceros.",
        "LOCATION": "Parámetros con nombre de dato de ubicación enviados a terceros.",
        "ADVERTISING": "Parámetros con nombre de identificador o campaña publicitaria enviados a terceros.",
        "SESSION": "Parámetros con nombre de sesión o token enviados a terceros.",
    }
    for category, refs in by_category.items():
        add(category, "inferido", labels[category], refs)
    add("ADVERTISING", "inferido", "Requests que coinciden con listas de publicidad.",
        [item["request_id"] for item in analyzed if item["category"] == "advertising"])
    return items
