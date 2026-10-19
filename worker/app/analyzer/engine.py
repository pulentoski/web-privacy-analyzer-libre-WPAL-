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
from app.analyzer import consent_mode, linker
from app.analyzer.config import AnalyzerConfig
from app.analyzer.fingerprinting import analyze_fingerprinting
from app.analyzer.lists import UNKNOWN_ENTITY
from app.analyzer.parameters import Param, extract, is_identifier_like, shannon_entropy, value_shapes
from app.browser.parties import registrable_domain

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
# Página de error de Chromium cuando un documento (típicamente un iframe) no carga (v1.4.5): lo que
# corre ahí es código del navegador, no del sitio.
ERROR_FRAME_PREFIX = "chrome-error://"
MAX_THIRD_PARTY_SERVICES = 80
# v1.4.8: propósitos (cookie_purposes.yaml §by_service_type) que no entran en «Servicios de terceros sin señales de rastreo».
SERVICE_PURPOSES_NOT_LISTED = ("publicidad", "analitica")
DATA_CATEGORIES = ("DEVICE", "IDENTIFIERS", "BEHAVIOR", "NETWORK", "LOCATION", "ADVERTISING", "SESSION")


def prepare_capture(capture: dict, *, start_url: str, page_url: str | None, result: dict | None = None) -> dict:
    """Adapta una captura en memoria (NetworkMonitor.finalize) al contrato de analyze()."""
    prepared = dict(capture)
    prepared["start_url"] = start_url
    prepared["tcf"] = (result or {}).get("tcf")
    prepared["consent"] = (result or {}).get("consent")
    # Señales de bloqueo antibot (point 3): título y estado HTTP de la navegación.
    prepared["title"] = (result or {}).get("title")
    prepared["page_meta"] = (result or {}).get("page_meta")
    prepared["http_status"] = (result or {}).get("http_status")
    prepared["page_url"] = page_url or start_url
    # Captura interactiva (v1.4.2): hora y tipo de cada clic, desplazamiento y tecla del usuario. None = no se registró.
    prepared["interactions"] = ((result or {}).get("interactive") or {}).get("interactions")
    # v1.4.10: páginas visitadas (URL de cada navegación, también las que no quedaron como request; linker _gl).
    prepared["timeline"] = ((result or {}).get("interactive") or {}).get("timeline")
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


# v1.4.8: después de la URL de la página solo puede venir el fin del valor o un separador. Si sigue un carácter de
# host o de ruta («.», «-», letras, «/otra-ruta»), es otra dirección que empieza igual: coincidencia parcial.
URL_BOUNDARY = frozenset("?#&=;,|\"' \t\r\n)]}>")


def _contains_page_url(value: str, needles: list[str]) -> bool:
    """El valor contiene la URL de la página completa (origen y ruta), no solo un trozo de ella."""
    for needle in needles:
        start = value.find(needle)
        while start != -1:
            rest = value[start + len(needle):]
            if not rest or rest[0] in URL_BOUNDARY or (rest[0] == "/" and (len(rest) == 1 or rest[1] in URL_BOUNDARY)):
                return True
            start = value.find(needle, start + 1)
    return False


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
    # Frames de error del navegador (v1.4.5): sus llamadas y scripts se descartan; solo se cuenta que no cargó.
    error_frames = _error_frames(capture, requests)
    if error_frames["ignored_calls"]:
        capture = {**capture, "fingerprinting": {**capture["fingerprinting"], "calls": [
            call for call in capture["fingerprinting"]["calls"] if not _in_error_frame(call)]}}
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

    # v1.4.2/v1.4.8: hosts de nube genéricos inferidos como servidor de Conversions API de Meta. Se detectan aquí
    # porque no son una organización distinta de Meta: cuentan como su dominio en la sincronización y el índice.
    server_side = config.server_side.detect(requests, params_by_request, party_by_id)
    meta_domain = config.server_side.meta_owner_domain
    capi_domains = {item["domain"] for item in server_side if item["domain"]} if meta_domain else set()

    def index_domain(domain: str | None) -> str | None:
        """Dominio con el que cuenta en el índice: el de Meta para un servidor CAPI inferido."""
        return meta_domain if domain in capi_domains else domain

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
        domain = index_domain(domain)
        entity = lists.entity(domain)
        return domain if entity == UNKNOWN_ENTITY else f"entidad:{entity}"

    # Dominios distintos de UNA misma organización (google.com / doubleclick.net) no son
    # sincronización entre partes: se exige que el valor llegue a dos dueños distintos. v1.4.6: dueños
    # distintos DEL SITIO; el sitio no cuenta como segunda organización. Si el valor llegó al sitio y a
    # una sola organización externa, es un identificador persistente enviado a esa organización.
    site_owners = {owner(domain) for domain in first_party_domains} | {f"entidad:{org}" for org in site_orgs}

    def external_owners(domains) -> set[str]:
        return {owner(domain) for domain in domains} - site_owners

    candidates, single_candidates = {}, {}
    for value, domains in shared.items():
        external = external_owners(domains)
        if len(external) >= 2:
            candidates[value] = domains
        elif len(external) == 1 and len({owner(domain) for domain in domains}) >= 2:
            single_candidates[value] = domains
    # Versiones de software, trozos del User-Agent y constantes del sitio llegan iguales a todo
    # el mundo: que dos organizaciones los reciban no les permite reconocer a nadie. Se
    # descartan, y queda constancia de cuántos y por qué (data/shared_constants.yaml).
    environment = config.shared_constants.environment(capture)
    synced, single_org, excluded = {}, {}, []
    for target, values in ((synced, candidates), (single_org, single_candidates)):
        for value, domains in values.items():
            why = config.shared_constants.classify(value, shared_names[value], environment)
            if why is None:
                target[value] = domains
            elif target is synced:
                excluded.append({"reason": why, "preview": _preview(value), "domains": len(domains)})
    # v1.4.9: sincronización por redirección. Un salto 3xx que lleva el mismo identificador de una organización
    # externa a otra distinta es EVIDENCIA de sincronización (la cadena se observó), no un indicio por el nombre.
    by_seq = {request.get("seq"): request for request in requests}
    values_by_request: dict[int, set[str]] = defaultdict(set)
    for param in value_params:
        if param.identifier_like and len(param.value) >= MIN_SHARED_VALUE_CHARS and param.value not in account_values:
            values_by_request[param.request_id].add(param.value)
    redirect_syncs = []
    for request in requests:
        previous = by_seq.get(request.get("redirected_from_seq")) if request.get("redirected_from_seq") is not None else None
        source_domain, target_domain = (previous or {}).get("registrable_domain"), request.get("registrable_domain")
        if previous is None or not source_domain or not target_domain:
            continue
        source_owner, target_owner = owner(source_domain), owner(target_domain)
        if source_owner == target_owner or source_owner in site_owners or target_owner in site_owners:
            continue  # salto dentro de la misma organización, o desde/hacia el sitio
        for value in sorted(values_by_request[previous["request_id"]] & values_by_request[request["request_id"]]):
            if config.shared_constants.classify(value, shared_names[value], environment) is not None:
                continue
            redirect_syncs.append({"value": value, "from": previous["request_id"], "to": request["request_id"],
                                   "from_domain": source_domain, "to_domain": target_domain, "status": previous.get("response_status")})
            # Cuenta como sincronización (un valor una sola vez, aunque ya la hubiera detectado la regla general).
            entry = synced.setdefault(value, defaultdict(set))
            entry[source_domain].add(previous["request_id"])
            entry[target_domain].add(request["request_id"])
    sync_by_request: dict[int, str] = {}
    for value, domains in synced.items():
        for request_ids in domains.values():
            for request_id in request_ids:
                sync_by_request.setdefault(request_id, value)

    # 2b. valor igual al de una cookie o un ítem de storage del snapshot
    stored: dict[str, str] = {}
    # v1.4.10: valor → (tipo, nombre) del dato guardado: cookie | local | session. Sirve para saber si el script que inició
    # la request leyó ESE dato (y solo entonces decir que lo copió).
    stored_item: dict[str, tuple[str, str]] = {}
    for cookie in capture.get("cookies") or []:
        stored.setdefault(cookie.get("value") or "", f"la cookie «{cookie.get('name')}»")
        stored_item.setdefault(cookie.get("value") or "", ("cookie", str(cookie.get("name") or "")[:120]))
    for item in capture.get("storage") or []:
        kind = "localStorage" if item.get("storage_type") == "local" else "sessionStorage"
        stored.setdefault(item.get("value") or "", f"el ítem «{item.get('key')}» de {kind}")
        stored_item.setdefault(item.get("value") or "", ("local" if item.get("storage_type") == "local" else "session",
                                                         str(item.get("key") or "")[:120]))
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
    # v1.4.10: «un script copió el valor de la cookie X» solo si se registró que el MISMO script que inició la request leyó
    # esa cookie o ese ítem de storage (`storage_reads`: [{script_url, kind: cookie|local|session, name}]). La captura actual
    # no registra esas lecturas: sin ellas el texto dice que el valor enviado coincide con la cookie, nunca que se copió.
    storage_reads = {
        (str(read["script_url"]), str(read.get("kind") or "cookie"), str(read["name"])[:120])
        for read in capture.get("storage_reads") or []
        if isinstance(read, dict) and isinstance(read.get("script_url"), str) and read.get("name") is not None
    }

    def copying_script(request_ids, value: str) -> str | None:
        """Script que inició TODAS esas requests y leyó el dato guardado con ese valor; None si no se registró."""
        item = stored_item.get(value)
        scripts = {by_id[request_id].get("initiator_script") or (by_id[request_id].get("initiator") or {}).get("script_url")
                   for request_id in request_ids}
        if not item or len(scripts) != 1 or None in scripts:
            return None
        script = next(iter(scripts))
        return script if (script, *item) in storage_reads else None

    def stored_details(request_ids, value: str) -> dict:
        """Datos del valor guardado para las frases: la cookie que coincide y, si se registró la lectura, quién la copió."""
        item, script = stored_item.get(value), copying_script(request_ids, value)
        return {**({"matched_cookie": item[1]} if item and item[0] == "cookie" else {}),
                **({"copied_by_script": script[:300]} if script else {})}

    def copy_sentence(request_ids, value: str) -> str:
        script = copying_script(request_ids, value)
        label = stored[value]
        of_label = "del " + label[3:] if label.startswith("el ") else "de " + label
        return (f" El script que inició la request ({script[:200]}) leyó {label}: un script copió el valor {of_label} en la URL "
                "o el cuerpo de la request.") if script else ""
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
        if _contains_page_url(param.value, needles):
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

    # --- 2d. v1.4.9: Client Hints (solicitud, envío y delegación; data/client_hints.yaml) ---
    def ch_organization(request: dict) -> str:
        domain = index_domain(request.get("registrable_domain"))
        entity = lists.entity(domain)
        return (domain or request.get("host") or UNKNOWN_ENTITY) if entity == UNKNOWN_ENTITY else entity

    navigations = [r for r in requests if r.get("is_navigation") and party_by_id.get(r["request_id"]) == "first_party"]
    main_document = next((r for r in navigations if (r.get("url") or "").rstrip("/") == (page_url or "").rstrip("/")), None) \
        or next((r for r in navigations if isinstance(r.get("response_status"), int) and r["response_status"] < 300), None)
    client_hints = config.client_hints.analyze(requests, party_by_id, ch_organization, main_document, capture.get("page_meta"))
    # Una sola vez por organización la solicitud (primera respuesta con Accept-CH); el envío, en cada request que lo llevó.
    ch_request_by_id = {item["first_request_id"]: item for item in client_hints["requests"]}
    ch_sent_by_id = {item["request_id"]: item for item in client_hints["sends"]}

    # --- 2f. v1.4.10: linker de Google (_gl) en URLs de navegación y redirección (app/analyzer/linker.py) ---
    # Transferencias de identificadores ya informadas por otra regla (valor → tipo de hallazgo), por request: un _gl que
    # ya cuenta como sincronización o identificador persistente no se informa ni se puntúa otra vez.
    transfers: dict[int, dict[str, str]] = defaultdict(dict)
    for item in redirect_syncs:
        for request_id in (item["from"], item["to"]):
            transfers[request_id].setdefault(item["value"], "redirect_sync")
    for value, domains in synced.items():
        for request_ids in domains.values():
            for request_id in request_ids:
                transfers[request_id].setdefault(value, "id_sync")
    for request_id, param in persistent_by_request.items():
        transfers[request_id].setdefault(param.value, "persistent_id" if param.value in synced else "persistent_id_org")
    linker_items = _linker_items(capture, requests, by_id, party_by_id, first_party_domains, site_orgs, lists, transfers,
                                 page_url)
    linker_by_request = {item["request_id"]: item for item in linker_items if item["counts_in_index"]}

    # --- 3. clasificación y score por request ---
    analyzed = []
    list_hits: dict[tuple[str, str], list] = defaultdict(list)
    library_by_id: dict[int, dict] = {}

    def cdn_recipient(library: dict, domain: str | None) -> str:
        """Receptor de una request a un CDN público: el CDN y su dueño (p. ej. «CDN público cdnjs (Cloudflare)»)."""
        entity = lists.entity(domain)
        return f"CDN público {library['cdn']}" + (f" ({entity})" if entity != UNKNOWN_ENTITY else "")

    def group_recipient(refs, domain: str) -> str:
        """Receptor de un grupo de requests a un dominio: el CDN si todas fueron al mismo CDN público; si no, la
        organización dueña del dominio (o el dominio). Nunca una librería: la librería no recibe la request."""
        cdns = {(library_by_id.get(rid) or {}).get("cdn") for rid in refs}
        if len(cdns) == 1 and None not in cdns:
            return cdn_recipient(library_by_id[refs[0]], domain)
        entity = lists.entity(domain)
        return domain if entity == UNKNOWN_ENTITY else entity
    for request in requests:
        request_id = request["request_id"]
        third_party = bool(request.get("third_party"))
        party = party_by_id[request_id]
        external = party == "third_party"  # tercero de OTRA organización
        domain = request.get("registrable_domain")
        own_params = [p for p in params_by_request.get(request_id, []) if p.source not in VALUE_SOURCES_EXCLUDED]
        mechanism = _mechanism(request)
        reasons = []
        # v1.4.6: un recurso de un CDN público se atribuye a la librería que sirve, no a la empresa del CDN.
        # v1.4.7: pero quien RECIBE la request (y sus fugas) es el CDN, no la librería.
        library = config.public_cdns.of(request.get("url"), request.get("host")) if third_party else None
        if library:
            library_by_id[request_id] = library
        recipient = cdn_recipient(library, domain) if library else None

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
            reason("persistent_id", f"El parámetro «{param.name}»: el valor enviado coincide con {stored[param.value]} del navegador."
                   + copy_sentence([request_id], param.value),
                   parameter=param.name, stored_in=stored[param.value], **stored_details([request_id], param.value))
        if request_id in leak_by_request:
            reason("url_leak", f"El parámetro «{leak_by_request[request_id].name}» contiene la URL de la página.",
                   parameter=leak_by_request[request_id].name, **({"recipient": recipient} if recipient else {}))
        if external and referer_by_request.get(request_id) == "full_url":
            reason("referer_full_url", "La cabecera Referer llevó a un tercero la URL completa de la página (ruta y parámetros).",
                   **({"recipient": recipient} if recipient else {}))
        if request_id in fingerprint["exfiltration_by_request"]:
            hit = fingerprint["exfiltration_by_request"][request_id][0]
            reason("fp_exfiltration", f"El parámetro «{hit['parameter']}» contiene un valor leído con {hit['api']} ({hit['form']}).",
                   parameter=hit["parameter"], api=hit["api"], form=hit["form"])
        if request_id in ch_request_by_id:
            asked = ch_request_by_id[request_id]["hints"]
            reason("client_hints_request", f"La respuesta pidió por Accept-CH datos de alta entropía del navegador ({', '.join(asked)}). "
                   + config.client_hints.texts.get("request", ""), hints=asked)
        if request_id in ch_sent_by_id:
            sent = ch_sent_by_id[request_id]["hints"]
            reason("client_hints_sent", f"La request llevó las cabeceras {', '.join(sent)} (Client Hints de alta entropía).", hints=sent)
        if request_id in linker_by_request:
            item = linker_by_request[request_id]["classification"]
            reason("linker_transfer", f"La URL de la request llevó el parámetro _gl (linker de Google) a {item['organization']}, "
                   f"tercero según {item['basis_label']}. Lo observado es la transferencia del parámetro, no que el destino "
                   "reconociera al visitante.", organization=item["organization"], basis=item["basis"])
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
        # v1.5.1: el subdominio publicitario de una organización (px.ads.linkedin.com) gana sobre la categoría de su
        # dominio («social») y sobre la de la lista. Nunca en requests del propio sitio.
        host_category = config.host_category(request.get("host"), domain) if party != "first_party" else None
        if host_category:
            category = host_category
        elif domain in config.domain_categories:
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
                "entity": library["label"] if library else (config.server_side.meta_organization_label or lists.entity(domain))
                if domain in capi_domains else lists.entity(domain),
                "library": library,
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
            f"distintos, de {len(external_owners(domains))} organizaciones distintas del sitio: {', '.join(sorted(domains)[:10])}.",
            refs,
            {"domains": sorted(domains), "owners": len(external_owners(domains)), "value_length": len(value), "value_shapes": list(value_shapes(value))},
        )

    def organization_name(domain: str) -> str:
        entity = lists.entity(domain)
        return domain if entity == UNKNOWN_ENTITY else entity

    for item in redirect_syncs:
        source, target = by_id[item["from"]], by_id[item["to"]]
        finding(
            "redirect_sync",
            "EVIDENCIA",
            f"La respuesta {item['status'] or 'de redirección'} de {item['from_domain']} (request #{source['seq'] + 1}) redirigió a "
            f"{item['to_domain']} (request #{target['seq'] + 1}) con el mismo identificador ({_preview(item['value'])}) en la dirección: "
            f"sincronización de identificadores entre {organization_name(item['from_domain'])} y {organization_name(item['to_domain'])}.",
            [item["from"], item["to"]],
            {"domains": [item["from_domain"], item["to_domain"]], "from_domain": item["from_domain"], "to_domain": item["to_domain"],
             "status": item["status"], "value_length": len(item["value"])},
        )

    def external_domain(domains) -> str:
        return next(domain for domain in sorted(domains) if owner(domain) not in site_owners)
    persistent_groups: dict[tuple[str, str], list[int]] = defaultdict(list)
    for request_id, param in persistent_by_request.items():
        persistent_groups[(param.value, by_id[request_id].get("registrable_domain") or "")].append(request_id)
    for (value, domain), refs in persistent_groups.items():
        if value in synced:
            finding(
                "persistent_id",
                "EVIDENCIA",
                f"El valor enviado a {domain} ({_preview(value)}) coincide con {stored[value]} del navegador." + copy_sentence(refs, value),
                refs,
                {"domain": domain, "stored_in": stored[value], **stored_details(refs, value)},
            )
            continue
        # v1.4.6: el valor no llegó a una segunda organización: no es sincronización (grupo 1, no grupo 5).
        finding(
            "persistent_id_org",
            "EVIDENCIA",
            f"Identificador persistente enviado a {organization_name(domain)}: el valor enviado a {domain} ({_preview(value)}) "
            f"coincide con {stored[value]} del navegador y no llegó a otra organización." + copy_sentence(refs, value),
            refs,
            {"domain": domain, "organization": organization_name(domain), "stored_in": stored[value], **stored_details(refs, value)},
        )
    persistent_pairs = set(persistent_groups)
    for value, domains in single_org.items():
        domain = external_domain(domains)
        if (value, domain) in persistent_pairs:
            continue  # ya informado arriba, con el dato guardado que coincide
        finding(
            "persistent_id_org",
            "EVIDENCIA",
            f"Identificador persistente enviado a {organization_name(domain)}: el mismo valor ({_preview(value)}) se envió al propio "
            f"sitio y a {domain}; no llegó a otra organización.",
            [request_id for request_ids in domains.values() for request_id in request_ids],
            {"domain": domain, "organization": organization_name(domain), "domains": sorted(domains), "value_length": len(value)},
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
            {"domain": domain, "parameter": name, "recipient": group_recipient(refs, domain)},
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
            {"domain": domain, "exposure": "full_url", "recipient": group_recipient(refs, domain)},
        )
    for (list_id, domain), hits in list_hits.items():
        finding(
            "list_match",
            "EVIDENCIA",
            f"{len(hits)} request(s) a {domain} coinciden con reglas de la lista {list_id} (p. ej. «{hits[0][1]}»).",
            [request_id for request_id, _ in hits],
            {"list": list_id, "domain": domain},
        )
    # v1.4.9: Client Hints. La solicitud nunca se presenta como recepción; el envío exige la cabecera en la request.
    for item in client_hints["requests"]:
        finding(
            "client_hints_requested",
            "EVIDENCIA",
            f"{item['organization']} pidió por Accept-CH {', '.join(item['hints'])}. {client_hints['request_text']}",
            item["request_ids"],
            {"organization": item["organization"], "hints": item["hints"], "hosts": item["hosts"], "sent": item["sent"]},
        )
    sends_by_org: dict[str, list[dict]] = defaultdict(list)
    for item in client_hints["sends"]:
        sends_by_org[item["organization"]].append(item)
    for organization, items in sorted(sends_by_org.items()):
        hints = sorted({hint for item in items for hint in item["hints"]})
        finding(
            "client_hints_sent",
            "EVIDENCIA",
            f"El navegador envió a {organization} las cabeceras {', '.join(hints)} en {len(items)} request(s).",
            [item["request_id"] for item in items],
            {"organization": organization, "hints": hints, "hosts": sorted({item["host"] or "" for item in items})[:10],
             "after_request": any(item["after_request"] for item in items)},
        )
    # v1.4.10: linker de Google (_gl). Tercero → gl_linker (grupo 1); propio, misma organización u «Organización no
    # disponible» → gl_linker_info (lista técnica, no suma). Si otra regla ya informó esa transferencia, no se duplica.
    for item in linker_items:
        if item["duplicate_of"] is None:
            finding("gl_linker" if item["classification"]["status"] == "third_party" else "gl_linker_info", "EVIDENCIA",
                    _linker_claim(item), item["evidence_refs"],
                    {"domain": item["destination"]["domain"], "destination_host": item["destination"]["host"],
                     "origin_host": item["origin"]["host"], "source": item["source"], "status": item["classification"]["status"],
                     "status_label": item["classification"]["label"], "organization": item["classification"]["organization"],
                     "basis": item["classification"]["basis"], "basis_label": item["classification"]["basis_label"],
                     "format": item["gl"]["format"], "fields": item["gl"]["fields"], "counts_in_index": item["counts_in_index"]})
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
    # v1.4.8: un valor igual al título o a la meta description/keywords de la página es texto de la página, no una búsqueda.
    page_meta = capture.get("page_meta") if isinstance(capture.get("page_meta"), dict) else {}
    page_texts = [capture.get("title"), page_meta.get("description"), page_meta.get("keywords")]
    search_leaks, search_page_text = config.har_signals.search_leaks(params_by_request, by_id, source_host, party_by_id,
                                                                     page_texts=page_texts)
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
    _persistent_cookie_findings(capture, requests, params, lists, finding, config.cookie_purposes, config.service_types)
    cookie_purposes = _cookie_purpose_findings(capture, requests, params, config.cookie_purposes, finding,
                                               lists=lists, service_types=config.service_types)
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

    # --- 4a. v1.4.2: rastreo del lado del servidor (detectado en el paso 1) y registro de interacción (docs/adr/030) ---
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

    def service_of(request: dict) -> dict | None:
        """Giro del servicio al que va ESTA request: su URL concreta, luego la organización y el dominio."""
        domain = request.get("registrable_domain")
        return config.service_types.of(entity=lists.entity(domain), domain=domain, host=request.get("host"), urls=[request.get("url")])

    interaction = config.interaction.correlate(
        capture.get("interactions"), requests, party_by_id, organization_of,
        lambda request: (service_of(request) or {}).get("type"))
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

    # Varias cuentas de analítica (v1.4.5): los IDs observados son EVIDENCIA; que sean cuentas distintas se
    # deduce de su forma documentada.
    analytics_accounts = config.account_ids.accounts(account_ids)
    for item in analytics_accounts:
        count = len(item["accounts"])
        if count >= 2:
            finding(
                "analytics_accounts",
                "EVIDENCIA",
                f"Los datos de la visita se enviaron a {count} cuentas de {item['vendor']}: en las requests se observaron {count} IDs de "
                f"cuenta distintos ({', '.join(item['accounts'][:12])}).",
                item["evidence_refs"],
                {"vendor": item["vendor"], "accounts": item["accounts"][:30], "count": count},
            )
        if item["discontinued"]:
            finding(
                "discontinued_tag",
                "EVIDENCIA",
                f"Etiqueta de un servicio descontinuado: se {'observó el ID' if len(item['discontinued']) == 1 else 'observaron los IDs'} "
                f"{', '.join(item['discontinued'][:12])} de {item['discontinued_label'] or item['vendor']}. Nota informativa: el servicio "
                "ya no procesa datos, pero la etiqueta sigue cargándose.",
                item["discontinued_refs"],
                {"vendor": item["vendor"], "service": item["discontinued_label"] or item["vendor"], "accounts": item["discontinued"][:30],
                 "count": len(item["discontinued"]), "informative": True},
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
        # v1.4.8: un servidor CAPI inferido cuenta como el dominio de Meta, no como un tercero más.
        "tracker_domains": len({index_domain(t["registrable_domain"]) for t in trackers if t["party"] == "third_party" and t["registrable_domain"]}),
        "id_sync": len(synced),
        "url_leak_recipients": len({index_domain(domain) for domain, _ in leak_groups} | {index_domain(d) for d in referer_groups}),
        # v1.4.6: las cookies funcionales (por su nombre, data/cookie_purposes.yaml) no suman al índice.
        "stored_items": len(capture.get("cookies") or []) - cookie_purposes["by_purpose"].get("funcional", 0)
                        + len(capture.get("storage") or []),
        "fp_scripts": len(fp_scripts),
        "fp_exfiltration": len({f["details"]["api"] for f in fingerprint["findings"] if f["heuristic"] == "exfiltration"}),
        "persistent_id_recipients": len({index_domain(domain) for _, domain in persistent_groups}),
        "third_party_domains": len({index_domain(domain) for domain in third_party_domains}),
        # Telemetría propia (v1.3.4): endpoints de eventos distintos + scripts de analítica propia.
        "first_party_telemetry": telemetry["endpoints"] + telemetry["scripts"],
    }
    # v1.4.9: cuántos de esos ítems se sostienen solo con EVIDENCIA. Un dominio rastreador cuenta como evidencia si
    # alguna de sus requests llega a la banda de rastreador con las razones de nivel EVIDENCIA, sin las inferencias.
    tracker_floor = next((band["max"] + 1 for band, following in zip(config.bands, config.bands[1:])
                          if following["name"] == config.scoring["tracker_min_band"]), 0)

    def evidence_score(item: dict) -> int:
        return max(0, min(100, sum(reason["weight"] for reason in item["reasons"] if reason["level"] == "EVIDENCIA")))

    evidence_counts = {
        "tracker_domains": len({index_domain(t["registrable_domain"]) for t in trackers if t["party"] == "third_party"
                                and t["registrable_domain"] and evidence_score(t) >= tracker_floor}),
        "fp_scripts": 0,  # patrón compatible con fingerprinting: siempre inferencia
        "first_party_telemetry": telemetry["scripts"],  # scripts conocidos = evidencia; endpoints por reglas = inferencia
    }
    # Asintótica: cada componente tiende a su tope sin alcanzarlo, y la suma nunca llega a 100.
    breakdown = []
    for component, spec in config.scoring["site_exposure"].items():
        count = counts.get(component, 0)
        points = round(spec["cap"] * (1 - math.exp(-count / spec["k"])), 2)
        evidence = min(count, evidence_counts.get(component, count))
        evidence_points = round(spec["cap"] * (1 - math.exp(-evidence / spec["k"])), 2)
        breakdown.append(
            {"component": component, "count": count, "cap": spec["cap"], "k": spec["k"], "points": points,
             # Parte de los puntos que se sostiene solo con evidencia; el resto depende de inferencias.
             "evidence_count": evidence, "evidence_points": evidence_points,
             "inference_points": round(max(0.0, points - evidence_points), 2)}
        )
    site_score = max(0, min(99, math.floor(sum(item["points"] for item in breakdown))))
    score_by_level = {"EVIDENCIA": round(sum(item["evidence_points"] for item in breakdown), 1),
                      "INFERENCIA": round(sum(item["inference_points"] for item in breakdown), 1)}

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
    # Servicios de terceros SIN señales de rastreo (v1.4.5): requests a otra organización por debajo de la banda
    # de rastreador, por organización y giro. Se informa siempre: que no haya rastreadores no es «sin terceros».
    services: dict[tuple[str, str], dict] = {}
    # v1.4.8: una organización de publicidad o analítica no es un «servicio sin señales de rastreo» aunque esa
    # request no llegue a la banda de rastreador; se cuenta aparte (tipos de cookie_purposes.yaml §by_service_type).
    excluded_services: dict[str, int] = Counter()
    tracker_domains_unknown = set((entities.get(UNKNOWN_ENTITY) or {}).get("domains") or ())
    for item in analyzed:
        if item["party"] != "third_party" or item["band"] in tracker_bands:
            continue
        request = by_id[item["request_id"]]
        domain = item["registrable_domain"] or request.get("host") or ""
        service = service_of(request)
        if service is None and item["registrable_domain"] in capi_domains:
            # Servidor CAPI inferido: es Meta (publicidad), no un servicio sin señales de rastreo.
            service = {"type": "server_side_meta", "label": config.server_side.meta_label}
        purpose = config.cookie_purposes.of_service(service["type"] if service else None)
        if purpose in SERVICE_PURPOSES_NOT_LISTED:
            excluded_services[purpose] += 1
            continue
        known = item["entity"] != UNKNOWN_ENTITY
        key = (item["entity"] if known else f"dominio:{domain}", service["type"] if service else "")
        library = item.get("library")
        entry = services.setdefault(key, {
            "organization": item["entity"], "service_type": service["type"] if service else None,
            "service_label": service["label"] if service else None, "domains": set(), "hosts": set(), "requests": 0,
            "evidence_refs": [],
            # v1.4.6: librería de un CDN público (la organización mostrada es la librería, no la empresa del CDN).
            "library": {key: library[key] for key in ("library", "cdn", "benign", "benign_label")} if library else None})
        entry["domains"].add(domain)
        entry["hosts"].add(request.get("host") or domain)
        entry["requests"] += 1
        if len(entry["evidence_refs"]) < 5:
            entry["evidence_refs"].append(item["request_id"])
    third_party_services = sorted(
        ({**entry, "domains": sorted(d for d in entry["domains"] if d)[:10], "hosts": sorted(h for h in entry["hosts"] if h)[:10],
          # La misma organización también figura en Rastreadores por otras requests. Sin dueño conocido solo
          # se afirma del mismo dominio: dos dominios «no disponibles» no son la misma organización.
          "in_trackers": (entry["organization"] in entities) if entry["organization"] != UNKNOWN_ENTITY
          else bool(entry["domains"] & tracker_domains_unknown)} for entry in services.values()),
        key=lambda entry: (-entry["requests"], entry["organization"], entry["service_label"] or ""))
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
                # v1.4.8: valores descartados por coincidir con el título o la meta description/keywords de la página.
                "search_leaks_page_text": search_page_text,
                # v1.4.9: Client Hints (solicitud ≠ envío; delegación como contexto) y puntos del índice por nivel.
                "client_hints": client_hints,
                # v1.4.10: _gl en URLs de navegación y redirección (presencia, campos decodificados y clasificación del destino).
                "linker": {"items": linker_items, "total": len(linker_items)},
                "score_by_level": score_by_level,
                "redirect_syncs": len(redirect_syncs),
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
                # v1.4.5: cuentas de medición por proveedor; servicios de terceros sin señales de rastreo
                # (nivel: la request es EVIDENCIA, el giro es contexto/INFERENCIA) y frames que no cargaron.
                "analytics_accounts": [{key: item[key] for key in ("vendor", "accounts", "discontinued", "discontinued_label")}
                                       for item in analytics_accounts],
                "third_party_services": {
                    "level": "EVIDENCIA", "service_level": "INFERENCIA",
                    # Las librerías de un mismo CDN público cuentan como una organización: la del CDN.
                    "organizations": len({f"cdn:{entry['library']['cdn']}" if entry.get("library") else entry["organization"]
                                          if entry["organization"] != UNKNOWN_ENTITY else entry["domains"][0]
                                          for entry in third_party_services if entry["domains"]}),
                    "requests": sum(entry["requests"] for entry in third_party_services),
                    "items": third_party_services[:MAX_THIRD_PARTY_SERVICES],
                    "truncated": len(third_party_services) > MAX_THIRD_PARTY_SERVICES,
                    # v1.4.8: requests a organizaciones de publicidad o analítica bajo la banda de rastreador, fuera de la lista.
                    "excluded_requests": dict(excluded_services),
                },
                "error_frames": error_frames,
                # v1.4.6: propósito de las cookies por su nombre (INFERENCIA), propias y de terceros.
                "cookie_purposes": cookie_purposes,
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


def _in_error_frame(item: dict) -> bool:
    return any(str(item.get(key) or "").startswith(ERROR_FRAME_PREFIX) for key in ("frame_url", "script_url", "initiator_script"))


def _error_frames(capture: dict, requests: list) -> dict:
    """Recuadros que no cargaron (v1.4.5). Chromium muestra en su lugar chrome-error://chromewebdata/, cuyo
    código es del navegador: sus llamadas a APIs se descartan y sus requests no se atribuyen al sitio."""
    fingerprinting = capture.get("fingerprinting") or {}
    calls = [call for call in (fingerprinting.get("calls") or []) if _in_error_frame(call)]
    attributed = [request["request_id"] for request in requests if _in_error_frame(request)]
    # Capturas nuevas: el monitor ya descartó esos lotes y solo dejó la cuenta.
    dropped = fingerprinting.get("error_frame_messages")
    dropped = dropped if isinstance(dropped, int) and not isinstance(dropped, bool) and dropped > 0 else 0
    return {
        "observed": bool(calls or attributed or dropped),
        "ignored_messages": dropped,
        "ignored_calls": len(calls),
        "ignored_scripts": len({call.get("script_url") or call.get("frame_url") for call in calls}),
        "requests": len(attributed),
    }


# v1.4.8 (docs/adr/035): sin señal dura, pocas requests o rastreo anómalo solo dejan esta nota (nivel POSIBLE).
POSSIBLE_VARIANT_TEXT = ("La página podría haber mostrado una versión distinta al navegador automatizado; "
                         "compare con un HAR propio.")


def _blocking(capture: dict, requests: list, config: dict, *, trackers: int | None = None,
              telemetry: dict | None = None, telemetry_min: int = 3) -> dict:
    """Señales de que el sitio detectó el navegador automatizado (point 3).

    v1.4.8: solo una señal dura (estado 403/429/503, título de desafío o firma antibot en la URL) marca la
    visita (`blocked`) y la saca del ranking. Pocas requests o rastreo anómalo, sin señal dura, quedan como
    `possible_variant` (POSIBLE), que no marca ni excluye. Nada de esto aplica a un HAR importado, a una
    captura interactiva ni a una navegación fallida (timeout o error de red: no hubo medición).
    """
    min_requests = config.get("min_requests", 20)
    http_status = capture.get("http_status")
    base = {"requests": len(requests), "http_status": http_status, "min_requests": min_requests}
    source = capture.get("source") or "scan"
    if source in ("har_import", "interactive") or capture.get("navigation_failed"):
        # HAR: navegador real del usuario. Interactiva: navegación humana. Fallida: no hay página que juzgar.
        reason = "navigation_failed" if capture.get("navigation_failed") else source
        return {"blocked": False, "partial": False, "signals": [], "note": None, "possible_variant": None,
                "not_applicable": reason, **base}
    bad_statuses = set(config.get("bad_statuses") or [])
    keywords = [_strip_accents(str(k).lower()) for k in config.get("title_keywords") or []]
    title = _strip_accents(str(capture.get("title") or "").lower())
    # Scan parcial (goto agotó el tiempo): pocas requests o poco rastreo se explican por el corte, no por el sitio.
    timed_out = capture.get("partial_navigation") is not None
    hard, soft = [], []
    if len(requests) < min_requests and not timed_out:
        soft.append({"signal": "few_requests",
                     "detail": f"Se capturaron {len(requests)} request(s), menos del umbral de {min_requests}."})
    matched = next((k for k in keywords if k and k in title), None)
    if matched:
        hard.append({"signal": "challenge_text", "detail": f"El título de la página contiene «{matched}»."})
    statuses = {http_status} | {r.get("response_status") for r in requests if r.get("is_navigation")}
    bad_seen = sorted(s for s in statuses if isinstance(s, int) and s in bad_statuses)
    if bad_seen:
        hard.append({"signal": "http_status", "detail": f"La navegación respondió con estado {', '.join(map(str, bad_seen))}."})
    anomaly = None if timed_out else _tracker_anomaly(len(requests), trackers, capture.get("history"), config.get("tracker_anomaly") or {})
    signature = _challenge_signature(requests, config)
    note = None
    own = (telemetry or {}).get("requests") or 0
    # v1.3.4: poco rastreo de terceros no basta si el sitio mide con infraestructura propia. Con título
    # normal, sin firma antibot y sin otra señal, queda una nota informativa en vez de la nota de versión distinta.
    if anomaly and not hard and not soft and not signature and title.strip() and own >= telemetry_min:
        note = {"signal": "low_third_party_tracking",
                "detail": f"Rastreo de terceros bajo; telemetría propia detectada ({own} requests de eventos al propio sitio o a su "
                          f"misma organización, y {trackers} de rastreo de terceros en {len(requests)} requests)."}
    elif anomaly:
        soft.append(anomaly)
    partial = None
    if signature:
        detail = (f"Se cargó un documento o frame cuya dirección contiene «{signature[0]}», "
                  f"firma habitual de una pantalla de verificación antibot ({signature[1]}).")
        # v1.3.2: la firma sola no basta. Si la página principal cargó y el rastreo es normal, el
        # desafío afectó a un componente (p. ej. un bloque de recomendaciones): aviso informativo.
        if not hard and not soft and _normal_tracking(len(requests), trackers, config.get("challenge_partial") or {}) \
                and not _is_challenge_page(capture, signature[0], config):
            partial = {"signal": "challenge_component",
                       "detail": f"{detail} El resto de la página cargó: {trackers} de {len(requests)} requests fueron de rastreo."}
        else:
            hard.append({"signal": "challenge_url", "detail": detail})
    possible_variant = None
    if soft and not hard:
        navigations = [r["request_id"] for r in requests if r.get("is_navigation") and r.get("request_id") is not None]
        possible_variant = {"level": "POSIBLE", "text": POSSIBLE_VARIANT_TEXT, "signals": soft, "evidence_refs": navigations[:5]}
    return {"blocked": bool(hard), "partial": partial is not None,
            # Con señal dura, las blandas acompañan como detalle.
            "signals": hard + soft if hard else ([partial] if partial else []),
            # Nota informativa (no marca ni excluye del ranking); None si no aplica o si la visita quedó marcada.
            "note": note if not hard else None,
            "possible_variant": possible_variant,
            **base}


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


def _cookie_domain(cookie: dict, registrable: list[str]) -> str:
    """Dominio registrable de la cookie: el de alguna request de la captura que lo contenga."""
    host = str(cookie.get("domain") or "").lstrip(".").lower()
    return next((known for known in registrable if host == known or host.endswith("." + known)), host)


MAX_COOKIE_ROWS = 200


def _cookie_purpose_findings(capture, requests, params, purposes, finding, *, lists=None, service_types=None) -> dict:
    """Propósito de cada cookie (v1.4.6). INFERENCIA: ni el nombre ni la organización prueban el uso.

    v1.4.7, dos pasos: (a) el nombre conocido; (b) si no, el tipo de servicio de la organización dueña del
    dominio de la cookie. Cada cookie lleva su base: «nombre» u «organizacion».

    Evidencia: las requests que fijaron o enviaron cookies con ese nombre; si ninguna viajó, la primera
    request de la visita (la cookie está en el snapshot del navegador al terminar).
    """
    cookies = [cookie for cookie in capture.get("cookies") or [] if isinstance(cookie, dict)]
    registrable = sorted({request["registrable_domain"] for request in requests if request.get("registrable_domain")}, key=len, reverse=True)
    by_name: dict[str, list[int]] = defaultdict(list)
    for param in params:
        if param.source in ("cookie", "set_cookie"):
            by_name[param.name].append(param.request_id)
    rows, groups = [], {}
    for cookie in cookies:
        name = str(cookie.get("name") or "")[:120]
        domain = _cookie_domain(cookie, registrable)[:120]
        purpose, basis, organization, service = purposes.of(name, domain), "nombre", None, None
        if purpose == purposes.UNCLASSIFIED and lists is not None and service_types is not None:
            entity = lists.entity(domain)
            found = service_types.of(entity=entity, domain=domain)
            by_service = purposes.of_service((found or {}).get("type"))
            if by_service:
                purpose, basis, service = by_service, "organizacion", found
                organization = domain if entity == UNKNOWN_ENTITY else entity
        if purpose == purposes.UNCLASSIFIED:
            basis = None
        rows.append({"name": name, "domain": domain, "purpose": purpose, "basis": basis,
                     "third_party": bool(cookie.get("third_party"))})
        group = groups.setdefault((purpose, basis), {"names": set(), "own": 0, "third": 0, "refs": [],
                                                     "organizations": set(), "services": set()})
        group["names"].add(name)
        group["third" if cookie.get("third_party") else "own"] += 1
        group["refs"] += by_name.get(cookie.get("name") or "", [])
        if organization:
            group["organizations"].add(organization)
            group["services"].add(service["label"])
    for purpose in purposes.purposes:
        for basis in ("nombre", "organizacion"):
            group = groups.get((purpose, basis))
            if not group or not requests:
                continue
            count = group["own"] + group["third"]
            names = sorted(group["names"])
            if basis == "nombre":
                how = f"tienen nombre de cookie de propósito «{purposes.label(purpose)}» ({', '.join(names[:8])})"
                why = "Es una inferencia por el nombre: no prueba qué guarda la cookie."
            else:
                how = (f"se clasifican como «{purposes.label(purpose)}» por la organización que las creó "
                       f"({', '.join(sorted(group['organizations'])[:6])}; {', '.join(sorted(group['services'])[:3])}): {', '.join(names[:8])}")
                why = "Es una inferencia por la organización: no prueba qué guarda la cookie."
            finding(
                "cookie_purpose_functional" if purpose == "funcional" else "cookie_purpose",
                "INFERENCIA",
                f"{count} cookie(s) {how}. {group['own']} del propio sitio y {group['third']} de terceros. {why}",
                group["refs"] or [requests[0]["request_id"]],
                {"purpose": purpose, "label": purposes.label(purpose), "basis": basis, "cookies": count, "first_party": group["own"],
                 "third_party": group["third"], "names": names[:20],
                 **({"organizations": sorted(group["organizations"])[:20]} if basis == "organizacion" else {})},
            )
    by_purpose = {purpose: 0 for purpose in (*purposes.purposes, purposes.UNCLASSIFIED)}
    by_basis = {"nombre": 0, "organizacion": 0}
    for row in rows:
        by_purpose[row["purpose"]] = by_purpose.get(row["purpose"], 0) + 1
        if row["basis"]:
            by_basis[row["basis"]] += 1
    return {"level": "INFERENCIA", "basis": "nombre_u_organizacion", "by_purpose": by_purpose, "by_basis": by_basis,
            "labels": {purpose: purposes.label(purpose) for purpose in by_purpose},
            "cookies": sorted(rows, key=lambda row: (row["purpose"], row["domain"], row["name"]))[:MAX_COOKIE_ROWS],
            "truncated": len(rows) > MAX_COOKIE_ROWS}


def _purpose_of(purposes, name, domain, lists, service_types) -> str:
    """Propósito de una cookie con los dos pasos (nombre; si no, tipo de servicio de la organización)."""
    purpose = purposes.of(name, domain)
    if purpose == purposes.UNCLASSIFIED and service_types is not None:
        found = service_types.of(entity=lists.entity(domain), domain=domain)
        purpose = purposes.of_service((found or {}).get("type")) or purpose
    return purpose


def _persistent_cookie_findings(capture, requests, params, lists, finding, purposes=None, service_types=None) -> None:
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
        domain = _cookie_domain(cookie, registrable)
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
             "names": sorted(group["names"])[:10], "third_party": group["third_party"],
             # v1.4.6: propósito por el nombre (INFERENCIA), conteo por propósito. v1.4.7: con el paso (b), por la
             # organización dueña del dominio de estas cookies.
             **({"purposes": dict(Counter(_purpose_of(purposes, name, domain, lists, service_types) for name in group["names"]))}
                if purposes else {})},
        )


LINKER_STATUS_LABELS = {"first_party": "Propio", "same_org": "Misma organización", "third_party": "Tercero",
                        "unknown_org": "Organización no disponible"}
LINKER_BASIS_LABELS = {"dominio_registrable": "dominio registrable", "mapa_entidades": "mapa de entidades",
                       "catalogo": "mapa de entidades (catálogo propio)", "alias": "alias de organización (org_aliases)"}
LINKER_SOURCE_LABELS = {"navigation": "navegación", "redirect": "redirección"}
LINKER_VIA_LABELS = {"referer": "Referer", "redirect": "cadena de redirección", "pagina_anterior": "página anterior"}


def _linker_items(capture, requests, by_id, party_by_id, first_party_domains, site_orgs, lists, transfers, page_url) -> list[dict]:
    """_gl en URLs de navegación y redirección, con el destino clasificado por el mismo criterio que el resto del análisis
    (propio · misma organización · tercero · «Organización no disponible») y el criterio que lo resolvió."""
    basis_of = getattr(lists, "entity_basis", None)
    items = []
    for candidate in linker.candidates(requests, timeline=capture.get("timeline"), page_url=page_url,
                                       start_url=capture.get("start_url")):
        request_id = candidate["request_id"]
        host = linker.host_of(candidate["url"])
        if request_id is not None:
            domain, party = by_id[request_id].get("registrable_domain"), party_by_id[request_id]
        else:
            # Página sin request de navegación: mismo criterio que party_of() con su dominio registrable.
            domain = registrable_domain(host)
            entity = lists.entity(domain)
            party = ("first_party" if domain in first_party_domains
                     else "same_org" if entity != UNKNOWN_ENTITY and entity in site_orgs else "third_party")
        entity = lists.entity(domain)
        if party == "first_party":
            status, basis = "first_party", "dominio_registrable"
        elif party == "third_party" and entity == UNKNOWN_ENTITY:
            status, basis = "unknown_org", "dominio_registrable"
        else:
            status, basis = party, (basis_of(domain) if basis_of else None) or "mapa_entidades"
        duplicate_of = next((kind for value, kind in sorted((transfers.get(request_id) or {}).items())
                             if value in candidate["values"]), None) if request_id is not None else None
        origin_host = linker.host_of(candidate["origin"]["url"])
        items.append({
            "source": candidate["source"],
            "source_label": LINKER_SOURCE_LABELS[candidate["source"]],
            "request_id": request_id,
            "seq": by_id[request_id].get("seq") if request_id is not None else None,
            "tab": candidate.get("tab"),
            "destination": {"url": linker.strip_url(candidate["url"]), "host": host, "domain": domain},
            "origin": {**candidate["origin"], "host": origin_host, "domain": registrable_domain(origin_host)},
            "redirect_chain": candidate["chain"],
            "gl": candidate["gl"],
            "classification": {"status": status, "label": LINKER_STATUS_LABELS[status],
                               "organization": entity if entity != UNKNOWN_ENTITY else (domain or host or UNKNOWN_ENTITY),
                               "basis": basis, "basis_label": LINKER_BASIS_LABELS[basis]},
            # Solo un tercero suma (señal linker_transfer de la request), y solo si hay request de navegación a la que
            # atribuirla y la transferencia no estaba ya informada por otra regla.
            "counts_in_index": status == "third_party" and request_id is not None and duplicate_of is None,
            "duplicate_of": duplicate_of,
            "evidence_refs": [ref for ref in candidate["evidence"] if ref is not None],
        })
    return items


def _linker_claim(item: dict) -> str:
    gl, cls, origin = item["gl"], item["classification"], item["origin"]
    if origin.get("via") == "url_de_entrada":
        where = " en la URL de entrada del scan"
    elif origin.get("host"):
        where = f" desde {origin['host']} ({LINKER_VIA_LABELS.get(origin.get('via'), 'origen')})"
    else:
        where = " (origen no registrado)"
    label = cls["label"] if cls["status"] == "unknown_org" else cls["label"].lower()
    text = (f"La URL de {item['source_label']} a {item['destination']['host']} llevó el parámetro _gl (linker de Google){where}. "
            f"Destino: {label} ({cls['organization']}), según {cls['basis_label']}.")
    if item["redirect_chain"]:
        text += f" Cadena de redirección: {len(item['redirect_chain'])} saltos."
    if gl["format"] != linker.FORMAT_V1:
        text += " El valor no tiene un formato reconocido: se registra solo su presencia, sin inferir su contenido."
    elif gl["fields"]:
        text += (" Campos decodificados (valores enmascarados): "
                 + ", ".join(f"{field['name']} = {field['value']}" for field in gl["fields"]) + ".")
        if gl["undecoded_fields"]:
            text += f" {gl['undecoded_fields']} campo(s) no se pudieron decodificar y no se informan."
    else:
        text += " Ningún campo se pudo decodificar: se registra solo su presencia, sin inferir su contenido."
    if item["counts_in_index"]:
        text += " Suma al puntaje de la request por ser un tercero."
    elif cls["status"] == "third_party":
        text += " No suma: no hay request de navegación a la que atribuirlo."
    else:
        text += " No suma al índice."
    return text + (" Es evidencia de la presencia y la transferencia del parámetro en la URL capturada; no muestra que el destino "
                   "reconociera al visitante ni que se completara una atribución.")


def _consent_findings(capture, requests, value_params, by_id, config, finding) -> dict:
    """TCF (lo que declara la página) y Consent Mode (lo que viaja a Google). Sin juicio legal."""
    first_ref = [requests[0]["request_id"]] if requests else []
    interaction = (capture.get("consent") or {}).get("interaction_seq")
    # v1.4.10: `banner_interaction` (antes `user_interaction`): si el escenario pulsó un botón del aviso de consentimiento.
    # No son los clics ni desplazamientos de la captura interactiva (`summary.interaction`).
    summary = {"tcf": None, "consent_mode": None, "banner_interaction": interaction is not None}
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
