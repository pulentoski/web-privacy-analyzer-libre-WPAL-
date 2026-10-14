"""Reglas de v1.4.2 que viven en YAML: registro de interacción, librerías benignas de canvas y
rastreo del lado del servidor (data/interaction_signals.yaml, benign_libraries.yaml,
server_side_tracking.yaml; docs/adr/030).

Nada de aquí afirma un propósito: la escucha de un evento y la secuencia temporal son hechos
observados (EVIDENCIA); el nombre de un parámetro o el parecido con un payload conocido son
INFERENCIA.
"""

import re
from collections import Counter, defaultdict
from urllib.parse import urlsplit

EVENT_PREFIX = "events."
# Mecanismos que existen para enviar (no para descargar): cuentan siempre.
BEACON_TYPES = frozenset({"ping", "beacon"})
BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})
MAX_INTERACTIONS = 3000
KINDS = ("click", "scroll", "key")
_LEAF = re.compile(r"[.\[\]]+")


def leaf(name: str) -> str:
    """Último segmento de un nombre de parámetro («ep.percent_scrolled» → «percent_scrolled»)."""
    parts = [part for part in _LEAF.split(name or "") if part]
    return (parts[-1] if parts else "").lower()


def _timestamp(value) -> float | None:
    if hasattr(value, "timestamp"):
        return value.timestamp()
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


class BenignLibraries:
    def __init__(self, raw: dict | None = None) -> None:
        self._patterns: list[tuple[str, str]] = []
        for library in (raw or {}).get("libraries") or []:
            if isinstance(library, dict) and isinstance(library.get("label"), str):
                self._patterns += [(str(pattern).lower(), library["label"]) for pattern in library.get("patterns") or [] if pattern]

    def match(self, script_url: str | None) -> str | None:
        """Etiqueta de la librería conocida, o None. Solo mira la ruta de la URL del script."""
        try:
            path = urlsplit(script_url or "").path.lower()
        except ValueError:
            return None
        if not path or not (script_url or "").startswith(("http://", "https://")):
            return None
        return next((label for pattern, label in self._patterns if pattern in path), None)


class ServerSideTracking:
    def __init__(self, raw: dict | None = None) -> None:
        raw = raw or {}
        self._suffixes = tuple(str(item).lower() for item in raw.get("cloud_suffixes") or [])
        meta = raw.get("meta") or {}
        self.meta_label = str(meta.get("label") or "")
        self._identifiers = frozenset(str(item).lower() for item in meta.get("identifiers") or [])
        self._payload = frozenset(str(item).lower() for item in meta.get("payload") or [])
        self._min_payload = int(meta.get("min_payload") or 2)

    def is_cloud_host(self, host: str | None) -> bool:
        host = (host or "").lower()
        return any(host == suffix or host.endswith("." + suffix) for suffix in self._suffixes)

    def detect(self, requests: list, params_by_request: dict, party_by_id: dict) -> list[dict]:
        """[{host, domain, signals, request_ids}] de hosts de nube genéricos con señales de eventos de Meta."""
        hosts: dict[str, dict] = {}
        for request in requests:
            host = request.get("host")
            if party_by_id.get(request["request_id"]) != "third_party" or not self.is_cloud_host(host):
                continue
            names = {leaf(param.name) for param in params_by_request.get(request["request_id"], [])}
            identifiers, payload = names & self._identifiers, names & self._payload
            if not identifiers and len(payload) < self._min_payload:
                continue
            entry = hosts.setdefault(host, {"host": host, "domain": request.get("registrable_domain"), "signals": set(), "request_ids": []})
            entry["signals"] |= identifiers | payload
            entry["request_ids"].append(request["request_id"])
        return [{**entry, "signals": sorted(entry["signals"]), "label": self.meta_label} for entry in sorted(hosts.values(), key=lambda item: item["host"])]


class InteractionSignals:
    def __init__(self, raw: dict | None = None) -> None:
        raw = raw or {}
        self.events = {str(key): str(value) for key, value in (raw.get("events") or {}).items()}
        self._categories = []
        for category, spec in (raw.get("payload") or {}).items():
            if isinstance(spec, dict):
                self._categories.append((str(category), str(spec.get("label") or category),
                                         frozenset(str(n).lower() for n in spec.get("names") or []),
                                         tuple(str(n).lower() for n in spec.get("contains") or [])))
        self._event_names = frozenset(str(n).lower() for n in raw.get("event_names") or [])
        self._event_values = frozenset(str(n).lower() for n in raw.get("event_values") or [])
        self._event_label = str(raw.get("event_label") or "evento de interacción")
        correlation = raw.get("correlation") or {}
        self.window_s = float(correlation.get("window_s") or 2)
        self.min_interactions = int(correlation.get("min_interactions") or 2)
        self.min_ratio = float(correlation.get("min_ratio") or 2)
        self.max_timeline = int(correlation.get("max_timeline") or 200)
        # v1.4.5: una descarga de recurso estático no es un envío de datos (data/interaction_signals.yaml).
        self._static_extensions = tuple("." + str(ext).lower().lstrip(".") for ext in correlation.get("static_extensions") or [])
        self._static_types = frozenset(str(kind) for kind in correlation.get("static_types") or [])
        self.delivery_services = frozenset(str(kind) for kind in correlation.get("delivery_service_types") or [])

    # --- 1. escucha (lo registra la instrumentación) ---

    def listened(self, apis: dict) -> list[str]:
        """Eventos de interacción que escucha un script, en el orden del YAML."""
        return [event for event in self.events if apis.get(EVENT_PREFIX + event)]

    def event_label(self, event: str) -> str:
        return self.events.get(event, event)

    # --- 2. datos de interacción en payloads ---

    def category_of(self, name: str, value: str | None = None) -> tuple[str, str] | None:
        segment = leaf(name)
        if not segment:
            return None
        for category, label, names, contains in self._categories:
            if segment in names or any(text in segment for text in contains):
                return category, label
        if segment in self._event_names and (value or "").strip().lower() in self._event_values:
            return "event", self._event_label
        return None

    def payloads(self, requests: list, params_by_request: dict, party_by_id: dict, excluded_sources=frozenset()) -> list[dict]:
        """[{domain, party, category, label, parameters, request_ids}] por dominio y categoría."""
        groups: dict[tuple[str, str], dict] = {}
        for request in requests:
            domain = request.get("registrable_domain") or ""
            for param in params_by_request.get(request["request_id"], []):
                if param.source in excluded_sources:
                    continue
                found = self.category_of(param.name, param.value)
                if found is None:
                    continue
                group = groups.setdefault((domain, found[0]), {
                    "domain": domain, "party": party_by_id.get(request["request_id"]), "category": found[0], "label": found[1],
                    "parameters": set(), "request_ids": []})
                group["parameters"].add(leaf(param.name))
                group["request_ids"].append(request["request_id"])
        return [{**group, "parameters": sorted(group["parameters"])[:12], "request_ids": sorted(set(group["request_ids"]))}
                for group in sorted(groups.values(), key=lambda item: (item["domain"], item["category"]))]

    # --- 3. correlación con la interacción del usuario (capturas interactivas) ---

    @staticmethod
    def clean_interactions(raw) -> list[tuple[float, str]] | None:
        """[(ts, kind)] ordenado. None = la captura no registró interacciones (no se inventa «0»)."""
        if not isinstance(raw, list):
            return None
        events = []
        for item in raw[:MAX_INTERACTIONS]:
            ts = _timestamp(item.get("ts")) if isinstance(item, dict) else None
            if ts is not None and item.get("kind") in KINDS:
                events.append((ts, item["kind"]))
        return sorted(events)

    def is_send(self, request: dict, service_type: str | None = None) -> bool:
        """¿La request ENVÍA datos (v1.4.5)? POST, beacon, ping, pixel o GET con parámetros.

        No cuentan las descargas de recursos estáticos (.js, .mjs, .wasm, .css, fuentes; imágenes sin
        parámetros) ni lo servido por un dominio de distribución de contenido (`service_type`).
        """
        if request.get("is_navigation"):
            return False
        kind = request.get("resource_type")
        if (request.get("method") or "GET").upper() in BODY_METHODS or kind in BEACON_TYPES:
            return True
        if service_type in self.delivery_services:
            return False
        try:
            path = urlsplit(request.get("url") or "").path.lower()
        except ValueError:
            path = ""
        if kind in self._static_types or path.endswith(self._static_extensions):
            return False
        # Lo que queda (xhr, fetch, imagen…) envía datos solo si los lleva en la dirección: un pixel es eso.
        return bool(request.get("query_params"))

    def correlate(self, interactions, requests: list, party_by_id: dict, organization_of, service_type_of=None) -> dict:
        events = self.clean_interactions(interactions)
        if events is None:
            return {"available": False}
        stamped = [(ts, request) for request in requests if (ts := _timestamp(request.get("ts"))) is not None]
        navigations = sorted(ts for ts, request in stamped if request.get("is_navigation") and request.get("resource_type") == "document"
                             and party_by_id.get(request["request_id"]) == "first_party")
        sends = sorted(
            ((ts, request["request_id"], organization_of(request), request.get("registrable_domain") or "", party_by_id.get(request["request_id"]))
             for ts, request in stamped if party_by_id.get(request["request_id"]) != "first_party"
             and self.is_send(request, service_type_of(request) if service_type_of else None)),
            key=lambda item: item[0],
        )
        totals = Counter(send[2] for send in sends)
        span = (max(ts for ts, _ in stamped) - min(ts for ts, _ in stamped)) if stamped else 0.0
        window = self.window_s
        per_org: dict[str, dict] = defaultdict(lambda: {"interactions": set(), "request_ids": [], "domains": set(), "party": None, "kinds": Counter()})
        timeline, covered, last_end = [], 0.0, None
        in_window: set = set()
        for index, (ts, kind) in enumerate(events):
            # Un clic que abre otra página trae consigo todo el tráfico de esa página: no es un envío de la interacción.
            navigated = any(ts <= nav <= ts + window for nav in navigations)
            hits = Counter()
            if not navigated:
                start = max(ts, last_end) if last_end is not None else ts
                covered += max(0.0, ts + window - start)
                last_end = max(last_end or 0.0, ts + window)
                for send_ts, request_id, organization, domain, party in sends:
                    if send_ts <= ts:
                        continue
                    if send_ts > ts + window:
                        break
                    entry = per_org[organization]
                    in_window.add(request_id)
                    if request_id not in entry["request_ids"]:
                        entry["request_ids"].append(request_id)
                    entry["interactions"].add(index)
                    entry["domains"].add(domain)
                    entry["party"] = party
                    entry["kinds"][kind] += 1
                    hits[organization] += 1
            if len(timeline) < self.max_timeline:
                timeline.append({"ts": ts, "kind": kind, "navigation": navigated,
                                 "sends": [{"organization": name, "requests": count} for name, count in hits.most_common(5)]})
        outside_by_org = Counter(send[2] for send in sends if send[1] not in in_window)
        organizations = []
        for name, entry in per_org.items():
            observed = len(entry["request_ids"])
            # Ritmo normal de la organización = sus envíos FUERA de las ventanas, por segundo. Con ese ritmo,
            # cuántos caerían dentro de las ventanas aunque el usuario no hubiera hecho nada.
            outside = outside_by_org[name]
            quiet = span - covered
            expected = round(outside * covered / quiet, 2) if quiet > 0 else float(outside)
            flagged = len(entry["interactions"]) >= self.min_interactions and observed >= max(2.0, self.min_ratio * expected)
            organizations.append({
                "organization": name, "party": entry["party"], "domains": sorted(d for d in entry["domains"] if d)[:10],
                "interactions": len(entry["interactions"]), "requests": observed, "expected": expected, "session_requests": totals[name],
                "kinds": dict(entry["kinds"]), "flagged": flagged, "request_ids": entry["request_ids"],
            })
        organizations.sort(key=lambda item: (not item["flagged"], -item["interactions"], item["organization"]))
        return {
            "available": True, "window_s": window, "interactions": dict(Counter(kind for _, kind in events)),
            "total": len(events), "organizations": organizations, "timeline": timeline,
            "timeline_truncated": len(events) > len(timeline),
        }
