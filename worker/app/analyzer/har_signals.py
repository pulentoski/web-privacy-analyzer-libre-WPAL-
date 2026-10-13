"""Fuga de búsqueda y ola de sincronización (v1.3, docs/adr/025). Reglas en data/har_signals.yaml.

Sirven igual para un scan del worker y para una captura HAR importada: solo miran las requests.
"""

from collections import defaultdict
from types import SimpleNamespace
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from app.analyzer.parameters import is_identifier_like, shannon_entropy, value_shapes

MAX_TERM_CHARS = 150
# Formas de valor que delatan que no es texto escrito por una persona.
NON_TEXT_SHAPES = frozenset({"uuid", "hex", "base64", "jwt", "timestamp", "numeric", "ip", "url", "email", "version"})
SEARCH_SOURCES_EXCLUDED = frozenset({"cookie", "set_cookie"})
MAX_NESTED_CHARS = 8192
MAX_NESTED_PAIRS = 100


def _leaf(name: str) -> str:
    return name.rsplit(".", 1)[-1].strip().lower()


def _group(name: str) -> str:
    return name.rsplit(".", 1)[0] if "." in name else ""


def _expanded(params: list) -> list:
    """Los parámetros más los pares de los valores que son, a su vez, un query («a=1&b=x y»).

    La telemetría suele anidar un query doblemente codificado dentro de un JSON; la decodificación
    general se detiene en la profundidad máxima antes de separar sus pares.
    """
    out = list(params)
    seen = {(param.source, param.name, param.value) for param in params}
    for param in params:
        value = param.value
        if param.source in SEARCH_SOURCES_EXCLUDED or "&" not in value or "=" not in value or len(value) > MAX_NESTED_CHARS:
            continue
        for key, item in parse_qsl(value, keep_blank_values=False)[:MAX_NESTED_PAIRS]:
            name = f"{param.name}.{key}"
            if not 1 <= len(key) <= 64 or (param.source, name, item) in seen:
                continue
            seen.add((param.source, name, item))
            shapes = value_shapes(item)
            out.append(SimpleNamespace(source=param.source, name=name, value=item, shapes=shapes,
                                       identifier_like=is_identifier_like(item, shapes, shannon_entropy(item))))
    return out


class HarSignals:
    def __init__(self, data: dict | None = None):
        data = data or {}
        search = data.get("search") or {}
        self.search_names = frozenset(str(name).lower() for name in search.get("names") or [])
        self.min_chars = int(search.get("min_chars", 3))
        self.max_chars = min(int(search.get("max_chars", MAX_TERM_CHARS)), MAX_TERM_CHARS)
        self.ignored = frozenset(str(value).lower() for value in search.get("ignored_values") or [])
        self.contextual = [
            {"marker": str(rule["marker"]).lower(), "equals": str(rule["equals"]).lower(), "term": str(rule["term"]).lower()}
            for rule in search.get("contextual") or []
            if isinstance(rule, dict) and {"marker", "equals", "term"} <= set(rule)
        ]
        wave = data.get("sync_wave") or {}
        self.patterns = tuple(str(pattern).lower() for pattern in wave.get("patterns") or [])
        self.window_s = float(wave.get("window_s", 3))
        self.min_requests = int(wave.get("min_requests", 4))
        self.min_organizations = int(wave.get("min_organizations", 3))

    # --- fuga de búsqueda ---

    @staticmethod
    def _term(param) -> str:
        """El valor como texto: el crudo de la URL («cartas+pokemon», «cartas%20pokemon») y el decodificado son el mismo término."""
        return " ".join(unquote_plus(param.value, errors="replace").split())

    def _is_term(self, param) -> bool:
        value = self._term(param)
        return (
            self.min_chars <= len(value) <= self.max_chars
            and any(char.isalpha() for char in value)
            and value.lower() not in self.ignored
            and not param.identifier_like
            and not (set(param.shapes) & NON_TEXT_SHAPES)
        )

    def search_leaks(self, params_by_request: dict, by_id: dict, page_host: str | None, party_by_id: dict) -> list[dict]:
        """Términos de búsqueda enviados a un host distinto del de la página.

        Devuelve un grupo por (host, término): {host, domain, term, parameter, rule, party, request_ids}.
        """
        if not self.search_names and not self.contextual:
            return []
        groups: dict[tuple[str, str], dict] = {}
        for request_id, params in params_by_request.items():
            request = by_id[request_id]
            host = (request.get("host") or "").lower()
            if not host or host == page_host:
                continue
            params = _expanded(params)
            candidates = []
            siblings: dict[str, dict[str, str]] = defaultdict(dict)
            for param in params:
                if param.source in SEARCH_SOURCES_EXCLUDED:
                    continue
                siblings[f"{param.source}|{_group(param.name)}"][_leaf(param.name)] = param.value
                if _leaf(param.name) in self.search_names and self._is_term(param):
                    candidates.append((param, "nombre"))
            for rule in self.contextual:
                for param in params:
                    if param.source in SEARCH_SOURCES_EXCLUDED or _leaf(param.name) != rule["term"] or not self._is_term(param):
                        continue
                    marker = siblings[f"{param.source}|{_group(param.name)}"].get(rule["marker"], "")
                    if marker.strip().lower() == rule["equals"]:
                        candidates.append((param, "contexto"))
            for param, rule_kind in candidates:
                term = self._term(param)
                entry = groups.setdefault((host, term.lower()), {
                    "host": host, "domain": request.get("registrable_domain") or host, "term": term, "parameter": _leaf(param.name),
                    "rule": rule_kind, "party": party_by_id.get(request_id), "request_ids": [],
                })
                if request_id not in entry["request_ids"]:
                    entry["request_ids"].append(request_id)
        return sorted(groups.values(), key=lambda entry: (entry["host"], entry["term"].lower()))

    # --- ola de sincronización ---

    def _is_sync(self, request: dict) -> bool:
        try:
            parts = urlsplit(request.get("url") or "")
        except ValueError:
            return False
        target = f"{(parts.hostname or '').lower()}{parts.path.lower()}"
        return any(pattern in target for pattern in self.patterns)

    def sync_wave(self, requests: list[dict], party_by_id: dict, owner) -> dict:
        """La mayor ráfaga de requests de sincronización hacia organizaciones distintas del sitio.

        `owner(domain)` identifica a la organización dueña. Sin hora de las requests (capturas
        antiguas) no se puede medir la ráfaga: `available` = False.
        """
        empty = {"available": True, "detected": False, "requests": 0, "organizations": 0, "domains": [], "initiator": None,
                 "duration_ms": None, "request_ids": []}
        if not self.patterns:
            return empty
        if any(request.get("ts") is None for request in requests):
            return {**empty, "available": False}
        hits = sorted(
            (request for request in requests
             if party_by_id.get(request["request_id"]) == "third_party" and request.get("registrable_domain") and self._is_sync(request)),
            key=lambda request: (request["ts"], request["seq"]),
        )
        best: list[dict] = []
        current: list[dict] = []
        for request in hits + [None]:
            if request is not None and (not current or request["ts"] - current[-1]["ts"] <= self.window_s):
                current.append(request)
                continue
            organizations = {owner(item["registrable_domain"]) for item in current}
            if len(current) >= self.min_requests and len(organizations) >= self.min_organizations and len(current) > len(best):
                best = current
            current = [request] if request is not None else []
        if not best:
            return empty
        domains = sorted({request["registrable_domain"] for request in best})
        return {
            "available": True, "detected": True, "requests": len(best),
            "organizations": len({owner(domain) for domain in domains}), "domains": domains[:40],
            # Quién la inicia: el host de la primera request de la ráfaga (p. ej. el iframe de sync de un
            # socio publicitario, que dispara las demás). Los píxeles suelen salir sin Referer ni stack.
            "initiator": (best[0].get("host") or "").lower() or None,
            "duration_ms": round((best[-1]["ts"] - best[0]["ts"]) * 1000),
            "request_ids": [request["request_id"] for request in best],
        }
