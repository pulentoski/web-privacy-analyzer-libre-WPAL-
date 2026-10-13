"""Telemetría propia (v1.3.4, docs/adr/028). Reglas en data/first_party_telemetry.yaml.

Envíos de eventos al propio sitio o a otro dominio de la misma organización: no son terceros, pero
son un método de recolección. Solo mira método, tipo, estado y URL de requests ya clasificadas.
"""

from collections import Counter
from urllib.parse import urlsplit

STATIC_TYPES = frozenset({"document", "script", "stylesheet", "font", "media", "manifest"})
OWN_PARTIES = frozenset({"first_party", "same_org"})
MAX_TEXT = 200


class FirstPartyTelemetry:
    def __init__(self, data: dict | None = None):
        data = data or {}
        self.segments = frozenset(str(item).strip("/").lower() for item in data.get("path_segments") or [] if item)
        self.status_204 = bool(data.get("status_204", False))
        self.known = [(str(rule["pattern"]).lower(), str(rule["name"])[:MAX_TEXT]) for rule in data.get("known") or []
                      if isinstance(rule, dict) and rule.get("pattern") and rule.get("name")]
        self.min_requests_for_note = int(data.get("min_requests_for_note", 3))
        self.max_listed = int(data.get("max_listed", 15))

    def classify(self, request: dict, party: str | None) -> dict | None:
        """{kind, name?} si la request es telemetría propia; None si no. kind: script | known | path | status_204."""
        if party not in OWN_PARTIES or (request.get("method") or "GET").upper() == "OPTIONS" or request.get("is_navigation"):
            return None
        try:
            parts = urlsplit(str(request.get("url") or ""))
        except ValueError:
            return None
        target = f"{(parts.hostname or '').lower()}{parts.path.lower()}"
        resource_type = request.get("resource_type")
        name = next((label for pattern, label in self.known if pattern in target), None)
        if name and resource_type == "script":
            return {"kind": "script", "name": name}
        if resource_type in STATIC_TYPES:
            return None
        if name:
            return {"kind": "known", "name": name}
        if self.segments & {segment for segment in parts.path.lower().split("/") if segment}:
            return {"kind": "path"}
        has_data = (request.get("method") or "GET").upper() == "POST" or bool(request.get("query_params"))
        if self.status_204 and request.get("response_status") == 204 and has_data:
            return {"kind": "status_204"}
        return None

    def detect(self, requests: list, party_by_id: dict) -> dict:
        """Resumen de la telemetría propia de la captura, con los ids de las requests que la respaldan."""
        endpoints: dict[tuple, dict] = {}
        scripts: dict[tuple, dict] = {}
        request_ids, kinds = [], Counter()
        for request in requests:
            request_id = request.get("request_id")
            hit = self.classify(request, party_by_id.get(request_id))
            if hit is None:
                continue
            try:
                parts = urlsplit(str(request.get("url") or ""))
            except ValueError:
                continue
            host, path = (parts.hostname or "").lower()[:MAX_TEXT], parts.path[:MAX_TEXT]
            table = scripts if hit["kind"] == "script" else endpoints
            entry = table.setdefault((host, path), {"host": host, "path": path, "kind": hit["kind"], "name": hit.get("name"),
                                                    "party": party_by_id.get(request_id), "requests": 0})
            entry["requests"] += 1
            kinds[hit["kind"]] += 1
            request_ids.append(request_id)
        order = lambda item: (-item["requests"], item["host"], item["path"])  # noqa: E731
        events = sum(entry["requests"] for entry in endpoints.values())
        return {
            # requests = envíos de eventos (los scripts de analítica se cuentan aparte: cargar no es enviar).
            "requests": events,
            "endpoints": len(endpoints),
            "scripts": len(scripts),
            "by_kind": dict(kinds),
            "hosts": sorted({entry["host"] for entry in endpoints.values()})[: self.max_listed],
            "endpoint_list": sorted(endpoints.values(), key=order)[: self.max_listed],
            "script_list": sorted(scripts.values(), key=order)[: self.max_listed],
            "request_ids": request_ids,
        }
