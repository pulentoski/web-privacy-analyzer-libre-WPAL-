"""IDs de cuenta del sitio (v1.2).

Un ID de medición de Analytics, un contenedor de Tag Manager o un pixel de anuncios
identifican al SITIO ante el proveedor, no al visitante: llegan iguales para cualquier
persona. Aquí se reconocen (por host, parámetro y forma, según data/account_ids.yaml) para
mostrarlos como "ID de cuenta del sitio" y sacarlos de "identificadores que persisten" y de
"sincronización entre organizaciones".
"""

import re
from urllib.parse import urlsplit

MAX_VALUE_CHARS = 128
MAX_ITEMS = 60
MAX_REFS = 5
LEVEL = "INFERENCIA"


class _Rule:
    def __init__(self, raw: dict) -> None:
        self.id = str(raw["id"])
        self.vendor = str(raw["vendor"])
        self.label = str(raw["label"])
        self.hosts = tuple(str(host).lower() for host in raw.get("hosts") or [])
        self.host_pattern = re.compile(raw["host_pattern"]) if raw.get("host_pattern") else None
        self.path_prefix = str(raw.get("path_prefix") or "")
        self.params = frozenset(str(name).lower() for name in raw.get("params") or [])
        self.pattern = re.compile(raw["pattern"]) if raw.get("pattern") else None
        self.path_pattern = re.compile(raw["path_pattern"]) if raw.get("path_pattern") else None
        # v1.4.5: la regla identifica una CUENTA de medición (varias = datos a varias cuentas) y, si el
        # valor tiene esta forma, es la etiqueta de un servicio descontinuado.
        self.account = bool(raw.get("account"))
        self.discontinued = re.compile(raw["discontinued_pattern"]) if raw.get("discontinued_pattern") else None
        self.discontinued_label = str(raw.get("discontinued_label") or "")
        if not (self.hosts or self.host_pattern):
            raise ValueError(f"account_ids.yaml: la regla {self.id!r} no declara hosts")
        if not ((self.params and self.pattern) or self.path_pattern):
            raise ValueError(f"account_ids.yaml: la regla {self.id!r} no declara params+pattern ni path_pattern")

    def host_matches(self, host: str) -> bool:
        if any(host == suffix or host.endswith("." + suffix) for suffix in self.hosts):
            return True
        return bool(self.host_pattern and self.host_pattern.search(host))


def _path(request: dict) -> str:
    try:
        return urlsplit(request.get("url") or "").path or "/"
    except ValueError:
        return "/"


class AccountIds:
    def __init__(self, config: dict | None = None, *, allow_fixtures: bool = False) -> None:
        config = config or {}
        self._rules = [_Rule(raw) for raw in config.get("rules") or []]
        self._test_hosts = frozenset(str(host).lower() for host in (config.get("test_hosts") or [])) if allow_fixtures else frozenset()

    def _candidates(self, request: dict) -> list[_Rule]:
        host = str(request.get("host") or "").lower()
        if not host:
            return []
        test_host = host in self._test_hosts
        path = _path(request)
        return [
            rule for rule in self._rules
            if (test_host or rule.host_matches(host)) and path.startswith(rule.path_prefix)
        ]

    def detect(self, requests: list[dict], params_by_request: dict) -> tuple[list[dict], set[str]]:
        """(IDs de cuenta observados, valores a excluir de persistencia y sincronización).

        Cada ID lleva nivel y evidence_refs (ids de request). Los que viajan en la ruta se
        informan, pero no entran en el conjunto de valores (no son parámetros).
        """
        found: dict[tuple[str, str], dict] = {}
        values: set[str] = set()

        def add(rule: _Rule, value: str, parameter: str | None, request: dict) -> None:
            item = found.get((rule.id, value))
            if item is None:
                if len(found) >= MAX_ITEMS:
                    return
                item = found[(rule.id, value)] = {
                    "rule": rule.id, "vendor": rule.vendor, "label": rule.label, "value": value, "parameter": parameter,
                    "domains": set(), "requests": 0, "level": LEVEL, "evidence_refs": [],
                }
            item["requests"] += 1
            if request.get("registrable_domain"):
                item["domains"].add(request["registrable_domain"])
            if len(item["evidence_refs"]) < MAX_REFS:
                item["evidence_refs"].append(request["request_id"])

        for request in requests:
            rules = self._candidates(request)
            if not rules:
                continue
            path = _path(request)
            for rule in rules:
                if rule.path_pattern:
                    match = rule.path_pattern.search(path)
                    if match:
                        add(rule, match.group("value"), None, request)
            seen: set[tuple[str, str]] = set()
            for param in params_by_request.get(request["request_id"]) or []:
                value = param.value
                if not isinstance(value, str) or not value or len(value) > MAX_VALUE_CHARS:
                    continue
                name = str(param.name).rsplit(".", 1)[-1].lower()
                for rule in rules:
                    if rule.pattern and name in rule.params and rule.pattern.match(value):
                        values.add(value)
                        if (rule.id, value) not in seen:  # la misma request repite el valor en fuentes decodificadas
                            seen.add((rule.id, value))
                            add(rule, value, name, request)
                        break
        items = [{**item, "domains": sorted(item["domains"])} for item in found.values()]
        items.sort(key=lambda item: (item["vendor"], item["label"], item["value"]))
        return items, values

    def accounts(self, items: list[dict]) -> list[dict]:
        """Cuentas de medición por proveedor (v1.4.5): [{vendor, accounts, discontinued, discontinued_label, evidence_refs}].

        Solo reglas marcadas `account: true`. `discontinued` = IDs con la forma de un servicio descontinuado.
        """
        rules = {rule.id: rule for rule in self._rules}
        vendors: dict[str, dict] = {}
        for item in items:
            rule = rules.get(item["rule"])
            if rule is None or not rule.account:
                continue
            entry = vendors.setdefault(item["vendor"], {"vendor": item["vendor"], "accounts": [], "discontinued": [],
                                                        "discontinued_label": "", "evidence_refs": [], "discontinued_refs": []})
            entry["accounts"].append(item["value"])
            entry["evidence_refs"] += item["evidence_refs"]
            if rule.discontinued and rule.discontinued.match(item["value"]):
                entry["discontinued"].append(item["value"])
                entry["discontinued_label"] = rule.discontinued_label
                entry["discontinued_refs"] += item["evidence_refs"]
        return sorted(vendors.values(), key=lambda entry: entry["vendor"])
