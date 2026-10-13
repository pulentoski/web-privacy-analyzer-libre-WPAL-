"""Listas de filtros (EasyList, EasyPrivacy) y mapa dominio -> entidad. Todo offline.

Los datos viven en data/lists/ (los descarga scripts/update-lists.sh en el host).
El motor Adblock es `adblock` (bindings de adblock-rust), ver docs/adr/004.
"""

import hashlib
import json
import logging
import pathlib

import adblock

logger = logging.getLogger(__name__)

MAX_RULE_CHARS = 300
UNKNOWN_ENTITY = "no_disponible"

# resource_type de Playwright -> tipo de request de la sintaxis Adblock.
_REQUEST_TYPES = {
    "document": "sub_frame",
    "stylesheet": "stylesheet",
    "image": "image",
    "media": "media",
    "font": "font",
    "script": "script",
    "xhr": "xmlhttprequest",
    "fetch": "xmlhttprequest",
    "ping": "ping",
    "beacon": "ping",
    "websocket": "websocket",
}


class FilterLists:
    """Un motor por lista, para poder decir QUÉ lista y qué regla coincidió.

    Los objetos de `adblock` no se pueden usar desde un hilo distinto al que los
    creó: cargar y consultar siempre desde el mismo hilo (ver app/analysis.py).
    """

    def __init__(self, data_dir: str | pathlib.Path, *, allow_fixtures: bool = False, license_profile: str = "no_comercial") -> None:
        if license_profile not in ("no_comercial", "comercial"):
            raise ValueError(f"Perfil de licencias desconocido: {license_profile!r}")
        lists_dir = pathlib.Path(data_dir) / "lists"
        self.license_profile = license_profile
        # Fuentes que existen pero NO se cargaron por su licencia: [{id, license, reason}].
        self.excluded: list[dict] = []
        self._engines: list[tuple[str, adblock.Engine]] = []
        self.sources: list[dict] = []
        self._entities: dict[str, str] = {}
        digest = hashlib.sha256()

        manifest_path = lists_dir / "MANIFEST.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {"sources": []}
        for source in manifest.get("sources", []):
            path = lists_dir / source["file"]
            if license_profile == "comercial" and source.get("noncommercial"):
                # Perfil comercial (docs/adr/019): una fuente NC ni siquiera se abre.
                self.excluded.append({"id": source["id"], "license": source.get("license"), "reason": "licencia no comercial"})
                continue
            if not path.exists():
                logger.warning("list_file_missing", extra={"list": source["id"]})
                continue
            if source.get("format") == "adblock":
                self._add_engine(source["id"], path)
            elif source.get("format") == "ddg-entity-map":
                self._load_ddg_entities(path)
            elif source.get("format") == "simple-entity-map":
                self._load_simple_entities(path)
            else:
                continue
            digest.update(source["sha256"].encode())
            self.sources.append(
                {key: source.get(key) for key in ("id", "version", "retrieved_at", "sha256", "license", "noncommercial")}
            )
        if license_profile == "comercial":
            digest.update(self._load_commercial_entities(lists_dir / "companiesdb"))
        if allow_fixtures:
            path = lists_dir / "test-fixtures.txt"
            self._add_engine("test-fixtures", path)
            digest.update(hashlib.sha256(path.read_bytes()).hexdigest().encode())
            self.sources.append({"id": "test-fixtures", "version": None, "retrieved_at": None, "sha256": None,
                                 "license": "proyecto", "noncommercial": False})
        digest.update(license_profile.encode() if license_profile != "no_comercial" else b"")
        self.version = digest.hexdigest()[:16]

    def _add_engine(self, list_id: str, path: pathlib.Path) -> None:
        filter_set = adblock.FilterSet(debug=True)  # debug: conserva el texto de la regla
        filter_set.add_filter_list(path.read_text(encoding="utf-8", errors="replace"))
        self._engines.append((list_id, adblock.Engine(filter_set)))

    def _load_ddg_entities(self, path: pathlib.Path) -> None:
        """Formato de Tracker Radar: {entidad: {displayName, properties: [dominio, ...]}}."""
        for name, entry in json.loads(path.read_text(encoding="utf-8")).items():
            if not isinstance(entry, dict):
                continue
            display = entry.get("displayName") or name
            for domain in entry.get("properties") or []:
                if isinstance(domain, str):
                    self._entities.setdefault(domain.lower(), str(display)[:200])

    def _load_commercial_entities(self, directory: pathlib.Path) -> bytes:
        """Mapa dominio → organización de AdGuard companiesdb (CC BY-SA 4.0). Lo genera scripts/update-companiesdb.sh."""
        try:
            source = json.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))["sources"][0]
            if source.get("noncommercial"):
                raise ValueError("la fuente del perfil comercial está marcada como no comercial")
            self._load_simple_entities(directory / source["file"])
        except (OSError, ValueError, KeyError, IndexError) as exc:
            # Sin la fuente alternativa el análisis sigue: las entidades quedan "no_disponible".
            logger.warning("commercial_entity_map_unavailable", extra={"error_type": type(exc).__name__})
            return b""
        self.sources.append({key: source.get(key) for key in ("id", "version", "retrieved_at", "sha256", "license", "noncommercial")})
        return str(source["sha256"]).encode()

    def _load_simple_entities(self, path: pathlib.Path) -> None:
        """Formato neutro para reemplazar la fuente: {dominio: entidad}."""
        for domain, name in json.loads(path.read_text(encoding="utf-8")).items():
            if isinstance(domain, str) and isinstance(name, str):
                self._entities.setdefault(domain.lower(), name[:200])

    def entity(self, registrable_domain: str | None) -> str:
        """Organización dueña del dominio, o "no_disponible" (nunca se inventa)."""
        if not registrable_domain:
            return UNKNOWN_ENTITY
        return self._entities.get(registrable_domain.lower(), UNKNOWN_ENTITY)

    def match(self, request: dict, source_host: str | None) -> list[dict]:
        """Listas cuya política bloquearía esta request: [{list, rule}]."""
        url, host = request.get("url"), request.get("host")
        # La navegación principal no es un recurso que una lista de filtros bloquee.
        if not url or not host or not source_host or request.get("seq") == 0 and request.get("is_navigation"):
            return []
        request_type = _REQUEST_TYPES.get(request.get("resource_type") or "", "other")
        matches = []
        for list_id, engine in self._engines:
            try:
                # third_party se pasa explícito: el del análisis (por dominio registrable).
                result = engine.check_network_urls_with_hostnames(
                    url, host, source_host, request_type, bool(request.get("third_party"))
                )
            except Exception:  # URL arbitraria del sitio: nunca debe tumbar el análisis
                continue
            if result.matched and not result.exception:
                matches.append({"list": list_id, "rule": (result.filter or "")[:MAX_RULE_CHARS]})
        return matches
