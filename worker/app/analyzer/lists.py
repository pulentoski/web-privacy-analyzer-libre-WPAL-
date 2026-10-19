"""Listas de filtros (EasyList, EasyPrivacy) y mapa dominio -> entidad. Todo offline.

Los datos viven en data/lists/ (los descarga scripts/update-lists.sh en el host).
El motor Adblock es `adblock` (bindings de adblock-rust), ver docs/adr/004.
"""

import hashlib
import json
import logging
import pathlib
import re
import unicodedata

import adblock
import yaml

logger = logging.getLogger(__name__)

MAX_RULE_CHARS = 300
UNKNOWN_ENTITY = "no_disponible"
_NAME_TOKEN = re.compile(r"^[^\W\d_]+(?:['’\-][^\W\d_]+)*\.?$")


def _fold(text: str) -> str:
    """Minúsculas y sin acentos, para comparar nombres."""
    return "".join(c for c in unicodedata.normalize("NFKD", text.lower()) if not unicodedata.combining(c))


class OrganizationCatalog:
    """Catálogo propio (data/organizations.yaml, v1.4.5): organización por sufijo de host, dominios de dueño
    desconocido y la regla que impide mostrar como organización el nombre de una persona natural.
    v1.4.6: alias de organización (data/org_aliases.yaml), que ganan sobre el resto."""

    def __init__(self, raw: dict | None = None, aliases: dict | None = None) -> None:
        raw = raw or {}
        self._aliases: list[tuple[str, str]] = sorted(
            ((str(domain).lower(), str(name)[:200]) for name, domains in ((aliases or {}).get("aliases") or {}).items()
             for domain in domains or [] if domain), key=lambda item: -len(item[0]))
        self._suffixes: list[tuple[str, str | None]] = []
        for name, suffixes in (raw.get("organizations") or {}).items():
            self._suffixes += [(str(suffix).lower(), str(name)[:200]) for suffix in suffixes or [] if suffix]
        self._suffixes += [(str(suffix).lower(), None) for suffix in raw.get("unknown") or [] if suffix]
        # El sufijo más largo gana (un host concreto sobre su dominio).
        self._suffixes.sort(key=lambda item: -len(item[0]))
        persons = raw.get("persons") or {}
        self._enabled = bool(persons)
        self._not_persons = frozenset(_fold(str(name)) for name in persons.get("not_persons") or [])
        self._legal = frozenset(_fold(str(word)) for word in persons.get("legal_forms") or [])
        self._words = frozenset(_fold(str(word)) for word in persons.get("org_words") or [])
        self._given = frozenset(_fold(str(word)) for word in persons.get("given_names") or [])

    def lookup(self, host: str | None) -> tuple[bool, str | None]:
        """(está en el catálogo, organización o None si se declaró desconocida)."""
        known, name, _ = self.lookup_basis(host)
        return known, name

    def lookup_basis(self, host: str | None) -> tuple[bool, str | None, str | None]:
        """Como lookup(), más la fuente que resolvió la organización (v1.4.10): «alias» | «catalogo» | None."""
        host = (host or "").lower()
        for suffix, name in self._aliases:
            if host == suffix or host.endswith("." + suffix):
                return True, name, "alias"
        for suffix, name in self._suffixes:
            if host == suffix or host.endswith("." + suffix):
                return True, name, "catalogo"
        return False, None, None

    def is_person(self, name: str, domains=(), legal_name: str | None = None) -> bool:
        """¿El nombre de esta entidad parece el de una persona natural? Ver el orden en organizations.yaml."""
        if not self._enabled or not isinstance(name, str) or _fold(name) in self._not_persons:
            return False
        tokens = name.split()
        if not 2 <= len(tokens) <= 4 or not all(_NAME_TOKEN.match(token) for token in tokens):
            return False
        words = [_fold(token).strip(".") for token in tokens]
        legal_words = [_fold(token).strip(".,") for token in (legal_name or name).split()]
        if any(word in self._legal for word in legal_words):
            return False
        if any(word in self._words for word in words + legal_words):
            return False
        if any(word in self._given for word in words):
            return True
        if len(domains) >= 3:
            return False
        labels = [re.sub(r"[^a-z0-9]", "", str(domain).lower().split(".")[0]) for domain in domains]
        compact = "".join(re.sub(r"[^a-z0-9]", "", word) for word in words)
        for label in labels:
            if not label:
                continue
            if label in compact or compact in label or any(len(word) >= 4 and word in label for word in words):
                return False
        return True

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
        # Nombre legal de cada entidad (el mapa de DDG lo trae aparte del nombre para mostrar).
        self._legal_names: dict[str, str] = {}
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
        # Catálogo propio (v1.4.5): organizaciones por sufijo de host y nombres de persona que no se muestran.
        catalog_path = pathlib.Path(data_dir) / "organizations.yaml"
        try:
            catalog_bytes = catalog_path.read_bytes()
            aliases = self._read_aliases(pathlib.Path(data_dir) / "org_aliases.yaml", digest)
            self.catalog = OrganizationCatalog(yaml.safe_load(catalog_bytes.decode("utf-8")) or {}, aliases)
            digest.update(hashlib.sha256(catalog_bytes).hexdigest().encode())
        except (OSError, ValueError, yaml.YAMLError) as exc:
            logger.warning("organization_catalog_unavailable", extra={"error_type": type(exc).__name__})
            self.catalog = OrganizationCatalog()
        by_name: dict[str, list[str]] = {}
        for domain, name in self._entities.items():
            by_name.setdefault(name, []).append(domain)
        self.persons = frozenset(name for name, domains in by_name.items()
                                 if self.catalog.is_person(name, domains, self._legal_names.get(name)))
        digest.update(license_profile.encode() if license_profile != "no_comercial" else b"")
        self.version = digest.hexdigest()[:16]

    @staticmethod
    def _read_aliases(path: pathlib.Path, digest) -> dict:
        """Alias de organización (v1.4.6). Sin el archivo, ninguno: el análisis sigue igual que antes."""
        try:
            raw = path.read_bytes()
        except OSError:
            return {}
        try:
            aliases = yaml.safe_load(raw.decode("utf-8")) or {}
        except (ValueError, yaml.YAMLError) as exc:
            logger.warning("org_aliases_unavailable", extra={"error_type": type(exc).__name__})
            return {}
        digest.update(hashlib.sha256(raw).hexdigest().encode())
        return aliases if isinstance(aliases, dict) else {}

    def _add_engine(self, list_id: str, path: pathlib.Path) -> None:
        filter_set = adblock.FilterSet(debug=True)  # debug: conserva el texto de la regla
        filter_set.add_filter_list(path.read_text(encoding="utf-8", errors="replace"))
        # optimize=False (v1.5.1): el motor optimizado une reglas parecidas en un solo filtro y devuelve el bloque
        # completo («/gtm.js <+> /gtm/gtm- <+> …»); sin optimizar devuelve la regla concreta que coincidió. Las
        # coincidencias son las mismas.
        self._engines.append((list_id, adblock.Engine(filter_set, optimize=False)))

    def _load_ddg_entities(self, path: pathlib.Path) -> None:
        """Formato de Tracker Radar: {entidad: {displayName, properties: [dominio, ...]}}."""
        for name, entry in json.loads(path.read_text(encoding="utf-8")).items():
            if not isinstance(entry, dict):
                continue
            display = entry.get("displayName") or name
            self._legal_names.setdefault(str(display)[:200], str(name))
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
        """Organización dueña del dominio, o "no_disponible" (nunca se inventa ni se nombra a una persona)."""
        if not registrable_domain:
            return UNKNOWN_ENTITY
        domain = registrable_domain.lower()
        known, name = self.catalog.lookup(domain)
        if known:
            return name or UNKNOWN_ENTITY
        name = self._entities.get(domain, UNKNOWN_ENTITY)
        return UNKNOWN_ENTITY if name in self.persons else name

    def entity_basis(self, registrable_domain: str | None) -> str | None:
        """Qué resolvió la organización de entity() (v1.4.10): «alias» (org_aliases.yaml), «catalogo» (organizations.yaml),
        «mapa_entidades» (lista de entidades) o None si no hay organización."""
        if self.entity(registrable_domain) == UNKNOWN_ENTITY:
            return None
        known, _, basis = self.catalog.lookup_basis((registrable_domain or "").lower())
        return basis if known else "mapa_entidades"

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
