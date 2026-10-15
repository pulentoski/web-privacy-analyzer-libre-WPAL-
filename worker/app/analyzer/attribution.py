"""v1.4.6 (docs/adr/033): librerías servidas por un CDN público y propósito de las cookies por su nombre.

Datos en data/organizations.yaml §public_cdns y data/cookie_purposes.yaml. Lo que se lee de la URL o del
nombre de una cookie viene del sitio analizado: es texto no confiable, acotado aquí.
"""

import fnmatch
import re
from urllib.parse import unquote, urlsplit

MAX_LIBRARY_CHARS = 80
# Nombre de paquete de npm o de repositorio: letras, dígitos, punto, guion y guion bajo (y «@scope/»).
_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,79}$")


class PublicCdns:
    """Atribuye un recurso de un CDN público a la librería que sirve, no a la empresa del CDN."""

    def __init__(self, raw: list | None = None, benign=None) -> None:
        self._by_host: dict[str, dict] = {}
        for entry in raw or []:
            if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
                continue
            prefixes = [(str(item.get("prefix")), int(item.get("segments") or 1))
                        for item in entry.get("prefixes") or [] if isinstance(item, dict) and item.get("prefix")]
            for host in entry.get("hosts") or []:
                self._by_host[str(host).lower()] = {"name": entry["name"][:40], "prefixes": prefixes}
        self._benign = benign

    def of(self, url: str | None, host: str | None) -> dict | None:
        """{cdn, library, label, benign, benign_label} o None si el host no es un CDN público declarado."""
        cdn = self._by_host.get((host or "").lower())
        if cdn is None:
            return None
        try:
            path = unquote(urlsplit(url or "").path)
        except ValueError:
            path = ""
        library = None
        for prefix, segments in cdn["prefixes"]:
            if path.startswith(prefix):
                library = _package(path[len(prefix):], segments)
                if library:
                    break
        benign_label = self._benign.match(url) if self._benign is not None else None
        label = (f"librería {library} en CDN público ({cdn['name']})" if library
                 else f"librería en CDN público ({cdn['name']})")
        return {"cdn": cdn["name"], "library": library, "label": label, "benign": benign_label is not None,
                "benign_label": benign_label}


def _package(rest: str, segments: int) -> str | None:
    """Nombre del paquete al inicio de la ruta, sin versión: «bootstrap@5.3.3/dist» → «bootstrap»."""
    parts = [part for part in rest.split("/") if part]
    if parts and parts[0].startswith("@") and segments == 1:
        segments = 2  # paquete con scope de npm: @scope/nombre
    if len(parts) < segments:
        return None
    names = []
    for index, part in enumerate(parts[:segments]):
        if index == segments - 1:
            # La versión va tras «@» (npm, gh) o es el tramo siguiente (cdnjs): aquí solo se corta la primera.
            head, _, _ = part[1:].partition("@") if part.startswith("@") else part.partition("@")
            part = ("@" + head) if part.startswith("@") else head
        bare = part[1:] if part.startswith("@") else part
        if not _SEGMENT.match(bare):
            return None
        names.append(part)
    name = "/".join(names)
    return name[:MAX_LIBRARY_CHARS] if name else None


class CookiePurposes:
    """Propósito de una cookie por su nombre conocido (INFERENCIA)."""

    UNCLASSIFIED = "sin_clasificar"

    def __init__(self, raw: dict | None = None) -> None:
        raw = raw or {}
        purposes = raw.get("purposes") or {}
        order = [str(name) for name in raw.get("order") or purposes.keys()]
        self.labels = {str(key): str(value) for key, value in (raw.get("labels") or {}).items()}
        self._rules: list[tuple[str, str]] = [
            (str(pattern).lower(), purpose) for purpose in order for pattern in purposes.get(purpose) or [] if pattern]
        self.purposes = tuple(order)

    def of(self, name: str | None) -> str:
        lowered = str(name or "").lower()
        for pattern, purpose in self._rules:
            if (fnmatch.fnmatchcase(lowered, pattern) if "*" in pattern else lowered == pattern):
                return purpose
        return self.UNCLASSIFIED

    def label(self, purpose: str) -> str:
        return self.labels.get(purpose, purpose)
