"""Parámetros de seguimiento en la URL de entrada (v1.2).

Una URL copiada de un anuncio o de un correo suele traer identificadores de clic (gclid,
fbclid…) y etiquetas de campaña (utm_*). Si se escanea tal cual, el sitio los reenvía a sus
proveedores y el resultado describe esa visita "etiquetada", no una visita directa. Por
defecto se quitan antes de escanear; se guardan la URL original y la escaneada.

Solo se toca la query: el resto de la URL y los demás parámetros quedan byte a byte iguales.
"""

import logging
import pathlib
from urllib.parse import unquote_plus, urlsplit, urlunsplit

import yaml

logger = logging.getLogger(__name__)

# Respaldo embebido: si data/tracking_params.yaml falta o no se puede leer, la limpieza
# sigue funcionando con esta lista mínima (nunca se queda sin quitar lo más común).
_FALLBACK_PARAMS = frozenset(
    {"gclid", "gclsrc", "gbraid", "wbraid", "dclid", "fbclid", "msclkid", "ttclid", "yclid", "_gl", "mc_eid"}
)
_FALLBACK_PREFIXES = ("utm_",)
MAX_REPORTED = 40


def _load(data_dir: str | pathlib.Path) -> tuple[frozenset, tuple]:
    """Lee la lista de data/tracking_params.yaml; ante cualquier fallo, usa el respaldo embebido."""
    try:
        raw = yaml.safe_load((pathlib.Path(data_dir) / "tracking_params.yaml").read_text(encoding="utf-8")) or {}
        exact = frozenset(str(name).lower() for name in (raw.get("exact") or []))
        prefixes = tuple(str(prefix).lower() for prefix in (raw.get("prefixes") or []))
        if not exact and not prefixes:
            raise ValueError("tracking_params.yaml vacío")
        return exact, prefixes
    except (OSError, ValueError, yaml.YAMLError) as exc:
        logger.warning("tracking_params_unavailable", extra={"error_type": type(exc).__name__})
        return _FALLBACK_PARAMS, _FALLBACK_PREFIXES


def _data_dir() -> str:
    try:
        from app.config import get_settings

        return get_settings().data_dir
    except Exception:  # fuera de la app (p. ej. un test directo): usa el respaldo embebido
        return "/app/data"


TRACKING_PARAMS, TRACKING_PREFIXES = _load(_data_dir())


def is_tracking_param(name: str) -> bool:
    name = name.lower()
    return name in TRACKING_PARAMS or name.startswith(TRACKING_PREFIXES)


def clean_url(url: str) -> tuple[str, list[str]]:
    """(URL sin parámetros de seguimiento, nombres quitados en orden de aparición y sin repetir)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url, []
    if not parts.query:
        return url, []
    kept, removed = [], []
    for segment in parts.query.split("&"):
        name = unquote_plus(segment.split("=", 1)[0])
        if segment and is_tracking_param(name):
            if name.lower() not in removed and len(removed) < MAX_REPORTED:
                removed.append(name.lower())
        elif segment:
            kept.append(segment)
    if not removed:
        return url, []
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "&".join(kept), parts.fragment)), removed


def inspect(url: str) -> dict:
    cleaned, removed = clean_url(url)
    return {"url": url, "cleaned_url": cleaned, "tracking_params": removed, "has_tracking_params": bool(removed)}


def describe(url: str, original_url: str | None) -> dict:
    """Campos que acompañan a un scan o a un grupo: URL original, escaneada y qué se quitó."""
    original = original_url or url
    removed = clean_url(original)[1] if original != url else []
    return {"original_url": original, "url_cleaned": bool(removed), "removed_params": removed}
