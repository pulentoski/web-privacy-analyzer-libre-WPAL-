"""Giro (tipo de servicio) de una organización o un dominio (v1.2.1, point 5).

CONTEXTO (Inferencia): a qué se dedica normalmente el servicio, no qué hizo en esta visita. Los
datos viven en data/service_types.yaml (la misma fuente que usa el worker). Si algo no está, el
giro es "tipo no identificado". Se muestra en Rastreadores, Fingerprinting, Panel y reportes.
"""

import logging
import pathlib
from functools import lru_cache

import yaml

from app.config import get_settings

logger = logging.getLogger(__name__)
UNKNOWN_SERVICE = "tipo no identificado"
UNKNOWN_ENTITY = "no_disponible"


class ServiceTypes:
    def __init__(self, raw: dict | None = None) -> None:
        raw = raw or {}
        self._by_entity: dict[str, dict] = {}
        self._by_domain: dict[str, dict] = {}
        # Patrones «host/ruta» (v1.4.2): un producto concreto dentro de una organización (p. ej. el pixel de Meta).
        self._by_url: list[tuple[str, dict]] = []
        for type_id, spec in (raw.get("types") or {}).items():
            if not isinstance(spec, dict):
                continue
            info = {"type": str(type_id), "label": str(spec.get("label") or UNKNOWN_SERVICE)}
            for entity in spec.get("entities") or []:
                if isinstance(entity, str):
                    self._by_entity.setdefault(entity, info)
            for domain in spec.get("domains") or []:
                if isinstance(domain, str):
                    self._by_domain.setdefault(domain.lower(), info)
            for pattern in spec.get("urls") or []:
                if isinstance(pattern, str) and pattern:
                    self._by_url.append((pattern.lower(), info))

    def _domain_match(self, value: str | None) -> dict | None:
        if not value:
            return None
        value = value.lower()
        if value in self._by_domain:
            return self._by_domain[value]
        return next((info for known, info in self._by_domain.items() if value.endswith("." + known)), None)

    def _url_match(self, urls) -> dict | None:
        hits: dict[str, tuple[int, dict]] = {}
        total = 0
        for url in urls or []:
            if not isinstance(url, str):
                continue
            # Se compara «host/ruta», sin esquema ni query.
            target = url.split("://", 1)[-1].split("?", 1)[0].lower()
            for pattern, info in self._by_url:
                if pattern in target:
                    hits[info["type"]] = (hits.get(info["type"], (0, info))[0] + 1, info)
                    break
            total += 1
        # v1.4.5: un grupo de URLs de varios productos (p. ej. todo Google) solo toma el giro de un
        # patrón si la mayoría de sus URLs lo cumple; con una sola URL basta que coincida.
        count, info = max(hits.values(), key=lambda item: item[0], default=(0, None))
        return info if count * 2 > total else None

    def of(self, *, entity: str | None = None, domain: str | None = None, urls=None) -> dict | None:
        by_url = self._url_match(urls)
        if by_url is not None:
            return by_url
        if entity and entity != UNKNOWN_ENTITY and entity in self._by_entity:
            return self._by_entity[entity]
        return self._domain_match(domain)


@lru_cache
def service_types() -> ServiceTypes:
    try:
        raw = yaml.safe_load((pathlib.Path(get_settings().data_dir) / "service_types.yaml").read_text(encoding="utf-8"))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        logger.warning("service_types_unavailable", extra={"error_type": type(exc).__name__})
        raw = {}
    return ServiceTypes(raw)
