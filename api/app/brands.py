"""Marca y dueño de una organización (v1.5.1): «LinkedIn (Microsoft)».

Solo presentación (data/brands.yaml). La organización (`entity`) sigue siendo la del análisis: agrupa, decide
«misma organización» y es la que se guarda. La marca se informa aparte (`brand`) y solo si el dueño resuelto para
ese dominio es exactamente el `owner` declarado.
"""

import pathlib
from functools import lru_cache

import yaml

from app.config import get_settings


@lru_cache
def _brands() -> dict[str, tuple[str, str]]:
    """Dominio registrable → (marca, dueño)."""
    raw = yaml.safe_load((pathlib.Path(get_settings().data_dir) / "brands.yaml").read_text(encoding="utf-8")) or {}
    table = {}
    for brand, rule in (raw.get("brands") or {}).items():
        for domain in rule["domains"]:
            table[str(domain).lower()] = (str(brand), str(rule["owner"]))
    return table


def _domain_of(host: str, domains: dict) -> str | None:
    host = host.lower().rstrip(".")
    while host:
        if host in domains:
            return host
        host = host.partition(".")[2]
    return None


def brand(entity: str | None, domain: str | None) -> str | None:
    """Marca del dominio (o host) si difiere de su dueño y el dueño coincide con `entity`; si no, None."""
    if not entity or not domain:
        return None
    table = _brands()
    key = _domain_of(domain, table)
    if key is None:
        return None
    name, owner = table[key]
    return name if owner == entity and name != entity else None


def group_brand(entity: str | None, domains: list[str]) -> str | None:
    """Marca de un grupo de dominios de una organización: solo si todos son de la misma marca."""
    found = {brand(entity, domain) for domain in domains or []}
    return found.pop() if len(found) == 1 else None


def label(entity: str | None, domain: str | None) -> str | None:
    """«Marca (Dueño)» cuando difieren; si no, la organización tal cual."""
    name = brand(entity, domain)
    return f"{name} ({entity})" if name else entity


def group_label(entity: str | None, domains: list[str]) -> str | None:
    """«Marca (Dueño)» de un grupo cuando todos sus dominios son de esa marca; si no, la organización."""
    name = group_brand(entity, domains)
    return f"{name} ({entity})" if name else entity
