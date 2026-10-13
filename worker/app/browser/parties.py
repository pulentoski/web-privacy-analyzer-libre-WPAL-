"""first-party / third-party por dominio registrable (eTLD+1).

Usa la Public Suffix List empaquetada con tldextract. Nunca se descarga en
runtime: el worker no tiene salida directa y la PSL remota sería un dato externo
sin versionar.
"""

import ipaddress

import tldextract

from app.config import settings

# Solo en tests: trata `fixtures.test` como sufijo público (igual que github.io), para
# que site/tracker-a/cdn-b.fixtures.test sean dominios registrables distintos (ADR 003).
FIXTURE_SUFFIXES = ("fixtures.test",)

_extract = tldextract.TLDExtract(
    suffix_list_urls=(),
    cache_dir=None,
    # Sufijos privados (github.io, herokuapp.com...): cada cliente es una parte distinta.
    include_psl_private_domains=True,
    extra_suffixes=FIXTURE_SUFFIXES if settings.allow_fixtures else (),
)


def registrable_domain(host: str | None) -> str | None:
    """Dominio registrable de un host, o None si no hay host. Las IP se devuelven tal cual."""
    if not isinstance(host, str):
        return None
    host = host.strip().strip("[]").rstrip(".").lower()
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        result = _extract(host)
    except Exception:  # host arbitrario del sitio: nunca debe tumbar la captura
        return host
    if result.suffix:
        # Sin `domain`, el host es él mismo un sufijo público.
        return f"{result.domain}.{result.suffix}" if result.domain else host
    # TLD fuera de la PSL: aplica la regla implícita "*" (eTLD = última etiqueta).
    return ".".join(host.split(".")[-2:])


def is_third_party(host: str | None, first_party_domains: set[str]) -> bool | None:
    domain = registrable_domain(host)
    if domain is None:
        return None
    return domain not in first_party_domains
