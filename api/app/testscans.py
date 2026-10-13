"""Scans que no son de un sitio real: el sitio de fixtures o los creados por una suite de tests."""

from urllib.parse import urlsplit

# Nombres reservados para pruebas y documentación (RFC 2606 / RFC 6761). Un scan de un host así
# no es de un sitio real: es del sitio de fixtures (*.fixtures.test) o lo creó una suite de tests.
TEST_SUFFIXES = (".test", ".example", ".invalid", ".localhost")
TEST_HOSTS = frozenset({"localhost", "example.com", "example.net", "example.org"})


def is_test_scan(url: str | None) -> bool:
    """True si el scan es del sitio de fixtures o de un nombre reservado para pruebas."""
    try:
        host = (urlsplit(url or "").hostname or "").rstrip(".").lower()
    except ValueError:
        return False
    if not host:
        return False
    return host in TEST_HOSTS or host.endswith(TEST_SUFFIXES) or any(host.endswith("." + name) for name in TEST_HOSTS)
