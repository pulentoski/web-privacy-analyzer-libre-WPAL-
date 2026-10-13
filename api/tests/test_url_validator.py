import asyncio
import os

import pytest

from app.security.url_validator import UrlValidationError, parse_legacy_ipv4, validate_url

# DNS simulado: los tests unitarios no dependen de la red.
FAKE_DNS = {
    "example.com": ["93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"],
    "localtest.me": ["127.0.0.1"],
    "10.0.0.1.nip.io": ["10.0.0.1"],
    "mixed.example.org": ["93.184.215.14", "192.168.1.10"],
    "mapped.example.org": ["::ffff:127.0.0.1"],
    "v6only.example.org": ["2606:2800:21f:cb07:6820:80da:af6b:8b2c"],
}


async def fake_resolver(host: str) -> list[str]:
    if host not in FAKE_DNS:
        raise OSError("NXDOMAIN")
    return FAKE_DNS[host]


def check(url: str):
    return asyncio.run(validate_url(url, resolver=fake_resolver))


def env(name: str) -> str:
    value = os.environ.get(name)
    assert value, f"Falta la variable de entorno {name} (ver .env.example)"
    return value


# Mismos casos que tests/ssrf del worker (SPEC §Seguridad).
BLOCKED = [
    "http://127.0.0.1",
    "http://localhost",
    "http://127.1",
    "http://2130706433",
    "http://0x7f000001",
    "http://0.0.0.0",
    "http://[::1]",
    "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.1",
    "http://192.168.1.1",
    "http://db:5432",
    "http://api:8000/health",
    "http://egress-proxy:3128",
    "http://localtest.me",
    "http://10.0.0.1.nip.io",
    "https://example.com:22",
]


@pytest.mark.parametrize("url", BLOCKED)
def test_blocked(url):
    with pytest.raises(UrlValidationError):
        check(url)


@pytest.mark.parametrize("variable", ["LAN_GATEWAY", "HOST_LAN_IP", "INTERNAL_GATEWAY"])
def test_blocked_addresses_from_preflight(variable):
    with pytest.raises(UrlValidationError) as excinfo:
        check(f"http://{env(variable)}")
    assert excinfo.value.code == "IP_FORBIDDEN"


@pytest.mark.parametrize(
    "url",
    [
        "http://100.64.0.1",
        "http://172.16.0.1",
        "http://172.31.255.255",
        "http://192.0.0.1",
        "http://198.18.0.1",
        "http://198.19.255.255",
        "http://224.0.0.1",
        "http://240.0.0.1",
        "http://255.255.255.255",
        "http://0177.0.0.1",
        "http://0x7f.0.0.1",
        "http://127.0.0.1.",
        "http://LOCALHOST",
        "http://localhost.",
        "http://foo.localhost",
        "http://printer.local",
        "http://metadata.google.internal",
        "http://mixed.example.org",
        "http://mapped.example.org",
        "http://v6only.example.org",
        "http://[::ffff:127.0.0.1]",
        "http://[fe80::1]",
        "http://no-existe.example.org",
        "http://example.com:8080",
        "http://user:pass@example.com",
        "http://example.com@127.0.0.1",
        "http://127.0.0.1\\@example.com",
        "http://exa mple.com",
        "http://example.com\n",
        "http://1.2.3.4.5",
        "http://256.0.0.1",
        "http://",
        "ftp://example.com",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "gopher://example.com",
        "example.com",
        "",
        "http://example.com/" + "a" * 2100,
    ],
)
def test_blocked_extra(url):
    with pytest.raises(UrlValidationError):
        check(url)


@pytest.mark.parametrize(
    "url,port",
    [
        ("https://example.com", 443),
        ("http://example.com", 80),
        ("https://example.com:443/path?q=1#f", 443),
        ("https://EXAMPLE.com.", 443),
    ],
)
def test_allowed(url, port):
    result = check(url)
    assert result.host == "example.com"
    assert result.port == port
    assert result.resolved_ips == ("93.184.215.14",)


def test_public_ip_literal_allowed():
    assert check("http://93.184.215.14").resolved_ips == ("93.184.215.14",)


@pytest.mark.parametrize(
    "url,code",
    [
        ("http://127.0.0.1", "IP_FORBIDDEN"),
        ("http://localhost", "HOST_FORBIDDEN"),
        ("http://db:5432", "PORT_NOT_ALLOWED"),
        ("http://db", "HOST_FORBIDDEN"),
        ("http://[::1]", "IPV6_NOT_SUPPORTED"),
        ("https://example.com:22", "PORT_NOT_ALLOWED"),
        ("http://localtest.me", "IP_FORBIDDEN"),
        ("ftp://example.com", "SCHEME_NOT_ALLOWED"),
        ("http://user@example.com", "CREDENTIALS_NOT_ALLOWED"),
        ("http://no-existe.example.org", "DNS_RESOLUTION_FAILED"),
    ],
)
def test_error_codes(url, code):
    with pytest.raises(UrlValidationError) as excinfo:
        check(url)
    assert excinfo.value.code == code


@pytest.mark.parametrize(
    "host,expected",
    [
        ("127.1", "127.0.0.1"),
        ("2130706433", "127.0.0.1"),
        ("0x7f000001", "127.0.0.1"),
        ("0177.0.0.1", "127.0.0.1"),
        ("10.1", "10.0.0.1"),
        ("192.168.257", "192.168.1.1"),
        ("1.2.3.4", "1.2.3.4"),
    ],
)
def test_legacy_ipv4_forms(host, expected):
    assert str(parse_legacy_ipv4(host)) == expected


def test_legacy_ipv4_non_numeric_is_none():
    assert parse_legacy_ipv4("example.com") is None


def test_dns_timeout_is_rejected(monkeypatch):
    monkeypatch.setattr("app.security.url_validator.DNS_TIMEOUT_S", 0.05)

    async def slow_resolver(host):
        await asyncio.sleep(1)
        return ["93.184.215.14"]

    with pytest.raises(UrlValidationError) as excinfo:
        asyncio.run(validate_url("http://example.com", resolver=slow_resolver))
    assert excinfo.value.code == "DNS_RESOLUTION_FAILED"


# --- Sitio de fixtures (F2, docs/adr/003) ---


async def _must_not_resolve(host: str) -> list[str]:
    raise AssertionError(f"no debería resolverse {host}")


@pytest.mark.parametrize("host", ["site.fixtures.test", "tracker-a.fixtures.test", "cdn-b.fixtures.test"])
def test_fixture_hosts_rejected_by_default(host):
    async def unresolvable(name: str) -> list[str]:
        raise OSError("NXDOMAIN")

    with pytest.raises(UrlValidationError):
        asyncio.run(validate_url(f"http://{host}/", resolver=unresolvable))


def test_fixture_hosts_accepted_only_with_flag():
    validated = asyncio.run(
        validate_url("http://site.fixtures.test/flood", resolver=_must_not_resolve, allow_fixtures=True)
    )
    assert validated.host == "site.fixtures.test" and validated.port == 80


@pytest.mark.parametrize(
    "url",
    [
        "https://site.fixtures.test/",  # solo HTTP plano
        "http://site.fixtures.test:8080/",  # solo puerto 80
        "http://otro.fixtures.test/",  # solo los tres nombres exactos
        "http://site.fixtures.test.evil.example/",
        "http://127.0.0.1/",  # el flag no relaja nada más
        "http://db/",
    ],
)
def test_fixture_flag_does_not_relax_anything_else(url):
    async def private(name: str) -> list[str]:
        return ["172.30.4.10"]

    with pytest.raises(UrlValidationError):
        asyncio.run(validate_url(url, resolver=private, allow_fixtures=True))
