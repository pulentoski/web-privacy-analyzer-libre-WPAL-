"""Mi exposición (F6): vista del servidor, IP offline, sala en memoria y privacidad."""

import hashlib
import json
import uuid
import re
import logging

import pytest
from pydantic import SecretStr
from sqlalchemy import text

from app.config import get_settings
from app.db import SessionLocal
from app.exposure_room import ATTRIBUTES, Room, room
from app.ipintel import IpIntel, classify
from app.routes import exposure

SECRET_VALUE = "valor-secreto-del-visitante-123"


def h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@pytest.fixture(autouse=True)
def clean_room():
    room.purge()
    exposure.compare_limiter.reset()
    yield
    room.purge()


def as_proxy(monkeypatch, forwarded):
    """Simula que la request llega por el nginx de confianza con esa IP de cliente."""
    monkeypatch.setattr(get_settings(), "trusted_proxies", "testclient")  # no parsea: se parchea client_ip
    monkeypatch.setattr(exposure, "client_ip", lambda request: forwarded)


# --- Qué ve el servidor ---


def test_server_view_returns_headers_and_marks_nothing_stored(client):
    response = client.get(
        "/api/exposure/server",
        headers={"User-Agent": "NavegadorDePrueba/1.0", "Accept-Language": "es-CL,es;q=0.9", "DNT": "1", "Sec-GPC": "1",
                 "Sec-CH-UA": '"Chromium";v="153"', "Sec-Fetch-Site": "same-origin", "X-Otra": "no debe salir"},
    )
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert body["stored"] is False
    assert "aunque JavaScript esté apagado" in body["note"]
    headers = body["headers"]
    assert headers["user-agent"] == "NavegadorDePrueba/1.0" and headers["accept-language"] == "es-CL,es;q=0.9"
    assert headers["dnt"] == "1" and headers["sec-gpc"] == "1" and headers["sec-fetch-site"] == "same-origin"
    assert headers["sec-ch-ua-platform"] is None  # no enviada: null, no cadena vacía
    assert "x-otra" not in headers and set(headers) == set(exposure.HEADERS)


@pytest.mark.parametrize(
    "ip, kind, is_public, fragment",
    [
        ("192.168.0.15", "private", False, "IP privada (misma red local)"),
        ("10.1.2.3", "private", False, "privada"),
        ("172.30.1.1", "private", False, "Acceso local: el servidor ve la red interna de Docker (172.30.x)"),
        ("127.0.0.1", "loopback", False, "mismo equipo"),
        ("100.64.3.4", "cgnat", False, "no es su IP pública"),
        ("169.254.1.1", "link_local", False, "enlace local"),
        ("8.8.8.8", "public", True, "IP pública observada"),
    ],
)
def test_observed_ip_is_labelled_honestly(client, monkeypatch, ip, kind, is_public, fragment):
    as_proxy(monkeypatch, ip)
    body = client.get("/api/exposure/server").json()
    assert body["ip"]["observed"] == ip and body["ip"]["kind"] == kind and body["ip"]["is_public"] is is_public
    assert fragment in body["ip"]["label"]
    if not is_public:
        # Una IP que no es pública nunca se presenta como tal ni recibe ubicación.
        assert "IP pública observada" not in body["ip"]["label"]
        assert body["ip_intel"]["applies"] is False and "no aplica" in body["ip_intel"]["note"]
        assert "country" not in body["ip_intel"]


@pytest.mark.parametrize(
    "ip, access",
    [("172.30.1.1", "local"), ("172.30.4.200", "local"), ("127.0.0.1", "local"), ("::1", "local"),
     ("192.168.0.15", "lan"), ("10.1.2.3", "lan"), ("172.31.0.5", "lan"), ("8.8.8.8", "public"), ("100.64.3.4", "other")],
)
def test_docker_gateway_and_loopback_are_local_access_not_the_visitor_ip(client, monkeypatch, ip, access):
    as_proxy(monkeypatch, ip)
    body = client.get("/api/exposure/server").json()["ip"]
    assert body["access"] == access
    if access == "local":
        # No se presenta como la IP de quien visita: se explica que es acceso local.
        assert body["label"].startswith("Acceso local:") and "se vería la IP real" in body["label"]
        assert body["is_public"] is False
    else:
        assert "Acceso local" not in body["label"]


def test_identifiability_levels_are_qualitative_and_justified(client):
    response = client.get("/api/exposure/identifiability")
    assert response.status_code == 200
    body = response.json()
    assert set(body["levels"]) == {"alto", "medio", "bajo"}
    assert "cualitativa" in body["note"]
    for name in ("canvas", "audio", "webgl", "fonts", "ua_client_hints"):
        assert body["attributes"][name]["level"] == "alto", name
    for name in ("screen", "timezone", "languages", "hardware_concurrency", "device_memory"):
        assert body["attributes"][name]["level"] == "medio", name
    for name in ("color_depth", "cookies_enabled"):
        assert body["attributes"][name]["level"] == "bajo", name
    entries = [*body["attributes"].values(), *body["headers"].values(), *body["connection"].values()]
    assert all(entry["level"] in body["levels"] and len(entry["rationale"]) > 15 for entry in entries)
    assert set(body["headers"]) == set(exposure.HEADERS)
    # Estimación cualitativa: sin cifras de entropía inventadas.
    assert "entropy" not in response.text and not re.search(r"\d+([.,]\d+)?\s*bits? de entrop", response.text)


def test_forwarded_header_from_untrusted_client_is_ignored(client):
    body = client.get("/api/exposure/server", headers={"X-Forwarded-For": "8.8.8.8"}).json()
    assert body["ip"]["observed"] != "8.8.8.8" and body["ip"]["source"] == "conexión directa"


# --- Inteligencia IP offline ---


def test_ip_classification():
    import ipaddress

    cases = {"192.168.1.1": "private", "10.0.0.1": "private", "172.16.5.5": "private", "127.0.0.1": "loopback",
             "169.254.0.1": "link_local", "100.64.0.1": "cgnat", "224.0.0.1": "reserved", "0.0.0.0": "reserved",
             "8.8.8.8": "public", "1.1.1.1": "public", "::1": "loopback", "fe80::1": "link_local", "fd00::1": "private"}
    for value, expected in cases.items():
        assert classify(ipaddress.ip_address(value)) == expected, value


@pytest.mark.needs_stack  # necesita la base de IP (DB-IP, no versionada); se omite en CI.
def test_offline_lookup_of_public_ips():
    intel = exposure.intel()
    google = intel.lookup("8.8.8.8")
    assert google["applies"] is True and google["country_code"] == "US"
    assert google["asn"] == "AS15169" and "Google" in google["organization"]
    assert google["attribution"] == "IP Geolocation by DB-IP" and google["attribution_url"] == "https://db-ip.com"
    assert "aproximado" in google["precision"] and "DB-IP Lite 20" in google["source"]
    # Nunca más precisión que el país.
    assert not {"city", "latitude", "longitude", "region"} & set(google)
    assert intel.lookup("::ffff:8.8.8.8")["asn"] == "AS15169"


@pytest.mark.parametrize("value", ["", "no-es-ip", "999.1.1.1", "8.8.8.8; DROP", None])
def test_lookup_never_raises_on_garbage(value):
    assert exposure.intel().lookup(value)["kind"] == "invalid"


def test_missing_database_is_no_disponible_not_invented(tmp_path):
    result = IpIntel(tmp_path).lookup("8.8.8.8")
    assert result["applies"] is True
    assert (result["country"], result["country_code"], result["asn"], result["organization"]) == ("no_disponible",) * 4


@pytest.mark.needs_stack  # necesita la base de IP (DB-IP, no versionada); se omite en CI.
def test_ip_lookup_endpoint(client):
    body = client.post("/api/exposure/ip-lookup", json={"ip": "1.1.1.1"}).json()
    assert body["stored"] is False and body["ip_intel"]["asn"] == "AS13335"
    private = client.post("/api/exposure/ip-lookup", json={"ip": "192.168.1.1"}).json()
    assert private["ip_intel"]["note"] == "no aplica (red privada)"
    assert client.post("/api/exposure/ip-lookup", json={"ip": "zz"}).json()["error_code"] == "INVALID_IP"
    assert client.post("/api/exposure/ip-lookup", json={"ip": "1.1.1.1", "extra": 1}).status_code == 422


# --- Comparación grupal de huellas ---


def payload(seed: str, **overrides) -> dict:
    return {"consent": True, "combined": h(f"combinada-{seed}"),
            "attributes": {"user_agent": h("ua-comun"), "screen": h(f"pantalla-{seed}"), "timezone": h("tz-comun")}, **overrides}


def test_compare_counts_shared_and_unique(client):
    first = client.post("/api/exposure/compare", json=payload("a")).json()
    assert first["participants"] == 1 and first["combined"] == {"same": 1, "unique": True}
    second = client.post("/api/exposure/compare", json=payload("b")).json()
    assert second["participants"] == 2 and second["combined"]["unique"] is True
    assert second["attributes"]["user_agent"] == {"same": 2, "reported": 2}
    assert second["attributes"]["screen"] == {"same": 1, "reported": 2}
    twin = client.post("/api/exposure/compare", json=payload("b")).json()
    assert twin["participants"] == 3 and twin["combined"] == {"same": 2, "unique": False}
    # Reenviar con el mismo participante actualiza, no suma.
    again = client.post("/api/exposure/compare", json=payload("b", participant=twin["participant"])).json()
    assert again["participants"] == 3 and again["participant"] == twin["participant"]


def test_compare_requires_consent(client):
    response = client.post("/api/exposure/compare", json=payload("a", consent=False))
    assert response.status_code == 400 and response.json()["error_code"] == "CONSENT_REQUIRED"
    assert client.post("/api/exposure/compare", json={k: v for k, v in payload("a").items() if k != "consent"}).status_code == 422
    assert room.count(3600) == 0


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p["attributes"].update(user_agent="Mozilla/5.0 (X11; Linux x86_64)"),  # valor en claro
        lambda p: p["attributes"].update(screen="1920x1080"),
        lambda p: p["attributes"].update(user_agent=h("x").upper()),
        lambda p: p["attributes"].update(user_agent=h("x")[:-1] + "g"),
        lambda p: p["attributes"].update(atributo_inventado=h("x")),
        lambda p: p.update(combined="192.168.0.15".ljust(64, "0").replace(".", "x")),
        lambda p: p.update(attributes={}),
    ],
)
def test_compare_accepts_hashes_only(client, mutate):
    body = payload("a")
    mutate(body)
    response = client.post("/api/exposure/compare", json=body)
    assert response.status_code == 400 and response.json()["error_code"] == "HASHES_ONLY"
    assert room.count(3600) == 0  # nada de un envío inválido queda guardado


def test_compare_rejects_extra_fields_and_oversized(client):
    assert client.post("/api/exposure/compare", json=payload("a", ip="1.2.3.4")).status_code == 422
    too_many = payload("a")
    too_many["attributes"] = {f"a{i}": h(str(i)) for i in range(len(ATTRIBUTES) + 1)}
    assert client.post("/api/exposure/compare", json=too_many).status_code == 422


def test_room_capacity_and_rate_limit(client, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "exposure_max_participants", 2)
    assert client.post("/api/exposure/compare", json=payload("a")).status_code == 200
    assert client.post("/api/exposure/compare", json=payload("b")).status_code == 200
    full = client.post("/api/exposure/compare", json=payload("c"))
    assert full.status_code == 429 and full.json()["error_code"] == "ROOM_FULL"
    monkeypatch.setattr(settings, "exposure_max_participants", 500)
    monkeypatch.setattr(settings, "exposure_rate_limit", 3)
    exposure.compare_limiter.reset()
    codes = [client.post("/api/exposure/compare", json=payload(str(i))).status_code for i in range(4)]
    assert codes == [200, 200, 200, 429]


def test_room_entries_expire(monkeypatch):
    local = Room()
    participant, _ = local.submit(h("c"), {"screen": h("s")}, None, ttl_s=3600, capacity=10)
    assert local.count(3600) == 1 and participant
    assert local.count(0) == 0  # TTL vencido: desaparece


def test_purge_needs_the_presenter_token(client, monkeypatch):
    settings = get_settings()
    client.post("/api/exposure/compare", json=payload("a"))
    monkeypatch.setattr(settings, "exposure_presenter_token", SecretStr(""))
    assert client.post("/api/exposure/purge").json()["error_code"] == "PURGE_DISABLED"
    monkeypatch.setattr(settings, "exposure_presenter_token", SecretStr("token-del-presentador"))
    for headers in ({}, {"X-Presenter-Token": "otro"}, {"X-Presenter-Token": "token-del-presentador "}):
        assert client.post("/api/exposure/purge", headers=headers).json()["error_code"] == "FORBIDDEN"
    assert room.count(3600) == 1
    before = client.get("/api/exposure/room").json()
    done = client.post("/api/exposure/purge", headers={"X-Presenter-Token": "token-del-presentador"})
    assert done.status_code == 200 and done.json() == {"purged": 1, "participants": 0}
    after = client.get("/api/exposure/room").json()
    assert after["participants"] == 0 and after["salt"] != before["salt"]  # sala nueva: hashes viejos no comparables


def test_room_info(client):
    info = client.get("/api/exposure/room").json()
    assert info["participants"] == 0 and info["ttl_s"] == 7200 and info["capacity"] == 500
    assert len(info["salt"]) == 32 and info["attributes"] == list(ATTRIBUTES)


# --- Privacidad: nada se guarda ---


def test_nothing_from_exposure_reaches_the_database(client):
    async def snapshot():
        async with SessionLocal() as session:
            tables = (await session.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY 1"))).scalars().all()
            counts = {}
            for table in tables:
                counts[table] = await session.scalar(text(f'SELECT count(*) FROM "{table}"'))
            return tables, counts

    tables, before = client.portal.call(snapshot)
    assert not [table for table in tables if "exposure" in table or "room" in table or "visitor" in table]
    client.get("/api/exposure/server", headers={"User-Agent": SECRET_VALUE})
    client.post("/api/exposure/ip-lookup", json={"ip": "8.8.4.4"})
    client.post("/api/exposure/compare", json=payload("privacidad"))
    client.get("/api/exposure/room")
    _, after = client.portal.call(snapshot)
    changed = {table: (before[table], after[table]) for table in before if before[table] != after[table] and table != "worker_heartbeats"}
    # Solo podrían cambiar tablas del worker en paralelo; ninguna es de exposición.
    assert not [table for table in changed if table not in ("jobs",) and not table.startswith(("scan_", "fp_", "request_", "parameters", "decoded_", "findings", "site_"))], changed


def test_logs_never_contain_client_values(client, caplog):
    caplog.set_level(logging.DEBUG)
    hashed = h("hash-que-tampoco-debe-loguearse")
    client.get(f"/api/exposure/server?filtrado={SECRET_VALUE}", headers={"User-Agent": SECRET_VALUE, "X-Forwarded-For": "203.0.113.77"})
    client.post("/api/exposure/ip-lookup", json={"ip": "203.0.113.77"})
    client.post("/api/exposure/compare", json={"consent": True, "combined": hashed, "attributes": {"screen": hashed}})
    client.post("/api/exposure/compare", json={"consent": True, "combined": SECRET_VALUE, "attributes": {"screen": SECRET_VALUE}})
    client.post("/api/exposure/ip-lookup", json={"ip": SECRET_VALUE})
    records = [record for record in caplog.records if record.name.startswith("app")]
    assert len([r for r in records if r.name == "app.access"]) == 5
    dumped = " ".join(str(record.__dict__) for record in records)
    for secret in (SECRET_VALUE, "203.0.113.77", hashed, "filtrado", "testclient"):
        assert secret not in dumped, f"el log contiene {secret!r}"
    # Lo único que queda de cada visita: método, ruta y estado.
    access = [r for r in records if r.name == "app.access"][0]
    assert (access.method, access.path, access.status_code) == ("GET", "/api/exposure/server", 200)


def test_room_ttl_through_the_api(client, monkeypatch):
    settings = get_settings()
    client.post("/api/exposure/compare", json=payload("a"))
    assert client.get("/api/exposure/room").json()["participants"] == 1
    monkeypatch.setattr(settings, "exposure_ttl_s", 0)  # todo lo guardado ya venció
    assert client.get("/api/exposure/room").json()["participants"] == 0
    fresh = client.post("/api/exposure/compare", json=payload("b")).json()
    assert fresh["participants"] == 1 and fresh["combined"]["unique"] is True


def test_scan_usage_names_readers_and_recipients_with_evidence(client):
    """Sobre los scans que haya guardados: "read" enlaza a la llamada y "sent" a la request."""
    body = client.get("/api/exposure/scan-usage").json()
    for entry in body["attributes"].values():
        for item in entry["read"]:
            assert item["example"]["call_ref"] and item["example"]["request_ref"] is None
        for item in entry["sent"]:
            # Una exfiltración siempre enlaza a la request donde se vio el valor.
            assert item["example"]["request_ref"]


@pytest.mark.parametrize(
    "url, excluded",
    [("http://site.fixtures.test/fp/", True), ("http://tracker-a.fixtures.test/t.js", True), ("http://site.example/", True),
     ("https://www.example.com/a", True), ("http://algo.test:8080/", True), ("http://localhost/", True), ("http://x.invalid/", True),
     ("https://www.linkedin.com/", False), ("https://es.aliexpress.com/?a=1", False), ("https://fixtures.test.cl/", False),
     ("https://contest.org/", False), ("https://myexample.com/", False), ("", False), (None, False), ("no es una url", False)],
)
def test_fixture_and_test_scans_are_recognised(url, excluded):
    assert exposure.is_test_scan(url) is excluded


def test_scan_usage_excludes_fixture_and_test_scans(client, monkeypatch):
    """Tres scans con una exfiltración cada uno: solo el del sitio real aparece en el cruce."""
    # Sin tope: los scans reales de la instalación pueden ocupar los 10 primeros puestos.
    monkeypatch.setattr(exposure, "TOP_USAGE", 10_000)
    tag = uuid.uuid4().hex[:10]
    jobs = {
        "real": (uuid.uuid4(), f"https://www.sitio-real-{tag}.cl/"),
        "fixture": (uuid.uuid4(), "http://site.fixtures.test/fp/"),
        "test": (uuid.uuid4(), "http://site.example/"),
    }
    labels = {kind: f"receptor-{kind}-{tag}.net" for kind in jobs}

    async def insert():
        async with SessionLocal() as session:
            for kind, (job_id, url) in jobs.items():
                await session.execute(text("INSERT INTO jobs (id, url, status) VALUES (:id, :url, 'completed')"), {"id": job_id, "url": url})
                await session.execute(
                    text(
                        "INSERT INTO fp_findings (job_id, script_url, heuristic, level, claim, call_refs, request_refs, details, analyzer_version) "
                        "VALUES (:job, 'https://cdn.invalid/fp.js', 'exfiltration', 'EVIDENCIA', 'claim de prueba', '[1]', '[]', CAST(:details AS jsonb), 'test')"
                    ),
                    {"job": job_id, "details": json.dumps({"api": "navigator.userAgent", "domain": labels[kind]})},
                )
            await session.commit()

    async def delete():
        async with SessionLocal() as session:
            await session.execute(text("DELETE FROM jobs WHERE id = ANY(:ids)"), {"ids": [job_id for job_id, _ in jobs.values()]})
            await session.commit()

    client.portal.call(insert)
    try:
        body = client.get("/api/exposure/scan-usage").json()
        sent = {item["label"]: item for item in body["attributes"]["user_agent"]["sent"]}
        assert labels["real"] in sent and sent[labels["real"]]["scans"] == 1 and sent[labels["real"]]["last_scan_at"]
        assert labels["fixture"] not in sent and labels["test"] not in sent
        # Ningún ejemplo del cruce enlaza a un scan de fixtures o de tests, en ningún atributo.
        examples = [item["example"]["site"] for entry in body["attributes"].values() for item in entry["read"] + entry["sent"]]
        assert examples and not [site for site in examples if exposure.is_test_scan(site)]
        assert "fixtures" in body["excludes"] and "tests" in body["excludes"]
    finally:
        client.portal.call(delete)
    after = client.get("/api/exposure/scan-usage").json()
    assert labels["real"] not in [item["label"] for item in after["attributes"].get("user_agent", {}).get("sent", [])]


def test_scan_usage_shape(client):
    body = client.get("/api/exposure/scan-usage").json()
    assert "Solo refleja los scans guardados" in body["note"]
    for entry in body["attributes"].values():
        for item in entry["read"] + entry["sent"]:
            assert item["label"] and item["label"] != "no_disponible" and item["scans"] >= 1
            assert item["example"]["job_id"] and (item["example"]["call_ref"] or item["example"]["request_ref"])
            assert isinstance(item["is_entity"], bool)
            # Fecha del scan más reciente de esa organización (ISO 8601).
            assert re.match(r"\d{4}-\d{2}-\d{2}T", item["last_scan_at"])
