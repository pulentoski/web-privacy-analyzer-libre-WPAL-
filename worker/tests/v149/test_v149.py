"""v1.4.9 (docs/adr/036): Client Hints (solicitud, envío y delegación), sincronización por redirección, cookie
copiada por un script, desglose Evidencia/Inferencia del índice y Appier como publicidad. Sin red."""

import asyncio

import pytest

from app.analyzer.config import load_config
from app.analyzer.engine import analyze
from app.browser.capture import page_meta
from app.config import settings
from tests.helpers import run_async
from tests.v121.test_party_blocking_service_consent import Lists, capture, req

VISITOR = "a3f9c2e1b7d44f6a9c0e5d2b8f1a6c3e"
ACCEPT_CH = [{"name": "accept-ch", "value": "Sec-CH-UA, Sec-CH-UA-Model, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Mobile"}]
SENT = [{"name": "sec-ch-ua", "value": '"Chromium";v="141"'}, {"name": "sec-ch-ua-model", "value": '""'},
        {"name": "sec-ch-ua-full-version-list", "value": '"Chromium";v="141.0.0.0"'}]
ENTITIES = {"airbnb.cl": "Airbnb", "adsone.example": "Ads One", "adstwo.example": "Ads Two", "appier.net": "Appier"}


@pytest.fixture(scope="module")
def config():
    return load_config(settings.data_dir, allow_fixtures=settings.allow_fixtures)


def run(cap, config):
    return analyze(cap, Lists(ENTITIES), config)


def reasons_of(result, request_id):
    return {reason["signal"]: reason for reason in next(item for item in result["requests"] if item["request_id"] == request_id)["reasons"]}


def findings_of(result, kind):
    return [item for item in result["findings"] if item["type"] == kind]


def client_hints(result):
    return result["site"]["summary"]["client_hints"]


# --- 4. Client Hints ---

def test_request_without_send_is_never_reception(config):
    cap = capture([req(1, "https://t.adsone.example/r", response_headers=ACCEPT_CH),
                   req(2, "https://t.adsone.example/p", headers=SENT[:1])],  # solo sec-ch-ua (baja entropía)
                  page_meta={"description": None, "keywords": None, "delegate_ch": None})
    result = run(cap, config)
    info = client_hints(result)
    [item] = info["requests"]
    assert item["organization"] == "Ads One" and item["hints"] == ["Sec-CH-UA-Full-Version-List", "Sec-CH-UA-Model"]
    assert item["sent"] == "no_observado" and info["sends"] == []
    [requested] = findings_of(result, "client_hints_requested")
    assert requested["level"] == "EVIDENCIA" and "no demuestra que los haya recibido" in requested["claim"]
    assert not findings_of(result, "client_hints_sent")
    assert "client_hints_request" in reasons_of(result, 1) and "client_hints_sent" not in reasons_of(result, 1)
    assert "client_hints_sent" not in reasons_of(result, 2)  # no se infiere el envío solo por Accept-CH
    # La primera request a la organización no los llevaba: condicionado por el navegador de captura.
    assert item["first_request_conditioned"] is True
    assert any("navegador de captura" in note for note in info["notes"])
    assert any("no basta para concluir que nunca" in note for note in info["notes"])


def test_request_then_send_is_confirmed_and_scored_once(config):
    cap = capture([req(1, "https://t.adsone.example/r", response_headers=ACCEPT_CH),
                   req(2, "https://t.adsone.example/r2", response_headers=ACCEPT_CH),   # misma organización: no suma otra vez
                   req(3, "https://t.adsone.example/p", headers=SENT)])
    result = run(cap, config)
    [item] = client_hints(result)["requests"]
    assert item["sent"] == "confirmado" and item["sent_hints"] == ["Sec-CH-UA-Full-Version-List", "Sec-CH-UA-Model"]
    assert "client_hints_request" in reasons_of(result, 1) and "client_hints_request" not in reasons_of(result, 2)
    sent = reasons_of(result, 3)["client_hints_sent"]
    weights = config.scoring["signals"]
    assert sent["weight"] == weights["client_hints_sent"]["weight"] > weights["client_hints_request"]["weight"]
    [finding] = findings_of(result, "client_hints_sent")
    assert finding["evidence_refs"] == [3] and finding["details"]["after_request"] is True


def test_delegation_detected_by_permissions_policy(config):
    cap = capture([req(1, "https://t.adsone.example/r", response_headers=ACCEPT_CH)])
    cap["requests"][0]["response_headers"] = [{"name": "permissions-policy", "value": 'ch-ua-model=(self "https://t.adsone.example")'}]
    delegation = client_hints(run(cap, config))["delegation"]
    assert delegation["status"] == "detectada" and delegation["label"] == "Delegación detectada"
    assert any("ch-ua-model" in item for item in delegation["evidence"])


def test_delegation_detected_by_meta(config):
    cap = capture([req(1, "https://t.adsone.example/r", response_headers=ACCEPT_CH)],
                  page_meta={"description": None, "keywords": None, "delegate_ch": "sec-ch-ua-model https://t.adsone.example"})
    assert client_hints(run(cap, config))["delegation"]["status"] == "detectada"


def test_no_delegation_detected_is_not_impossibility(config):
    cap = capture([req(1, "https://t.adsone.example/r", response_headers=ACCEPT_CH)],
                  page_meta={"description": None, "keywords": None, "delegate_ch": None})
    cap["requests"][0]["response_headers"] = [{"name": "content-type", "value": "text/html"}]
    delegation = client_hints(run(cap, config))["delegation"]
    assert delegation["status"] == "sin_delegacion" and delegation["label"] == "Sin delegación detectada"
    assert "no prueba que el envío sea imposible" in delegation["note"]


def test_insufficient_evidence_is_not_determined(config):
    # Sin el meta leído (scan anterior, HAR) la delegación no se puede determinar.
    cap = capture([req(1, "https://t.adsone.example/r", response_headers=ACCEPT_CH)])
    delegation = client_hints(run(cap, config))["delegation"]
    assert delegation["status"] == "no_determinado" and delegation["label"] == "No determinado"
    assert any("meta delegate-ch" in item for item in delegation["evidence"])
    assert delegation["note"] is None  # la nota «sin delegación…» solo acompaña a ese estado


def test_first_party_accept_ch_is_not_a_third_party_request(config):
    cap = capture([req(1, "https://www.airbnb.cl/app", third_party=False, response_headers=ACCEPT_CH)])
    assert client_hints(run(cap, config))["requests"] == []


# --- 3. Sincronización por redirección ---

def redirect(first_url, second_url):
    first = req(1, first_url, params={"uid": VISITOR}, status=302)
    second = req(2, second_url, params={"partner_uid": VISITOR})
    second["redirected_from_seq"] = 1
    return capture([first, second])


def test_redirect_carrying_the_identifier_to_another_org_is_sync_evidence(config):
    result = run(redirect("https://s.adsone.example/sync", "https://m.adstwo.example/match"), config)
    [item] = findings_of(result, "redirect_sync")
    assert item["level"] == "EVIDENCIA" and item["evidence_refs"] == [1, 2]
    assert "302" in item["claim"] and "request #2" in item["claim"] and "request #3" in item["claim"]
    breakdown = {entry["component"]: entry for entry in result["site"]["breakdown"]}
    assert breakdown["id_sync"]["count"] == 1  # un valor, una vez


def test_redirect_inside_one_org_is_not_sync(config):
    result = run(redirect("https://anylist.c.appier.net/r2", "https://s.c.appier.net/aprcm"), config)
    assert not findings_of(result, "redirect_sync") and not findings_of(result, "id_sync")


# --- 5. Cookie copiada por un script ---

COOKIES = [{"name": "_atrk_siteuid", "value": VISITOR, "domain": "www.airbnb.cl", "expires": None, "third_party": False}]


def test_cookie_value_without_cookie_header_was_copied_by_a_script(config):
    cap = capture([req(1, "https://anylist.c.appier.net/r2", params={"siteuid": VISITOR})], cookies=COOKIES)
    reason = reasons_of(run(cap, config), 1)["persistent_id"]
    assert "un script copió el valor de la cookie «_atrk_siteuid» en la URL o el cuerpo de la request" in reason["detail"]
    assert reason["data"]["copied_cookie"] == "_atrk_siteuid"


def test_request_that_sent_cookies_is_not_called_a_copy(config):
    cap = capture([req(1, "https://anylist.c.appier.net/r2", params={"siteuid": VISITOR},
                       headers=[{"name": "Cookie", "value": "x=1"}])], cookies=COOKIES)
    reason = reasons_of(run(cap, config), 1)["persistent_id"]
    assert "copió" not in reason["detail"] and "copied_cookie" not in reason["data"]


# --- 2. Evidencia + Inferencia en el índice ---

def test_breakdown_splits_evidence_and_inference(config):
    cap = capture([req(1, "https://t.adsone.example/r", response_headers=ACCEPT_CH),
                   req(2, "https://m.adstwo.example/p.gif", params={"uid": VISITOR})])
    result = run(cap, config)
    for entry in result["site"]["breakdown"]:
        assert entry["evidence_count"] <= entry["count"]
        assert abs(entry["evidence_points"] + entry["inference_points"] - entry["points"]) < 0.02
    by_level = result["site"]["summary"]["score_by_level"]
    assert set(by_level) == {"EVIDENCIA", "INFERENCIA"}
    assert abs(by_level["EVIDENCIA"] + by_level["INFERENCIA"] - sum(e["points"] for e in result["site"]["breakdown"])) < 0.2


# --- 6. Appier → publicidad ---

def test_appier_is_advertising(config):
    assert config.service_types.of(entity="Appier", domain="appier.net")["type"] == "advertising"
    assert config.service_types.of(entity="Appier", domain="appier.com")["type"] == "advertising"


# --- captura: si el meta no se pudo leer, la delegación no puede darse por ausente ---

class BrokenPage:
    async def evaluate(self, script):
        raise asyncio.TimeoutError


def test_page_meta_failure_does_not_claim_the_meta_was_read():
    meta = run_async(page_meta(BrokenPage()))
    assert "delegate_ch" not in meta
