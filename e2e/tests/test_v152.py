"""v1.5.2: comparación de visitas desde la interfaz, y un scan normal que sigue dando lo mismo que en la v1.5.1.

El fixture /v152/ da un identificador por perfil (cookie persistente), una cookie de sesión, localStorage e IndexedDB, y
los reenvía por URL, cabecera y cuerpo; un perfil que vuelve con estado pide además /v152/welcome-back.gif.
"""

import json
import re

from playwright.sync_api import expect

from . import scan_golden

PAGE = "http://site.fixtures.test/v152/"
PERSISTENT = ("se observó un identificador persistente entre dos visitas con el mismo perfil; "
              "el perfil limpio de control mostró un resultado distinto")
ONLY_V2 = "cambio observado en el perfil persistente que no apareció en los perfiles limpios"
ALSO = "también observado en el control"
WARNING = "Tres visitas no prueban causalidad."


def test_normal_scan_matches_v151():
    """Huella de un scan normal (golden/scan_v151.json, generada con el código de la v1.5.1)."""
    expected = json.loads(scan_golden.GOLDEN.read_text(encoding="utf-8"))
    assert scan_golden.scan_fingerprints() == expected


def test_visit_comparison_from_the_interface(session):
    page = session.page
    session.goto("#/analyze")
    page.fill("#url", PAGE)
    expect(page.get_by_test_id("comparison-interval")).to_have_value("300")
    page.get_by_test_id("comparison-interval").fill("3")
    page.get_by_test_id("comparison-submit").click()
    view = page.get_by_test_id("comparison-view")
    expect(view).to_be_visible(timeout=15_000)
    assert re.search(r"#/comparison/[0-9a-f-]{36}$", page.url)
    # La advertencia se ve desde el principio, también mientras la comparación está en curso.
    expect(page.get_by_test_id("comparison-warning")).to_contain_text(WARNING)
    expect(view).to_have_attribute("data-status", "valida", timeout=300_000)
    expect(page.get_by_test_id("comparison-validity")).to_contain_text("Válida")
    expect(page.get_by_test_id("comparison-visit")).to_have_count(3)
    expect(page.get_by_test_id("comparison-interval-info")).to_contain_text("configurado 3 s")

    expect(page.get_by_test_id("class-text-persistent")).to_have_text(PERSISTENT)
    expect(page.get_by_test_id("class-text-only_visit_2")).to_have_text(ONLY_V2)
    expect(page.get_by_test_id("class-text-also_control")).to_have_text(ALSO)
    cookie_row = page.locator("[data-testid=item-persistent][data-kind=cookies]").filter(has_text="v152_uid")
    expect(cookie_row).to_have_count(1)
    expect(page.locator("[data-testid=item-persistent][data-kind=storage]").filter(has_text="v152_ls")).to_have_count(1)
    # Si hay más de una fila, el mensaje trae las filas de la api (sin enmascarar) para ver de dónde sale la otra.
    comparison_id = page.url.rsplit("/", 1)[-1]
    rows = [item for item in scan_golden.call(f"/api/comparisons/{comparison_id}?reveal=true")["result"]["classes"]["persistent"]["items"]
            if item["kind"] == "url" and "idb" in json.dumps(item).lower()]
    assert len(rows) == 1, rows
    expect(page.locator("[data-testid=item-persistent][data-kind=url]").filter(has_text="idb")).to_have_count(1)
    expect(cookie_row.get_by_test_id("item-visit-3")).to_have_text("valor distinto")
    only_v2 = page.locator("[data-testid=item-only_visit_2][data-kind=requests]").filter(has_text="/v152/welcome-back.gif")
    expect(only_v2).to_have_count(1)
    expect(only_v2.get_by_test_id("item-visit-1")).to_have_text("no observado en esta captura")
    expect(page.get_by_test_id("comparison-result")).not_to_contain_text("no existe")

    # Valores enmascarados por defecto; el interruptor los muestra completos.
    value = cookie_row.locator("td").nth(2)
    expect(value).to_contain_text("…[32 caracteres]")
    page.get_by_test_id("comparison-reveal").check()
    expect(value).to_have_text(re.compile(r"^[0-9a-f]{32}$"))
    session.assert_clean("comparación de visitas")

    # El Historial la lista; el Panel no incluye sus visitas.
    session.goto("#/history")
    expect(page.get_by_test_id("comparison-row").first).to_be_visible(timeout=15_000)
