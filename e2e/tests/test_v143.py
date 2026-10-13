"""v1.4.3: el indicador de recursos reserva en el contenido un hueco igual a su alto, de modo que el
último elemento de cada ruta queda visible y clicable (ya no lo tapa la consola fija al pie), y se
puede minimizar a un ícono con la preferencia recordada en localStorage. En ambos temas."""

import pytest
from playwright.sync_api import expect

from .conftest import BASE_URL, Session, ensure_scan

SITE = "http://site.fixtures.test/"

# Tras bajar del todo, comprueba en el DOM que el último elemento visible del contenido no queda
# tapado por la consola fija: su centro hace hit-test a sí mismo (o a su contenido), no a la consola.
CHECK_LAST = """() => {
  const main = document.querySelector('main.app-main');
  const rc = document.querySelector('[data-testid=resources]');
  window.scrollTo(0, document.body.scrollHeight);
  const visible = (el) => {
    const r = el.getBoundingClientRect(), s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' && s.pointerEvents !== 'none';
  };
  const leaves = [...main.querySelectorAll('*')].filter((el) => el.children.length === 0 && el.textContent.trim() && visible(el));
  const el = leaves.length ? leaves[leaves.length - 1] : main.lastElementChild;
  const r = el.getBoundingClientRect();
  const cx = Math.min(Math.max(r.left + r.width / 2, 1), window.innerWidth - 1);
  const cy = Math.min(Math.max(r.top + r.height / 2, 1), window.innerHeight - 1);
  const hit = document.elementFromPoint(cx, cy);
  return {
    pad: parseFloat(getComputedStyle(main).paddingBottom),
    consoleHeight: rc.getBoundingClientRect().height,
    consoleTop: rc.getBoundingClientRect().top,
    bottom: r.bottom, cy, inViewport: cy > 0 && cy < window.innerHeight,
    coveredByConsole: rc.contains(hit),
    hitsSelf: el === hit || el.contains(hit) || (hit && hit.contains(el)),
    tag: el.tagName.toLowerCase(),
  };
}"""


def reserved_and_console(page):
    return page.evaluate("""() => {
      const main = document.querySelector('main.app-main');
      const rc = document.querySelector('[data-testid=resources]');
      return { pad: parseFloat(getComputedStyle(main).paddingBottom), consoleHeight: rc.getBoundingClientRect().height };
    }""")


def last_element_clear_of_console(session, route):
    """Tras ir a la ruta y bajar del todo, el último elemento del contenido es visible y clicable."""
    page = session.page
    session.goto(route)
    expect(page.get_by_test_id("resources-toggle")).to_be_visible()
    info = page.evaluate(CHECK_LAST)
    # El contenido reserva un hueco al menos tan alto como la consola.
    assert info["pad"] >= info["consoleHeight"] - 1, (route, info)
    # El último elemento queda a la vista, por encima de la consola...
    assert info["inViewport"] and info["bottom"] <= info["consoleTop"] + 1, (route, info)
    # ...y nada lo tapa en su centro: el punto hace hit-test al propio elemento, no a la consola.
    assert not info["coveredByConsole"] and info["hitsSelf"], (route, info)


@pytest.mark.parametrize("theme", ["classic", "purple"])
def test_last_element_of_each_route_stays_visible_and_clickable(session, shared, browser, theme):
    page = session.page
    page.set_viewport_size({"width": 1024, "height": 560})  # bajo a propósito: las páginas desbordan
    session.goto("#/")
    session.set_theme(theme)
    job_id = ensure_scan(shared, browser, "v143", SITE)
    routes = ["#/", "#/analyze", "#/analyze?advanced=1", "#/history", "#/glossary", f"#/scan/{job_id}"]
    for route in routes:
        last_element_clear_of_console(session, route)
    session.assert_clean(f"rutas largas ({theme})")


@pytest.mark.parametrize("theme", ["classic", "purple"])
def test_console_minimizes_to_an_icon_and_remembers_the_choice(session, theme):
    page = session.page
    page.set_viewport_size({"width": 1024, "height": 560})
    session.goto("#/glossary")
    session.set_theme(theme)
    expect(page.get_by_test_id("resources-toggle")).to_be_visible()
    expanded = reserved_and_console(page)

    # Minimizar: queda solo el ícono; el hueco reservado se achica.
    page.get_by_test_id("resources-minimize").click()
    expect(page.get_by_test_id("resources-restore")).to_be_visible()
    expect(page.get_by_test_id("resources-toggle")).to_have_count(0)
    minimized = reserved_and_console(page)
    assert minimized["consoleHeight"] < expanded["consoleHeight"]
    assert minimized["pad"] < expanded["pad"]
    assert minimized["pad"] >= minimized["consoleHeight"] - 1

    # La preferencia se recuerda: al recargar arranca minimizada.
    session.goto("#/history")
    expect(page.get_by_test_id("resources-restore")).to_be_visible()
    expect(page.get_by_test_id("resources-toggle")).to_have_count(0)

    # Restaurar: vuelve la consola mini y el hueco crece; la preferencia también se recuerda.
    page.get_by_test_id("resources-restore").click()
    expect(page.get_by_test_id("resources-toggle")).to_be_visible()
    session.goto("#/glossary")
    expect(page.get_by_test_id("resources-toggle")).to_be_visible()
    expect(page.get_by_test_id("resources-restore")).to_have_count(0)
    session.assert_clean(f"minimizar consola ({theme})")
