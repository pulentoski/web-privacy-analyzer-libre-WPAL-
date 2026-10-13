"""Render de reportes a PDF sin red (F8, criterio 6)."""

import pytest

from app.render import html_to_pdf
from tests.helpers import fixtures_call, run_async

CLEAN = """<!doctype html><html lang="es"><head><meta charset="utf-8"><style>h1{color:#123}</style></head>
<body><h1>Reporte</h1><p>Resumen ejecutivo</p><img alt="" src="data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw=="></body></html>"""
HOSTILE = """<!doctype html><html><head>
<link rel="stylesheet" href="http://tracker-a.fixtures.test/render-probe.css">
<script src="http://tracker-a.fixtures.test/render-probe.js"></script>
<script>fetch('http://tracker-a.fixtures.test/render-probe-fetch'); document.title = 'js-ejecutado';</script>
</head><body><p>Texto del reporte</p>
<img src="http://tracker-a.fixtures.test/render-probe.gif">
<img src="https://example.com/render-probe.png">
<iframe src="http://site.fixtures.test/"></iframe>
</body></html>"""


@pytest.mark.needs_stack  # renderiza con Chromium real (Playwright); requiere el stack.
def test_self_contained_report_renders_with_zero_network_requests():
    pdf, info = run_async(html_to_pdf(CLEAN))
    assert pdf[:5] == b"%PDF-" and info["bytes"] == len(pdf) > 1000
    assert info["network_requests_attempted"] == 0 and info["attempted"] == []


def test_anything_the_page_tries_to_load_is_blocked_and_counted(fixtures_site):
    """Control: si el HTML intentara salir a la red, se contaría y, además, nada llegaría al servidor."""
    fixtures_call("/__reset", "POST")
    pdf, info = run_async(html_to_pdf(HOSTILE))
    assert pdf[:5] == b"%PDF-"
    assert info["network_requests_attempted"] >= 3, info
    assert any("render-probe.gif" in url for url in info["attempted"])
    received = fixtures_call("/__received")["requests"]
    assert [request for request in received if "render-probe" in json_text(request)] == []
    # JavaScript está desactivado en el render: el fetch del script inline nunca se intentó.
    assert not any("render-probe-fetch" in url for url in info["attempted"])


def json_text(value) -> str:
    import json

    return json.dumps(value)


def test_render_browser_has_no_proxy_configured():
    """El navegador del render se lanza sin proxy: en la red del worker no tiene ruta a internet."""
    import inspect

    from app import render

    source = inspect.getsource(render.html_to_pdf)
    assert "proxy" not in source.replace("Sin proxy", "") and "offline=True" in source and "java_script_enabled=False" in source
