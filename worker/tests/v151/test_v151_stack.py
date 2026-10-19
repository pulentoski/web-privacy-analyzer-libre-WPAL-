"""v1.5.1: el título de la página es `document.title`, nunca el título provisional de la pestaña («Loading <URL>») que
Chromium devuelve en page.title() mientras dura una navegación. Con el stack de test (Chromium, proxy y fixtures)."""

import asyncio
import uuid

from playwright.async_api import async_playwright

from app.browser.capture import page_title
from app.browser.launcher import context_kwargs, launch_kwargs
from tests.helpers import SITE, run_async

FROM, TO = f"{SITE}/", f"{SITE}/v151/"
TO_TITLE = "v1.5.1: enmascarado del detalle de request"


def test_title_is_never_the_provisional_tab_title(fixtures_site):
    async def scenario():
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(**launch_kwargs(f"scan-{uuid.uuid4()}"))
            try:
                page = await (await browser.new_context(**context_kwargs())).new_page()
                await page.goto(FROM, wait_until="load")
                from_title = await page_title(page)
                seen, provisional = set(), 0
                for _ in range(8):
                    navigation = asyncio.ensure_future(page.goto(TO, wait_until="load"))
                    while not navigation.done():
                        seen.add(await page_title(page))
                        provisional += (await page.title()).startswith("Loading ")
                    await navigation
                    seen.add(await page_title(page))
                    await page.goto(FROM, wait_until="load")
                return from_title, seen, provisional
            finally:
                await browser.close()

    from_title, seen, provisional = run_async(scenario())
    # Durante la navegación el título es el del documento anterior, el del nuevo o ninguno; nunca el provisional.
    assert seen <= {from_title, TO_TITLE, "", None}, seen
    assert TO_TITLE in seen
    print(f"\npage.title() devolvió el título provisional en {provisional} lecturas; page_title(), en ninguna")
