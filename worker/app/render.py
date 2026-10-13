"""Convierte a PDF los reportes HTML que genera la api (F8, docs/adr/018).

El HTML es nuestro, pero incluye texto capturado de sitios no confiables. Por eso se
renderiza sin red (navegador sin proxy en un contenedor sin salida, contexto offline y
toda request abortada), sin JavaScript y sin tocar el disco.
"""

import asyncio
import json
import logging

from playwright.async_api import async_playwright

from app.config import settings

logger = logging.getLogger(__name__)

CLAIM_SQL = """
UPDATE report_files SET status = 'rendering'
 WHERE id = (SELECT id FROM report_files WHERE kind = 'pdf' AND status = 'pending'
              ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1)
RETURNING id, subject_type, subject_id, reveal, sha256
"""
MAX_HTML_BYTES = 8_000_000


async def html_to_pdf(html: str) -> tuple[bytes, dict]:
    """PDF A4 del HTML. Devuelve también cuántas requests de red intentó la página (debe ser 0)."""
    attempted: list[str] = []
    async with async_playwright() as playwright:
        # Sin proxy: este navegador no tiene ninguna ruta hacia fuera.
        browser = await playwright.chromium.launch(headless=True, chromium_sandbox=settings.chromium_sandbox)
        try:
            context = await browser.new_context(offline=True, java_script_enabled=False, service_workers="block")

            async def block(route):
                attempted.append(route.request.url[:200])
                await route.abort()

            await context.route("**/*", block)
            page = await context.new_page()
            await page.set_content(html, wait_until="load", timeout=30000)
            pdf = await page.pdf(
                format="A4", print_background=True, margin={"top": "16mm", "bottom": "16mm", "left": "14mm", "right": "14mm"},
                display_header_footer=True, header_template="<span></span>",
                footer_template='<div style="font-size:8px;width:100%;text-align:center;color:#555">Página <span class="pageNumber"></span> de <span class="totalPages"></span></div>',
            )
        finally:
            await browser.close()
    return pdf, {"network_requests_attempted": len(attempted), "attempted": attempted[:10], "bytes": len(pdf)}


async def render_loop(pool) -> None:
    while True:
        try:
            row = await pool.fetchrow(CLAIM_SQL)
        except Exception as exc:
            logger.error("render_claim_failed", extra={"error_type": type(exc).__name__})
            row = None
        if row is None:
            await asyncio.sleep(settings.poll_interval_s)
            continue
        try:
            html = await pool.fetchval(
                # El sha256 ata el PDF al mismo JSON que su HTML: si el reporte se regeneró entretanto, no coincide.
                "SELECT data FROM report_files WHERE subject_type = $1 AND subject_id = $2 AND kind = 'html' AND reveal = $3 AND sha256 = $4",
                row["subject_type"], row["subject_id"], row["reveal"], row["sha256"],
            )
            if html is None or len(html) > MAX_HTML_BYTES:
                raise ValueError("HTML ausente o demasiado grande")
            pdf, info = await asyncio.wait_for(html_to_pdf(bytes(html).decode("utf-8")), 90)
            await pool.execute(
                "UPDATE report_files SET status = 'ready', data = $2, render_info = $3::jsonb "
                "WHERE id = $1 AND sha256 = $4 AND status = 'rendering'",
                row["id"], pdf, json.dumps(info), row["sha256"],
            )
            logger.info("report_rendered", extra={"report_file_id": row["id"], "subject_type": row["subject_type"], **{k: info[k] for k in ("network_requests_attempted", "bytes")}})
        except Exception as exc:
            logger.exception("report_render_failed", extra={"report_file_id": row["id"]})
            await pool.execute(
                "UPDATE report_files SET status = 'failed', render_info = $2::jsonb WHERE id = $1 AND sha256 = $3 AND status = 'rendering'",
                row["id"], json.dumps({"error": type(exc).__name__}), row["sha256"],
            )
