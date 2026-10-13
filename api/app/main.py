import logging
import time

from fastapi import FastAPI, Request

from app.errors import register_error_handlers
from app.version import APP_VERSION
from app.routes import analysis, exposure, har, health, history, interactive, panel, privacy, reports, resources, scans

logger = logging.getLogger("app.access")

# Documentación OpenAPI en /docs y /openapi.json. Solo se llega por el puerto de la api
# (127.0.0.1:8000): el nginx del frontend no reenvía estas rutas, así que en modo demo no
# quedan expuestas en la red local. Swagger UI carga sus scripts desde un CDN en el
# navegador de quien la abre; /openapi.json no depende de nada externo.
app = FastAPI(
    title="Web Privacy & Tracker Analyzer",
    version=APP_VERSION,
    description="Análisis dinámico de sitios web: qué cargan, a qué terceros contactan y con qué nivel de evidencia.",
    docs_url="/docs", redoc_url=None, openapi_url="/openapi.json",
)
register_error_handlers(app)
app.include_router(health.router)
app.include_router(scans.router)
app.include_router(analysis.router)
app.include_router(exposure.router)
app.include_router(privacy.router)
app.include_router(reports.router)
app.include_router(history.router)
app.include_router(panel.router)
app.include_router(har.router)
app.include_router(interactive.router)
app.include_router(resources.router)


@app.middleware("http")
async def access_log(request: Request, call_next):
    started = time.perf_counter()
    response = await call_next(request)
    logger.info(
        "request",
        extra={
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "duration_ms": round((time.perf_counter() - started) * 1000, 1),
        },
    )
    return response
