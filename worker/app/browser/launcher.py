"""Único punto donde se configura Chromium. Nadie más debe llamar a launch().

Todo el tráfico del navegador sale por el egress-proxy (SPEC §Seguridad, capa 2).
"""

from app.config import accept_language, language_list, settings

# Host reservado (RFC 6761) que nunca resuelve. Los servicios propios de Chromium (cuentas,
# GCM, actualizador de componentes) se apuntan aquí y este host se excluye del proxy: la
# conexión falla dentro del contenedor y no sale ninguna request (docs/adr/013).
BLACKHOLE = "blackhole.invalid"
PROXY_BYPASS = f"<-loopback>;{BLACKHOLE}"

CHROMIUM_ARGS = [
    # Sin "<-loopback>" Chromium conecta directo a loopback, saltándose el proxy.
    f"--proxy-bypass-list={PROXY_BYPASS}",
    # Tráfico propio del navegador (no de las páginas): fuera. El resto lo apagan las
    # políticas gestionadas de worker/chromium-policies/.
    "--no-pings",
    "--disable-domain-reliability",
    f"--gaia-url=http://{BLACKHOLE}",
    f"--gcm-checkin-url=http://{BLACKHOLE}/checkin",
    f"--gcm-registration-url=http://{BLACKHOLE}/register",
    f"--gcm-mcs-endpoint={BLACKHOLE}:5228",
    f"--component-updater=url-source=http://{BLACKHOLE}/update",
    # QUIC es UDP y no pasa por un proxy HTTP.
    "--disable-quic",
    # Sin esto, un frame ACCEPT_CH (Client Hints por ALPS, p. ej. los frontends de Google) reinicia la
    # navegación, el reinicio queda abortado (ERR_ABORTED) y goto no termina nunca (docs/adr/035).
    "--disable-features=AcceptCHFrame",
    # WebRTC no puede abrir UDP fuera del proxy (evita fugas de IP y de tráfico).
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    # Perfil base (docs/adr/008): sin esto navigator.webdriver es true y el sitio ve un bot.
    "--disable-blink-features=AutomationControlled",
    "--window-size=1440,900",
]

# Solo con ALLOW_FIXTURES=1 (tests): el sitio de fixtures es HTTP plano y sin contexto
# seguro no existe navigator.serviceWorker, así que no se podría probar su bloqueo.
# chromium-headless-shell ignora este flag; por eso se usa el binario completo (ADR 003).
FIXTURE_ORIGINS = (
    "http://site.fixtures.test",
    "http://tracker-a.fixtures.test",
    "http://cdn-b.fixtures.test",
    "http://metrics.site.fixtures.test",
)


# Usuario de proxy para usos que no son un scan (tests, sondeos manuales).
ADHOC_PROXY_USER = "scan-00000000-0000-0000-0000-000000000000"


def launch_kwargs(proxy_user: str | None = None) -> dict:
    args = list(CHROMIUM_ARGS)
    if settings.allow_fixtures:
        args.append("--unsafely-treat-insecure-origin-as-secure=" + ",".join(FIXTURE_ORIGINS))
    return {
        # Ventana real sobre Xvfb: el modo headless se delata en el User-Agent ("HeadlessChrome").
        "headless": settings.headless,
        # Chromium completo, no chromium-headless-shell: mismo binario en tests y producción (ADR 003).
        "channel": "chromium",
        "chromium_sandbox": settings.chromium_sandbox,
        "proxy": {
            "server": settings.egress_proxy_url,
            "bypass": PROXY_BYPASS,
            # El usuario etiqueta en el log del proxy cada conexión de este navegador.
            "username": proxy_user or ADHOC_PROXY_USER,
            "password": settings.proxy_scan_secret.get_secret_value(),
        },
        "args": args,
    }


def context_kwargs(profile: dict | None = None) -> dict:
    """Opciones del contexto. Con `profile` (app/browser/profiles.py) se emula ese dispositivo."""
    if profile is not None:
        from app.browser.profiles import context_overrides

        return {"service_workers": "block", "accept_downloads": False, **context_overrides(profile)}
    return {
        # Un Service Worker puede servir respuestas que la captura no ve (SPEC §Limitaciones).
        "service_workers": "block",
        "accept_downloads": False,
        # Sin emulación de viewport: pantalla y ventana son las reales del display virtual,
        # coherentes entre sí (screen 1920x1080, ventana 1440x900).
        "no_viewport": True,
        # Perfil base en el idioma y la zona horaria configurados (WORKER_LOCALE, WORKER_TIMEZONE; por defecto
        # es-CL y America/Santiago): navigator.language(s), Intl y Accept-Language dicen lo mismo, que es lo
        # que compara el detector de inconsistencias (app/analyzer/consistency.py).
        "locale": settings.worker_locale,
        "timezone_id": settings.worker_timezone,
        # Accept-Language de los subrecursos; el de las navegaciones lo fija base_session_setup(). Hacen falta
        # los dos para que TODAS las requests digan lo mismo (comprobado con el sitio de fixtures).
        "extra_http_headers": {"Accept-Language": accept_language(settings.worker_locale)},
    }


def base_session_setup() -> list[tuple[str, dict]]:
    """Órdenes CDP que completan el perfil base en cada página y en cada iframe de otro proceso.

    Con `locale`, Playwright anuncia un solo idioma («es-CL»). Un Chrome real en español de Chile anuncia
    también el genérico: navigator.languages = [es-CL, es] y Accept-Language «es-CL,es;q=0.9». Esta orden lo
    fija para JavaScript y para las navegaciones (documentos); los subrecursos toman la cabecera de
    context_kwargs(). userAgent vacío = no se toca el User-Agent ni los Client Hints.
    """
    return [("Emulation.setUserAgentOverride", {"userAgent": "", "acceptLanguage": ",".join(language_list(settings.worker_locale))})]


async def apply_base_profile(context, page) -> None:
    """Aplica base_session_setup() a una página que no pasa por NetworkMonitor (el sondeo de atributos)."""
    session = await context.new_cdp_session(page)
    for method, params in base_session_setup():
        await session.send(method, params)


async def launch_browser(playwright, proxy_user: str | None = None):
    return await playwright.chromium.launch(**launch_kwargs(proxy_user))


async def new_context(browser, profile: dict | None = None):
    return await browser.new_context(**context_kwargs(profile))


def persistent_kwargs(user_data_dir: str, proxy_user: str | None = None) -> dict:
    """Opciones del contexto persistente de la comparación de visitas (v1.5.2, docs/adr/040).

    Las mismas del navegador y del contexto efímero, más la caché HTTP dentro del directorio del perfil: así la caché
    de un perfil nunca la ve el otro y se borra con él.
    """
    kwargs = launch_kwargs(proxy_user)
    kwargs["args"] = [*kwargs["args"], f"--disk-cache-dir={user_data_dir}/cache"]
    return {**kwargs, **context_kwargs()}


async def launch_persistent_context(playwright, user_data_dir: str, proxy_user: str | None = None):
    """Solo para las visitas de una comparación: los scans normales e interactivos siguen con new_context() efímero."""
    return await playwright.chromium.launch_persistent_context(user_data_dir, **persistent_kwargs(user_data_dir, proxy_user))
