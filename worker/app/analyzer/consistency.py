"""Detector de inconsistencias del fingerprint (F7). Función pura.

Compara lo que ve un script (`js`) con lo que ve el servidor (`headers`) y los atributos
entre sí. Los valores observados son EVIDENCIA; que la combinación sea "poco común o
detectable" es INFERENCIA. No dice que alguien haya detectado nada.
"""

IGNORED_OS = {None, "software"}


def _os_from_list(value: str | None, rules: list[dict]) -> str | None:
    if not isinstance(value, str):
        return None
    for rule in rules:
        if "contains" in rule and rule["contains"] in value:
            return rule["os"]
        if "prefix" in rule and value.startswith(rule["prefix"]):
            return rule["os"]
    return None


def _unquote(value: str | None) -> str | None:
    return value.strip().strip('"') if isinstance(value, str) else None


def _region(locale: str | None) -> str | None:
    if not isinstance(locale, str) or "-" not in locale:
        return None
    region = locale.split(";")[0].split(",")[0].split("-")[-1].strip()
    return region.upper() if len(region) == 2 else None


def check(js: dict | None, headers: dict | None, rules: dict) -> list[dict]:
    """Lista de inconsistencias: {rule, title, observed, level, inference, inference_level}."""
    js, headers = js or {}, headers or {}
    found: list[dict] = []

    def add(rule: str, title: str, observed: dict) -> None:
        found.append(
            {"rule": rule, "title": title, "observed": {k: v for k, v in observed.items() if v is not None},
             "level": "EVIDENCIA", "inference": rules["inference"], "inference_level": "INFERENCIA"}
        )

    os_rules = rules["os_from"]
    ua_ch = js.get("ua_ch") or {}
    sources = {
        "User-Agent (JavaScript)": (js.get("user_agent"), _os_from_list(js.get("user_agent"), os_rules["user_agent"])),
        "User-Agent (cabecera)": (headers.get("user-agent"), _os_from_list(headers.get("user-agent"), os_rules["user_agent"])),
        "navigator.platform": (js.get("platform"), _os_from_list(js.get("platform"), os_rules["platform"])),
        "Client Hints (JavaScript)": (ua_ch.get("platform"), os_rules["ua_ch_platform"].get(ua_ch.get("platform"))),
        "Sec-CH-UA-Platform (cabecera)": (_unquote(headers.get("sec-ch-ua-platform")), os_rules["ua_ch_platform"].get(_unquote(headers.get("sec-ch-ua-platform")))),
        "GPU (WebGL)": (js.get("webgl_renderer"), _os_from_list(js.get("webgl_renderer"), os_rules["webgl_renderer"])),
    }
    systems = {name: os for name, (_, os) in sources.items() if os not in IGNORED_OS}
    if len(set(systems.values())) > 1:
        add(
            "os_mismatch",
            "El sistema operativo no coincide entre fuentes",
            {name: f"{sources[name][0]} → {systems[name]}" for name in systems},
        )

    if js.get("user_agent") and headers.get("user-agent") and js["user_agent"] != headers["user-agent"]:
        add("ua_js_vs_header", "El User-Agent que lee un script no es el que recibe el servidor",
            {"JavaScript": js["user_agent"], "cabecera": headers["user-agent"]})
    mobile_header = {"?1": True, "?0": False}.get(headers.get("sec-ch-ua-mobile"))
    mobile_signals = {
        "Client Hints (JavaScript)": ua_ch.get("mobile"),
        "Sec-CH-UA-Mobile (cabecera)": mobile_header,
        "User-Agent contiene «Mobile»": ("Mobile" in js["user_agent"]) if js.get("user_agent") else None,
    }
    known = {name: value for name, value in mobile_signals.items() if value is not None}
    if len(set(known.values())) > 1:
        add("mobile_mismatch", "Las señales de «dispositivo móvil» se contradicen", {k: str(v) for k, v in known.items()})

    languages = js.get("languages") or []
    accept = headers.get("accept-language")
    if languages and accept and accept.split(",")[0].split(";")[0].strip().lower() != str(languages[0]).lower():
        add("language_js_vs_header", "El idioma que lee un script no es el de Accept-Language",
            {"navigator.languages": ", ".join(map(str, languages)), "Accept-Language": accept})
    country = (rules.get("timezone_country") or {}).get(js.get("timezone"))
    region = _region(languages[0] if languages else None) or _region(accept)
    if country and region and country != region:
        add("timezone_vs_locale", "La zona horaria y el idioma apuntan a países distintos",
            {"zona horaria": f"{js.get('timezone')} → {country}", "idioma": f"{languages[0] if languages else accept} → {region}"})

    is_mobile = bool(known) and any(known.values())
    touch = js.get("max_touch_points")
    width = (js.get("screen") or [None])[0]
    if is_mobile and touch == 0:
        add("mobile_without_touch", "Se declara móvil pero no tiene puntos táctiles", {"maxTouchPoints": 0})
    if is_mobile and isinstance(width, int) and width > rules.get("mobile_max_screen_width", 1000):
        add("mobile_with_desktop_screen", "Se declara móvil con una pantalla de escritorio", {"pantalla": f"{width} px de ancho"})
    if known and not is_mobile and systems and set(systems.values()) <= {"windows", "macos", "linux"} and isinstance(touch, int) and touch > 0 and isinstance(width, int) and width < 600:
        add("desktop_with_phone_screen", "Se declara de escritorio con pantalla y táctil de teléfono", {"pantalla": f"{width} px", "maxTouchPoints": touch})

    if js.get("webdriver") is True:
        add("webdriver_flag", "navigator.webdriver indica un navegador automatizado", {"navigator.webdriver": "true"})
    for artifact in js.get("artifacts") or []:
        add("spoofing_artifact", "Rastro del propio mecanismo de emulación", {"artefacto": str(artifact)[:200]})
    return found
