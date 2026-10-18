import os
import re
import socket
from dataclasses import dataclass, field


class Secret:
    """Valor secreto: repr(), str() y los logs muestran "**********", nunca el contenido.

    Quien lo necesita de verdad lo pide con get_secret_value() (misma interfaz que
    SecretStr de pydantic, que usa la api).
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def get_secret_value(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret('**********')" if self._value else "Secret('')"

    def __str__(self) -> str:
        return "**********" if self._value else ""

    def __bool__(self) -> bool:
        return bool(self._value)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Secret) and other._value == self._value

    def __hash__(self) -> int:
        return hash(self._value)

    def __reduce__(self):
        # Tampoco se serializa por accidente (pickle, copias a otros procesos).
        raise TypeError("Secret no se serializa")


LICENSE_PROFILES = ("no_comercial", "comercial")


def _license_profile(value: str) -> str:
    profile = value.strip().lower() or "no_comercial"
    if profile not in LICENSE_PROFILES:
        raise ValueError(f"LICENSE_PROFILE debe ser uno de {LICENSE_PROFILES}, no {value!r}")
    return profile


def _locale(value: str) -> str:
    """Locale BCP 47 del perfil base (p. ej. es-CL). Se valida aquí: llega tal cual a Chromium y a una cabecera."""
    locale = value.strip() or "es-CL"
    if not re.fullmatch(r"[a-z]{2,3}(-[A-Z][a-z]{3})?(-([A-Z]{2}|\d{3}))?", locale):
        raise ValueError(f"WORKER_LOCALE no es un locale válido (ejemplo: es-CL): {value!r}")
    return locale


def _timezone(value: str) -> str:
    """Zona horaria IANA del perfil base (p. ej. America/Santiago)."""
    zone = value.strip() or "America/Santiago"
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_+\-]*(/[A-Za-z0-9_+\-]+){0,2}", zone):
        raise ValueError(f"WORKER_TIMEZONE no es una zona horaria IANA válida (ejemplo: America/Santiago): {value!r}")
    return zone


def language_list(locale: str) -> list[str]:
    """Idiomas preferidos de un Chrome configurado en ese idioma: el regional y el genérico («es-CL», «es»)."""
    language = locale.split("-")[0]
    return [locale] if language == locale else [locale, language]


def accept_language(locale: str) -> str:
    """Cabecera Accept-Language que envía ese Chrome: «es-CL,es;q=0.9»."""
    return ",".join(name if index == 0 else f"{name};q={1 - index / 10:.1f}" for index, name in enumerate(language_list(locale)))


def _bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    postgres_user: str = field(default_factory=lambda: os.environ["POSTGRES_USER"])
    postgres_password: Secret = field(default_factory=lambda: Secret(os.environ["POSTGRES_PASSWORD"]))
    postgres_db: str = field(default_factory=lambda: os.environ["POSTGRES_DB"])
    postgres_host: str = field(default_factory=lambda: os.environ.get("POSTGRES_HOST", "db"))
    worker_id: str = field(default_factory=socket.gethostname)
    egress_proxy_url: str = field(
        default_factory=lambda: os.environ.get("EGRESS_PROXY_URL", "http://egress-proxy:3128")
    )
    # Credenciales del proxy: el usuario identifica al scan (docs/adr/016).
    proxy_scan_secret: Secret = field(default_factory=lambda: Secret(os.environ.get("PROXY_SCAN_SECRET", "")))
    scanlog_dir: str = field(default_factory=lambda: os.environ.get("SCANLOG_DIR", "/var/log/scanlog"))
    # Servicio de IP pública para el país de la IP de salida (v1.5.0, docs/adr/038). Vacío = no se consulta
    # y el país queda «desconocido». Se consulta por el egress-proxy, una vez por scan, fuera del tráfico analizado.
    egress_ip_service_url: str = field(
        default_factory=lambda: os.environ.get("EGRESS_IP_SERVICE_URL", "https://api.ipify.org").strip()
    )
    chromium_sandbox: bool = field(default_factory=lambda: _bool(os.environ.get("CHROMIUM_SANDBOX", "true")))
    max_concurrent_scans: int = field(default_factory=lambda: int(os.environ.get("MAX_CONCURRENT_SCANS", "2")))
    scan_timeout_s: int = field(default_factory=lambda: int(os.environ.get("SCAN_TIMEOUT_S", "90")))
    max_requests: int = field(default_factory=lambda: int(os.environ.get("MAX_REQUESTS", "1500")))
    # Override del umbral de "pocas requests" de la alerta antibot; None = usar data/scoring.yaml.
    blocking_min_requests: int | None = field(
        default_factory=lambda: int(os.environ["BLOCKING_MIN_REQUESTS"]) if os.environ.get("BLOCKING_MIN_REQUESTS") else None
    )
    max_body_capture_bytes: int = field(
        default_factory=lambda: int(os.environ.get("MAX_BODY_CAPTURE_BYTES", "65536"))
    )
    # Solo stacks de test: habilita el sitio de fixtures (docs/adr/003).
    allow_fixtures: bool = field(default_factory=lambda: _bool(os.environ.get("ALLOW_FIXTURES", "0")))
    # Perfil base (docs/adr/008): Chromium con ventana real sobre un display virtual (Xvfb).
    # HEADLESS=true vuelve al modo headless, que se anuncia como "HeadlessChrome".
    headless: bool = field(default_factory=lambda: _bool(os.environ.get("HEADLESS", "false")))
    display: str = field(default_factory=lambda: os.environ.get("DISPLAY", ":99"))
    # Perfil base (v1.4.5): idioma y zona horaria del navegador del worker, coherentes entre sí. Sin esto
    # Chromium se presenta en inglés y en UTC, y los sitios responden distinto (p. ej. reCAPTCHA con hl=en).
    worker_locale: str = field(default_factory=lambda: _locale(os.environ.get("WORKER_LOCALE", "")))
    worker_timezone: str = field(default_factory=lambda: _timezone(os.environ.get("WORKER_TIMEZONE", "")))
    # Instrumentación de APIs de fingerprinting (F4). Ver docs/adr/007.
    fp_instrumentation: bool = field(default_factory=lambda: _bool(os.environ.get("FP_INSTRUMENTATION", "true")))
    log_level: str = field(default_factory=lambda: os.environ.get("LOG_LEVEL", "INFO"))
    heartbeat_interval_s: int = 10
    reaper_interval_s: int = 10
    poll_interval_s: float = 1.0
    # Fin de captura: load + esta ventana sin requests nuevas (SPEC F2).
    network_idle_s: float = 3.0
    # Tiempo extra tras SCAN_TIMEOUT_S para volcar lo capturado (headers, snapshot, DB).
    finalize_grace_s: int = 20
    # Margen sobre el timeout del scan antes de considerar el job abandonado.
    lease_margin_s: int = 45
    heartbeat_file: str = "/tmp/worker-heartbeat"
    # Listas y pesos del analizador (montado de solo lectura desde ./data).
    data_dir: str = field(default_factory=lambda: os.environ.get("DATA_DIR", "/app/data"))
    # Si el worker muere a mitad de un análisis, se reencola pasado este tiempo.
    analysis_lease_s: int = 300
    # Perfil de licencias de las fuentes de datos (docs/adr/019): no_comercial | comercial.
    license_profile: str = field(default_factory=lambda: _license_profile(os.environ.get("LICENSE_PROFILE", "")))
    # Retención (docs/OPERACION.md): los scans terminados más antiguos se borran solos. 0 = no borrar.
    scan_retention_days: int = field(default_factory=lambda: int(os.environ.get("SCAN_RETENTION_DAYS", "30")))
    retention_interval_s: int = 3600
    # Captura interactiva (v1.4, docs/adr/029): display propio, cierre por inactividad y duración máxima.
    interactive_display: str = field(default_factory=lambda: os.environ.get("INTERACTIVE_DISPLAY", ":98"))
    interactive_idle_s: int = field(default_factory=lambda: int(os.environ.get("INTERACTIVE_IDLE_S", "600")))
    interactive_max_s: int = field(default_factory=lambda: int(os.environ.get("INTERACTIVE_MAX_S", "1800")))
    interactive_max_requests: int = field(default_factory=lambda: int(os.environ.get("INTERACTIVE_MAX_REQUESTS", "4000")))
    interactive_vnc_port: int = 5900
    interactive_screen: tuple = (1440, 900)
    # Indicador de recursos (v1.4): cada cuánto publica el worker sus contadores de cgroup.
    resources_interval_s: float = 5.0

    @property
    def lease_s(self) -> int:
        return self.scan_timeout_s + self.lease_margin_s


settings = Settings()
