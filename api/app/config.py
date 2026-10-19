from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    postgres_user: str
    # SecretStr: repr(), str() y los errores de validación muestran "**********", nunca el valor.
    postgres_password: SecretStr
    postgres_db: str
    postgres_host: str = "db"
    postgres_port: int = 5432
    log_level: str = "INFO"
    worker_heartbeat_max_age_s: int = 30
    # Solo stacks de test: acepta el sitio de fixtures (docs/adr/003).
    allow_fixtures: bool = False
    # POST /api/scans: máximo de scans nuevos por IP en la ventana, y tope de jobs en cola.
    scan_rate_limit: int = 10
    scan_rate_window_s: int = 60
    max_queued_jobs: int = 20
    # Importar HAR (v1.3): tamaño máximo del archivo. nginx aplica el mismo tope en /api/har/.
    har_max_bytes: int = 50 * 1024 * 1024
    # Privacy Test (F7): máximo de scans de un grupo (escenarios × perfiles × corridas).
    max_group_jobs: int = 10
    profiles_dir: str = "/app/data/profiles"
    # Comparación de visitas (v1.5.2): intervalo por defecto entre las visitas 1 y 2.
    visit_comparison_interval_s: int = 300
    # Proxies cuyo X-Forwarded-For se acepta (IPs o redes, separadas por comas): el nginx del frontend.
    trusted_proxies: str = ""
    # Redes internas de Docker (docker-compose.yml). Una visita con IP de estas redes llegó por el
    # gateway de Docker desde el propio equipo: no es la IP del visitante (Mi exposición).
    docker_internal_networks: str = "172.30.0.0/16"
    # Mi exposición (F6). El grupo de comparación vive en memoria; nada va a la base de datos.
    ipdb_dir: str = "/app/data/ipdb"
    data_dir: str = "/app/data"
    # Reportes (F8): marca opcional. El logo vive fuera del repo (docs/adr/018).
    report_brand_name: str = ""
    report_brand_dir: str = "/app/brand"
    exposure_ttl_s: int = 7200
    exposure_max_participants: int = 500
    exposure_rate_limit: int = 20
    exposure_rate_window_s: int = 60
    # Token del administrador para purgar el grupo. Vacío = purga remota desactivada.
    exposure_presenter_token: SecretStr = SecretStr("")
    # Modo demo (scripts/demo.sh): "1" o "exposure". Con cualquiera de los dos NO se puede
    # borrar el historial (F10): en una demo hay público en la red.
    demo_mode: str = "0"
    # Captura interactiva (v1.4): si el worker no toma la sesión en este tiempo, se da por perdida.
    interactive_start_timeout_s: int = 120
    # Indicador de recursos (v1.4). El frontend publica su muestra en un puerto que no se expone al host.
    frontend_resources_url: str = "http://frontend:8082/resources.json"
    resources_memory_alert_percent: float = 85.0
    # Una muestra más vieja que esto ya no describe el consumo actual: "no_disponible".
    resources_max_age_s: int = 20

    @property
    def demo(self) -> bool:
        return self.demo_mode.strip().lower() not in ("", "0", "false", "no", "off")

    @property
    def trusted_proxy_networks(self) -> list:
        import ipaddress

        networks = []
        for item in self.trusted_proxies.split(","):
            if item.strip():
                networks.append(ipaddress.ip_network(item.strip(), strict=False))
        return networks

    @property
    def docker_networks(self) -> list:
        import ipaddress

        return [ipaddress.ip_network(item.strip(), strict=False) for item in self.docker_internal_networks.split(",") if item.strip()]

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password.get_secret_value()}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
