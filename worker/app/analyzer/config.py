"""Configuración del analizador: todo sale de data/*.yaml, nada está en el código."""

import json
import logging
import pathlib
from dataclasses import dataclass, field

import yaml

from app.analyzer.account_ids import AccountIds
from app.analyzer.constants import SharedConstants
from app.analyzer.first_party_telemetry import FirstPartyTelemetry
from app.analyzer.har_signals import HarSignals
from app.analyzer.parameters import NameCategories
from app.analyzer.service_types import ServiceTypes

logger = logging.getLogger(__name__)

LEVELS = ("EVIDENCIA", "INFERENCIA", "POSIBLE", "DESCONOCIDO")

from app.analyzer.interaction import BenignLibraries, InteractionSignals, ServerSideTracking  # noqa: E402
from app.analyzer.attribution import CookiePurposes, PublicCdns  # noqa: E402

@dataclass(frozen=True)
class AnalyzerConfig:
    names: NameCategories
    scoring: dict
    domain_categories: dict[str, str]
    google_domains: frozenset = frozenset()
    cmp_names: dict = None  # cmpId -> nombre (lista de IAB); {} si no está el archivo
    # Valores compartidos que no son identificadores (data/shared_constants.yaml).
    shared_constants: SharedConstants = field(default_factory=SharedConstants)
    # IDs de cuenta del sitio (data/account_ids.yaml): no son identificadores del visitante.
    account_ids: AccountIds = field(default_factory=AccountIds)
    # Giro de cada organización/dominio (data/service_types.yaml): contexto, no evidencia.
    service_types: ServiceTypes = field(default_factory=ServiceTypes)
    # Señales de bloqueo antibot (scoring.yaml §blocking).
    blocking: dict = field(default_factory=dict)
    # Plantillas de conclusión de consentimiento (consent_mode.yaml §conclusions).
    consent_conclusions: dict = field(default_factory=dict)
    # Fuga de búsqueda y ola de sincronización (data/har_signals.yaml, v1.3).
    har_signals: HarSignals = field(default_factory=HarSignals)
    # Telemetría propia (data/first_party_telemetry.yaml, v1.3.4).
    first_party_telemetry: FirstPartyTelemetry = field(default_factory=FirstPartyTelemetry)
    # v1.4.2 (docs/adr/030): registro de interacción, librerías benignas de canvas y rastreo del lado del servidor.
    interaction: InteractionSignals = field(default_factory=InteractionSignals)
    benign_libraries: BenignLibraries = field(default_factory=BenignLibraries)
    server_side: ServerSideTracking = field(default_factory=ServerSideTracking)
    # v1.4.6 (docs/adr/033): librerías de CDN públicos (organizations.yaml §public_cdns) y propósito de cookies.
    public_cdns: PublicCdns = field(default_factory=PublicCdns)
    cookie_purposes: CookiePurposes = field(default_factory=CookiePurposes)

    @property
    def bands(self) -> list[dict]:
        return self.scoring["bands"]

    def band(self, score: int) -> str:
        for band in self.bands:
            if score <= band["max"]:
                return band["name"]
        return self.bands[-1]["name"]

    def band_at_least(self, name: str) -> list[str]:
        names = [band["name"] for band in self.bands]
        return names[names.index(name):]

    @property
    def tracker_bands(self) -> list[str]:
        return self.band_at_least(self.scoring["tracker_min_band"])


def load_config(data_dir: str | pathlib.Path, *, allow_fixtures: bool = False, license_profile: str = "no_comercial",
                blocking_min_requests: int | None = None) -> AnalyzerConfig:
    data_dir = pathlib.Path(data_dir)

    def read(name: str) -> dict:
        return yaml.safe_load((data_dir / name).read_text(encoding="utf-8")) or {}

    scoring = read("scoring.yaml")
    # Override operativo del umbral de "pocas requests" (v1.2.1): el resto del §blocking sale del YAML.
    if blocking_min_requests is not None:
        scoring.setdefault("blocking", {})["min_requests"] = blocking_min_requests
    for name, signal in scoring["signals"].items():
        if signal.get("level") not in LEVELS or not isinstance(signal.get("weight"), int):
            raise ValueError(f"scoring.yaml: señal {name!r} sin weight entero o level válido")
    domain_categories = {
        str(domain).lower(): category
        for category, domains in read("domain_categories.yaml").items()
        for domain in domains or []
    }
    consent = read("consent_mode.yaml")
    google = set(consent.get("google_domains") or [])
    if allow_fixtures:
        google |= set(consent.get("test_domains") or [])
    service_types = ServiceTypes(read("service_types.yaml"))
    cmp_names = {}
    try:
        if license_profile == "comercial":
            # La lista de CMP de IAB no tiene licencia explícita: en el perfil comercial no se abre
            # y el reporte muestra solo el número de CMP (docs/adr/019).
            raise KeyError("excluida")
        cmps = json.loads((data_dir / "iab" / "cmp-list.json").read_text(encoding="utf-8"))["cmps"]
        cmp_names = {int(entry["id"]): str(entry["name"])[:120] for entry in cmps.values()}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        # Sin la lista se muestra solo el número de CMP, pero que conste por qué.
        if license_profile != "comercial":
            logger.warning("cmp_list_unavailable", extra={"error_type": type(exc).__name__})
        cmp_names = {}
    benign = BenignLibraries(read("benign_libraries.yaml"))
    return AnalyzerConfig(
        names=NameCategories(read("param_names.yaml")), scoring=scoring, domain_categories=domain_categories,
        google_domains=frozenset(google), cmp_names=cmp_names,
        shared_constants=SharedConstants(read("shared_constants.yaml")),
        account_ids=AccountIds(read("account_ids.yaml"), allow_fixtures=allow_fixtures),
        service_types=service_types, blocking=scoring.get("blocking") or {},
        consent_conclusions=consent.get("conclusions") or {},
        har_signals=HarSignals(read("har_signals.yaml")),
        first_party_telemetry=FirstPartyTelemetry(read("first_party_telemetry.yaml")),
        interaction=InteractionSignals(read("interaction_signals.yaml")),
        benign_libraries=benign,
        server_side=ServerSideTracking(read("server_side_tracking.yaml")),
        public_cdns=PublicCdns(read("organizations.yaml").get("public_cdns"), benign),
        cookie_purposes=CookiePurposes(read("cookie_purposes.yaml")),
    )
