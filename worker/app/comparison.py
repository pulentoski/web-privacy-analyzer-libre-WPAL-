"""Comparación de visitas (v1.5.2, docs/adr/040): perfiles A y B en disco y verificación de su estado.

Tres visitas a la misma URL, cada una un job normal con el protocolo de visita de la v1.5.0:
  1. perfil A limpio (directorio nuevo y vacío);
  2. perfil A persistente: el mismo directorio, tras cerrar el navegador y esperar el intervalo configurado;
  3. perfil B limpio de control: otro directorio nuevo y vacío, otro proceso de Chromium, otro usuario de proxy.

Las tres usan el mismo mecanismo (contexto persistente de Playwright con la caché dentro del perfil), para que la única
diferencia entre ellas sea el estado con que abre el perfil. Lo que se guarda del estado son huellas: sha256 de cada
archivo del perfil y de cada valor de cookie, nunca los valores. Los directorios se borran al terminar la comparación.
"""

import hashlib
import json
import logging
import os
import pathlib
import shutil
import uuid
from datetime import datetime, timedelta, timezone

from app.browser.launcher import CHROMIUM_ARGS
from app.browser.visit import load_protocol
from app.config import accept_language, settings

logger = logging.getLogger(__name__)

PROFILE_BY_VISIT = {1: "A", 2: "A", 3: "B"}
MAX_LISTED = 20  # cookies o archivos que se nombran como ejemplo de una diferencia
DIR_MODE = 0o700


class ProfileError(Exception):
    """El directorio del perfil no está como debe (p. ej. el de A desapareció antes de la visita 2)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def job_visit(job) -> dict | None:
    """{"id", "visit", "profile"} si el job es una visita de una comparación; None si es un scan normal."""
    raw = job["options"] if "options" in job.keys() else None
    try:
        options = json.loads(raw) if isinstance(raw, str) else (raw or {})
    except ValueError:
        return None
    value = options.get("comparison") if isinstance(options, dict) else None
    if not isinstance(value, dict) or value.get("visit") not in PROFILE_BY_VISIT:
        return None
    try:
        comparison_id = str(uuid.UUID(str(value.get("id"))))
    except ValueError:
        return None
    return {"id": comparison_id, "visit": value["visit"], "profile": PROFILE_BY_VISIT[value["visit"]]}


def comparison_dir(comparison_id: str) -> pathlib.Path:
    # uuid.UUID() otra vez: el nombre del directorio nunca sale de un texto sin validar.
    return pathlib.Path(settings.comparison_profiles_dir) / str(uuid.UUID(comparison_id))


def profile_dir(comparison_id: str, profile: str) -> pathlib.Path:
    if profile not in ("A", "B"):
        raise ValueError(profile)
    return comparison_dir(comparison_id) / profile


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def manifest(root: pathlib.Path) -> dict:
    """Huella del contenido del directorio: sha256 de cada archivo regular (ruta relativa → hash) y su resumen."""
    files = {}
    for path in sorted(root.rglob("*")) if root.is_dir() else []:
        if path.is_symlink() or not path.is_file():
            continue
        digest = hashlib.sha256()
        try:
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1 << 20), b""):
                    digest.update(chunk)
        except OSError:
            continue
        files[str(path.relative_to(root))] = digest.hexdigest()
    total = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
    return {"files": files, "digest": total}


def inventory(root: pathlib.Path) -> dict:
    """Qué almacenes dejó Chromium en el perfil: base de cookies, Local Storage, IndexedDB (orígenes) y caché HTTP."""
    default = root / "Default"

    def size(path: pathlib.Path) -> int:
        return sum(item.stat().st_size for item in path.rglob("*") if item.is_file() and not item.is_symlink()) if path.is_dir() else 0

    indexeddb = default / "IndexedDB"
    origins = sorted(
        item.name.removesuffix(".indexeddb.leveldb")
        for item in (indexeddb.iterdir() if indexeddb.is_dir() else [])
        if item.name.endswith(".indexeddb.leveldb")
    )
    return {
        "cookies_db": (default / "Cookies").is_file(),
        "local_storage_bytes": size(default / "Local Storage"),
        "indexeddb_origins": origins,
        "indexeddb_bytes": size(indexeddb),
        "cache_bytes": size(root / "cache"),
    }


def cookie_fingerprints(cookies: list[dict]) -> dict:
    """Cookies del contexto como huellas: (dominio, ruta, nombre) + sha256 del valor. Separa persistentes y de sesión."""
    persistent, session = [], 0
    for cookie in cookies:
        expires = cookie.get("expires")
        if not isinstance(expires, (int, float)) or expires <= 0:
            session += 1  # -1 = cookie de sesión: no sobrevive al cierre del navegador
            continue
        persistent.append({
            "domain": str(cookie.get("domain") or "")[:255],
            "path": str(cookie.get("path") or "")[:512],
            "name": str(cookie.get("name") or "")[:256],
            "sha256": hashlib.sha256(str(cookie.get("value") or "").encode("utf-8", "replace")).hexdigest(),
            "expires": float(expires),
        })
    persistent.sort(key=lambda item: (item["domain"], item["path"], item["name"]))
    return {"persistent": persistent, "session": session}


def missing_cookies(expected: list[dict], loaded: list[dict], at_epoch: float) -> list[dict]:
    """Cookies persistentes de la visita 1, aún vigentes al abrir la visita 2, que el perfil no cargó con el mismo valor."""
    have = {(item["domain"], item["path"], item["name"], item["sha256"]) for item in loaded}
    return [
        {"domain": item["domain"], "path": item["path"], "name": item["name"]}
        for item in expected
        if item["expires"] > at_epoch and (item["domain"], item["path"], item["name"], item["sha256"]) not in have
    ]


def conditions(job, result: dict | None) -> dict:
    """Condiciones de la visita, para comprobar que las tres se hicieron igual (la api lista las diferencias)."""
    measurement = (result or {}).get("measurement") or {}
    return {
        "url": job["url"],
        "browser_version": (measurement.get("browser") or {}).get("version"),
        "browser_mode": "headless" if settings.headless else "headful",
        "locale": settings.worker_locale,
        "timezone": settings.worker_timezone,
        "accept_language": accept_language(settings.worker_locale),
        "fp_instrumentation": settings.fp_instrumentation,
        "visit_protocol_version": load_protocol().version,
        "scan_timeout_s": settings.scan_timeout_s,
        "max_requests": settings.max_requests,
        "max_body_capture_bytes": settings.max_body_capture_bytes,
        "chromium_args_sha256": hashlib.sha256("\n".join(CHROMIUM_ARGS).encode()).hexdigest()[:16],
        # País de la IP de salida (v1.5.0); la IP no se guarda. La misma IP en las tres visitas es un límite (ADR 040).
        "egress_country": (measurement.get("egress_country") or {}).get("country_code") if isinstance(measurement.get("egress_country"), dict) else None,
        "worker_id": settings.worker_id,
        "profile_mode": "persistent_context",
    }


class ProfileSession:
    """Perfil en disco de una visita. capture.run_scan llama a launching/before_navigation/before_close/closed."""

    def __init__(self, visit: dict, previous: dict | None) -> None:
        self.visit = visit
        self.path = profile_dir(visit["id"], visit["profile"])
        self.user_data_dir = str(self.path)
        self.previous = previous  # estado que dejó la visita 1 (solo para la visita 2)
        self.state: dict = {"profile": visit["profile"]}

    def prepare(self) -> None:
        """Antes de lanzar Chromium: crea el perfil limpio (visitas 1 y 3) o comprueba que el de A sigue intacto (visita 2)."""
        start: dict = {"dir_existed": self.path.exists()}
        if self.visit["visit"] in (1, 3):
            if self.path.exists():
                # Con un solo intento por visita no debería pasar; si pasa, el perfil «limpio» no lo sería.
                raise ProfileError("COMPARISON_PROFILE_NOT_CLEAN", "El directorio del perfil limpio ya existía.")
            comparison_dir(self.visit["id"]).mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
            self.path.mkdir(mode=DIR_MODE)
            start["files_before_launch"] = sum(1 for _ in self.path.rglob("*"))
            if self.visit["profile"] == "B":
                other = profile_dir(self.visit["id"], "A")
                # B no comparte nada con A: otro directorio (y la caché HTTP va dentro de cada uno).
                start["separate_from_a"] = os.path.realpath(other) != os.path.realpath(self.path)
        else:
            if not self.path.is_dir():
                start["manifest_matches"] = False
                self.state["start"] = start
                raise ProfileError("COMPARISON_STATE_LOST", "El directorio del perfil A no estaba al empezar la visita 2.")
            expected = (self.previous or {}).get("end", {}).get("manifest") or {}
            current = manifest(self.path)
            changed = sorted(name for name in set(expected.get("files", {})) | set(current["files"])
                             if expected.get("files", {}).get(name) != current["files"].get(name))
            start["manifest_matches"] = bool(expected) and current["digest"] == expected.get("digest")
            start["manifest_changed_files"] = changed[:MAX_LISTED]
            start["manifest_changed_count"] = len(changed)
        self.state["start"] = start

    def launching(self) -> None:
        self.state["launched_at"] = now_iso()

    async def before_navigation(self, context) -> None:
        start = self.state.setdefault("start", {})
        try:
            cookies = cookie_fingerprints(await context.cookies())
        except Exception:  # sin lectura no se puede verificar: queda como no verificado, no como «sin cookies»
            start["cookies_read"] = False
            return
        start["cookies_read"] = True
        start["cookies_at_start"] = len(cookies["persistent"]) + cookies["session"]
        if self.visit["visit"] == 2:
            expected = (self.previous or {}).get("end", {}).get("cookies", {}).get("persistent", [])
            missing = missing_cookies(expected, cookies["persistent"], datetime.now(timezone.utc).timestamp())
            start["persistent_cookies_expected"] = sum(1 for item in expected if item["expires"] > datetime.now(timezone.utc).timestamp())
            start["persistent_cookies_missing"] = len(missing)
            start["missing_examples"] = missing[:MAX_LISTED]

    async def before_close(self, context) -> None:
        try:
            self.state["end"] = {"cookies": cookie_fingerprints(await context.cookies())}
        except Exception:
            self.state["end"] = {"cookies": None}

    def closed(self) -> None:
        self.state["closed_at"] = now_iso()

    def record_disk(self) -> None:
        """Con el navegador cerrado, Chromium ya escribió su estado: esto es lo que hay en disco (bloqueante: en un hilo)."""
        end = self.state.setdefault("end", {})
        end["manifest"] = manifest(self.path)
        end["inventory"] = inventory(self.path)


def next_not_before(visit: int, closed_at: str | None, interval_s: int) -> datetime:
    """Hora desde la que se puede tomar la visita siguiente: la 2 espera el intervalo desde el cierre de la 1."""
    base = datetime.fromisoformat(closed_at) if closed_at else datetime.now(timezone.utc)
    return base + timedelta(seconds=interval_s if visit == 1 else 0)


def remove(comparison_id: str) -> None:
    shutil.rmtree(comparison_dir(comparison_id), ignore_errors=True)


ACTIVE_SQL = "SELECT DISTINCT comparison_id::text FROM jobs WHERE comparison_id IS NOT NULL AND status IN ('queued', 'running')"


async def purge_orphans(pool) -> list[str]:
    """Borra los perfiles de comparaciones que ya no tienen visitas pendientes (terminadas, fallidas o borradas)."""
    root = pathlib.Path(settings.comparison_profiles_dir)
    if not root.is_dir():
        return []
    active = {row[0] for row in await pool.fetch(ACTIVE_SQL)}
    removed = []
    for item in root.iterdir():
        try:
            name = str(uuid.UUID(item.name))
        except ValueError:
            continue  # solo se tocan los directorios que crea este módulo
        if name not in active:
            shutil.rmtree(item, ignore_errors=True)
            removed.append(name)
    if removed:
        logger.info("comparison_profiles_purged", extra={"count": len(removed)})
    return removed
