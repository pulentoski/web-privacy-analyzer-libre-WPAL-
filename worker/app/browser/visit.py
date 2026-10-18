"""Protocolo de visita fijo de un scan (v1.5.0, docs/adr/038): carga → espera → scroll → espera → cierre.

Los tiempos están en data/visit_protocol.yaml. Cada etapa queda registrada con su hora de inicio y de fin,
si se completó (y por qué no) y qué requests empezaron durante ella (por `seq`, que crece con la llegada).
La captura sigue activa durante el cierre de la pestaña: de esa etapa se registran solo los envíos que el
navegador informó de verdad; el cierre no garantiza capturar todos los beacons de salida.
"""

import asyncio
import pathlib
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache

import yaml
from playwright.async_api import Error as PlaywrightError

from app.config import settings

PROTOCOL_FILE = "visit_protocol.yaml"
STAGES = ("carga", "espera", "scroll", "espera", "cierre")
POLL_S = 0.1
MAX_STAGE_SEQS = 200
# Paso de scroll si no se pudo leer la altura de la ventana.
DEFAULT_STEP_PX = 720
END_TOLERANCE_PX = 2

# Lee la posición desde la página: dato NO confiable, solo decide cuándo dejar de bajar.
SCROLL_STATE_JS = """() => {
  const el = document.scrollingElement || document.documentElement;
  if (!el) return null;
  return [el.scrollTop, el.scrollHeight - el.clientHeight, window.innerHeight];
}"""
# Respaldo si la rueda no movió el documento (p. ej. el puntero quedó sobre un recuadro con scroll propio).
SCROLL_BY_JS = """(step) => {
  const el = document.scrollingElement || document.documentElement;
  if (el) el.scrollTop = el.scrollTop + step;
}"""


class InvalidProtocol(ValueError):
    pass


def _number(value: object, name: str, low: float, high: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
        raise InvalidProtocol(f"{PROTOCOL_FILE}: {name} debe ser un número entre {low} y {high}")
    return value


@dataclass(frozen=True)
class Protocol:
    version: int
    wait_s: tuple[float, float]
    scroll_max_s: float
    scroll_step_ms: int
    close_observe_s: float

    def planned(self, index: int) -> dict:
        """Parámetros de la etapa `index` tal como están en el YAML."""
        return [
            {},
            {"duration_s": self.wait_s[0]},
            {"max_s": self.scroll_max_s, "step_interval_ms": self.scroll_step_ms},
            {"duration_s": self.wait_s[1]},
            {"observe_s": self.close_observe_s},
        ][index]

    @property
    def fixed_s(self) -> float:
        """Tiempo máximo de las etapas con tiempo propio (todas menos la carga)."""
        return sum(self.wait_s) + self.scroll_max_s + self.close_observe_s


def parse_protocol(raw: object) -> Protocol:
    if not isinstance(raw, dict) or not isinstance(raw.get("stages"), list):
        raise InvalidProtocol(f"{PROTOCOL_FILE}: faltan protocol_version o stages")
    version = raw.get("protocol_version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise InvalidProtocol(f"{PROTOCOL_FILE}: protocol_version debe ser un entero ≥ 1")
    stages = raw["stages"]
    names = tuple(stage.get("name") if isinstance(stage, dict) else None for stage in stages)
    if names != STAGES:
        raise InvalidProtocol(f"{PROTOCOL_FILE}: las etapas deben ser exactamente {', '.join(STAGES)}")
    allowed = [{"name"}, {"name", "duration_s"}, {"name", "max_s", "step_interval_ms"}, {"name", "duration_s"}, {"name", "observe_s"}]
    for stage, keys in zip(stages, allowed):
        if set(stage) != keys:
            raise InvalidProtocol(f"{PROTOCOL_FILE}: la etapa {stage['name']} admite solo {sorted(keys)}")
    return Protocol(
        version=version,
        wait_s=(_number(stages[1]["duration_s"], "espera.duration_s", 0, 60), _number(stages[3]["duration_s"], "espera.duration_s", 0, 60)),
        scroll_max_s=_number(stages[2]["max_s"], "scroll.max_s", 0, 120),
        scroll_step_ms=int(_number(stages[2]["step_interval_ms"], "scroll.step_interval_ms", 50, 5000)),
        close_observe_s=_number(stages[4]["observe_s"], "cierre.observe_s", 0, 60),
    )


@lru_cache(maxsize=4)
def _load(path: str) -> Protocol:
    return parse_protocol(yaml.safe_load(pathlib.Path(path).read_text(encoding="utf-8")))


def load_protocol(data_dir: str | None = None) -> Protocol:
    return _load(str(pathlib.Path(data_dir or settings.data_dir) / PROTOCOL_FILE))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class StageLog:
    """Registro de las cinco etapas. `counter()` = requests capturadas hasta ahora (seq de la siguiente)."""

    def __init__(self, protocol: Protocol, counter) -> None:
        self._protocol = protocol
        self._counter = counter
        self._stages: list[dict] = []

    @property
    def current(self) -> dict | None:
        return self._stages[-1] if self._stages else None

    def start(self) -> dict:
        index = len(self._stages)
        entry = {
            "name": STAGES[index], "order": index + 1, "planned": self._protocol.planned(index),
            "completed": False, "started_at": _now(), "ended_at": None, "reason": None,
            "first_seq": self._counter(), "requests": 0,
        }
        self._stages.append(entry)
        return entry

    def end(self, entry: dict, completed: bool, reason: str, **extra) -> None:
        end_seq = self._counter()
        entry.update(completed=completed, ended_at=_now(), reason=reason, requests=end_seq - entry["first_seq"], **extra)
        entry["request_seqs"] = list(range(entry["first_seq"], end_seq))[:MAX_STAGE_SEQS]

    def skip_rest(self, reason: str) -> None:
        """Etapas que no llegaron a empezar: constan como no completadas, sin hora."""
        while len(self._stages) < len(STAGES):
            index = len(self._stages)
            self._stages.append({
                "name": STAGES[index], "order": index + 1, "planned": self._protocol.planned(index),
                "completed": False, "started_at": None, "ended_at": None, "reason": reason,
                "first_seq": None, "requests": 0, "request_seqs": [],
            })

    def result(self) -> dict:
        stages = []
        for entry in self._stages:
            stage = dict(entry)
            stage.pop("first_seq", None)
            stages.append(stage)
        return {"protocol_version": self._protocol.version, "applies": True, "stages": stages}


def interrupted(page, monitor, deadline: float) -> str | None:
    """Motivo para cortar la etapa en curso, o None si puede seguir."""
    if monitor.truncated:
        return "max_requests"
    if page.is_closed():
        return "page_closed"
    if asyncio.get_running_loop().time() >= deadline:
        return "scan_timeout"
    return None


async def wait_stage(page, monitor, deadline: float, duration_s: float) -> str | None:
    """Pausa sin interacción con la captura activa. Devuelve el motivo si se cortó antes."""
    loop = asyncio.get_running_loop()
    until = loop.time() + duration_s
    while loop.time() < until:
        reason = interrupted(page, monitor, deadline)
        if reason:
            return reason
        await asyncio.sleep(min(POLL_S, max(0.0, until - loop.time())))
    return None


async def _scroll_state(page) -> tuple[float, float, float] | None:
    try:
        raw = await asyncio.wait_for(page.evaluate(SCROLL_STATE_JS), 2)
    except (PlaywrightError, asyncio.TimeoutError):
        return None
    if not isinstance(raw, list) or len(raw) != 3 or not all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in raw):
        return None
    return float(raw[0]), float(raw[1]), float(raw[2])


async def scroll_stage(page, monitor, deadline: float, max_s: float, step_ms: int) -> tuple[str | None, bool]:
    """Baja un viewport por paso hasta el final del documento o hasta `max_s`.

    Devuelve (motivo de corte o None, llegó al final). Rueda del mouse (eventos wheel y scroll reales); si la
    rueda no movió el documento, se mueve con scrollTop.
    """
    loop = asyncio.get_running_loop()
    until = loop.time() + max_s
    while True:
        reason = interrupted(page, monitor, deadline)
        if reason:
            return reason, False
        state = await _scroll_state(page)
        if state is not None and state[0] >= state[1] - END_TOLERANCE_PX:
            return None, True
        if loop.time() >= until:
            return None, False
        step = int(min(max(state[2], 100), 4000)) if state is not None else DEFAULT_STEP_PX
        try:
            await page.mouse.move(5, 5)
            await page.mouse.wheel(0, step)
        except PlaywrightError:
            return ("page_closed" if page.is_closed() else "scroll_failed"), False
        await asyncio.sleep(min(step_ms / 1000, max(0.0, until - loop.time())))
        after = await _scroll_state(page)
        if state is not None and after is not None and after[0] <= state[0] and after[0] < after[1] - END_TOLERANCE_PX:
            try:
                await asyncio.wait_for(page.evaluate(SCROLL_BY_JS, step), 2)
            except (PlaywrightError, asyncio.TimeoutError):
                pass


async def close_stage(page, observe_s: float) -> bool:
    """Cierra la pestaña ejecutando beforeunload/pagehide y observa `observe_s` segundos. True = se cerró."""
    loop = asyncio.get_running_loop()
    closed = asyncio.Event()
    page.once("close", lambda _: closed.set())

    async def on_dialog(dialog) -> None:
        # Un aviso «¿salir de la página?» no puede retener la pestaña.
        try:
            await (dialog.accept() if dialog.type == "beforeunload" else dialog.dismiss())
        except PlaywrightError:
            pass

    page.on("dialog", on_dialog)
    until = loop.time() + observe_s
    try:
        await page.close(run_before_unload=True)
    except PlaywrightError:
        pass
    try:
        await asyncio.wait_for(closed.wait(), max(0.0, until - loop.time()))
    except asyncio.TimeoutError:
        pass
    remaining = until - loop.time()
    if remaining > 0:
        await asyncio.sleep(remaining)
    return page.is_closed()
