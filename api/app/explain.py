"""Frases técnicas y grupos de hallazgos (F10, docs/adr/021).

Una línea que nombra el mecanismo y lo explica, antes del detalle. Las plantillas están en
data/explanations.yaml y son deterministas: aquí solo se rellenan con los datos reales del
hallazgo o de la request. Dos garantías que este módulo impone, además de los tests:

  - una frase de nivel distinto de EVIDENCIA siempre lleva un matiz ("podría", "es compatible
    con"...); si una plantilla no lo tuviera, se usa la frase genérica de ese nivel;
  - si falta un dato para rellenar la plantilla, no se inventa: se usa la frase genérica.

Lo que se inserta en las plantillas viene del sitio analizado (nombres de parámetros,
dominios). Aquí es texto y como texto debe pintarse: nunca como HTML.
"""

import pathlib
import re
from collections import Counter
from functools import lru_cache
from urllib.parse import urlsplit

import yaml

from app.config import get_settings

UNKNOWN = "no_disponible"
LEVELS = ("EVIDENCIA", "INFERENCIA", "POSIBLE", "DESCONOCIDO")
MAX_VALUE_CHARS = 80
MAX_STEP_ITEMS = 40
MAX_COMPANIES = 3
# Grupos de «Hallazgos por grupo» (v1.4.2: se añade «Registro de interacción»).
STEP_COUNT = 8
TOKEN = re.compile(r"\{(\w+)(?:([|?])([^|{}]*)\|([^|{}]*))?\}")
# Heurísticas de fingerprinting que son inferencia sobre el propósito (no la lectura en sí).
FP_STORY_TYPES = frozenset({"canvas_fingerprinting", "font_enumeration", "audio_fingerprinting", "webgl_fingerprinting",
                            "webgl_unmasked_read", "webrtc_ip_discovery", "property_sweep"})


class Joined(str):
    """Lista ya armada con join_names(): cada elemento se acotó por separado, el conjunto no se corta."""


def clean(value) -> str:
    """Texto capturado listo para una frase: sin caracteres de control y acotado."""
    if isinstance(value, Joined):
        return str(value)
    text = "".join(ch for ch in str(value) if ch.isprintable())
    return text if len(text) <= MAX_VALUE_CHARS else text[:MAX_VALUE_CHARS] + "…"


def join_names(names: list[str], limit: int = MAX_COMPANIES) -> str:
    names = [clean(name) for name in names if name]
    if not names:
        return ""
    shown, rest = names[:limit], len(names) - limit
    if rest > 0:
        return Joined(", ".join(shown) + f" y {rest} más")
    return Joined(shown[0] if len(shown) == 1 else ", ".join(shown[:-1]) + " y " + shown[-1])


def company(entity: str | None, domain: str | None) -> str:
    """Cómo se nombra a quien recibió algo: la organización si se conoce; si no, el dominio."""
    if entity and entity != UNKNOWN:
        return entity
    return domain or ""


def script_host(script_url: str | None) -> str:
    """Host de un script para nombrarlo cuando no se conoce su organización."""
    match = re.search(r"https?://[^\s)]+", script_url or "")
    try:
        return (urlsplit(match.group(0)).hostname or "") if match else ""
    except ValueError:
        return ""


class Explanations:
    def __init__(self, data: dict) -> None:
        self.hedges = [str(hedge).lower() for hedge in data["hedges"]]
        self.fallback = data["fallback"]
        self.signals = data["signals"]
        self.findings = data["findings"]
        self.steps = data["steps"]
        self.none = data["none"]
        self.data_names = data["data_names"]
        self.api_attributes = data["api_attributes"]
        self.list_names = data.get("list_names") or {}
        self.consent_states = data.get("consent_states") or {}
        # Nombres de los eventos de interacción (data/interaction_signals.yaml); sin el archivo se usa la clave.
        self.event_names: dict = {}
        self._validate()

    # --- validación de las plantillas (falla al cargar, no al mostrar) ---

    def hedged(self, text: str) -> bool:
        lowered = text.lower()
        return any(hedge in lowered for hedge in self.hedges)

    def _validate(self) -> None:
        for level in LEVELS:
            if level not in self.fallback:
                raise ValueError(f"explanations.yaml: falta fallback para {level}")
            if level != "EVIDENCIA" and not self.hedged(self.fallback[level]):
                raise ValueError(f"explanations.yaml: el fallback de {level} se redacta como hecho")
        for group, entries in (("signals", self.signals), ("findings", self.findings)):
            for name, spec in entries.items():
                for level in LEVELS:
                    if level != "EVIDENCIA" and level in spec and not self.hedged(spec[level]):
                        raise ValueError(f"explanations.yaml: {group}.{name}.{level} se redacta como hecho")
        ids = [step["id"] for step in self.steps]
        if len(ids) != STEP_COUNT or len(set(ids)) != STEP_COUNT:
            raise ValueError(f"explanations.yaml: «Hallazgos por grupo» debe tener {STEP_COUNT} pasos distintos")
        for step in self.steps:
            if "inference" in step and not self.hedged(step["inference"]):
                raise ValueError(f"explanations.yaml: steps.{step['id']}.inference se redacta como hecho")
        for name, spec in self.findings.items():
            if spec.get("step") is not None and spec["step"] not in ids:
                raise ValueError(f"explanations.yaml: findings.{name}.step no existe")

    # --- render ---

    @staticmethod
    def render(template: str, variables: dict) -> str | None:
        """Rellena la plantilla. None si falta algún dato (no se inventa nada)."""
        missing = False

        def substitute(match: re.Match) -> str:
            nonlocal missing
            name, mode, one, many = match.groups()
            value = variables.get(name)
            if value is None or value == "":
                missing = True
                return ""
            if mode is None:
                return clean(value)
            form = one if value == 1 else many
            return form if mode == "?" else f"{value} {form}"

        text = TOKEN.sub(substitute, template)
        return None if missing else text

    def phrase(self, templates: dict | None, level: str, variables: dict) -> dict:
        """{text, level, generic}: la frase de ese nivel, o la genérica si no hay o no se puede rellenar."""
        level = level if level in LEVELS else "DESCONOCIDO"
        text = self.render(templates[level], variables) if templates and level in templates else None
        generic = text is None or (level != "EVIDENCIA" and not self.hedged(text))
        return {"text": self.fallback[level] if generic else text, "level": level, "generic": generic}

    def data_name(self, api: str | None) -> str:
        return self.data_names.get(self.api_attributes.get(api or "", ""), self.data_names["_default"])

    # --- requests ---

    def request_phrase(self, *, reasons: list | None, entity: str | None, domain: str | None, third_party: bool | None,
                       party: str | None = None) -> dict | None:
        """Frase técnica de una request, según su señal de mayor prioridad. None = sin análisis."""
        if reasons is None:
            return None
        known = [reason for reason in reasons if isinstance(reason, dict) and reason.get("signal") in self.signals]
        same_org = party == "same_org" and "same_org" in self.signals
        if same_org:
            # Otro dominio del mismo dueño (v1.4.2): las señales «a tercero» por dominio no lo describen.
            known = [reason for reason in known if reason["signal"] not in ("third_party", "third_party_static_clean")]
        variables = {"empresa": company(entity, domain)}
        if not known:
            signal = "same_org" if same_org else "third_party" if third_party else "_first_party"
            return {**self.phrase(self.signals[signal], "EVIDENCIA", variables), "signal": signal}
        reason = max(known, key=lambda item: self.signals[item["signal"]].get("priority", 0))
        data = reason.get("data") if isinstance(reason.get("data"), dict) else {}
        others = [name for name in data.get("other_entities") or [] if name != entity] or list(data.get("other_domains") or [])
        variables.update({
            "parametro": data.get("parameter"),
            "dato": self.data_name(data.get("api")) if data.get("api") else None,
            "otras": join_names(others),
            "guardado": data.get("stored_in"),
            "lista": self.list_names.get(data.get("list") or reason["signal"].removeprefix("list_")),
        })
        return {**self.phrase(self.signals[reason["signal"]], reason.get("level"), variables), "signal": reason["signal"]}

    # --- hallazgos ---

    def finding_variables(self, finding: dict, entities: dict[str, str], scripts: dict[str, str]) -> tuple[dict, list[str]]:
        """Variables de la plantilla y las organizaciones involucradas en el hallazgo."""
        kind = finding.get("type")
        details = finding.get("details") if isinstance(finding.get("details"), dict) else {}
        refs = finding.get("evidence_refs")
        ref_count = len((refs or {}).get("requests") or []) if isinstance(refs, dict) else len(refs or [])
        domain = details.get("domain")
        name = company(entities.get(domain) or details.get("entity"), domain) if domain else ""
        variables: dict = {"empresa": name, "parametro": details.get("parameter"), "n": ref_count}
        companies = [name] if name else []
        if finding.get("kind") == "fingerprinting" and kind != "exfiltration":
            script = finding.get("script_url") or ""
            name = company(scripts.get(script), script_host(script)) or "origen no identificado"
            variables.update({"empresa": name, "n": details.get("distinct_fonts") or len(details.get("properties") or []) or None})
            companies = [name]
        if kind == "exfiltration":
            variables["dato"] = self.data_name(details.get("api"))
        elif kind == "id_sync":
            owners = list(dict.fromkeys(company(entities.get(item), item) for item in details.get("domains") or []))
            variables["empresas"], companies = join_names(owners), owners
        elif kind == "persistent_id":
            variables["guardado"] = details.get("stored_in")
        elif kind == "persistent_cookie":
            variables.update({
                "quien": f"{name}, organización distinta del sitio," if details.get("third_party") else f"el propio sitio ({name})",
                "n": details.get("cookies"), "dias": details.get("max_days"),
            })
        elif kind == "list_match":
            variables["lista"] = self.list_names.get(details.get("list"))
        elif kind == "tcf_state":
            cmp_name = details.get("cmp_name")
            variables["cmp"] = cmp_name if cmp_name and cmp_name != UNKNOWN else (f"CMP n.º {details['cmp_id']}" if details.get("cmp_id") is not None else "no identificada")
            companies = []
        elif kind == "consent_mode_state":
            variables.update({"publicidad": self.consent_states.get(details.get("ad_storage"), "sin definir"),
                              "medicion": self.consent_states.get(details.get("analytics_storage"), "sin definir")})
            companies = []
        elif kind == "consent_mode_granted_without_interaction":
            variables.update({"que": {"ad_storage": "publicidad", "analytics_storage": "medición"}.get(details.get("signal"))})
            companies = []
        elif kind == "cname_cloaking":
            variables.update({"host": details.get("host"), "destino": details.get("cname_target")})
            companies = [details["organization"]] if details.get("organization") else []
        elif kind == "first_party_telemetry":
            variables.update({"n": details.get("requests"), "hosts": ", ".join((details.get("hosts") or [])[:4]) or UNKNOWN})
            companies = []
        elif kind == "first_party_analytics_script":
            variables.update({"nombres": ", ".join((details.get("names") or [])[:4]) or UNKNOWN})
            companies = []
        elif kind == "search_leak":
            variables.update({"termino": details.get("term"), "host": details.get("host")})
        elif kind == "sync_wave":
            variables.update({"organizaciones": details.get("organizations"), "n": details.get("requests"), "iniciador": details.get("initiator")})
        elif kind == "fp_read":
            variables["datos"] = details.get("datos")
        elif kind == "interaction_listener":
            variables["eventos"] = join_names([self.event_names.get(event, event) for event in details.get("events") or []], 7)
        elif kind == "interaction_payload":
            variables["que"] = details.get("label")
        elif kind == "interaction_sent":
            name = company(entities.get(domain), details.get("organization") or domain)
            variables.update({"empresa": name, "n": details.get("requests"), "k": details.get("interactions")})
            companies = [name] if name else []
        elif kind == "server_side_meta":
            variables["empresa"] = details.get("host") or name
            companies = [variables["empresa"]]
        return variables, companies

    def finding_phrase(self, finding: dict, entities: dict[str, str] | None = None, scripts: dict[str, str] | None = None) -> dict:
        variables, companies = self.finding_variables(finding, entities or {}, scripts or {})
        spec = self.findings.get(finding.get("type"))
        return {**self.phrase(spec, finding.get("level"), variables), "step": (spec or {}).get("step"), "companies": companies}

    # --- «Hallazgos por grupo» ---

    def story(self, findings: list[dict], entities: dict[str, str], scripts: dict[str, str], source: str = "scan") -> dict:
        """Los pasos, siempre en el mismo orden, con sus frases, conteos, niveles y evidencia.

        `source` (scan | har_import | interactive) elige el texto del grupo fijo: en una captura
        interactiva hubo navegación humana y no se dice «visita automatizada».

        `findings`: {key, kind, type, level, claim, evidence_refs: {requests, calls}, details, script_url}.
        """
        by_step: dict[str, list[dict]] = {step["id"]: [] for step in self.steps}
        for finding in findings:
            phrase = self.finding_phrase(finding, entities, scripts)
            if phrase["step"] in by_step:
                by_step[phrase["step"]].append({
                    "key": finding.get("key"), "type": finding.get("type"), "level": phrase["level"], "plain": phrase["text"],
                    "claim": finding.get("claim"), "evidence_refs": finding.get("evidence_refs") or {"requests": [], "calls": []},
                    "companies": phrase["companies"],
                })
        steps = []
        for number, step in enumerate(self.steps, start=1):
            items = by_step[step["id"]]
            technical = (step.get("technical_by_source") or {}).get(source) or step["technical"]
            base = {"id": step["id"], "number": number, "title": step["title"], "technical": technical, "icon": step.get("icon")}
            if "fixed" in step:
                fixed = (step.get("fixed_by_source") or {}).get(source) or step["fixed"]
                steps.append({**base, "fixed": True, "observed": True, "count": None, "levels": {},
                              "sentences": [{"text": text, "level": "DESCONOCIDO"} for text in fixed], "items": [], "total_items": 0})
                continue
            # Lo observado primero; dentro de cada nivel, el orden del análisis.
            items.sort(key=lambda item: LEVELS.index(item["level"]))
            evidence = [item for item in items if item["level"] == "EVIDENCIA"]
            other = [item for item in items if item["level"] != "EVIDENCIA"]
            sentences = []
            if evidence:
                ranked = [name for name, _ in Counter(name for item in evidence for name in item["companies"]).most_common()]
                variables = {"k": len(ranked) or None, "n": len(evidence), "empresas": join_names(ranked)}
                text = self.render(step["evidence"], variables)
                sentences.append({"text": text or self.fallback["EVIDENCIA"], "level": "EVIDENCIA"})
            if other:
                level = other[0]["level"]
                text = self.render(step["inference"], {"n": len(other)})
                sentences.append({"text": text if text and self.hedged(text) else self.fallback[level], "level": level})
            if not items:
                sentences.append({"text": self.none, "level": None})
            steps.append({
                **base, "fixed": False, "observed": bool(items), "count": len(items),
                "levels": dict(Counter(item["level"] for item in items)), "sentences": sentences,
                "items": [{key: value for key, value in item.items() if key != "companies"} for item in items[:MAX_STEP_ITEMS]],
                "total_items": len(items),
            })
        return {"steps": steps, "none": self.none}

    def fp_reads(self, scripts: list[dict], call_refs: dict[str, list[int]]) -> list[dict]:
        """Hallazgos «un script leyó...» (EVIDENCIA), uno por script, a partir de sus llamadas registradas."""
        out = []
        for script in scripts:
            attributes = list(dict.fromkeys(
                self.api_attributes[entry["api"]] for entry in script.get("apis") or [] if entry.get("api") in self.api_attributes
            ))
            refs = call_refs.get(script.get("script_url") or "", [])
            if not attributes or not refs:
                continue
            labels = [self.data_names.get(attribute, self.data_names["_default"]) for attribute in attributes]
            apis = ", ".join(f"{entry['api']} ×{entry['count']}" for entry in (script.get("apis") or [])[:8])
            out.append({
                "key": None, "kind": "fingerprinting", "type": "fp_read", "level": "EVIDENCIA", "script_url": script.get("script_url"),
                "claim": f"El script {script.get('script_url') or '(script no identificado)'} llamó a estas APIs instrumentadas: {apis}"
                         + (" y otras." if len(script.get("apis") or []) > 8 else "."),
                "evidence_refs": {"requests": [], "calls": refs[:50]},
                "details": {"datos": join_names(labels, 4), "attributes": attributes},
            })
        return out


class Glossary:
    def __init__(self, data: dict) -> None:
        self.terms = data["terms"]
        self.panels = data["panels"]
        ids = [term["id"] for term in self.terms]
        if len(ids) != len(set(ids)):
            raise ValueError("glossary.yaml: términos repetidos")
        for name, panel in self.panels.items():
            unknown = set(panel.get("terms") or []) - set(ids)
            if unknown:
                raise ValueError(f"glossary.yaml: el panel {name} cita términos que no existen: {sorted(unknown)}")

    def as_dict(self) -> dict:
        return {"terms": self.terms, "panels": self.panels}


def _read(name: str) -> dict:
    return yaml.safe_load((pathlib.Path(get_settings().data_dir) / name).read_text(encoding="utf-8"))


@lru_cache
def explanations() -> Explanations:
    loaded = Explanations(_read("explanations.yaml"))
    try:
        loaded.event_names = {str(key): str(value) for key, value in (_read("interaction_signals.yaml").get("events") or {}).items()}
    except (OSError, ValueError, AttributeError):
        loaded.event_names = {}
    return loaded


@lru_cache
def glossary() -> Glossary:
    return Glossary(_read("glossary.yaml"))
