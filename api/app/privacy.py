"""Comparación del Privacy Test (F7): funciones puras sobre los scans de un grupo.

Regla de la fase: toda comparación usa agregados de varias corridas (mediana, rango y
"apareció en k de N"), no un scan aislado. Y ningún texto afirma anonimato: solo qué
cambió, qué permaneció y qué sigue siendo observable.
"""

import re
import statistics
from collections import defaultdict

REAL = "real"
UNKNOWN = "no_disponible"
MAX_ITEMS = 60
IP_NOTE = (
    "La dirección IP es la misma en todas las corridas: ningún perfil la cambia. Un sitio la ve igual "
    "que antes, y con ella el país y el proveedor de internet."
)
# Atributos comparados entre el navegador real y cada perfil: (clave, etiqueta, cómo leerlo).
ATTRIBUTES = [
    ("user_agent", "User-Agent (JavaScript)", lambda js, h: js.get("user_agent")),
    ("header_user_agent", "User-Agent (cabecera)", lambda js, h: h.get("user-agent")),
    ("platform", "navigator.platform", lambda js, h: js.get("platform")),
    ("ua_ch_platform", "Client Hints: plataforma", lambda js, h: (js.get("ua_ch") or {}).get("platform")),
    ("header_sec_ch_ua_platform", "Sec-CH-UA-Platform (cabecera)", lambda js, h: h.get("sec-ch-ua-platform")),
    ("languages", "Idiomas (JavaScript)", lambda js, h: ", ".join(js.get("languages") or []) or None),
    ("header_accept_language", "Accept-Language (cabecera)", lambda js, h: h.get("accept-language")),
    ("timezone", "Zona horaria", lambda js, h: js.get("timezone")),
    ("screen", "Pantalla", lambda js, h: "x".join(map(str, js["screen"])) if js.get("screen") else None),
    ("device_pixel_ratio", "Densidad de píxeles", lambda js, h: js.get("device_pixel_ratio")),
    ("max_touch_points", "Puntos táctiles", lambda js, h: js.get("max_touch_points")),
    ("hardware_concurrency", "Núcleos de CPU", lambda js, h: js.get("hardware_concurrency")),
    ("device_memory", "Memoria del dispositivo", lambda js, h: js.get("device_memory")),
    ("webgl_vendor", "GPU: fabricante (WebGL)", lambda js, h: js.get("webgl_vendor")),
    ("webgl_renderer", "GPU: modelo (WebGL)", lambda js, h: js.get("webgl_renderer")),
    ("canvas_hash", "Huella de canvas", lambda js, h: js.get("canvas_hash")),
]
# Si PERMANECEN iguales, siguen sirviendo para reconocer este equipo.
IDENTIFYING = {"canvas_hash", "webgl_renderer", "hardware_concurrency", "device_memory"}
SEPARATORS = re.compile(r"[-._:|~]")


def stats(values: list[int]) -> dict | None:
    if not values:
        return None
    return {"median": statistics.median(values), "min": min(values), "max": max(values), "values": values}


def cell_key(scenario: str | None, profile: str | None) -> str:
    return f"{scenario or 'sin_escenario'}|{profile or REAL}"


def preview(value: str) -> str:
    return value if len(value) <= 10 else f"{value[:6]}…({len(value)} caracteres)"


def failures(jobs: list[dict]) -> list[dict]:
    """Scans sin resultado, agrupados por código y mensaje de error."""
    grouped: dict[tuple[str, str], dict] = {}
    for job in jobs:
        if job["status"] == "failed":
            code, message = job.get("error_code") or UNKNOWN, job.get("error_message") or ""
        elif job.get("analysis_status") == "failed":
            code, message = "ANALYSIS_FAILED", "La captura terminó, pero el análisis falló."
        else:
            continue
        entry = grouped.setdefault((code, message), {"error_code": code, "message": message[:300], "count": 0, "job_ids": []})
        entry["count"] += 1
        if len(entry["job_ids"]) < 10:
            entry["job_ids"].append(job["job_id"])
    return sorted(grouped.values(), key=lambda entry: (-entry["count"], entry["error_code"]))


def _median(cell: dict | None):
    value = ((cell or {}).get("tracker_requests") or {}).get("median")
    return None if value is None else (int(value) if float(value).is_integer() else value)


def _conclusion(cells: list[dict], consent: dict | None, jobs: list[dict]) -> dict:
    """Una línea, por plantilla, con su nivel. Solo usa cifras ya calculadas en el resultado."""
    completed = [cell for cell in cells if cell["completed"] > 0]
    if not completed:
        return {"kind": "sin_resultado", "level": "DESCONOCIDO", "text": "Ningún scan terminó: no hay datos que comparar.", "data": {}}
    scenarios = {cell["scenario"] for cell in cells if cell["scenario"]}
    if consent and consent["not_applicable"] and scenarios & {"aceptar", "rechazar"}:
        # No se pulsó ningún botón: todas las corridas hicieron lo mismo, sea cual sea su escenario.
        return {"kind": "banner_no_reconocido", "level": "EVIDENCIA",
                "text": "Banner no reconocido: los escenarios fueron equivalentes.", "data": {"scenarios": sorted(scenarios)}}
    by_scenario = {}
    for cell in completed:
        by_scenario.setdefault(cell["scenario"], cell)  # el primer perfil de cada escenario (el real, si está)
    reject = by_scenario.get("rechazar")
    baseline = by_scenario.get("aceptar") or by_scenario.get("sin_interaccion")
    if consent and not consent["not_applicable"] and reject and baseline and _median(reject) is not None and _median(baseline) is not None:
        still = consent["findings"]["post_reject"]["items"]
        organizations = len({item.get("entity") if item.get("entity") not in (None, UNKNOWN) else item["domain"] for item in still})
        received = (
            "ninguna organización siguió recibiendo datos" if organizations == 0
            else "1 organización siguió recibiendo datos" if organizations == 1
            else f"{organizations} organizaciones siguieron recibiendo datos"
        )
        return {
            "kind": "rechazo", "level": "EVIDENCIA",
            "text": f"Al rechazar: {_median(baseline)} → {_median(reject)} requests de rastreo; {received}.",
            "data": {"baseline": baseline["scenario"], "before": _median(baseline), "after": _median(reject), "organizations": organizations},
        }
    medians = [_median(cell) for cell in completed if _median(cell) is not None]
    profiles = {cell["profile"] for cell in completed}
    if len(profiles) > 1 and medians:
        return {
            "kind": "perfiles", "level": "EVIDENCIA",
            "text": f"Con {len(profiles)} perfiles: entre {min(medians)} y {max(medians)} requests de rastreo por visita; la IP no cambió.",
            "data": {"profiles": len(profiles), "min": min(medians), "max": max(medians)},
        }
    runs = sum(cell["completed"] for cell in completed)
    return {
        "kind": "medicion", "level": "EVIDENCIA",
        "text": f"{medians[0] if medians else 0} requests de rastreo por visita (mediana de {runs} {'corrida' if runs == 1 else 'corridas'}).",
        "data": {"median": medians[0] if medians else 0, "runs": runs},
    }


def _cells(jobs: list[dict], counts: dict, trackers_by_job: dict) -> tuple[list[dict], dict]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for job in jobs:
        grouped[cell_key(job["scenario"], job["profile"])].append(job)
    cells, stability = [], {}
    for key, members in grouped.items():
        done = [job for job in members if job["status"] == "completed" and job["analysis_status"] == "completed"]
        domains: dict[str, dict] = {}
        for job in done:
            seen = {}
            for row in trackers_by_job.get(job["job_id"], []):
                seen.setdefault(row["domain"], row["entity"])
            for domain, entity in seen.items():
                entry = domains.setdefault(domain, {"domain": domain, "entity": entity, "appeared": 0})
                entry["appeared"] += 1
        for entry in domains.values():
            entry["of"] = len(done)
        stability[key] = domains
        cells.append(
            {
                "key": key, "scenario": members[0]["scenario"], "profile": members[0]["profile"] or REAL,
                "runs": len(members), "completed": len(done),
                # Motivo de las corridas que no terminaron, agrupado (v1.2).
                "failures": failures([job for job in members if job not in done]),
                "requests": stats([counts[job["job_id"]]["requests"] for job in done]),
                "third_party_domains": stats([counts[job["job_id"]]["third_party_domains"] for job in done]),
                "tracker_requests": stats([len(trackers_by_job.get(job["job_id"], [])) for job in done]),
                "tracker_domains": sorted(domains.values(), key=lambda e: (-e["appeared"], e["domain"]))[:MAX_ITEMS],
            }
        )
    return cells, stability


def _tracker_differences(cells: list[dict], stability: dict) -> list[dict]:
    """Dominios cuya presencia como tracker difiere entre grupos, con su estabilidad k/N en cada uno."""
    if len(cells) < 2:
        return []
    out = []
    for domain in sorted({domain for domains in stability.values() for domain in domains}):
        by_cell, fractions, entity = {}, set(), None
        for cell in cells:
            entry = stability[cell["key"]].get(domain)
            appeared = entry["appeared"] if entry else 0
            entity = entity or (entry["entity"] if entry else None)
            by_cell[cell["key"]] = {"appeared": appeared, "of": cell["completed"]}
            fractions.add((appeared, cell["completed"]))
        if len(fractions) > 1:
            out.append({"domain": domain, "entity": entity, "by_cell": by_cell})
    return out[:MAX_ITEMS]


def _consent(jobs: list[dict], trackers_by_job: dict) -> dict | None:
    runs = [job for job in jobs if job.get("consent")]
    if not runs:
        return None
    detected = [job for job in runs if job["consent"].get("banner_detected")]

    def aggregate(selected: list[tuple[dict, list[dict]]]) -> list[dict]:
        resources: dict[str, dict] = {}
        for job, rows in selected:
            seen = set()
            for row in rows:
                resource = f"{row['host']}{row['path']}"
                entry = resources.setdefault(resource, {"resource": resource, "domain": row["domain"], "entity": row["entity"], "runs": 0, "evidence": []})
                if resource not in seen:
                    seen.add(resource)
                    entry["runs"] += 1
                if len(entry["evidence"]) < 6:
                    entry["evidence"].append({"job_id": job["job_id"], "request_id": row["request_id"]})
        for entry in resources.values():
            entry["of"] = len(selected)
        return sorted(resources.values(), key=lambda e: (-e["runs"], e["resource"]))[:MAX_ITEMS]

    # Antes de cualquier interacción: todo lo anterior al clic, o todo el scan si no hubo clic.
    before = []
    for job in detected:
        limit = job["consent"].get("interaction_seq")
        rows = [row for row in trackers_by_job.get(job["job_id"], []) if limit is None or row["seq"] < limit]
        before.append((job, rows))
    rejected = [job for job in detected if job["consent"].get("status") == "rechazado"]
    after_reject = [
        (job, [row for row in trackers_by_job.get(job["job_id"], []) if row["seq"] >= job["consent"]["interaction_seq"]])
        for job in rejected
    ]
    accepted = [job for job in detected if job["consent"].get("status") == "aceptado"]
    after_accept = [
        (job, [row for row in trackers_by_job.get(job["job_id"], []) if row["seq"] >= job["consent"]["interaction_seq"]])
        for job in accepted
    ]
    pre = aggregate(before)
    post_reject = aggregate(after_reject)
    post_accept = aggregate(after_accept)
    elsewhere = {entry["resource"] for entry in pre} | {entry["resource"] for entry in post_reject}
    only_accept = [entry for entry in post_accept if entry["resource"] not in elsewhere]
    banner_job = next((job["job_id"] for job in detected if job["consent"].get("has_banner_image")), None)
    first = (detected or runs)[0]["consent"]
    return {
        "cmp": first.get("cmp_name"),
        "banner_detected_runs": len(detected),
        "runs": len(runs),
        "banner_job_id": banner_job,
        "scenarios": [
            {"job_id": job["job_id"], "scenario": job["scenario"], "run": job["run"], "status": job["consent"].get("status"),
             "verified": job["consent"].get("verified"), "verified_by": (job["consent"].get("state") or {}).get("verified_by"),
             "reason": job["consent"].get("reason")}
            for job in runs
        ],
        "not_applicable": not detected,
        "findings": {
            "pre_consent": {
                "level": "EVIDENCIA",
                "claim": "Requests de tracking enviadas antes de cualquier interacción con el banner de consentimiento.",
                "runs": len(before), "items": pre,
            },
            "post_reject": {
                "level": "EVIDENCIA",
                "claim": "Requests de tracking enviadas después de pulsar «rechazar».",
                "runs": len(after_reject),
                "verified_runs": sum(1 for job in rejected if job["consent"].get("verified") is True),
                "items": post_reject,
            },
            "only_after_accept": {
                "level": "EVIDENCIA",
                "claim": "Recursos de tracking que solo aparecieron después de pulsar «aceptar».",
                "runs": len(after_accept), "items": only_accept,
            },
        },
        "note": "Se describe lo observado en estas corridas. No es un juicio sobre el cumplimiento de ninguna norma.",
    }


def _profiles(jobs: list[dict]) -> dict | None:
    probes: dict[str, dict] = {}
    for job in jobs:
        info = job.get("profile_info")
        if info and info.get("js") and job["profile"] not in probes:
            probes[job["profile"]] = info
    if not probes:
        return None
    real = probes.get(REAL)
    others = [name for name in probes if name != REAL]
    rows = []
    for key, label, read in ATTRIBUTES:
        real_value = read(real["js"], real["headers"] or {}) if real else None
        values, statuses = {}, {}
        for name in others:
            value = read(probes[name]["js"], probes[name]["headers"] or {})
            values[name] = value
            if real is None:
                statuses[name] = "SIN_REFERENCIA"
            elif real_value is None and value is not None:
                statuses[name] = "NUEVO"
            elif value == real_value:
                statuses[name] = "PERMANECIO"
            else:
                statuses[name] = "CAMBIO"
        rows.append({
            "attribute": key, "label": label, "real": real_value, "values": values, "status": statuses,
            # Igual que en el navegador real y útil para reconocer el equipo: sigue observable.
            "potentially_identifying": [name for name in others if statuses[name] == "PERMANECIO" and key in IDENTIFYING],
        })
    rows.append({
        "attribute": "ip", "label": "Dirección IP", "real": "la misma en todas las corridas",
        "values": {name: "la misma en todas las corridas" for name in others},
        "status": {name: "PERMANECIO" for name in others}, "potentially_identifying": list(others), "not_modifiable": True,
    })
    summary = {}
    for name in others:
        summary[name] = {
            "changed": [row["label"] for row in rows if row["status"].get(name) == "CAMBIO"],
            "remained": [row["label"] for row in rows if row["status"].get(name) == "PERMANECIO"],
            "new": [row["label"] for row in rows if row["status"].get(name) == "NUEVO"],
            "potentially_identifying": [row["label"] for row in rows if name in row["potentially_identifying"]],
        }
    return {
        "has_real_reference": real is not None,
        "profiles": [{"name": name, "label": probes[name].get("label"), "declared_coherent": probes[name].get("declared_coherent")} for name in probes],
        "attributes": rows,
        "summary": summary,
        "inconsistencies": {name: probes[name].get("inconsistencies") for name in probes},
        "ip_note": IP_NOTE,
    }


def _persistent_ids(jobs: list[dict], ids_by_job: dict) -> dict:
    """Valores con forma de identificador que se repiten entre corridas LIMPIAS (sin cookies previas)."""
    done = [job for job in jobs if job["status"] == "completed"]
    by_profile: dict[str, list[dict]] = defaultdict(list)
    for job in done:
        by_profile[job["profile"] or REAL].append(job)
    # (dominio, parámetro) -> perfil -> valor -> {jobs, evidence}
    table: dict[tuple, dict] = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: {"jobs": set(), "evidence": []})))
    entities: dict[str, str] = {}
    for job in done:
        for row in ids_by_job.get(job["job_id"], []):
            entry = table[(row["domain"], row["name"])][job["profile"] or REAL][row["value"]]
            entry["jobs"].add(job["job_id"])
            if len(entry["evidence"]) < 4:
                entry["evidence"].append({"job_id": job["job_id"], "request_id": row["request_id"]})
            entities.setdefault(row["domain"], row.get("entity"))
    findings = []
    for (domain, name), per_profile in table.items():
        for profile, values in per_profile.items():
            runs = len(by_profile[profile])
            if runs < 2:
                continue
            for value, entry in values.items():
                if len(entry["jobs"]) < 2:
                    continue
                others = []
                for other, other_values in per_profile.items():
                    if other == profile:
                        continue
                    if value in other_values:
                        others.append({"profile": other, "result": "SE_MANTIENE"})
                        continue
                    mine = [segment for segment in SEPARATORS.split(value) if len(segment) >= 8]
                    shared = sorted({segment for candidate in other_values for segment in SEPARATORS.split(candidate) if segment in mine})
                    others.append({"profile": other, "result": "CAMBIA_EN_PARTE" if shared else "CAMBIA",
                                   "kept_parts": [preview(segment) for segment in shared]})
                results = {item["result"] for item in others}
                if not others:
                    inference = "No había cookies ni almacenamiento previos: el valor se derivó de atributos del navegador, de la IP, o es una constante del sitio. Con un solo perfil no se puede distinguir."
                elif results == {"CAMBIA"}:
                    inference = "Cambia al cambiar de perfil: depende de atributos que el perfil modifica (User-Agent, pantalla, zona horaria...)."
                elif "CAMBIA_EN_PARTE" in results:
                    inference = "Una parte cambia con el perfil y otra se mantiene: la parte que se mantiene no depende de los atributos modificados (por ejemplo, de la IP, que ningún perfil cambia)."
                else:
                    inference = "Se mantiene al cambiar de perfil: depende de la IP o de atributos que el perfil no modifica, o es una constante del sitio (clave o versión)."
                findings.append({
                    "domain": domain, "entity": entities.get(domain), "parameter": name, "profile": profile,
                    "value_preview": preview(value), "same_in_runs": len(entry["jobs"]), "of_runs": runs,
                    "level": "EVIDENCIA",
                    "claim": f"El mismo valor ({preview(value)}) se envió a {domain} en el parámetro «{name}» en {len(entry['jobs'])} de {runs} corridas con contextos nuevos (sin cookies previas).",
                    "across_profiles": others, "inference": inference, "inference_level": "INFERENCIA",
                    "changes_with_profile": bool(others) and results <= {"CAMBIA", "CAMBIA_EN_PARTE"},
                    "evidence": entry["evidence"],
                })
    findings.sort(key=lambda f: (not f["changes_with_profile"], -f["same_in_runs"], f["domain"], f["parameter"]))
    return {
        "items": findings[:MAX_ITEMS],
        "total": len(findings),
        "comparable_profiles": sorted(profile for profile, members in by_profile.items() if len(members) >= 2),
        "note": "Para afirmar que un valor se repite hacen falta al menos 2 corridas del mismo perfil. Un valor repetido no es necesariamente un identificador: puede ser una clave del sitio.",
    }


def build_result(jobs: list[dict], counts: dict, tracker_rows: list[dict], id_rows: list[dict], account_ids: dict | None = None) -> dict:
    trackers_by_job: dict[str, list[dict]] = defaultdict(list)
    for row in tracker_rows:
        trackers_by_job[row["job_id"]].append(row)
    ids_by_job: dict[str, list[dict]] = defaultdict(list)
    # IDs de cuenta del sitio (pixel, contenedor, ID de medición): se repiten en cada corrida
    # porque identifican al sitio, no al visitante. No cuentan como identificadores persistentes.
    account_ids = account_ids or {}
    excluded: dict[tuple[str, str], dict] = {}
    for row in id_rows:
        known = {item["value"]: item for item in account_ids.get(row["job_id"], [])}
        if row["value"] in known:
            item = known[row["value"]]
            excluded.setdefault((item["rule"], item["value"]), {key: item[key] for key in ("rule", "vendor", "label", "value")})
            continue
        ids_by_job[row["job_id"]].append(row)
    site_ids: dict[tuple[str, str], dict] = {}
    for items in account_ids.values():
        for item in items:
            site_ids.setdefault((item["rule"], item["value"]), {key: item[key] for key in ("rule", "vendor", "label", "value")})
    cells, stability = _cells(jobs, counts, trackers_by_job)
    consent = _consent(jobs, trackers_by_job)
    persistent = _persistent_ids(jobs, ids_by_job)
    persistent["account_ids_excluded"] = len(excluded)
    return {
        "conclusion": _conclusion(cells, consent, jobs),
        "failures": failures(jobs),
        "account_ids": sorted(site_ids.values(), key=lambda item: (item["vendor"], item["label"], item["value"]))[:MAX_ITEMS],
        "cells": cells,
        "tracker_differences": _tracker_differences(cells, stability),
        "consent": consent,
        "profiles": _profiles(jobs),
        "persistent_ids": persistent,
        "limitations": [
            "Cambiar el perfil cambia lo que el navegador dice ser; no cambia la IP ni hace que deje de ser reconocible.",
            "Los conteos varían entre visitas: se muestran mediana y rango, y cada tracker con «apareció en k de N corridas».",
            "Con pocas corridas, una diferencia entre grupos puede ser variación normal del sitio.",
            "Los perfiles emulan solo navegadores Chromium; los iframes de terceros y los workers pueden ver valores reales.",
        ],
    }
