"""Heurísticas de fingerprinting sobre las llamadas a APIs registradas (F4).

Criterios basados en OpenWPM (Englehardt & Narayanan, 2016). Lo que aquí se llama
"fingerprinting" es siempre INFERENCIA: un patrón de uso compatible con esa
técnica. Lo único que se afirma como EVIDENCIA es lo observado: que un script
llamó a una API y que un valor leído aparece en una request saliente.
"""

import hashlib
from collections import defaultdict

MAX_REFS = 50
UNKNOWN_SCRIPT = "(script no identificado)"
MAX_LISTENER_FINDINGS = 80


def script_key(call: dict) -> str:
    """Script al que se atribuye una llamada.

    Si la instrumentación no obtuvo URL (código inline evaluado, eval, new Function), se
    atribuye al documento del frame donde corrió, que sí es un dato confiable (lo da
    Playwright). La api usa la misma regla en SQL: mantenerlas iguales.
    """
    if call["script_url"]:
        return call["script_url"]
    frame = (call.get("frame_url") or "").split("?")[0].split("#")[0]
    return f"(inline o eval en {frame})" if frame else ""

CANVAS_READS = ("canvas.toDataURL", "canvas.toBlob", "canvas.getImageData")
AUDIO_READS = ("audio.getChannelData", "audio.getFloatFrequencyData")
# v1.4.8: candidatos ICE que leyó la página, por tipo de dirección. Con IP = la dirección quedó expuesta al script.
ICE_CANDIDATES = ("webrtc.icecandidate.local_ip", "webrtc.icecandidate.public_ip", "webrtc.icecandidate.mdns")
ICE_SCOPE_LABELS = {"webrtc.icecandidate.local_ip": "IP local", "webrtc.icecandidate.public_ip": "IP pública"}
WEBGL_UNMASKED = ("webgl.UNMASKED_RENDERER_WEBGL", "webgl.UNMASKED_VENDOR_WEBGL")
SWEEP_PREFIXES = ("navigator.", "screen.", "window.devicePixelRatio", "intl.timeZone")
INFERRED = ("canvas_fingerprinting", "font_enumeration", "audio_fingerprinting", "webgl_fingerprinting",
            "webrtc_ip_discovery", "property_sweep")

# Atributo -> APIs que lo leen. El estado de cada uno sale de aquí.
ATTRIBUTES = {
    "canvas": CANVAS_READS,
    "fonts": ("canvas.measureText", "fonts.check"),
    "webgl_vendor": ("webgl.UNMASKED_VENDOR_WEBGL",),
    "webgl_renderer": ("webgl.UNMASKED_RENDERER_WEBGL",),
    "webgl_parameters": ("webgl.getParameter", "webgl.getSupportedExtensions", "webgl.readPixels"),
    "audio": ("audio.OfflineAudioContext", "audio.startRendering") + AUDIO_READS,
    "webrtc": ("webrtc.RTCPeerConnection", "webrtc.createDataChannel", "webrtc.createOffer", "webrtc.onicecandidate") + ICE_CANDIDATES,
    "user_agent": ("navigator.userAgent",),
    "user_agent_client_hints": ("navigator.userAgentData.getHighEntropyValues",),
    "platform": ("navigator.platform",),
    "hardware_concurrency": ("navigator.hardwareConcurrency",),
    "device_memory": ("navigator.deviceMemory",),
    "languages": ("navigator.languages",),
    "plugins": ("navigator.plugins", "navigator.mimeTypes"),
    "webdriver": ("navigator.webdriver",),
    "max_touch_points": ("navigator.maxTouchPoints",),
    "screen": ("screen.width", "screen.height", "screen.availWidth", "screen.availHeight", "screen.colorDepth",
               "screen.pixelDepth", "window.devicePixelRatio"),
    "timezone": ("intl.timeZone",),
    "media_queries": ("window.matchMedia",),
    "media_devices": ("mediaDevices.enumerateDevices",),
    "battery": ("navigator.getBattery",),
    "permissions": ("permissions.query",),
    "gpu_adapter": ("gpu.requestAdapter",),
    "speech_voices": ("speechSynthesis.getVoices",),
    "storage_estimate": ("storage.estimate",),
}


def _refs(values) -> list[int]:
    return sorted(set(values))[:MAX_REFS]


def _label(script_url: str) -> str:
    return script_url or UNKNOWN_SCRIPT


def analyze_fingerprinting(fingerprinting: dict | None, value_params: list, by_id: dict, thresholds: dict, *,
                           benign=None, interaction=None) -> dict:
    """Devuelve scripts, hallazgos, atributos y qué requests llevan valores leídos."""
    empty = {
        "instrumented": fingerprinting is not None, "truncated": False, "scripts": [], "findings": [],
        "attributes": [], "fp_scripts": set(), "exfiltration_by_request": {},
    }
    if not fingerprinting:
        return empty
    calls = fingerprinting.get("calls") or []
    available = set(fingerprinting.get("available") or [])

    by_script: dict[str, dict] = defaultdict(lambda: {"apis": defaultdict(int), "call_ids": defaultdict(list), "rows": []})
    calls = [{**call, "script_url": script_key(call)} for call in calls]
    for call in calls:
        script = by_script[call["script_url"]]
        script["apis"][call["api"]] += call["count"]
        script["call_ids"][call["api"]].append(call["call_id"])
        script["rows"].append(call)

    findings: list[dict] = []

    def finding(script_url, heuristic, level, claim, call_refs, request_refs=(), details=None) -> None:
        call_refs, request_refs = _refs(call_refs), _refs(request_refs)
        if call_refs or request_refs:  # ningún hallazgo sin evidencia
            findings.append(
                {"script_url": script_url, "heuristic": heuristic, "level": level, "claim": claim,
                 "call_refs": call_refs, "request_refs": request_refs, "details": details or {}}
            )

    min_size = thresholds["canvas_min_size"]
    for script_url, script in by_script.items():
        apis, ids, name = script["apis"], script["call_ids"], _label(script_url)

        def refs(*names):
            return [call_id for api in names for call_id in ids.get(api, [])]

        # Canvas: escribió texto o >= 2 colores y luego leyó un área >= 16x16.
        for row in script["rows"]:
            for read in row["details"].get("reads", []):
                if read.get("kind") != "canvas":
                    continue
                big = min(read["canvas_width"], read["canvas_height"], abs(read["read_width"]), abs(read["read_height"])) >= min_size
                library = benign.match(script_url) if benign is not None else None
                if big and (read["text_written"] or read["colors"] >= 2) and library:
                    # Librería de uso conocido (v1.4.2): la lectura es un hecho, pero no se infiere fingerprinting.
                    finding(
                        script_url, "canvas_read_benign", "EVIDENCIA",
                        f"El script {name} leyó el contenido de un canvas de {read['canvas_width']}x{read['canvas_height']} con {row['api']}. "
                        f"Coincide con una librería de uso conocido ({library}): no se marca como fingerprinting.",
                        [row["call_id"]],
                        details={"api": row["api"], "width": read["canvas_width"], "height": read["canvas_height"], "library": library},
                    )
                    break
                if big and (read["text_written"] or read["colors"] >= 2):
                    finding(
                        script_url, "canvas_fingerprinting", "INFERENCIA",
                        f"El script {name} dibujó {'texto' if read['text_written'] else 'varios colores'} en un canvas de "
                        f"{read['canvas_width']}x{read['canvas_height']} y luego leyó su contenido con {row['api']}. "
                        "Es un patrón compatible con canvas fingerprinting.",
                        [row["call_id"]] + refs("canvas.fillText", "canvas.strokeText"),
                        details={"api": row["api"], "width": read["canvas_width"], "height": read["canvas_height"]},
                    )
                    break
            else:
                continue
            break
        # Escucha de interacción (v1.4.2): que el script escucha es un hecho; para qué, no se afirma.
        listened = interaction.listened(apis) if interaction is not None else []
        if listened and len([f for f in findings if f["heuristic"] == "interaction_listener"]) < MAX_LISTENER_FINDINGS:
            labels = ", ".join(interaction.event_label(event) for event in listened)
            finding(
                script_url, "interaction_listener", "EVIDENCIA",
                f"El script {name} registró escuchas de eventos de interacción: {labels}. Que escucha es un hecho observado; "
                "el propósito (funcionamiento de la página, medición o grabación) no se observa.",
                refs(*("events." + event for event in listened)),
                details={"events": listened, "listeners": sum(apis.get("events." + event, 0) for event in listened)},
            )
        fonts = max((row["details"].get("distinct_fonts", 0) for row in script["rows"]), default=0)
        if fonts >= thresholds["font_threshold"]:
            finding(
                script_url, "font_enumeration", "INFERENCIA",
                f"El script {name} midió texto con {fonts} fuentes distintas (measureText). "
                "Es un patrón compatible con la enumeración de fuentes instaladas.",
                refs("canvas.measureText"), details={"distinct_fonts": fonts},
            )
        if apis.get("audio.OfflineAudioContext") and apis.get("audio.createOscillator") and apis.get(
            "audio.createDynamicsCompressor"
        ) and any(apis.get(api) for api in AUDIO_READS):
            finding(
                script_url, "audio_fingerprinting", "INFERENCIA",
                f"El script {name} generó audio fuera de línea con un oscilador y un compresor y leyó el resultado. "
                "Es un patrón compatible con audio fingerprinting.",
                refs("audio.OfflineAudioContext", "audio.createOscillator", "audio.createDynamicsCompressor", *AUDIO_READS),
            )
        unmasked = [api for api in WEBGL_UNMASKED if apis.get(api)]
        if unmasked:
            what = " y ".join(api.split(".")[1] for api in unmasked)
            finding(
                script_url, "webgl_unmasked_read", "EVIDENCIA",
                f"El script {name} leyó {what} mediante WebGL (fabricante y modelo de la GPU).",
                refs(*unmasked), details={"parameters": unmasked},
            )
            finding(
                script_url, "webgl_fingerprinting", "INFERENCIA",
                f"La lectura de {what} por el script {name} es compatible con fingerprinting por WebGL.",
                refs(*unmasked),
            )
        # v1.4.8: crear una RTCPeerConnection y recibir candidatos ICE con IP son hechos observados (grupo 2).
        exposed = [api for api in ICE_CANDIDATES if api in ICE_SCOPE_LABELS and apis.get(api)]
        if apis.get("webrtc.RTCPeerConnection"):
            finding(
                script_url, "webrtc_connection", "EVIDENCIA",
                f"El script {name} creó {apis['webrtc.RTCPeerConnection']} conexión(es) WebRTC (RTCPeerConnection).",
                refs("webrtc.RTCPeerConnection"),
                details={"connections": apis["webrtc.RTCPeerConnection"],
                         "mdns_candidates": apis.get("webrtc.icecandidate.mdns", 0)},
            )
        if exposed:
            kinds = " y ".join(ICE_SCOPE_LABELS[api] for api in exposed)
            finding(
                script_url, "webrtc_ice_exposed", "EVIDENCIA",
                f"El script {name} recibió candidatos ICE de WebRTC con {kinds} del equipo "
                f"({sum(apis[api] for api in exposed)} lectura(s)). La dirección no se registra en este análisis.",
                refs(*exposed), details={"scopes": [api.rsplit(".", 1)[1] for api in exposed],
                                         "reads": {api.rsplit(".", 1)[1]: apis[api] for api in exposed}},
            )
        if (apis.get("webrtc.createDataChannel") or apis.get("webrtc.createOffer")) and apis.get("webrtc.onicecandidate"):
            finding(
                script_url, "webrtc_ip_discovery", "INFERENCIA",
                f"El script {name} abrió una conexión WebRTC y escuchó candidatos ICE: patrón compatible con un intento "
                "de descubrir direcciones IP." + (" Obtuvo candidatos con dirección IP (ver hallazgo de Evidencia)." if exposed else
                " El worker bloquea el UDP fuera del proxy y no se observaron candidatos con IP."),
                refs("webrtc.RTCPeerConnection", "webrtc.createDataChannel", "webrtc.createOffer", "webrtc.onicecandidate", *exposed),
                details={"blocked_by_policy": not exposed},
            )
        swept = sorted(api for api in apis if api.startswith(SWEEP_PREFIXES))
        if len(swept) >= thresholds["sweep_threshold"]:
            finding(
                script_url, "property_sweep", "INFERENCIA",
                f"El script {name} leyó {len(swept)} propiedades distintas de navigator/screen. "
                "Es un patrón compatible con la recolección de atributos del dispositivo.",
                refs(*swept), details={"properties": swept},
            )

    # --- Exfiltración: un valor leído (o su hash) aparece en una request saliente ---
    needles: dict[str, list[tuple[str, str, int, str]]] = defaultdict(list)  # aguja -> (api, script, call_id, forma)
    min_chars = thresholds["min_value_chars"]
    for call in calls:
        value = call["details"].get("value")
        if isinstance(value, str) and len(value) >= min_chars:
            needles[value].append((call["api"], call["script_url"], call["call_id"], "valor"))
            raw = value.encode("utf-8", "replace")
            for algorithm in ("sha256", "sha1", "md5"):
                needles[hashlib.new(algorithm, raw).hexdigest()].append(
                    (call["api"], call["script_url"], call["call_id"], f"{algorithm} del valor")
                )
        for read in call["details"].get("reads", []):
            if read.get("sha256"):
                needles[read["sha256"]].append((call["api"], call["script_url"], call["call_id"], "sha256 del contenido leído"))

    exfiltration_by_request: dict[int, list[dict]] = defaultdict(list)
    groups: dict[tuple[str, str, str], dict] = {}
    if needles:
        shortest = min(len(needle) for needle in needles)
        for param in value_params:
            if len(param.value) < shortest:
                continue
            lowered = param.value.lower()
            matched = [
                needle for needle in needles
                if len(needle) <= len(param.value) and (needle in param.value or needle in lowered)
            ]
            # Un valor contenido en otro que también coincide no cuenta aparte: "Linux x86_64"
            # (navigator.platform) aparece dentro de cualquier User-Agent enviado.
            matched = [needle for needle in matched if not any(needle != other and needle in other for other in matched)]
            for needle in matched:
                request = by_id[param.request_id]
                domain = request.get("registrable_domain") or ""
                for api, script_url, call_id, form in needles[needle]:
                    group = groups.setdefault(
                        (api, domain, form), {"call_refs": [], "request_refs": [], "scripts": set(), "param": param.name}
                    )
                    group["call_refs"].append(call_id)
                    group["request_refs"].append(param.request_id)
                    group["scripts"].add(script_url)
                    exfiltration_by_request[param.request_id].append({"api": api, "parameter": param.name, "form": form})
    for (api, domain, form), group in groups.items():
        scripts = ", ".join(_label(script) for script in sorted(group["scripts"])[:3])
        finding(
            sorted(group["scripts"])[0], "exfiltration", "EVIDENCIA",
            f"Un valor leído con {api} ({form}) aparece en el parámetro «{group['param']}» de una request a {domain}. "
            f"Lo leyó: {scripts}.",
            group["call_refs"], group["request_refs"],
            details={"api": api, "domain": domain, "form": form, "parameter": group["param"]},
        )

    fp_scripts = {f["script_url"] for f in findings if f["heuristic"] in INFERRED and f["script_url"]}
    observed_apis = {api for api, _, _ in groups}

    attributes = []
    for attribute, attribute_apis in ATTRIBUTES.items():
        rows = [call for call in calls if call["api"] in attribute_apis and call["count"] > 0]
        if any(api in observed_apis for api in attribute_apis):
            status = "OBSERVADO"
        elif rows:
            status = "UTILIZADO"
        elif any(api in available for api in attribute_apis):
            status = "DISPONIBLE"
        else:
            status = "NO_DISPONIBLE"
        request_refs = [ref for (api, _, _), group in groups.items() if api in attribute_apis for ref in group["request_refs"]]
        attributes.append(
            {
                "attribute": attribute,
                "status": status,
                # Solo valores cortos (UA, renderer, zona horaria...); nunca contenido de canvas o audio.
                "value": next((row["details"]["value"] for row in rows if "value" in row["details"]), None),
                "scripts": sorted({row["script_url"] for row in rows})[:20],
                "call_refs": _refs(row["call_id"] for row in rows),
                "request_refs": _refs(request_refs),
            }
        )

    scripts_out = []
    for script_url, script in sorted(by_script.items()):
        # Las escuchas de eventos no son lecturas de atributos: no cuentan en la tabla de fingerprinting.
        read_apis = {api: count for api, count in script["apis"].items() if not api.startswith("events.")}
        if not read_apis:
            continue
        scripts_out.append(
            {
                "script_url": script_url,
                "apis": [{"api": api, "count": count} for api, count in sorted(read_apis.items())],
                "total_calls": sum(read_apis.values()),
                "heuristics": sorted({f["heuristic"] for f in findings if f["script_url"] == script_url}),
                "fingerprinting_inferred": script_url in fp_scripts,
            }
        )
    return {
        "instrumented": True,
        "truncated": bool(fingerprinting.get("truncated")),
        "scripts": scripts_out,
        "findings": findings,
        "attributes": attributes,
        "fp_scripts": fp_scripts,
        "exfiltration_by_request": dict(exfiltration_by_request),
    }
