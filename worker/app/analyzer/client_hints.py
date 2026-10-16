"""Client Hints: solicitud, envío y delegación (v1.4.9, docs/adr/036). Reglas en data/client_hints.yaml.

Todo lo que se lee aquí viene del sitio (cabeceras y meta): no confiable. Solo se compara texto acotado y se
devuelven nombres de hints de una lista cerrada; los valores de las cabeceras Sec-CH-UA-* no se copian.
"""

from collections import defaultdict

MAX_EVIDENCE_CHARS = 300
MAX_ITEMS = 40


def _headers(headers) -> list[tuple[str, str]]:
    out = []
    for header in headers or []:
        if isinstance(header, dict) and isinstance(header.get("name"), str) and isinstance(header.get("value"), str):
            out.append((header["name"].lower(), header["value"]))
    return out


def _directive(hint: str) -> str:
    """Sec-CH-UA-Model → ch-ua-model (nombre en Permissions-Policy y delegate-ch)."""
    return hint.removeprefix("sec-")


class ClientHintsRules:
    def __init__(self, raw: dict | None = None) -> None:
        raw = raw or {}
        self.high_entropy = tuple(str(name).lower() for name in raw.get("high_entropy") or [] if name)
        self._canonical = {str(name).lower(): str(name) for name in raw.get("high_entropy") or [] if name}
        self.texts = {str(key): str(value) for key, value in (raw.get("texts") or {}).items()}
        self.labels = {str(key): str(value) for key, value in (raw.get("delegation_labels") or {}).items()}

    def name(self, hint: str) -> str:
        return self._canonical.get(hint, hint)

    def requested(self, response_headers) -> list[str]:
        """Hints de alta entropía que pide una respuesta (Accept-CH o Critical-CH), en el orden de la lista."""
        asked = set()
        for name, value in _headers(response_headers):
            if name in ("accept-ch", "critical-ch"):
                asked |= {token.strip().lower() for token in value[:4000].split(",") if token.strip()}
        return [hint for hint in self.high_entropy if hint in asked]

    def sent(self, request_headers) -> list[str]:
        """Hints de alta entropía presentes como cabecera en la request."""
        names = {name for name, _ in _headers(request_headers)}
        return [hint for hint in self.high_entropy if hint in names]

    def delegation(self, document: dict | None, page_meta: dict | None) -> dict:
        """Estado de la delegación por el documento principal, con la evidencia usada."""
        evidence = []
        directives = {_directive(hint) for hint in self.high_entropy}
        detected = False
        headers = _headers((document or {}).get("response_headers")) if document else []
        policy = [value for name, value in headers if name == "permissions-policy"]
        for value in policy:
            for item in value[:4000].split(","):
                feature, _, allow = item.strip().partition("=")
                feature, allow = feature.strip().lower(), allow.strip()
                if feature not in directives:
                    continue
                # Delegar = permitir a alguien más que el propio origen: «*» u otro origen entre comillas.
                others = "*" in allow or '"' in allow
                evidence.append(f"Permissions-Policy: {feature}={allow}"[:MAX_EVIDENCE_CHARS])
                detected = detected or others
        meta = page_meta.get("delegate_ch") if isinstance(page_meta, dict) else None
        if isinstance(meta, str) and meta.strip():
            evidence.append(f'<meta http-equiv="delegate-ch" content="{meta.strip()}">'[:MAX_EVIDENCE_CHARS])
            lowered = meta.lower()
            detected = detected or any(hint in lowered or _directive(hint) in lowered for hint in self.high_entropy)
        if detected:
            status = "detectada"
        elif document is not None and document.get("response_headers") is not None and isinstance(page_meta, dict) \
                and "delegate_ch" in page_meta:
            status = "sin_delegacion"
            if not evidence:
                evidence.append("El documento principal no envió Permissions-Policy con ch-ua-* ni la página tiene meta delegate-ch.")
        else:
            status = "no_determinado"
            missing = []
            if document is None or document.get("response_headers") is None:
                missing.append("no se registraron las cabeceras del documento principal")
            elif not policy:
                missing.append("el documento principal no envió Permissions-Policy")
            if not (isinstance(page_meta, dict) and "delegate_ch" in page_meta):
                missing.append("en esta captura no se leyó el meta delegate-ch de la página")
            text = "; ".join(missing)
            evidence.append(text[:1].upper() + text[1:] + ".")
        return {"status": status, "label": self.labels.get(status, status), "evidence": evidence[:6],
                "level": "CONTEXTO" if status != "detectada" else "EVIDENCIA",
                "note": self.texts.get("no_delegation") if status == "sin_delegacion" else None}

    def analyze(self, requests: list, party_by_id: dict, organization_of, document: dict | None, page_meta: dict | None) -> dict:
        """Solicitudes y envíos por organización de otra parte, y la delegación del sitio.

        `organization_of(request)` = nombre de la organización (o el dominio si no se conoce).
        """
        ordered = sorted(requests, key=lambda request: request.get("seq") or 0)
        solicitations: dict[str, dict] = {}
        sends: list[dict] = []
        first_seq: dict[str, int] = {}
        first_has_hints: dict[str, bool] = {}
        for request in ordered:
            if party_by_id.get(request["request_id"]) != "third_party":
                continue
            org = organization_of(request)
            sent = self.sent(request.get("request_headers"))
            if org not in first_seq:
                first_seq[org], first_has_hints[org] = request.get("seq") or 0, bool(sent)
            if sent:
                previous = solicitations.get(org)
                sends.append({"request_id": request["request_id"], "seq": request.get("seq"), "host": request.get("host"),
                              "organization": org, "hints": [self.name(hint) for hint in sent],
                              # Envío confirmado tras una solicitud de la misma organización (si no, delegado o propio del navegador).
                              "after_request": bool(previous) and set(sent) & set(previous["_hints"]) != set()})
            asked = self.requested(request.get("response_headers"))
            if asked:
                entry = solicitations.setdefault(org, {"organization": org, "_hints": set(), "hosts": set(), "request_ids": [],
                                                       "first_request_id": request["request_id"]})
                entry["_hints"] |= set(asked)
                entry["hosts"].add(request.get("host") or "")
                if len(entry["request_ids"]) < MAX_ITEMS:
                    entry["request_ids"].append(request["request_id"])
        sent_by_org: dict[str, set] = defaultdict(set)
        for item in sends:
            sent_by_org[item["organization"]] |= {hint.lower() for hint in item["hints"]}
        items = []
        for org, entry in sorted(solicitations.items()):
            hints = [hint for hint in self.high_entropy if hint in entry["_hints"]]
            received = [hint for hint in hints if hint in sent_by_org.get(org, set())]
            items.append({
                "organization": org, "hints": [self.name(hint) for hint in hints], "hosts": sorted(h for h in entry["hosts"] if h)[:10],
                "request_ids": entry["request_ids"], "first_request_id": entry["first_request_id"],
                # Estado del envío de lo pedido: «confirmado» solo con la cabecera en una request a esa organización.
                "sent": "confirmado" if received else "no_observado", "sent_hints": [self.name(hint) for hint in received],
                # La primera request a la organización no llevaba los hints: condicionado por el navegador de captura.
                "first_request_conditioned": not first_has_hints.get(org, False),
            })
        notes = []
        if items:
            notes.append(self.texts.get("capture_browser"))
            if any(item["sent"] == "no_observado" for item in items):
                notes.append(self.texts.get("no_send_observed"))
        return {
            "level": "EVIDENCIA", "request_text": self.texts.get("request"),
            "requests": items[:MAX_ITEMS], "sends": sends[:MAX_ITEMS * 5],
            "delegation": self.delegation(document, page_meta),
            "notes": [note for note in notes if note],
        }
