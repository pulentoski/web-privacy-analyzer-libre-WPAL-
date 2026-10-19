"""Resumen de un scan (v1.6.0, docs/adr/042): «Quién recibió más datos» y el scan anterior del mismo sitio.

Solo lee lo que el análisis ya guardó (hallazgos, fingerprinting y request_analysis): no analiza ni puntúa nada nuevo.
Un tipo de dato «recibido» por una organización = hay un hallazgo de ese tipo cuya evidencia incluye una request a esa
organización (tercero). Es el mismo criterio de nivel que el hallazgo: aquí no se sube ni se baja.
"""

UNKNOWN = "no_disponible"

# Tipo de dato → hallazgos que lo muestran. El orden es el de la columna en la interfaz.
DATA_TYPES = {
    "identificador": ("id_sync", "redirect_sync", "sync_wave", "persistent_id", "persistent_id_org", "identifier_param",
                      "session_token_third_party"),
    "url": ("url_leak", "referer_leak"),
    "consentimiento": ("consent_mode_state", "tcf", "tcf_state"),
    "dispositivo": ("client_hints_sent",),  # + exfiltraciones del fingerprinting (fp_findings)
    "busqueda": ("search_leak",),
}
DATA_LABELS = {"identificador": "Identificador", "url": "URL de la página", "consentimiento": "Consentimiento",
               "dispositivo": "Dispositivo", "busqueda": "Búsqueda"}
FINDING_TYPE = {finding: data_type for data_type, findings in DATA_TYPES.items() for finding in findings}
MAX_RECIPIENTS = 50


def org_key(entity: str | None, domain: str | None) -> tuple:
    """Sin organización conocida no se juntan dominios distintos (mismo criterio que Rastreadores)."""
    return (entity,) if entity and entity != UNKNOWN else (UNKNOWN, domain or "")


def recipients(requests: dict[int, dict], findings: list[dict], exfiltrations: list[dict], cookies: list[dict],
               tracker_bands: tuple, label=lambda entity, domains: entity) -> list[dict]:
    """Ranking por organización (tercero): tipos de dato recibidos, luego requests de tracking.

    `requests`: request_id → {entity, party, band, domain}. `findings`: {type, evidence_refs}. `exfiltrations`:
    {request_refs} de fp_findings con heurística exfiltration. `cookies`: detalles de los hallazgos persistent_cookie.
    """
    groups: dict[tuple, dict] = {}

    def group(key: tuple, entity: str | None, domain: str | None) -> dict:
        item = groups.setdefault(key, {"entity": entity or UNKNOWN, "domains": [], "types": set(), "tracking_requests": 0,
                                       "longest_cookie_days": None, "longest_cookie": None})
        if domain and domain not in item["domains"]:
            item["domains"].append(domain)
        return item

    def third(request_id) -> tuple | None:
        row = requests.get(request_id) if isinstance(request_id, int) else None
        if not row or row.get("party") != "third_party":
            return None
        return org_key(row.get("entity"), row.get("domain")), row

    for row in requests.values():
        if row.get("party") == "third_party" and row.get("band") in tracker_bands:
            group(org_key(row.get("entity"), row.get("domain")), row.get("entity"), row.get("domain"))["tracking_requests"] += 1
    sources = [(FINDING_TYPE.get(item.get("type")), item.get("evidence_refs")) for item in findings]
    sources += [("dispositivo", item.get("request_refs")) for item in exfiltrations]
    for data_type, refs in sources:
        if data_type is None:
            continue
        for request_id in refs if isinstance(refs, list) else []:
            found = third(request_id)
            if found:
                key, row = found
                group(key, row.get("entity"), row.get("domain"))["types"].add(data_type)
    for details in cookies:
        if not isinstance(details, dict) or str(details.get("third_party")).lower() != "true":
            continue
        days = details.get("max_days")
        try:
            days = int(days)
        except (TypeError, ValueError):
            continue
        key = org_key(details.get("entity"), details.get("domain"))
        if key in groups and (groups[key]["longest_cookie_days"] is None or days > groups[key]["longest_cookie_days"]):
            names = details.get("names")
            groups[key]["longest_cookie_days"] = days
            groups[key]["longest_cookie"] = names[0] if isinstance(names, list) and len(names) == 1 else None

    ranked = sorted(
        (item for item in groups.values() if item["types"] or item["tracking_requests"]),
        key=lambda item: (-len(item["types"]), -item["tracking_requests"], str(label(item["entity"], item["domains"]) or "")),
    )
    out = []
    for position, item in enumerate(ranked[:MAX_RECIPIENTS], start=1):
        types = [data_type for data_type in DATA_TYPES if data_type in item["types"]]
        out.append({
            "rank": position,
            "organization": item["entity"],
            "label": label(item["entity"], item["domains"]) if item["entity"] != UNKNOWN else None,
            "domains": item["domains"],
            "data_types": types,
            "data_type_labels": [DATA_LABELS[data_type] for data_type in types],
            "tracking_requests": item["tracking_requests"],
            "longest_cookie_days": item["longest_cookie_days"],
            "longest_cookie": item["longest_cookie"],
        })
    return out


def previous_scan(current_version: int | None, candidates: list[dict]) -> dict:
    """El scan anterior del mismo sitio (el más reciente antes de este), solo si tiene el mismo protocolo de visita.

    `candidates`: del más nuevo al más antiguo, con job_id, created_at, score, band y protocol_version.
    """
    if not candidates:
        return {"previous": None, "reason": "sin_scan_anterior"}
    latest = candidates[0]
    if current_version is None or latest["protocol_version"] != current_version:
        return {"previous": None, "reason": "otro_protocolo"}
    return {"previous": latest, "reason": None}
