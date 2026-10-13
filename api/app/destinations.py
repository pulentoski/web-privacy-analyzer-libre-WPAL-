"""Inteligencia por destino (F8): a qué IP, red y país fue cada dominio, y de quién es.

Dos fuentes independientes que no se mezclan ni se arbitran:
- dueño del DOMINIO (mapa de entidades de F3);
- red y país de la IP a la que el proxy conectó (DB-IP Lite, aproximado).
Si no coinciden (un dominio de una empresa servido desde la nube de otra) se muestran las dos.
"""

import pathlib
import re
from collections import defaultdict

import yaml
from sqlalchemy import text

from app.cname import CnameResolver, cloaking_target
from app.config import get_settings
from app.ipintel import IpIntel

UNKNOWN = "no_disponible"
LOCATION_NOTE = "Ubicación aproximada del servidor según su IP (base DB-IP Lite). No indica dónde se almacenan ni procesan los datos."
_state: dict = {}


def _resources():
    if not _state:
        settings = get_settings()
        data = {}
        try:
            data = yaml.safe_load((pathlib.Path(settings.data_dir) / "cname_trackers.yaml").read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            data = {}
        targets = dict(data.get("targets") or {})
        test_dns = {}
        if settings.allow_fixtures:
            targets.update(data.get("test_targets") or {})
            test_dns = data.get("test_dns") or {}
        _state.update(intel=IpIntel(settings.ipdb_dir), targets=targets, resolver=CnameResolver(test_dns))
    return _state


def _tokens(name: str) -> set[str]:
    return {token for token in re.split(r"[^a-z0-9]+", (name or "").lower()) if len(token) >= 4 and token not in {"inc", "corp", "limited", "company", "services", "technologies", "group"}}


async def build_destinations(session, job) -> dict:
    resources = _resources()
    intel = resources["intel"]
    params = {"job_id": job.id}
    hosts = (
        await session.execute(
            text(
                "SELECT r.host, r.registrable_domain AS domain, bool_or(COALESCE(a.party = 'third_party', r.third_party)) AS third_party, "
                "bool_or(a.party = 'same_org') AS same_org, count(*) AS requests, "
                "bool_or(r.blocked_by_proxy) AS blocked, min(r.id) AS request_id, "
                "max(a.entity) FILTER (WHERE a.entity <> 'no_disponible') AS entity "
                "FROM scan_requests r LEFT JOIN request_analysis a ON a.request_id = r.id "
                "WHERE r.job_id = :job_id AND r.host IS NOT NULL GROUP BY r.host, r.registrable_domain ORDER BY count(*) DESC LIMIT 1000"
            ),
            params,
        )
    ).mappings().all()
    connections = (await session.execute(text("SELECT host, ip, connections FROM scan_destinations WHERE job_id = :job_id"), params)).mappings().all()
    has_proxy_log = len(connections) > 0
    # Captura importada: las IP son las que registró el navegador del usuario, no el proxy.
    imported = (job.result or {}).get("source") == "har_import"
    ips_by_host: dict[str, list[str]] = defaultdict(list)
    for row in connections:
        if row["ip"]:
            ips_by_host[row["host"]].append(row["ip"])

    domains: dict[str, dict] = {}
    for row in hosts:
        domain = row["domain"] or row["host"]
        entry = domains.setdefault(domain, {"domain": domain, "third_party": bool(row["third_party"]),
                                            # Tercero = otra organización (request_analysis.party), no «otro dominio».
                                            "party": "third_party" if row["third_party"] else "same_org" if row["same_org"] else "first_party",
                                            "hosts": [], "requests": 0,
                                            "entity": UNKNOWN, "ips": [], "_seen": set(), "blocked": False})
        entry["hosts"].append(row["host"])
        entry["requests"] += row["requests"]
        entry["blocked"] = entry["blocked"] or bool(row["blocked"])
        if row["entity"]:
            entry["entity"] = row["entity"]
        for ip in ips_by_host.get(row["host"], []):
            if ip not in entry["_seen"] and len(entry["ips"]) < 12:
                entry["_seen"].add(ip)
                entry["ips"].append({"ip": ip, **intel.lookup(ip)})
    countries: dict[str, dict] = {}
    out = []
    for entry in domains.values():
        entry.pop("_seen")
        if not entry["ips"]:
            # Nunca se inventa una IP: se dice por qué no hay.
            entry["ip_status"] = UNKNOWN
            entry["ip_reason"] = (
                "El proxy no completó la conexión: la denegó o no pudo resolver o alcanzar el destino." if entry["blocked"] else
                "El HAR importado no trae la IP del servidor para este dominio." if imported else
                "Este scan es anterior al registro de conexiones del proxy." if not has_proxy_log else
                "El proxy no registró ninguna conexión a este dominio (la request no llegó a salir)."
            )
        else:
            entry["ip_status"] = "observada"
            entry["ip_reason"] = None
        organizations = sorted({ip["organization"] for ip in entry["ips"] if ip.get("applies") and ip["organization"] != UNKNOWN})
        entry["network_organizations"] = organizations
        # Fuentes distintas: se muestran ambas, sin decidir cuál "es" el responsable.
        entry["sources_differ"] = bool(
            entry["entity"] != UNKNOWN and organizations and not any(_tokens(entry["entity"]) & _tokens(name) for name in organizations)
        )
        for ip in entry["ips"]:
            if ip.get("applies") and ip.get("country_code") not in (None, UNKNOWN):
                country = countries.setdefault(ip["country_code"], {"country_code": ip["country_code"], "country": ip["country"], "domains": set(), "third_party_domains": set()})
                country["domains"].add(entry["domain"])
                if entry["third_party"]:
                    country["third_party_domains"].add(entry["domain"])
        out.append(entry)

    cname = await _cname_cloaking(session, job, hosts, resources)
    return {
        "has_proxy_log": has_proxy_log,
        "domains": sorted(out, key=lambda e: (-e["requests"], e["domain"]))[:300],
        "countries": sorted(
            ({"country_code": c["country_code"], "country": c["country"], "domains": len(c["domains"]), "third_party_domains": len(c["third_party_domains"]),
              "examples": sorted(c["domains"])[:6]} for c in countries.values()),
            key=lambda c: (-c["domains"], c["country_code"]),
        ),
        "location_note": LOCATION_NOTE,
        "ip_database": intel.lookup("8.8.8.8").get("source", UNKNOWN),
        "attribution": {"text": "IP Geolocation by DB-IP", "url": "https://db-ip.com"},
        "cname_cloaking": cname,
    }


async def _cname_cloaking(session, job, hosts, resources) -> dict:
    """Subdominios del propio sitio cuyo CNAME apunta a un tracker conocido."""
    first_party = [row for row in hosts if not row["third_party"] and row["domain"] and row["host"] != row["domain"]]
    capture_hosts = {row["host"] for row in hosts}
    stored = {
        row["host"]: (row["status"], row["chain"])
        for row in (await session.execute(text("SELECT host, status, chain FROM scan_cnames WHERE job_id = :job_id"), {"job_id": job.id})).mappings()
    }
    missing = [row["host"] for row in first_party if row["host"] not in stored]
    if missing:
        resolved = await resources["resolver"].resolve_all(missing, capture_hosts)
        for host, (status, chain) in resolved.items():
            stored[host] = (status, chain)
            await session.execute(
                text("INSERT INTO scan_cnames (job_id, host, chain, status) VALUES (:job, :host, CAST(:chain AS jsonb), :status) "
                     "ON CONFLICT (job_id, host) DO NOTHING"),
                {"job": job.id, "host": host, "chain": __import__("json").dumps(chain), "status": status},
            )
        await session.commit()
    findings, checked = [], 0
    for row in first_party:
        status, chain = stored.get(row["host"], ("skipped", []))
        if status == "resolved":
            checked += 1
        hit = cloaking_target(chain, row["domain"], resources["targets"]) if chain else None
        if hit:
            name, target, organization = hit
            findings.append({
                "host": row["host"], "site_domain": row["domain"], "cname_chain": chain, "cname_target": name, "target_domain": target,
                "organization": organization, "requests": row["requests"], "evidence_refs": [row["request_id"]],
                "level": "EVIDENCIA",
                "claim": f"El subdominio {row['host']} del propio sitio es un alias DNS (CNAME) de {name}.",
                "inference_level": "INFERENCIA",
                "inference": f"{target} pertenece a {organization}: las requests a ese subdominio llegan a un tercero aunque el navegador las trate como propias del sitio.",
            })
    return {"checked_hosts": checked, "first_party_subdomains": len(first_party), "findings": findings,
            "note": "Solo se consulta el DNS de subdominios del propio sitio que aparecen en la captura."}
