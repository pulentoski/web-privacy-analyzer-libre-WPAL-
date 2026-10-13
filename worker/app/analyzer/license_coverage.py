"""Mide cuántos dominios quedan sin organización en cada perfil de licencias (docs/adr/019).

Lee por stdin un JSON {"conjunto": ["dominio", ...]} y escribe una tabla Markdown.
Lo invoca scripts/license-coverage.sh con los dominios de las muestras y de los fixtures.
"""

import json
import sys

from app.analyzer.lists import UNKNOWN_ENTITY, FilterLists
from app.browser.parties import registrable_domain
from app.config import settings


def measure(domain_sets: dict[str, list[str]]) -> list[dict]:
    profiles = {name: FilterLists(settings.data_dir, allow_fixtures=settings.allow_fixtures, license_profile=name) for name in ("no_comercial", "comercial")}
    rows = []
    for label, hosts in domain_sets.items():
        domains = sorted({registrable_domain(host) or host for host in hosts})
        known = {name: {domain for domain in domains if lists.entity(domain) != UNKNOWN_ENTITY} for name, lists in profiles.items()}
        rows.append({
            "set": label, "domains": len(domains),
            "no_comercial": len(known["no_comercial"]), "comercial": len(known["comercial"]),
            "lost": sorted(known["no_comercial"] - known["comercial"]), "gained": sorted(known["comercial"] - known["no_comercial"]),
            "unknown_in_both": len(set(domains) - known["no_comercial"] - known["comercial"]),
        })
    return rows


def main() -> None:
    rows = measure(json.load(sys.stdin))
    percent = lambda part, whole: f"{part} ({round(100 * part / whole)} %)" if whole else "0"  # noqa: E731
    print("| Conjunto | Dominios de terceros | Con organización: no comercial | Con organización: comercial | Pierden organización | Ganan organización | Sin organización en ambos |")
    print("|---|---|---|---|---|---|---|")
    for row in rows:
        print(f"| {row['set']} | {row['domains']} | {percent(row['no_comercial'], row['domains'])} | {percent(row['comercial'], row['domains'])} "
              f"| {len(row['lost'])} | {len(row['gained'])} | {row['unknown_in_both']} |")
    for row in rows:
        if row["lost"]:
            print(f"\nPierden organización en «{row['set']}»: {', '.join(row['lost'])}")
        if row["gained"]:
            print(f"\nGanan organización en «{row['set']}»: {', '.join(row['gained'])}")


if __name__ == "__main__":
    main()
