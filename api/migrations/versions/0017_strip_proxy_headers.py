"""Quita Proxy-Authorization y Proxy-Connection de las capturas guardadas (v1.5.3, docs/adr/041)

Son cabeceras del navegador con el egress-proxy, no del sitio: en las requests `http://` Chromium las enviaba al proxy y
la captura las guardaba, con el usuario del scan y PROXY_SCAN_SECRET en base64. Desde 1.5.3 el worker no las guarda; aquí
se borran de `scan_requests` (cabeceras de request y de respuesta) y del staging de HAR importados. No cambia ninguna
otra cabecera ni el orden de las demás, y el analizador no las usa: puntaje, clasificación y hallazgos no cambian.
Irreversible: el downgrade no las restaura.

Revision ID: 0017
Revises: 0016
"""
from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None

PROXY = "('proxy-authorization', 'proxy-connection')"


def _strip(column: str) -> str:
    """Expresión que devuelve el arreglo `column` sin las cabeceras del proxy, en el mismo orden."""
    return (
        f"(SELECT coalesce(jsonb_agg(h ORDER BY n), '[]'::jsonb) FROM jsonb_array_elements({column}) WITH ORDINALITY AS e(h, n) "
        f"WHERE lower(btrim(coalesce(h->>'name', ''))) NOT IN {PROXY})"
    )


def _has(column: str) -> str:
    return (
        f"(jsonb_typeof({column}) = 'array' AND EXISTS (SELECT 1 FROM jsonb_array_elements({column}) AS e(h) "
        f"WHERE lower(btrim(coalesce(h->>'name', ''))) IN {PROXY}))"
    )


def upgrade() -> None:
    for column in ("request_headers", "response_headers"):
        op.execute(f"UPDATE scan_requests SET {column} = {_strip(column)} WHERE {_has(column)}")
    # Staging de HAR importados: {"entries": [{..., "request_headers": [...], "response_headers": [...]}], ...}
    for column in ("request_headers", "response_headers"):
        op.execute(
            "UPDATE har_imports SET payload = jsonb_set(payload, '{entries}', ("
            "SELECT coalesce(jsonb_agg(CASE WHEN " + _has(f"r->'{column}'") + " THEN jsonb_set(r, '{" + column + "}', "
            + _strip(f"r->'{column}'") + ") ELSE r END ORDER BY i), '[]'::jsonb) "
            "FROM jsonb_array_elements(payload->'entries') WITH ORDINALITY AS q(r, i))) "
            "WHERE jsonb_typeof(payload->'entries') = 'array' AND payload::text ILIKE '%proxy-%'"
        )


def downgrade() -> None:
    pass  # irreversible: las cabeceras borradas no se pueden restaurar (y no deben).
