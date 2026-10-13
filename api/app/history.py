"""Borrado del historial (F10): un scan o todo.

Borrar un scan arrastra su captura, su análisis y sus reportes por la cascada que ya existe
(claves foráneas ON DELETE CASCADE y los triggers de report_files, migración 0008). Aquí no
se enumera qué tablas tocar para borrar: solo para MEDIR cuánto ocupaba lo borrado.

Nada de esto toca backups/: los respaldos son archivos del host, fuera de la base.
Las funciones no hacen commit: lo hace quien las llama.
"""

import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

# Tablas con datos de scans que no cuelgan de jobs.id por una columna job_id.
EXTRA_TABLES = ("jobs", "test_groups", "report_files")


async def job_tables(session: AsyncSession) -> list[str]:
    """Tablas hijas de jobs (columna job_id con clave foránea), leídas del catálogo."""
    rows = await session.execute(
        text(
            "SELECT DISTINCT c.conrelid::regclass::text AS name FROM pg_constraint c "
            "JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey) "
            "WHERE c.contype = 'f' AND c.confrelid = 'jobs'::regclass AND a.attname = 'job_id' ORDER BY 1"
        )
    )
    return [row.name for row in rows]


async def data_bytes(session: AsyncSession, job_ids: list[uuid.UUID] | None, group_ids: list[uuid.UUID] | None = None) -> int:
    """Bytes que ocupan las filas de esos scans (o de todos, con None), reportes incluidos.

    Es el tamaño de los datos tal como están guardados (pg_column_size de cada fila, con su
    compresión). No incluye índices.
    """
    total = 0
    everything = job_ids is None
    for table in await job_tables(session):
        # `table` viene del catálogo de Postgres, no de un cliente.
        query = f"SELECT coalesce(sum(pg_column_size(t.*)), 0) FROM {table} t" + ("" if everything else " WHERE t.job_id = ANY(:ids)")
        total += int(await session.scalar(text(query), {} if everything else {"ids": job_ids}))
    if everything:
        for table in EXTRA_TABLES:
            total += int(await session.scalar(text(f"SELECT coalesce(sum(pg_column_size(t.*)), 0) FROM {table} t")))
        return total
    total += int(await session.scalar(text("SELECT coalesce(sum(pg_column_size(t.*)), 0) FROM jobs t WHERE t.id = ANY(:ids)"), {"ids": job_ids}))
    total += int(await session.scalar(
        text("SELECT coalesce(sum(pg_column_size(t.*)), 0) FROM report_files t WHERE (t.subject_type = 'scan' AND t.subject_id = ANY(:ids)) "
             "OR (t.subject_type = 'group' AND t.subject_id = ANY(:groups))"),
        {"ids": job_ids, "groups": group_ids or []},
    ))
    if group_ids:
        total += int(await session.scalar(text("SELECT coalesce(sum(pg_column_size(t.*)), 0) FROM test_groups t WHERE t.id = ANY(:groups)"), {"groups": group_ids}))
    return total


async def stats(session: AsyncSession) -> dict:
    row = (
        await session.execute(
            text("SELECT (SELECT count(*) FROM jobs) AS scans, (SELECT count(*) FROM test_groups) AS groups, (SELECT count(*) FROM report_files) AS reports")
        )
    ).one()
    tables = [*await job_tables(session), *EXTRA_TABLES]
    disk = int(await session.scalar(text("SELECT coalesce(sum(pg_total_relation_size(name::regclass)), 0) FROM unnest(CAST(:tables AS text[])) AS name"), {"tables": tables}))
    return {"scans": row.scans, "groups": row.groups, "reports": row.reports, "disk_bytes": disk}


async def delete_scan(session: AsyncSession, job_id: uuid.UUID) -> dict | None:
    """Borra un scan. Si era el último de su grupo de Privacy Test, borra también el grupo."""
    group_id = (await session.execute(text("SELECT group_id FROM jobs WHERE id = :id FOR UPDATE"), {"id": job_id})).first()
    if group_id is None:
        return None
    group_id = group_id[0]
    last_of_group = group_id is not None and await session.scalar(
        text("SELECT count(*) FROM jobs WHERE group_id = :group AND id <> :id"), {"group": group_id, "id": job_id}
    ) == 0
    groups = [group_id] if last_of_group else []
    freed = await data_bytes(session, [job_id], groups)
    reports_before = await session.scalar(text("SELECT count(*) FROM report_files"))
    await session.execute(text("DELETE FROM jobs WHERE id = :id"), {"id": job_id})
    if last_of_group:
        await session.execute(text("DELETE FROM test_groups WHERE id = :group"), {"group": group_id})
    reports = reports_before - await session.scalar(text("SELECT count(*) FROM report_files"))
    return {"scans": 1, "groups": len(groups), "reports": reports, "bytes_freed": freed}


async def delete_all(session: AsyncSession) -> dict:
    """Borra todos los scans y todos los grupos de Privacy Test, con todo lo que cuelga de ellos."""
    # Bloquea las altas mientras se mide y se borra: lo que se informa es lo que se borró.
    await session.execute(text("LOCK TABLE jobs, test_groups IN SHARE ROW EXCLUSIVE MODE"))
    before = await stats(session)
    freed = await data_bytes(session, None)
    # Primero se vacían las tablas hijas, de una vez, en vez de dejar que la cascada las
    # recorra scan por scan (ver también los índices de la migración 0010). La cascada sigue
    # siendo la que garantiza el resultado: corre igual al borrar jobs y test_groups, y además
    # se lleva los report_files (trigger) y cualquier tabla que no estuviera en la lista.
    tables = await job_tables(session)
    for table in sorted(tables, key=lambda name: name == "scan_requests"):  # scan_requests al final: otras la referencian
        await session.execute(text(f"DELETE FROM {table}"))
    await session.execute(text("DELETE FROM test_groups"))  # arrastra los scans de cada grupo
    await session.execute(text("DELETE FROM jobs"))
    after = await stats(session)
    return {
        "scans": before["scans"] - after["scans"], "groups": before["groups"] - after["groups"],
        "reports": before["reports"] - after["reports"], "bytes_freed": freed,
    }
