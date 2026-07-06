"""Database engine/session management (SQLite by default, PostgreSQL-ready)."""

from __future__ import annotations

import logging
from typing import AsyncIterator, Optional

from sqlalchemy import inspect
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from .orm import Base
from .settings import get_settings

logger = logging.getLogger("ocspweb.db")

_engine: Optional[AsyncEngine] = None
_session_factory: Optional[async_sessionmaker[AsyncSession]] = None


def get_engine() -> AsyncEngine:
    global _engine, _session_factory
    if _engine is None:
        settings = get_settings()
        url = settings.resolved_database_url
        kwargs = {}
        if url.startswith("sqlite"):
            kwargs["connect_args"] = {"timeout": 30}
        _engine = create_async_engine(url, **kwargs)
        _session_factory = async_sessionmaker(_engine, expire_on_commit=False)
    return _engine


def session_factory() -> async_sessionmaker[AsyncSession]:
    get_engine()
    assert _session_factory is not None
    return _session_factory


def _reconcile_existing_tables(conn: Connection) -> None:
    """Bring already-existing tables up to the current model.

    ``create_all`` only creates *missing* tables; it never alters a table that
    already exists. A database created before the multi-user schema still has
    the old ``runs`` / ``profiles`` / ``ca_certificates`` tables, so the new
    ``workspace_id`` / ``created_by_user_id`` columns (and their indexes) are
    absent and startup provisioning blows up with ``no such column``.

    This performs only *additive* changes — new columns (which are all nullable
    or defaulted, so existing rows stay valid) and missing indexes. It is
    idempotent and a no-op on a freshly created database. Anything that would
    require a destructive rewrite (a new NOT NULL column without a default, a
    changed unique constraint) is left to a real migration and logged.
    """
    inspector = inspect(conn)
    existing = set(inspector.get_table_names())
    dialect = conn.dialect

    for table in Base.metadata.sorted_tables:
        if table.name not in existing:
            continue  # create_all just built it with the full, current schema
        present = {c["name"] for c in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name in present:
                continue
            if not column.nullable and column.default is None and column.server_default is None:
                logger.warning(
                    "cannot auto-add non-nullable column %s.%s without a default; "
                    "a manual migration is required",
                    table.name,
                    column.name,
                )
                continue
            coltype = column.type.compile(dialect=dialect)
            conn.exec_driver_sql(
                f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" {coltype}'
            )
            logger.info("added missing column %s.%s", table.name, column.name)

    # Create any indexes the model defines that the (older) table is missing.
    for table in Base.metadata.sorted_tables:
        if table.name not in existing:
            continue
        for index in table.indexes:
            index.create(bind=conn, checkfirst=True)

    # Relax pre-multi-user *global* uniques to the per-workspace composites the
    # models now declare (same-named CA/profile may exist in many workspaces).
    _reconcile_composite_unique(
        conn, "ca_certificates", "fingerprint_sha256",
        ["workspace_id", "fingerprint_sha256"], "uq_ca_certificates_ws_fingerprint",
    )
    _reconcile_composite_unique(
        conn, "profiles", "name",
        ["workspace_id", "name"], "uq_profiles_ws_name",
    )


def _reconcile_composite_unique(
    conn: Connection,
    table_name: str,
    single_col: str,
    composite_cols: list,
    composite_name: str,
) -> None:
    """Relax a pre-multi-user *global* ``UNIQUE(single_col)`` to the
    per-workspace ``UNIQUE(composite_cols)`` the model now declares.

    Single-user databases created ``ca_certificates`` with
    ``UNIQUE(fingerprint_sha256)`` and ``profiles`` with ``UNIQUE(name)``, which
    wrongly prevent the same CA/profile from existing in more than one workspace
    (uploads and cross-workspace sharing fail with an IntegrityError). Idempotent
    — a no-op once the composite is already in place. Runs after the column/index
    reconciliation so the SQLite table rebuild can copy every current column.
    """
    inspector = inspect(conn)
    if table_name not in set(inspector.get_table_names()):
        return

    def cols(entry: dict) -> list:
        return list(entry.get("column_names") or [])

    uniques = inspector.get_unique_constraints(table_name)
    has_composite = any(set(cols(u)) == set(composite_cols) for u in uniques)
    stale = [u for u in uniques if cols(u) == [single_col]]
    if has_composite and not stale:
        return  # already correct

    if conn.dialect.name == "sqlite":
        # SQLite cannot drop a table-level UNIQUE; rebuild the table. By now
        # _reconcile_existing_tables has added every current column, so a plain
        # column-list copy is safe.
        table = Base.metadata.tables[table_name]
        col_list = ", ".join(f'"{c.name}"' for c in table.columns)
        tmp = f"_{table_name}_old"
        conn.exec_driver_sql(f"ALTER TABLE {table_name} RENAME TO {tmp}")
        # Index names are database-global in SQLite and survive the rename, so
        # drop the old table's named indexes before recreating the table (whose
        # fresh indexes reuse the same names). Auto-indexes from the dropped
        # UNIQUE go away with the old table.
        for idx in inspect(conn).get_indexes(tmp):
            name = idx.get("name")
            if name and not name.startswith("sqlite_autoindex"):
                conn.exec_driver_sql(f'DROP INDEX IF EXISTS "{name}"')
        table.create(bind=conn)
        conn.exec_driver_sql(
            f"INSERT INTO {table_name} ({col_list}) SELECT {col_list} FROM {tmp}"
        )
        conn.exec_driver_sql(f"DROP TABLE {tmp}")
        logger.info(
            "rebuilt %s: replaced global unique on %s with composite %s",
            table_name, single_col, tuple(composite_cols),
        )
        return

    # PostgreSQL and other backends can alter constraints in place.
    for u in stale:
        conn.exec_driver_sql(f'ALTER TABLE {table_name} DROP CONSTRAINT "{u["name"]}"')
        logger.info("dropped stale global unique %s on %s", u["name"], table_name)
    if not has_composite:
        cols_sql = ", ".join(composite_cols)
        conn.exec_driver_sql(
            f"ALTER TABLE {table_name} ADD CONSTRAINT {composite_name} UNIQUE ({cols_sql})"
        )
        logger.info("added composite unique %s on %s", composite_name, table_name)


async def init_db() -> None:
    engine = get_engine()
    async with engine.begin() as conn:
        if engine.url.get_backend_name() == "sqlite":
            from sqlalchemy import text

            await conn.execute(text("PRAGMA journal_mode=WAL"))
        await conn.run_sync(Base.metadata.create_all)
        # create_all cannot upgrade tables that predate the multi-user schema;
        # add the new nullable columns/indexes to them before anything reads.
        await conn.run_sync(_reconcile_existing_tables)


async def dispose_db() -> None:
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None


async def get_session() -> AsyncIterator[AsyncSession]:
    async with session_factory()() as session:
        yield session
