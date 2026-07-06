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

    _reconcile_ca_cert_unique(conn)


def _reconcile_ca_cert_unique(conn: Connection) -> None:
    """Relax the pre-multi-user *global* unique on ``ca_certificates`` to the
    per-workspace composite the model now declares.

    Single-user databases created ``ca_certificates`` with
    ``UNIQUE (fingerprint_sha256)``, which wrongly prevents the same CA from
    being saved in more than one workspace (uploads and cross-workspace sharing
    fail with an IntegrityError). Replace it with
    ``UNIQUE (workspace_id, fingerprint_sha256)``. Idempotent; a no-op once the
    composite is already in place. Runs after the column/index reconciliation
    so the SQLite table rebuild can copy every current column.
    """
    inspector = inspect(conn)
    if "ca_certificates" not in set(inspector.get_table_names()):
        return

    def cols(entry: dict) -> list:
        return list(entry.get("column_names") or [])

    uniques = inspector.get_unique_constraints("ca_certificates")
    has_composite = any(set(cols(u)) == {"workspace_id", "fingerprint_sha256"} for u in uniques)
    stale = [u for u in uniques if cols(u) == ["fingerprint_sha256"]]
    if has_composite and not stale:
        return  # already correct

    if conn.dialect.name == "sqlite":
        # SQLite cannot drop a table-level UNIQUE; rebuild the table. By now
        # _reconcile_existing_tables has added every current column, so a plain
        # column-list copy is safe.
        table = Base.metadata.tables["ca_certificates"]
        col_list = ", ".join(f'"{c.name}"' for c in table.columns)
        conn.exec_driver_sql("ALTER TABLE ca_certificates RENAME TO _ca_certificates_old")
        # Index names are database-global in SQLite and survive the rename, so
        # drop the old table's named indexes before recreating the table (whose
        # fresh indexes reuse the same names). Auto-indexes from the dropped
        # UNIQUE go away with the old table.
        for idx in inspect(conn).get_indexes("_ca_certificates_old"):
            name = idx.get("name")
            if name and not name.startswith("sqlite_autoindex"):
                conn.exec_driver_sql(f'DROP INDEX IF EXISTS "{name}"')
        table.create(bind=conn)
        conn.exec_driver_sql(
            f"INSERT INTO ca_certificates ({col_list}) "
            f"SELECT {col_list} FROM _ca_certificates_old"
        )
        conn.exec_driver_sql("DROP TABLE _ca_certificates_old")
        logger.info(
            "rebuilt ca_certificates: replaced global fingerprint unique with the "
            "per-workspace composite"
        )
        return

    # PostgreSQL and other backends can alter constraints in place.
    for u in stale:
        conn.exec_driver_sql(f'ALTER TABLE ca_certificates DROP CONSTRAINT "{u["name"]}"')
        logger.info("dropped stale global unique %s on ca_certificates", u["name"])
    if not has_composite:
        conn.exec_driver_sql(
            "ALTER TABLE ca_certificates ADD CONSTRAINT uq_ca_certificates_ws_fingerprint "
            "UNIQUE (workspace_id, fingerprint_sha256)"
        )
        logger.info("added composite unique on ca_certificates(workspace_id, fingerprint_sha256)")


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
