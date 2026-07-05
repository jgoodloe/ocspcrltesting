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
