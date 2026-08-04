"""Alembic environment for the independent SaaS control-plane schema."""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import Connection, engine_from_config, pool

from saas.control_plane import execution_models as _execution_models  # noqa: F401
from saas.control_plane import isolation_models as _isolation_models  # noqa: F401
from saas.control_plane import scheduling_models as _scheduling_models  # noqa: F401
from saas.control_plane import worktree_models as _worktree_models  # noqa: F401
from saas.control_plane.db_models import SaasBase

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

db_url = os.environ.get("OMNIGENT_SAAS_DB_URL")
if db_url:
    config.set_main_option("sqlalchemy.url", db_url)


def _configure(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=SaasBase.metadata,
        render_as_batch=True,
        version_table="saas_alembic_version",
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_offline() -> None:
    """Emit migration SQL without opening a database connection."""

    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=SaasBase.metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        version_table="saas_alembic_version",
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Apply migrations using a supplied transaction or an isolated engine."""

    connection = config.attributes.get("connection")
    if connection is not None:
        _configure(connection)
        return

    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as opened_connection:
        _configure(opened_connection)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
