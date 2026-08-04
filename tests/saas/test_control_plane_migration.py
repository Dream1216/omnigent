from __future__ import annotations

from pathlib import Path

import sqlalchemy as sa
from alembic import command
from alembic.config import Config

from saas.control_plane import SaasBase


def _migration_config(connection: sa.Connection) -> Config:
    root = Path(__file__).resolve().parents[2]
    config = Config(root / "saas/control_plane/alembic.ini")
    config.set_main_option(
        "script_location",
        str(root / "saas/control_plane/migrations"),
    )
    config.attributes["connection"] = connection
    return config


def test_control_plane_migration_matches_declared_model_columns() -> None:
    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection:
        config = _migration_config(connection)
        command.upgrade(config, "head")

        inspector = sa.inspect(connection)
        application_tables = set(inspector.get_table_names()) - {"saas_alembic_version"}
        assert application_tables == set(SaasBase.metadata.tables)
        for table_name, table in SaasBase.metadata.tables.items():
            migrated_columns = {column["name"] for column in inspector.get_columns(table_name)}
            assert migrated_columns == set(table.columns.keys())

        revision = connection.execute(
            sa.text("SELECT version_num FROM saas_alembic_version")
        ).scalar_one()
        assert revision == "p4g000000001"

        command.downgrade(config, "base")
        remaining_tables = set(sa.inspect(connection).get_table_names())
        assert remaining_tables <= {"saas_alembic_version"}
    engine.dispose()
