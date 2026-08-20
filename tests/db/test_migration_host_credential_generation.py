"""Tests for external-host credential CAS metadata migration."""

from __future__ import annotations

from pathlib import Path

import sqlalchemy as sa
from alembic import command

from omnigent.db.utils import _build_alembic_config, clear_engine_cache


def test_host_credential_generation_migrates_existing_rows_and_downgrades(
    tmp_path: Path,
) -> None:
    """Existing hosts start at generation zero and both columns are reversible."""
    uri = f"sqlite:///{tmp_path / 'credential-generation.db'}"
    engine = sa.create_engine(uri)
    config = _build_alembic_config(uri)

    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "g8b9c0d1e2f3")
        connection.execute(
            sa.text(
                """
                INSERT INTO hosts (
                    workspace_id, host_id, user_id, name, status, created_at, updated_at
                ) VALUES (
                    0, :host_id, 'alice@example.com', 'existing-host', 2, 1, 1
                )
                """
            ),
            {"host_id": bytes.fromhex("0123456789abcdef0123456789abcdef")},
        )
        command.upgrade(config, "h8c0d1e2f3a4")
        migrated = connection.execute(
            sa.text(
                "SELECT credential_generation, credential_operation_id "
                "FROM hosts WHERE name = 'existing-host'"
            )
        ).one()
        assert migrated == (0, None)

        command.downgrade(config, "g8b9c0d1e2f3")

    columns = {column["name"] for column in sa.inspect(engine).get_columns("hosts")}
    assert "credential_generation" not in columns
    assert "credential_operation_id" not in columns
    engine.dispose()
    clear_engine_cache()
