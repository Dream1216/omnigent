from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

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
        assert revision == "pc5a00000003"
        preflight_indexes = {
            value["name"] for value in inspector.get_indexes("saas_enterprise_access_preflights")
        }
        assert {
            "ix_enterprise_access_preflight_requester",
            "ix_enterprise_access_preflight_inbox",
        } <= preflight_indexes
        assert "ix_tenant_membership_directory" in {
            value["name"] for value in inspector.get_indexes("saas_tenant_memberships")
        }
        assert "ix_space_membership_member_directory" in {
            value["name"] for value in inspector.get_indexes("saas_space_memberships")
        }
        assert "ix_invitation_tenant_status_expiry" in {
            value["name"] for value in inspector.get_indexes("saas_membership_invitations")
        }

        command.downgrade(config, "base")
        remaining_tables = set(sa.inspect(connection).get_table_names())
        assert remaining_tables <= {"saas_alembic_version"}
    engine.dispose()


def test_enterprise_lifecycle_migration_backfills_legacy_terminal_states() -> None:
    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection:
        config = _migration_config(connection)
        command.upgrade(config, "p6a000000002")

        metadata = sa.MetaData()
        metadata.reflect(
            bind=connection,
            only=(
                "saas_global_users",
                "saas_tenants",
                "saas_spaces",
                "saas_projects",
                "saas_enterprise_groups",
                "saas_enterprise_custom_roles",
            ),
        )
        user_id = uuid4()
        tenant_id = uuid4()
        space_id = uuid4()
        project_id = uuid4()
        group_id = uuid4()
        role_id = uuid4()
        legacy_time = datetime(2026, 8, 4, 12, tzinfo=timezone.utc)
        connection.execute(
            metadata.tables["saas_global_users"].insert(),
            {
                "id": user_id.hex,
                "status": "active",
                "security_version": 1,
                "created_at": legacy_time,
                "updated_at": legacy_time,
            },
        )
        connection.execute(
            metadata.tables["saas_tenants"].insert(),
            {
                "id": tenant_id.hex,
                "slug": "legacy-lifecycle",
                "name": "Legacy Lifecycle",
                "status": "active",
                "plan": "enterprise",
                "home_region": "cn-east-1",
                "created_at": legacy_time,
                "updated_at": legacy_time,
            },
        )
        connection.execute(
            metadata.tables["saas_spaces"].insert(),
            {
                "id": space_id.hex,
                "tenant_id": tenant_id.hex,
                "slug": "legacy-space",
                "name": "Legacy Space",
                "status": "active",
                "created_at": legacy_time,
                "updated_at": legacy_time,
            },
        )
        connection.execute(
            metadata.tables["saas_projects"].insert(),
            {
                "id": project_id.hex,
                "tenant_id": tenant_id.hex,
                "space_id": space_id.hex,
                "name": "Legacy Project",
                "visibility": "restricted",
                "created_by": user_id.hex,
                "status": "active",
                "authorization_version": 1,
                "created_at": legacy_time,
                "updated_at": legacy_time,
            },
        )
        connection.execute(
            metadata.tables["saas_enterprise_groups"].insert(),
            {
                "id": group_id.hex,
                "tenant_id": tenant_id.hex,
                "name": "Legacy Archived Group",
                "status": "archived",
                "version": 2,
                "created_by": user_id.hex,
                "created_at": legacy_time,
                "updated_at": legacy_time,
            },
        )
        connection.execute(
            metadata.tables["saas_enterprise_custom_roles"].insert(),
            {
                "id": role_id.hex,
                "tenant_id": tenant_id.hex,
                "space_id": space_id.hex,
                "project_id": project_id.hex,
                "name": "Legacy Retired Role",
                "permissions": ["project.read_metadata"],
                "status": "retired",
                "version": 2,
                "created_by": user_id.hex,
                "created_at": legacy_time,
                "updated_at": legacy_time,
            },
        )

        command.upgrade(config, "head")
        group = connection.execute(
            sa.text(
                "SELECT archived_at, archived_by, archive_reason "
                "FROM saas_enterprise_groups WHERE id = :id"
            ),
            {"id": group_id.hex},
        ).one()
        role = connection.execute(
            sa.text(
                "SELECT retired_at, retired_by, retire_reason "
                "FROM saas_enterprise_custom_roles WHERE id = :id"
            ),
            {"id": role_id.hex},
        ).one()

        assert group.archived_at is not None
        assert group.archived_by == user_id.hex
        assert group.archive_reason == "legacy-state-backfill:p6a000000003"
        assert role.retired_at is not None
        assert role.retired_by == user_id.hex
        assert role.retire_reason == "legacy-state-backfill:p6a000000003"
    engine.dispose()
