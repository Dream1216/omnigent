from __future__ import annotations

import json
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid4

import pytest
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
        assert revision == "p0s000000002"
        first_run_scope = next(
            foreign_key
            for foreign_key in inspector.get_foreign_keys("saas_tenant_onboardings")
            if foreign_key["name"] == "fk_tenant_onboarding_first_run_scope"
        )
        assert first_run_scope["constrained_columns"] == [
            "first_run_id",
            "tenant_id",
            "space_id",
            "default_project_id",
        ]
        assert first_run_scope["referred_table"] == "saas_runs"
        assert first_run_scope["referred_columns"] == [
            "id",
            "tenant_id",
            "space_id",
            "project_id",
        ]
        assert first_run_scope["options"].get("ondelete") == "RESTRICT"
        runtime_placement = next(
            foreign_key
            for foreign_key in inspector.get_foreign_keys("saas_tenant_onboardings")
            if foreign_key["name"] == "fk_tenant_onboarding_runtime_placement"
        )
        assert runtime_placement["constrained_columns"] == ["runtime_placement_id"]
        assert runtime_placement["referred_table"] == "saas_runtime_placements"
        assert runtime_placement["referred_columns"] == ["id"]
        assert runtime_placement["options"].get("ondelete") == "RESTRICT"
        onboarding_checks = {
            check["name"] for check in inspector.get_check_constraints("saas_tenant_onboardings")
        }
        assert {
            "ck_tenant_onboarding_runtime_request",
            "ck_tenant_onboarding_initial_placement",
            "ck_tenant_onboarding_ready_placement",
            "ck_tenant_onboarding_failure_evidence",
        } <= onboarding_checks
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


@pytest.mark.parametrize(
    ("legacy_status", "runtime_ready", "activated", "expected_cursor"),
    (
        ("billing_ready", False, False, "billing"),
        ("runtime_ready", True, False, "runtime"),
        ("active", True, True, "project"),
    ),
)
def test_onboarding_vertical_migration_backfills_ids_snapshot_and_pending_intent(
    legacy_status: str,
    runtime_ready: bool,
    activated: bool,
    expected_cursor: str,
) -> None:
    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection:
        config = _migration_config(connection)
        command.upgrade(config, "p0s000000001")
        now = datetime(2026, 8, 24, 3, 0, tzinfo=timezone.utc)
        identifiers = {
            name: uuid4()
            for name in (
                "registration_id",
                "onboarding_id",
                "user_id",
                "tenant_id",
                "space_id",
                "subscription_id",
                "runtime_partition_id",
                "outbox_id",
            )
        }
        values = {name: str(value) for name, value in identifiers.items()}
        connection.execute(
            sa.text(
                "INSERT INTO saas_global_users (id, status, security_version) "
                "VALUES (:user_id, 'active', 1)"
            ),
            values,
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenants "
                "(id, slug, name, status, plan, home_region, lifecycle_version) "
                "VALUES (:tenant_id, 'legacy-vertical', 'Legacy Vertical', "
                "'provisioning', 'starter', 'cn-east-1', 1)"
            ),
            values,
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_spaces (id, tenant_id, slug, name, status) "
                "VALUES (:space_id, :tenant_id, 'default', 'Default', 'suspended')"
            ),
            values,
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_self_service_registrations "
                "(id, email_normalized, email_hash, tenant_name, tenant_slug, "
                "default_space_name, default_space_slug, plan_key, plan_policy_revision, "
                "home_region, status, challenge_generation, expires_at, verified_at, "
                "terminal_at, user_id, tenant_id, space_id, subscription_id, "
                "runtime_partition_id, onboarding_id, idempotency_key, request_hash, "
                "version, created_at, updated_at) VALUES "
                "(:registration_id, 'legacy@example.test', :email_hash, 'Legacy Vertical', "
                "'legacy-vertical', 'Default', 'default', 'starter', 'starter-v1', "
                "'cn-east-1', 'verified', 1, :expires_at, :now, :now, :user_id, "
                ":tenant_id, :space_id, :subscription_id, :runtime_partition_id, "
                ":onboarding_id, :idempotency_key, :request_hash, 2, :now, :now)"
            ),
            {
                **values,
                "email_hash": "a" * 64,
                "idempotency_key": "b" * 64,
                "request_hash": "c" * 64,
                "now": now,
                "expires_at": now.replace(day=25),
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenant_onboardings "
                "(id, registration_id, user_id, tenant_id, space_id, subscription_id, "
                "runtime_partition_id, plan_key, plan_policy_revision, home_region, "
                "trial_days, trial_started_at, trial_ends_at, status, idempotency_key, "
                "request_hash, version, attempt_count, available_at, billing_ready_at, "
                "runtime_ready_at, activated_at, last_transition_at, created_at, updated_at) "
                "VALUES "
                "(:onboarding_id, :registration_id, :user_id, :tenant_id, :space_id, "
                ":subscription_id, :runtime_partition_id, 'starter', 'starter-v1', "
                "'cn-east-1', 14, :now, :trial_ends_at, :legacy_status, "
                ":saga_key, :saga_hash, 2, 1, :now, :now, :runtime_ready_at, "
                ":activated_at, :now, :now, :now)"
            ),
            {
                **values,
                "now": now,
                "trial_ends_at": now.replace(day=31),
                "saga_key": "d" * 64,
                "saga_hash": "e" * 64,
                "legacy_status": legacy_status,
                "runtime_ready_at": now if runtime_ready else None,
                "activated_at": now if activated else None,
            },
        )
        old_payload = {
            "onboarding_id": str(identifiers["onboarding_id"]),
            "registration_id": str(identifiers["registration_id"]),
            "tenant_id": str(identifiers["tenant_id"]),
            "plan_policy_revision": "starter-v1",
        }
        connection.execute(
            sa.text(
                "INSERT INTO saas_control_plane_outbox "
                "(id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
                "idempotency_key, request_hash, attempt_count, available_at) VALUES "
                "(:outbox_id, :tenant_id, 'tenant_onboarding', :onboarding_key, "
                "'onboarding.billing.requested', :payload, 'legacy-billing-intent', "
                ":outbox_hash, 0, :now)"
            ),
            {
                **values,
                "onboarding_key": str(identifiers["onboarding_id"]),
                "payload": json.dumps(old_payload),
                "outbox_hash": "f" * 64,
                "now": now,
            },
        )

        command.upgrade(config, "p0s000000002")
        registration = connection.execute(
            sa.text(
                "SELECT default_project_id, pricing_snapshot_id, entitlement_id, "
                "runtime_binding_id, plan_snapshot, plan_snapshot_hash "
                "FROM saas_self_service_registrations WHERE id = :registration_id"
            ),
            values,
        ).one()
        saga = connection.execute(
            sa.text(
                "SELECT default_project_id, pricing_snapshot_id, entitlement_id, "
                "runtime_binding_id, plan_snapshot, plan_snapshot_hash, "
                "status, failure_stage, compensation_cursor, runtime_placement_id, "
                "runtime_target_snapshot, runtime_request_hash, trial_started_at, "
                "trial_ends_at, activated_at FROM saas_tenant_onboardings "
                "WHERE id = :onboarding_id"
            ),
            values,
        ).one()
        snapshot = {
            "schema_version": 1,
            "key": "starter",
            "policy_revision": "starter-v1",
            "trial_days": 14,
            "currency": "USD",
            "trial_run_limit": 100,
            "trial_concurrency_limit": 2,
            "runtime_type": "omnigent",
            "capacity_class": "starter",
            "default_project_name": "Getting Started",
            "default_project_visibility": "private",
            "quota_resource": "interactive_runs",
            "quota_limit": 100,
        }
        canonical_snapshot = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
        assert tuple(UUID(str(value)) for value in registration[:4]) == tuple(
            UUID(str(value)) for value in saga[:4]
        )
        assert json.loads(registration.plan_snapshot) == snapshot
        assert json.loads(saga.plan_snapshot) == snapshot
        assert (
            registration.plan_snapshot_hash
            == sha256(canonical_snapshot.encode("utf-8")).hexdigest()
        )
        assert saga.plan_snapshot_hash == registration.plan_snapshot_hash
        assert saga.status == "manual_review"
        assert saga.failure_stage == f"legacy_{legacy_status}"
        assert saga.compensation_cursor == expected_cursor
        assert saga.runtime_placement_id is None
        assert saga.runtime_target_snapshot is None
        assert saga.runtime_request_hash is None
        assert saga.trial_started_at is not None
        assert saga.trial_ends_at > saga.trial_started_at
        assert (saga.activated_at is not None) is activated
        with pytest.raises(sa.exc.IntegrityError):
            with connection.begin_nested():
                connection.execute(
                    sa.text(
                        "UPDATE saas_tenant_onboardings "
                        "SET runtime_target_snapshot = '{}' WHERE id = :onboarding_id"
                    ),
                    values,
                )
        with pytest.raises(sa.exc.IntegrityError):
            with connection.begin_nested():
                connection.execute(
                    sa.text(
                        "UPDATE saas_tenant_onboardings "
                        "SET compensation_cursor = 'unbounded' WHERE id = :onboarding_id"
                    ),
                    values,
                )

        outbox = connection.execute(
            sa.text(
                "SELECT payload, request_hash FROM saas_control_plane_outbox WHERE id = :outbox_id"
            ),
            values,
        ).one()
        payload = json.loads(outbox.payload)
        assert payload == {
            **old_payload,
            "user_id": str(identifiers["user_id"]),
            "space_id": str(identifiers["space_id"]),
            "default_project_id": str(UUID(str(saga.default_project_id))),
            "expected_status": "tenant_created",
            "version": 2,
        }
        assert (
            outbox.request_hash
            == sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
        )

        command.downgrade(config, "p0s000000001")
        registration_columns = {
            column["name"]
            for column in sa.inspect(connection).get_columns("saas_self_service_registrations")
        }
        assert "default_project_id" not in registration_columns
        legacy_saga = connection.execute(
            sa.text(
                "SELECT status, trial_started_at, trial_ends_at, activated_at "
                "FROM saas_tenant_onboardings WHERE id = :onboarding_id"
            ),
            values,
        ).one()
        assert legacy_saga.status == legacy_status
        assert legacy_saga.trial_started_at is not None
        assert legacy_saga.trial_ends_at > legacy_saga.trial_started_at
        assert (legacy_saga.activated_at is not None) is activated
    engine.dispose()


@pytest.mark.parametrize(
    ("legacy_status", "published_old_billing", "expected_event"),
    (
        ("tenant_created", True, "onboarding.billing.requested"),
        ("compensating", False, "onboarding.compensation.requested"),
    ),
)
def test_onboarding_vertical_migration_ensures_nonterminal_recovery_wake(
    legacy_status: str,
    published_old_billing: bool,
    expected_event: str,
) -> None:
    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection:
        config = _migration_config(connection)
        command.upgrade(config, "p0s000000001")
        now = datetime(2026, 8, 24, 5, 0, tzinfo=timezone.utc)
        identifiers = {
            name: uuid4()
            for name in (
                "registration_id",
                "onboarding_id",
                "user_id",
                "tenant_id",
                "space_id",
                "subscription_id",
                "runtime_partition_id",
                "old_outbox_id",
                "duplicate_outbox_a",
                "duplicate_outbox_b",
            )
        }
        values = {name: str(value) for name, value in identifiers.items()}
        connection.execute(
            sa.text(
                "INSERT INTO saas_global_users (id, status, security_version) "
                "VALUES (:user_id, 'active', 1)"
            ),
            values,
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenants "
                "(id, slug, name, status, plan, home_region, lifecycle_version) "
                "VALUES (:tenant_id, :tenant_slug, 'Recovery Wake', "
                "'provisioning', 'starter', 'cn-east-1', 1)"
            ),
            {**values, "tenant_slug": f"recovery-{legacy_status}"},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_spaces (id, tenant_id, slug, name, status) "
                "VALUES (:space_id, :tenant_id, 'default', 'Default', 'suspended')"
            ),
            values,
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_self_service_registrations "
                "(id, email_normalized, email_hash, tenant_name, tenant_slug, "
                "default_space_name, default_space_slug, plan_key, plan_policy_revision, "
                "home_region, status, challenge_generation, expires_at, verified_at, "
                "terminal_at, user_id, tenant_id, space_id, subscription_id, "
                "runtime_partition_id, onboarding_id, idempotency_key, request_hash, "
                "version, created_at, updated_at) VALUES "
                "(:registration_id, :email, :email_hash, 'Recovery Wake', :tenant_slug, "
                "'Default', 'default', 'starter', 'starter-v1', 'cn-east-1', 'verified', "
                "1, :expires_at, :now, :now, :user_id, :tenant_id, :space_id, "
                ":subscription_id, :runtime_partition_id, :onboarding_id, "
                ":registration_key, :registration_hash, 2, :now, :now)"
            ),
            {
                **values,
                "email": f"{legacy_status}@example.test",
                "email_hash": sha256(legacy_status.encode()).hexdigest(),
                "tenant_slug": f"recovery-{legacy_status}",
                "registration_key": sha256(f"key:{legacy_status}".encode()).hexdigest(),
                "registration_hash": sha256(f"hash:{legacy_status}".encode()).hexdigest(),
                "now": now,
                "expires_at": now.replace(day=25),
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenant_onboardings "
                "(id, registration_id, user_id, tenant_id, space_id, subscription_id, "
                "runtime_partition_id, plan_key, plan_policy_revision, home_region, "
                "trial_days, status, idempotency_key, request_hash, version, attempt_count, "
                "available_at, last_transition_at, created_at, updated_at) VALUES "
                "(:onboarding_id, :registration_id, :user_id, :tenant_id, :space_id, "
                ":subscription_id, :runtime_partition_id, 'starter', 'starter-v1', "
                "'cn-east-1', 14, :legacy_status, :saga_key, :saga_hash, 2, 0, "
                ":now, :now, :now, :now)"
            ),
            {
                **values,
                "legacy_status": legacy_status,
                "saga_key": sha256(f"saga:{legacy_status}".encode()).hexdigest(),
                "saga_hash": sha256(f"request:{legacy_status}".encode()).hexdigest(),
                "now": now,
            },
        )
        if published_old_billing:
            old_payload = {
                "onboarding_id": str(identifiers["onboarding_id"]),
                "registration_id": str(identifiers["registration_id"]),
                "tenant_id": str(identifiers["tenant_id"]),
            }
            connection.execute(
                sa.text(
                    "INSERT INTO saas_control_plane_outbox "
                    "(id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
                    "idempotency_key, request_hash, attempt_count, available_at, published_at) "
                    "VALUES (:old_outbox_id, :tenant_id, 'tenant_onboarding', "
                    ":onboarding_key, 'onboarding.billing.requested', :payload, "
                    ":old_key, :old_hash, 1, :now, :now)"
                ),
                {
                    **values,
                    "onboarding_key": str(identifiers["onboarding_id"]),
                    "payload": json.dumps(old_payload),
                    "old_key": sha256(b"published-old-billing").hexdigest(),
                    "old_hash": sha256(
                        json.dumps(old_payload, sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest(),
                    "now": now,
                },
            )
            for duplicate_name in ("duplicate_outbox_a", "duplicate_outbox_b"):
                duplicate_payload = {
                    **old_payload,
                    "legacy_duplicate": duplicate_name,
                }
                connection.execute(
                    sa.text(
                        "INSERT INTO saas_control_plane_outbox "
                        "(id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
                        "idempotency_key, request_hash, attempt_count, available_at) "
                        "VALUES (:duplicate_id, :tenant_id, 'tenant_onboarding', "
                        ":onboarding_key, 'onboarding.billing.requested', :payload, "
                        ":duplicate_key, :duplicate_hash, 3, :now)"
                    ),
                    {
                        **values,
                        # ORM writes use compact UUID hex on SQLite, while raw
                        # legacy fixtures may contain the dashed form.
                        "duplicate_id": identifiers[duplicate_name].hex,
                        "onboarding_key": str(identifiers["onboarding_id"]),
                        "payload": json.dumps(duplicate_payload),
                        "duplicate_key": sha256(duplicate_name.encode()).hexdigest(),
                        "duplicate_hash": sha256(
                            json.dumps(
                                duplicate_payload, sort_keys=True, separators=(",", ":")
                            ).encode()
                        ).hexdigest(),
                        "now": now,
                    },
                )

        command.upgrade(config, "p0s000000002")

        saga = connection.execute(
            sa.text(
                "SELECT status, version, default_project_id, failure_stage, "
                "compensation_cursor FROM saas_tenant_onboardings "
                "WHERE id = :onboarding_id"
            ),
            values,
        ).one()
        assert saga.status == legacy_status
        if legacy_status == "compensating":
            assert saga.failure_stage == "tenant_created"
            assert saga.compensation_cursor == "billing"
        wakes = connection.execute(
            sa.text(
                "SELECT payload, request_hash, idempotency_key, claimed_at, claim_token, "
                "last_error FROM saas_control_plane_outbox "
                "WHERE aggregate_type = 'tenant_onboarding' "
                "AND aggregate_key = :onboarding_key AND event_type = :expected_event "
                "AND published_at IS NULL"
            ),
            {
                "onboarding_key": str(identifiers["onboarding_id"]),
                "expected_event": expected_event,
            },
        ).all()
        assert len(wakes) == 1
        wake = wakes[0]
        payload = json.loads(wake.payload)
        assert payload == {
            "onboarding_id": str(identifiers["onboarding_id"]),
            "registration_id": str(identifiers["registration_id"]),
            "user_id": str(identifiers["user_id"]),
            "tenant_id": str(identifiers["tenant_id"]),
            "space_id": str(identifiers["space_id"]),
            "default_project_id": str(UUID(str(saga.default_project_id))),
            "expected_status": legacy_status,
            "version": saga.version,
        }
        assert (
            wake.request_hash
            == sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        )
        assert (
            wake.idempotency_key
            == sha256(
                (
                    f"p0s000000002:{identifiers['onboarding_id']}:{expected_event}:{saga.version}"
                ).encode()
            ).hexdigest()
        )
        assert wake.claimed_at is None
        assert wake.claim_token is None
        assert wake.last_error is None
        if published_old_billing:
            assert (
                connection.execute(
                    sa.text(
                        "SELECT count(*) FROM saas_control_plane_outbox "
                        "WHERE id = :old_outbox_id AND published_at IS NOT NULL"
                    ),
                    values,
                ).scalar_one()
                == 1
            )

        command.downgrade(config, "p0s000000001")
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


def test_scim_schema_extension_migration_defaults_and_refuses_lossy_downgrade() -> None:
    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection:
        config = _migration_config(connection)
        command.upgrade(config, "head")
        inspector = sa.inspect(connection)
        assert {"provider_type", "attribute_mapping"} <= {
            column["name"] for column in inspector.get_columns("saas_enterprise_scim_directories")
        }
        assert {"core_attributes", "enterprise_attributes"} <= {
            column["name"] for column in inspector.get_columns("saas_enterprise_scim_users")
        }

        now = datetime(2026, 8, 10, 8, tzinfo=timezone.utc)
        user_id, tenant_id, directory_id = uuid4(), uuid4(), uuid4()
        connection.execute(
            sa.text(
                "INSERT INTO saas_global_users "
                "(id, status, security_version, created_at, updated_at) "
                "VALUES (:id, 'active', 1, :now, :now)"
            ),
            {"id": user_id.hex, "now": now},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenants "
                "(id, slug, name, status, plan, home_region, created_at, updated_at) "
                "VALUES (:id, 'scim-migration', 'SCIM Migration', 'active', "
                "'enterprise', 'cn-east-1', :now, :now)"
            ),
            {"id": tenant_id.hex, "now": now},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_enterprise_scim_directories "
                "(id, tenant_id, display_name, provider_type, attribute_mapping, "
                "token_hash, token_prefix, status, version, configured_by, "
                "created_at, updated_at) "
                "VALUES (:id, :tenant_id, 'Migration IdP', 'okta', :mapping, :token_hash, "
                "'omniscim_migration', 'active', 1, :configured_by, :now, :now)"
            ),
            {
                "id": directory_id.hex,
                "tenant_id": tenant_id.hex,
                "mapping": (
                    '{"department":"urn:ietf:params:scim:schemas:extension:'
                    'enterprise:2.0:User:department"}'
                ),
                "token_hash": "a" * 64,
                "configured_by": user_id.hex,
                "now": now,
            },
        )

        with pytest.raises(RuntimeError, match="cannot downgrade SCIM schema extensions"):
            command.downgrade(config, "pc6a00000001")

        connection.execute(
            sa.text("DELETE FROM saas_enterprise_scim_directories WHERE id = :id"),
            {"id": directory_id.hex},
        )
        command.downgrade(config, "pc6a00000001")
        downgraded = sa.inspect(connection)
        assert "provider_type" not in {
            column["name"] for column in downgraded.get_columns("saas_enterprise_scim_directories")
        }
    engine.dispose()
