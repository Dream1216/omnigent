from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROLE_SQL = (ROOT / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
VERTICAL_MIGRATION = (
    ROOT / "saas/control_plane/migrations/versions/p0s000000002_onboarding_vertical_chain.py"
).read_text(encoding="utf-8")


def _write_grants(role: str, privilege: str) -> dict[str, frozenset[str]]:
    grants: dict[str, frozenset[str]] = {}
    without_comments = re.sub(r"--[^\n]*", "", ROLE_SQL)
    for raw_statement in without_comments.split(";"):
        statement = " ".join(raw_statement.split())
        grant_match = re.fullmatch(r"GRANT (.+?) ON (.+?) TO (.+)", statement)
        if grant_match is None:
            continue
        recipients = {item.strip() for item in grant_match.group(3).split(",")}
        if role not in recipients:
            continue
        privileges = grant_match.group(1)
        privilege_match = re.search(
            rf"\b{privilege}\b(?:\s*\(([^)]*)\))?",
            privileges,
        )
        if privilege_match is None:
            continue
        assert privilege_match.group(1) is not None, (
            f"{role} must not receive table-level {privilege}: {statement}"
        )
        columns = frozenset(column.strip() for column in privilege_match.group(1).split(","))
        for table in (item.strip() for item in grant_match.group(2).split(",")):
            assert re.fullmatch(r"saas_[a-z0-9_]+", table), (
                f"unexpected {privilege} target for {role}: {table}"
            )
            assert table not in grants, f"duplicate {privilege} grant for {role} on {table}"
            grants[table] = columns
    return grants


def test_registration_write_grants_are_column_scoped_and_minimal() -> None:
    inserts = _write_grants("saas_registration", "INSERT")
    assert inserts == {
        "saas_self_service_registrations": frozenset(
            {
                "id",
                "email_normalized",
                "email_hash",
                "display_name",
                "tenant_name",
                "tenant_slug",
                "default_space_name",
                "default_space_slug",
                "plan_key",
                "plan_policy_revision",
                "home_region",
                "status",
                "challenge_generation",
                "expires_at",
                "verified_at",
                "terminal_at",
                "user_id",
                "tenant_id",
                "space_id",
                "subscription_id",
                "runtime_partition_id",
                "default_project_id",
                "pricing_snapshot_id",
                "entitlement_id",
                "runtime_binding_id",
                "onboarding_id",
                "plan_snapshot",
                "plan_snapshot_hash",
                "idempotency_key",
                "request_hash",
                "version",
                "created_at",
                "updated_at",
            }
        ),
        "saas_email_verification_challenges": frozenset(
            {
                "id",
                "registration_id",
                "generation",
                "token_hash",
                "status",
                "delivery_status",
                "delivery_attempts",
                "delivery_idempotency_key",
                "last_delivery_error_code",
                "expires_at",
                "delivered_at",
                "consumed_at",
                "expired_at",
                "revoked_at",
                "created_at",
                "updated_at",
            }
        ),
        "saas_self_service_events": frozenset(
            {
                "id",
                "aggregate_type",
                "aggregate_id",
                "tenant_id",
                "user_id",
                "sequence",
                "event_type",
                "from_status",
                "to_status",
                "facts",
                "facts_hash",
                "previous_hash",
                "event_hash",
                "occurred_at",
            }
        ),
        "saas_global_users": frozenset(
            {"id", "status", "display_name", "primary_email_normalized", "security_version"}
        ),
        "saas_identity_connections": frozenset(
            {
                "id",
                "user_id",
                "provider",
                "issuer",
                "subject",
                "email_normalized",
                "email_verified",
                "status",
            }
        ),
        "saas_password_credentials": frozenset(
            {
                "user_id",
                "login_email_normalized",
                "password_hash",
                "password_version",
                "failed_attempts",
                "locked_until",
            }
        ),
        "saas_control_plane_outbox": frozenset(
            {
                "id",
                "tenant_id",
                "aggregate_type",
                "aggregate_key",
                "event_type",
                "payload",
                "idempotency_key",
                "request_hash",
                "attempt_count",
                "available_at",
                "claimed_at",
                "claim_token",
                "published_at",
            }
        ),
    }

    updates = _write_grants("saas_registration", "UPDATE")
    assert updates == {
        "saas_self_service_registrations": frozenset(
            {
                "status",
                "challenge_generation",
                "expires_at",
                "verified_at",
                "terminal_at",
                "version",
                "updated_at",
            }
        ),
        "saas_email_verification_challenges": frozenset(
            {
                "status",
                "delivery_status",
                "delivery_attempts",
                "last_delivery_error_code",
                "delivered_at",
                "consumed_at",
                "expired_at",
                "revoked_at",
                "updated_at",
            }
        ),
    }
    immutable_registration_columns = {
        "email_normalized",
        "email_hash",
        "user_id",
        "tenant_id",
        "space_id",
        "subscription_id",
        "runtime_partition_id",
        "default_project_id",
        "pricing_snapshot_id",
        "entitlement_id",
        "runtime_binding_id",
        "plan_snapshot",
        "plan_snapshot_hash",
        "onboarding_id",
        "deletion_manifest_id",
    }
    assert immutable_registration_columns.isdisjoint(updates["saas_self_service_registrations"])


def test_rate_limit_tables_have_zero_service_role_acl_and_exact_function_entries() -> None:
    normalized = " ".join(re.sub(r"--[^\n]*", "", ROLE_SQL).split())
    statements = [
        " ".join(value.split()) for value in re.sub(r"--[^\n]*", "", ROLE_SQL).split(";")
    ]
    for table in (
        "saas_registration_rate_limit_policies",
        "saas_registration_rate_limits",
    ):
        for role in ("saas_registration", "saas_platform"):
            assert any(
                statement.startswith("REVOKE ALL PRIVILEGES ON")
                and table in statement
                and role in statement.split(" FROM ")[-1]
                for statement in statements
            )
            assert not any(
                statement.startswith("GRANT ")
                and " ON " in statement
                and table in statement.split(" ON ", 1)[1].split(" TO ", 1)[0]
                and role in statement.split(" TO ", 1)[-1]
                for statement in statements
            )
    assert (
        "GRANT EXECUTE ON FUNCTION public.saas_consume_registration_rate_limit( "
        "text, text, text, text, text, text, text, text ) TO saas_registration"
    ) in normalized
    assert (
        "GRANT EXECUTE ON FUNCTION public.saas_prune_registration_rate_limits( "
        "text, text, integer ) TO saas_platform"
    ) in normalized
    assert (
        "GRANT EXECUTE ON FUNCTION public.saas_registration_rate_limit_status() TO saas_platform"
    ) in normalized


def test_onboarding_vertical_chain_write_grants_are_exact_and_exclude_runs() -> None:
    inserts = _write_grants("saas_onboarding", "INSERT")
    assert inserts == {
        "saas_tenant_onboardings": frozenset(
            {
                "id",
                "registration_id",
                "user_id",
                "tenant_id",
                "space_id",
                "subscription_id",
                "runtime_partition_id",
                "default_project_id",
                "pricing_snapshot_id",
                "entitlement_id",
                "runtime_binding_id",
                "plan_key",
                "plan_policy_revision",
                "plan_snapshot",
                "plan_snapshot_hash",
                "home_region",
                "trial_days",
                "trial_started_at",
                "trial_ends_at",
                "status",
                "idempotency_key",
                "request_hash",
                "version",
                "attempt_count",
                "available_at",
                "claimed_at",
                "claim_token",
                "lease_expires_at",
                "last_error_code",
                "last_error_detail",
                "billing_ready_at",
                "runtime_ready_at",
                "project_ready_at",
                "activated_at",
                "first_run_id",
                "completed_at",
                "compensated_at",
                "failure_stage",
                "compensation_cursor",
                "runtime_placement_id",
                "runtime_target_snapshot",
                "runtime_request_hash",
                "last_transition_at",
                "created_at",
                "updated_at",
            }
        ),
        "saas_self_service_events": frozenset(
            {
                "id",
                "aggregate_type",
                "aggregate_id",
                "tenant_id",
                "user_id",
                "sequence",
                "event_type",
                "from_status",
                "to_status",
                "facts",
                "facts_hash",
                "previous_hash",
                "event_hash",
                "occurred_at",
            }
        ),
        "saas_tenants": frozenset(
            {"id", "slug", "name", "status", "plan", "home_region", "lifecycle_version"}
        ),
        "saas_spaces": frozenset({"id", "tenant_id", "slug", "name", "status"}),
        "saas_tenant_memberships": frozenset(
            {"tenant_id", "user_id", "role", "status", "version", "joined_at"}
        ),
        "saas_space_memberships": frozenset(
            {"tenant_id", "space_id", "user_id", "role", "status", "version", "joined_at"}
        ),
        "saas_control_plane_outbox": frozenset(
            {
                "id",
                "tenant_id",
                "aggregate_type",
                "aggregate_key",
                "event_type",
                "payload",
                "idempotency_key",
                "request_hash",
                "attempt_count",
                "available_at",
                "claimed_at",
                "claim_token",
                "published_at",
            }
        ),
        "saas_billing_subscriptions": frozenset(
            {
                "id",
                "tenant_id",
                "plan_key",
                "provider",
                "provider_customer_ref",
                "provider_subscription_ref",
                "status",
                "current_period_start",
                "current_period_end",
                "trial_ends_at",
                "cancel_at_period_end",
                "provider_event_cursor",
                "version",
                "updated_by",
            }
        ),
        "saas_pricing_snapshots": frozenset(
            {
                "id",
                "tenant_id",
                "plan_key",
                "currency",
                "rates",
                "version",
                "effective_from",
                "effective_until",
                "created_by",
            }
        ),
        "saas_billing_entitlements": frozenset(
            {
                "id",
                "tenant_id",
                "subscription_id",
                "scope_type",
                "scope_key",
                "space_id",
                "project_id",
                "user_id",
                "model_key",
                "meter",
                "unit",
                "limit_quantity",
                "reserved_quantity",
                "consumed_quantity",
                "concurrency_limit",
                "active_reservations",
                "hard_limit",
                "period",
                "period_start",
                "period_end",
                "status",
                "version",
                "updated_by",
            }
        ),
        "saas_billing_balances": frozenset(
            {
                "tenant_id",
                "currency",
                "available_minor",
                "reserved_minor",
                "consumed_minor",
                "version",
            }
        ),
        "saas_runtime_partitions": frozenset(
            {
                "id",
                "tenant_id",
                "space_id",
                "placement_id",
                "runtime_type",
                "runtime_version",
                "physical_partition_key",
                "placement_generation",
                "source_revision",
                "adapter_contract_version",
                "status",
            }
        ),
        "saas_runtime_identity_aliases": frozenset(
            {"runtime_partition_id", "user_id", "runtime_user_key", "status"}
        ),
        "saas_projects": frozenset(
            {
                "id",
                "tenant_id",
                "space_id",
                "name",
                "visibility",
                "created_by",
                "status",
                "authorization_version",
            }
        ),
        "saas_project_memberships": frozenset(
            {
                "tenant_id",
                "space_id",
                "project_id",
                "subject_type",
                "subject_id",
                "role",
                "status",
                "expires_at",
                "created_by",
                "version",
            }
        ),
        "saas_runtime_resource_bindings": frozenset(
            {
                "id",
                "runtime_partition_id",
                "tenant_id",
                "space_id",
                "project_id",
                "resource_type",
                "runtime_resource_id",
                "saas_resource_id",
                "partition_generation",
                "binding_generation",
                "status",
            }
        ),
        "saas_admission_quotas": frozenset(
            {
                "id",
                "tenant_id",
                "space_id",
                "project_id",
                "resource",
                "limit_units",
                "reserved_units",
                "consumed_units",
                "version",
            }
        ),
    }

    updates = _write_grants("saas_onboarding", "UPDATE")
    assert updates == {
        "saas_tenant_onboardings": frozenset(
            {
                "trial_started_at",
                "trial_ends_at",
                "status",
                "version",
                "attempt_count",
                "available_at",
                "claimed_at",
                "claim_token",
                "lease_expires_at",
                "last_error_code",
                "last_error_detail",
                "billing_ready_at",
                "runtime_ready_at",
                "project_ready_at",
                "activated_at",
                "first_run_id",
                "completed_at",
                "compensated_at",
                "failure_stage",
                "compensation_cursor",
                "runtime_placement_id",
                "runtime_target_snapshot",
                "runtime_request_hash",
                "last_transition_at",
                "updated_at",
            }
        ),
        "saas_tenants": frozenset({"status", "lifecycle_version", "updated_at"}),
        "saas_spaces": frozenset({"status", "updated_at"}),
        "saas_billing_subscriptions": frozenset(
            {
                "status",
                "current_period_start",
                "current_period_end",
                "trial_ends_at",
                "cancel_at_period_end",
                "provider_event_cursor",
                "version",
                "updated_by",
                "updated_at",
            }
        ),
        "saas_billing_entitlements": frozenset(
            {
                "status",
                "period_start",
                "period_end",
                "version",
                "updated_by",
                "updated_at",
            }
        ),
        "saas_runtime_partitions": frozenset({"status", "updated_at"}),
        "saas_runtime_identity_aliases": frozenset({"status"}),
        "saas_projects": frozenset({"status", "authorization_version", "updated_at"}),
        "saas_project_memberships": frozenset({"status", "version", "updated_at"}),
        "saas_runtime_resource_bindings": frozenset({"status"}),
    }
    for table in (
        "saas_tenant_memberships",
        "saas_space_memberships",
        "saas_pricing_snapshots",
        "saas_billing_balances",
        "saas_admission_quotas",
        "saas_runs",
    ):
        assert table not in updates
    assert "saas_runs" not in inserts


def test_onboarding_roles_revoke_historical_table_level_privileges_first() -> None:
    normalized = " ".join(re.sub(r"--[^\n]*", "", ROLE_SQL).split())
    assert re.search(
        r"REVOKE ALL PRIVILEGES ON .*saas_self_service_registrations.*"
        r"saas_control_plane_outbox FROM saas_registration, saas_onboarding;",
        normalized,
    )


def test_onboarding_outbox_policy_accepts_only_vertical_chain_requests() -> None:
    expected = {
        "onboarding.billing.requested",
        "onboarding.runtime.requested",
        "onboarding.project.requested",
        "onboarding.activation.requested",
        "onboarding.compensation.requested",
    }
    declared = set(re.findall(r'"(onboarding\.[a-z]+\.requested)"', VERTICAL_MIGRATION))
    assert declared == expected
    for forbidden in (
        "onboarding.billing.ready",
        "onboarding.runtime.ready",
        "onboarding.project.ready",
        "onboarding.activated",
        "onboarding.compensated",
    ):
        assert forbidden not in VERTICAL_MIGRATION
    assert "AS RESTRICTIVE FOR INSERT TO saas_onboarding" in VERTICAL_MIGRATION


def test_onboarding_vertical_reads_and_compensation_are_exactly_bounded() -> None:
    normalized_roles = " ".join(re.sub(r"--[^\n]*", "", ROLE_SQL).split())
    assert (
        "GRANT SELECT ( id, slug, name, status, plan, home_region, lifecycle_version, "
        "created_at, updated_at ), INSERT"
    ) in normalized_roles
    assert (
        "GRANT SELECT ( id, tenant_id, slug, name, status, created_at, updated_at ), INSERT"
    ) in normalized_roles
    assert (
        "id, runtime_type, data_region, failure_domain, official_schema_revision, "
        "capacity_class, status"
    ) in normalized_roles
    normalized_migration = " ".join(VERTICAL_MIGRATION.split())
    assert "runtime_placement_id IS NULL" in normalized_migration
    assert "saas_runtime_placements.status = 'active'" in normalized_migration
    assert (
        "onboarding_scope.runtime_placement_id = saas_runtime_placements.id"
        in normalized_migration
    )
    assert (
        "saas_runtime_partitions.placement_id = onboarding_scope.runtime_placement_id"
        in normalized_migration
    )
    assert "runtime_target_snapshot ->> 'placement_id'" in normalized_migration
    assert "saas_runtime_partitions.placement_id::text" in normalized_migration
    assert "runtime_target_snapshot ->> 'runtime_type'" in normalized_migration
    assert "saas_runtime_partitions.runtime_type" in normalized_migration
    assert "status = 'suspended' AND lifecycle_version = 2" in normalized_migration
    assert "onboarding_scope.status = 'compensating'" in normalized_migration
    for policy, roles in (
        ("rls_billing_subscriptions_metering_exact", "saas_metering"),
        ("rls_pricing_snapshots_metering_exact", "saas_metering"),
        ("rls_runtime_placements_scope", "saas_platform, saas_app"),
        ("rls_runtime_partitions_privacy_verifier_read", "saas_privacy_verifier"),
        (
            "rls_saas_project_memberships_privacy_target",
            "saas_platform, saas_platform_governance",
        ),
    ):
        assert policy in normalized_migration
        assert roles in normalized_migration
    assert 'op.execute(f"ALTER POLICY {policy} ON {table} TO {roles}")' in VERTICAL_MIGRATION


def test_platform_planning_columns_remain_force_rls_invisible() -> None:
    normalized = " ".join(re.sub(r"--[^\n]*", "", ROLE_SQL).split())
    assert (
        "GRANT SELECT (principal_id, role, status, expires_at) "
        "ON saas_platform_role_assignments "
        "TO saas_registration, saas_onboarding;"
    ) in normalized
    assert (
        "GRANT SELECT (principal_id, token_hash, revoked_at, expires_at) "
        "ON saas_platform_support_sessions "
        "TO saas_registration, saas_onboarding;"
    ) in normalized
    assert (
        "GRANT SELECT (principal_id, role, status, expires_at) "
        "ON saas_platform_role_assignments TO saas_onboarding_status;"
    ) in normalized
    assert (
        "GRANT SELECT (principal_id, token_hash, revoked_at, expires_at) "
        "ON saas_platform_support_sessions TO saas_onboarding_status;"
    ) in normalized
    assert (
        "GRANT SELECT (tenant_id, user_id, status) ON saas_tenant_memberships "
        "TO saas_registration;"
    ) in normalized
    assert (
        "GRANT SELECT (tenant_id, user_id, status) ON saas_tenant_memberships TO saas_onboarding;"
    ) in normalized
    assert (
        "GRANT SELECT (tenant_id, space_id, user_id, status) "
        "ON saas_space_memberships TO saas_onboarding;"
    ) in normalized

    platform_policy_sources = "\n".join(
        (ROOT / migration).read_text(encoding="utf-8")
        for migration in (
            "saas/control_plane/migrations/versions/pc1a00000001_platform_security_foundation.py",
            "saas/control_plane/migrations/versions/pc3a00000001_platform_governed_access.py",
        )
    )
    for role in ("saas_registration", "saas_onboarding"):
        assert role not in platform_policy_sources
        assert not re.search(rf"GRANT\s+saas_platform(?:_[a-z_]+)?\s+TO\s+{role}", normalized)


def test_status_acl_replay_revokes_every_current_select_column_before_regrant() -> None:
    start = ROLE_SQL.index("-- Customer onboarding status has a dedicated")
    end = ROLE_SQL.index("GRANT SELECT, INSERT, UPDATE ON", start)
    status_sql = ROLE_SQL[start:end]
    targets = set(re.findall(r"\('([^']+)', '([^']+)'\)", status_sql))

    assert targets == {
        ("saas_onboarding_status", "saas_tenant_onboardings"),
        ("saas_onboarding_status", "saas_tenant_memberships"),
        ("saas_onboarding_status", "saas_platform_role_assignments"),
        ("saas_onboarding_status", "saas_platform_support_sessions"),
        ("saas_app", "saas_tenant_onboardings"),
    }
    assert "FROM pg_attribute AS attribute" in status_sql
    assert "attribute.attnum > 0" in status_sql
    assert "NOT attribute.attisdropped" in status_sql
    assert "ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']" in status_sql
    assert "string_agg(quote_ident(attribute.attname)" in status_sql
    assert "'REVOKE ' || target_privilege" in status_sql
    assert "quote_ident(target_table)" in status_sql
    assert "quote_ident(target_role)" in status_sql
    assert "%" not in status_sql

    dynamic_revoke_end = status_sql.index("$$;")
    for exact_grant in (
        "ON saas_platform_role_assignments TO saas_onboarding_status;",
        "ON saas_platform_support_sessions TO saas_onboarding_status;",
        ") ON saas_tenant_onboardings TO saas_onboarding_status;",
        "ON saas_tenant_memberships TO saas_onboarding_status;",
    ):
        assert status_sql.index(exact_grant) > dynamic_revoke_end
    assert "ON saas_tenant_onboardings TO saas_app" not in status_sql
