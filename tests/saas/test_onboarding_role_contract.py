from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROLE_SQL = (ROOT / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")


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
                "onboarding_id",
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
                "last_error",
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
        "onboarding_id",
    }
    assert immutable_registration_columns.isdisjoint(updates["saas_self_service_registrations"])


def test_onboarding_can_insert_initial_owner_but_cannot_update_identity_or_role() -> None:
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
                "plan_key",
                "plan_policy_revision",
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
                "activated_at",
                "compensated_at",
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
                "last_error",
                "published_at",
            }
        ),
    }

    updates = _write_grants("saas_onboarding", "UPDATE")
    assert updates == {}
    for table in ("saas_tenant_memberships", "saas_space_memberships"):
        assert table not in updates


def test_onboarding_roles_revoke_historical_table_level_privileges_first() -> None:
    normalized = " ".join(re.sub(r"--[^\n]*", "", ROLE_SQL).split())
    assert re.search(
        r"REVOKE ALL PRIVILEGES ON .*saas_self_service_registrations.*"
        r"saas_control_plane_outbox FROM saas_registration, saas_onboarding;",
        normalized,
    )


def test_platform_planning_columns_remain_force_rls_invisible() -> None:
    normalized = " ".join(re.sub(r"--[^\n]*", "", ROLE_SQL).split())
    assert (
        "GRANT SELECT (principal_id, role, status, expires_at) "
        "ON saas_platform_role_assignments TO saas_registration, saas_onboarding;"
    ) in normalized
    assert (
        "GRANT SELECT (principal_id, token_hash, revoked_at, expires_at) "
        "ON saas_platform_support_sessions TO saas_registration, saas_onboarding;"
    ) in normalized
    assert (
        "GRANT SELECT (tenant_id, user_id) ON saas_tenant_memberships TO saas_registration;"
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
