from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import DBAPIError

from saas.control_plane.db_models import (
    ControlPlaneOutboxEvent,
    IdentityConnection,
    Tenant,
    TenantMembership,
)
from saas.control_plane.identity import IdentityManagementService, VerifiedIdentityAssertion
from saas.control_plane.identity_event_models import IdentityProviderStateRecord
from saas.control_plane.onboarding import TenantCreationIntentService, TenantOnboardingCoordinator
from saas.control_plane.onboarding_models import TenantCreationIntentRecord, TenantOnboardingRecord
from saas.control_plane.onboarding_status import OnboardingStatusError
from saas.control_plane.rls import RlsContext, apply_rls_context
from tests.saas.test_onboarding_postgresql import (
    _policy,
    _production_status_service,
    _role_sessions,
)
from tests.saas.test_onboarding_postgresql import (
    isolated_onboarding_engine as isolated_onboarding_engine,
)


def _actor(sessions):
    subject = uuid4().hex
    user_id = (
        IdentityManagementService(sessions)
        .resolve_verified_login(
            VerifiedIdentityAssertion(
                provider="casdoor",
                issuer="https://auth.example.test",
                subject=subject,
                email=f"workspace-{subject}@example.test",
                email_verified=True,
            )
        )
        .user_id
    )
    assert user_id is not None
    return user_id


def test_real_postgresql_verified_phone_workspace_authority_and_policy_rollback(
    isolated_onboarding_engine,
):
    from alembic import command

    from tests.saas.test_casdoor_migration import _config

    engine = isolated_onboarding_engine
    auth = _role_sessions(engine, "saas_authenticator")
    creation = TenantCreationIntentService(auth, policy=_policy())

    def phone_actor(*, provider="casdoor", verified=True, state="active", checked=True):
        user = (
            IdentityManagementService(auth)
            .resolve_verified_login(
                VerifiedIdentityAssertion(
                    provider,
                    "https://auth.example.test",
                    uuid4().hex,
                    None,
                    False,
                    phone_number="+12025550100" if verified else None,
                    phone_number_verified=verified,
                )
            )
            .user_id
        )
        assert user is not None
        if state is not None:
            with auth.begin() as db:
                connection_id = db.scalar(
                    sa.select(IdentityConnection.id).where(IdentityConnection.user_id == user)
                )
                db.add(
                    IdentityProviderStateRecord(
                        connection_id=connection_id,
                        subject_locator_sha256=uuid4().hex * 2,
                        status=state,
                        snapshot_sha256="a" * 64 if checked else None,
                        checked_at=datetime.now(timezone.utc) if checked else None,
                    )
                )
        return user

    actor = phone_actor()
    accepted = creation.create(actor_id=actor, tenant_name="Verified phone", idempotency_key="one")
    assert (
        creation.create(
            actor_id=actor, tenant_name="Verified phone", idempotency_key="one"
        ).intent_id
        == accepted.intent_id
    )
    email = _actor(auth)
    creation.create(actor_id=email, tenant_name="Legacy verified email", idempotency_key="email")
    with engine.connect() as connection:
        template = dict(
            connection.execute(
                sa.select(TenantCreationIntentRecord.__table__).where(
                    TenantCreationIntentRecord.id == accepted.intent_id
                )
            )
            .mappings()
            .one()
        )
        assert connection.scalar(sa.select(sa.func.count()).select_from(Tenant)) == 0

    def raw_values(user):
        values = dict(template)
        for field in (
            "id",
            "tenant_id",
            "space_id",
            "subscription_id",
            "pricing_snapshot_id",
            "entitlement_id",
            "runtime_partition_id",
            "default_project_id",
            "runtime_binding_id",
            "onboarding_id",
        ):
            values[field] = uuid4()
        values.update(
            user_id=user, tenant_slug="workspace-" + uuid4().hex, idempotency_key=uuid4().hex * 2
        )
        return values

    def denied_insert(actor_id, values):
        with pytest.raises(DBAPIError) as denied:
            with auth.begin() as db:
                apply_rls_context(db, RlsContext(actor_id=actor_id))
                db.execute(sa.insert(TenantCreationIntentRecord).values(**values))
        assert getattr(denied.value.orig, "sqlstate", None) == "42501"

    for options in (
        {"state": None},
        {"checked": False},
        {"state": "disabled"},
        {"state": "deleted"},
        {"verified": False},
        {"provider": "enterprise_oidc"},
    ):
        user = phone_actor(**options)
        denied_insert(user, raw_values(user))
    other = phone_actor()
    denied_insert(other, raw_values(actor))
    with engine.begin() as connection:
        email_connection = connection.scalar(
            sa.select(IdentityConnection.id).where(IdentityConnection.user_id == email)
        )
        connection.execute(
            sa.insert(IdentityProviderStateRecord).values(
                connection_id=email_connection,
                subject_locator_sha256="e" * 64,
                status="disabled",
                snapshot_sha256="b" * 64,
                checked_at=datetime.now(timezone.utc),
            )
        )
    denied_insert(email, raw_values(email))
    with engine.begin() as connection:
        command.downgrade(_config(connection), "cd4b00000001")
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(TenantCreationIntentRecord))
            == 2
        )
    denied_insert(actor, raw_values(actor))
    with engine.begin() as connection:
        command.upgrade(_config(connection), "head")
    assert (
        creation.create(
            actor_id=actor, tenant_name="After policy reapply", idempotency_key="reapply"
        ).intent_id
        != accepted.intent_id
    )


def test_real_postgresql_workspace_intent_role_scope_and_worker_handoff(
    isolated_onboarding_engine,
):
    engine = isolated_onboarding_engine
    auth = _role_sessions(engine, "saas_authenticator")
    actor, other = _actor(auth), _actor(auth)
    creation = TenantCreationIntentService(auth, policy=_policy())
    accepted = creation.create(
        actor_id=actor, tenant_name="First workspace", idempotency_key="one"
    )
    assert creation.list_for_actor(other) == []
    with _production_status_service(engine) as status:
        assert status.for_workspace(actor, accepted.intent_id).state == "pending"
        with pytest.raises(OnboardingStatusError):
            status.for_workspace(other, accepted.intent_id)
        worker = TenantOnboardingCoordinator(
            _role_sessions(engine, "saas_onboarding"), policy=_policy()
        )
        started = worker.start_intent(
            creation_intent_id=accepted.intent_id, idempotency_key="worker"
        )
        assert started.registration_id is None and started.creation_intent_id == accepted.intent_id
        assert status.for_workspace(actor, accepted.intent_id).state == "provisioning"
        with engine.begin() as connection:
            connection.execute(
                sa.insert(TenantMembership).values(
                    tenant_id=started.tenant_id,
                    user_id=other,
                    role="member",
                    status="active",
                    version=1,
                )
            )
        assert status.for_workspace(other, accepted.intent_id).state == "provisioning"
    with auth() as db:
        apply_rls_context(db, RlsContext(actor_id=other))
        assert db.get(TenantCreationIntentRecord, accepted.intent_id) is not None
        apply_rls_context(db, RlsContext(actor_id=uuid4()))
        assert db.scalar(sa.select(TenantCreationIntentRecord.id)) is None
    with pytest.raises(DBAPIError) as denied:
        with auth.begin() as db:
            apply_rls_context(db, RlsContext(actor_id=other))
            db.execute(
                sa.text(
                    "INSERT INTO saas_tenants (id, slug, name, status, plan, home_region, "
                    "lifecycle_version) "
                    "VALUES (:id, :slug, 'forged', 'provisioning', 'starter', 'cn-east-1', 1)"
                ),
                {"id": uuid4(), "slug": f"forged-{uuid4().hex}"},
            )
    assert getattr(denied.value.orig, "sqlstate", None) == "42501"
    with auth() as db:
        apply_rls_context(db, RlsContext(actor_id=actor))
        original = db.get(TenantCreationIntentRecord, accepted.intent_id)
        assert original is not None
        values = {
            column.name: getattr(original, column.name) for column in original.__table__.columns
        }
    values.update(id=uuid4(), tenant_slug=f"forged-{uuid4().hex}", idempotency_key=uuid4().hex * 2)
    with pytest.raises(DBAPIError) as forged_actor:
        with auth.begin() as db:
            apply_rls_context(db, RlsContext(actor_id=other))
            db.execute(sa.insert(TenantCreationIntentRecord).values(**values))
    assert getattr(forged_actor.value.orig, "sqlstate", None) == "42501"


def test_real_postgresql_concurrent_workspace_replay_is_atomic(isolated_onboarding_engine):
    engine = isolated_onboarding_engine
    auth = _role_sessions(engine, "saas_authenticator")
    actor = _actor(auth)
    creation = TenantCreationIntentService(auth, policy=_policy())

    def request():
        return creation.create(actor_id=actor, tenant_name="Concurrent", idempotency_key="same")

    with ThreadPoolExecutor(2) as pool:
        first, second = list(pool.map(lambda _: request(), range(2)))
    assert first.intent_id == second.intent_id
    assert sorted([first.replayed, second.replayed]) == [False, True]
    with engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(TenantCreationIntentRecord))
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(ControlPlaneOutboxEvent)
                .where(ControlPlaneOutboxEvent.event_type == "onboarding.tenant.requested")
            )
            == 1
        )
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(TenantOnboardingRecord)) == 0
        )


def test_workspace_acl_replay_removes_stale_relation_and_column_authorities(
    isolated_onboarding_engine,
):
    from pathlib import Path

    engine = isolated_onboarding_engine
    with engine.begin() as connection:
        connection.exec_driver_sql("GRANT SELECT ON saas_tenant_creation_intents TO saas_app")
        connection.exec_driver_sql(
            "GRANT UPDATE (user_id) ON saas_tenant_creation_intents TO saas_onboarding"
        )
        connection.exec_driver_sql(
            "GRANT SELECT (plan_snapshot) ON saas_tenant_creation_intents "
            "TO saas_onboarding_status"
        )
        connection.exec_driver_sql(
            (Path(__file__).parents[2] / "saas/control_plane/postgresql_roles.sql").read_text()
        )
        assert (
            connection.scalar(
                sa.text(
                    "SELECT has_table_privilege('saas_app', "
                    "'saas_tenant_creation_intents', 'SELECT')"
                )
            )
            is False
        )
        assert (
            connection.scalar(
                sa.text(
                    "SELECT has_column_privilege('saas_onboarding', "
                    "'saas_tenant_creation_intents', "
                    "'user_id', 'UPDATE')"
                )
            )
            is False
        )
        assert (
            connection.scalar(
                sa.text(
                    "SELECT has_column_privilege('saas_onboarding_status', "
                    "'saas_tenant_creation_intents', "
                    "'plan_snapshot', 'SELECT')"
                )
            )
            is False
        )
    with _production_status_service(engine):
        pass
