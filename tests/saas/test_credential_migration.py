from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import UUID

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane import (
    CredentialMigrationRecord,
    GlobalUser,
    IdentityManagementService,
    LifecycleError,
    MembershipLifecycleService,
    PasswordCredentialService,
    SaasBase,
    VerifiedIdentityAssertion,
)
from saas.control_plane.credential_migration import (
    CredentialImportClaim,
    CredentialMigrationError,
    CredentialMigrationPolicy,
    CredentialMigrationService,
    VerifiedMigrationIdentity,
)
from saas.control_plane.db_models import (
    ControlPlaneOutboxEvent,
    IdentityConnection,
    PasswordCredential,
)

NOW = datetime(2026, 11, 1, 1, tzinfo=timezone.utc)
OLD_PASSWORD = "initial-migration-password"
NEW_PASSWORD = "replacement-migration-password"


class Provider:
    def __init__(self) -> None:
        self.calls: list[CredentialImportClaim] = []
        self.mutations: dict[str, object] = {}
        self.failure: CredentialMigrationError | None = None

    def ensure_import(self, claim: CredentialImportClaim) -> VerifiedMigrationIdentity:
        self.calls.append(claim)
        if self.failure is not None:
            raise self.failure
        return replace(
            VerifiedMigrationIdentity(
                issuer=claim.issuer,
                organization=claim.organization,
                subject=claim.subject,
                username=claim.username,
                email=claim.email,
                email_verified=True,
                active=True,
                marker_verified=True,
            ),
            **self.mutations,
        )


@dataclass
class Source:
    sessions: sessionmaker[Session]
    user_id: UUID
    passwords: PasswordCredentialService
    lifecycle: MembershipLifecycleService
    identities: IdentityManagementService
    provider: Provider
    service: CredentialMigrationService

    def prepare(self, *, key: str = "migration", batch: str = "batch-v1"):
        return self.service.prepare(
            user_id=self.user_id,
            batch_id=batch,
            expected_password_version=1,
            idempotency_key=key,
            now=NOW,
        )


@pytest.fixture
def source():
    engine = sa.create_engine(
        "sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False}
    )

    @sa.event.listens_for(engine, "connect")
    def foreign_keys(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")

    SaasBase.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    identities = IdentityManagementService(sessions)
    user = identities.provision_identity(
        VerifiedIdentityAssertion(
            provider="legacy",
            issuer="urn:legacy-migration",
            subject="source-user",
            email="migrate@example.test",
            email_verified=True,
        )
    )
    passwords = PasswordCredentialService(sessions)
    passwords.set_password(
        user_id=user,
        new_password=OLD_PASSWORD,
        expected_version=None,
        idempotency_key="initial-password",
        now=NOW,
    )
    provider = Provider()
    service = CredentialMigrationService(
        sessions,
        provider=provider,
        policy=CredentialMigrationPolicy(
            issuer="https://auth.example.test",
            organization="customers",
            policy_sha256="a" * 64,
        ),
    )
    yield Source(
        sessions,
        user,
        passwords,
        MembershipLifecycleService(sessions),
        identities,
        provider,
        service,
    )
    engine.dispose()


def test_prepare_is_hash_only_and_does_not_cut_over_legacy_login(source: Source):
    receipt = source.prepare()
    assert receipt.status == "pending"
    assert source.prepare() == receipt
    assert (
        source.passwords.authenticate("migrate@example.test", OLD_PASSWORD, now=NOW)
        == source.user_id
    )
    with source.sessions() as db:
        record = db.get(CredentialMigrationRecord, receipt.id)
        credential = db.get(PasswordCredential, source.user_id)
        user = db.get(GlobalUser, source.user_id)
        assert (
            record.source_password_sha256 == sha256(credential.password_hash.encode()).hexdigest()
        )
        assert (user.credential_owner, user.migration_state) == ("legacy", "pending")
        assert user.security_version == record.source_security_version
        events = list(db.scalars(sa.select(ControlPlaneOutboxEvent)))
        assert OLD_PASSWORD not in repr([e.payload for e in events])
        assert credential.password_hash not in repr([e.payload for e in events])
    assert not source.provider.calls
    with pytest.raises(CredentialMigrationError) as busy:
        source.prepare(key="another-key", batch="another-batch")
    assert busy.value.code == "migration_already_pending"
    with pytest.raises(CredentialMigrationError) as changed:
        source.prepare(key="another-key")
    assert changed.value.code == "idempotency_conflict"


def test_pending_identity_review_cannot_be_auto_approved_by_migration(source: Source):
    conflict = source.identities.resolve_verified_login(
        VerifiedIdentityAssertion(
            provider="casdoor",
            issuer="https://auth.example.test",
            subject=str(source.user_id),
            email="migrate@example.test",
            email_verified=True,
        )
    )
    assert conflict.user_id is None and conflict.conflict_id is not None
    receipt = source.prepare()
    result = source.service.run_once(receipt.id, cutover=True, now=NOW)
    assert result.status == "conflict" and result.last_error_code == "identity_review_required"
    from saas.control_plane.db_models import IdentityConflict

    with source.sessions() as db:
        review = db.get(IdentityConflict, conflict.conflict_id)
        assert review.status == "pending" and review.resolved_by is None
        assert db.get(GlobalUser, source.user_id).credential_owner == "legacy"
    assert (
        source.passwords.authenticate("migrate@example.test", OLD_PASSWORD, now=NOW)
        == source.user_id
    )


@pytest.mark.parametrize("entry", ["resolve_verified_login", "provision_identity"])
def test_unfinished_import_cannot_create_a_second_account_after_source_email_change(source, entry):
    receipt = source.prepare()
    assert source.service.run_once(receipt.id, now=NOW).status == "imported"
    with source.sessions.begin() as db:
        db.get(PasswordCredential, source.user_id).login_email_normalized = "changed@example.test"
        db.get(GlobalUser, source.user_id).primary_email_normalized = "changed@example.test"
        for connection in db.scalars(sa.select(IdentityConnection)):
            connection.email_normalized = "changed@example.test"
    assertion = VerifiedIdentityAssertion(
        provider="casdoor",
        issuer=receipt.issuer,
        subject=receipt.provider_subject,
        email="migrate@example.test",
        email_verified=True,
    )
    with pytest.raises(LifecycleError) as denied:
        getattr(source.identities, entry)(assertion)
    assert denied.value.code == "identity_migration_pending"
    with source.sessions() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(GlobalUser)) == 1


def test_staged_import_then_cutover_preserves_user_and_rejects_retained_password(source: Source):
    receipt = source.prepare()
    old = source.lifecycle.issue_auth_session(
        user_id=source.user_id,
        authn_method="password",
        expires_at=NOW + timedelta(hours=1),
        now=NOW,
    )
    with source.sessions() as db:
        old_hash = db.get(PasswordCredential, source.user_id).password_hash
    staged = source.service.run_once(receipt.id, now=NOW)
    assert staged.status == "imported"
    assert (
        source.passwords.authenticate("migrate@example.test", OLD_PASSWORD, now=NOW)
        == source.user_id
    )
    completed = source.service.run_once(receipt.id, cutover=True, now=NOW + timedelta(seconds=1))
    assert completed.status == "completed"
    assert completed.user_id == source.user_id
    assert source.service.run_once(receipt.id, cutover=True) == completed
    assert source.prepare() == completed
    assert len(source.provider.calls) == 2
    assert OLD_PASSWORD not in repr(source.provider.calls[0])
    assert old_hash not in repr(source.provider.calls[0])
    with source.sessions() as db:
        user = db.get(GlobalUser, source.user_id)
        assert (user.credential_owner, user.migration_state) == ("casdoor", "cutover")
        assert user.security_version == old.security_version + 1
        assert db.get(PasswordCredential, source.user_id).password_hash == old_hash
        record = db.get(CredentialMigrationRecord, receipt.id)
        connection = db.get(IdentityConnection, record.identity_connection_id)
        assert (connection.user_id, connection.issuer, connection.subject) == (
            source.user_id,
            completed.issuer,
            str(source.user_id),
        )
        assert connection.email_verified is True
        assert db.scalar(sa.select(sa.func.count()).select_from(GlobalUser)) == 1
    with pytest.raises(LifecycleError) as denied:
        source.passwords.authenticate("migrate@example.test", OLD_PASSWORD, now=NOW)
    assert denied.value.code == "invalid_credentials"
    with pytest.raises(LifecycleError):
        source.lifecycle.validate_auth_session(old.token, now=NOW + timedelta(seconds=2))
    with pytest.raises(LifecycleError) as replay:
        source.passwords.set_password(
            user_id=source.user_id,
            new_password=OLD_PASSWORD,
            expected_version=None,
            idempotency_key="initial-password",
            now=NOW,
        )
    assert replay.value.code == "identity_provider_required"
    resolved = source.identities.resolve_verified_login(
        VerifiedIdentityAssertion(
            provider="casdoor",
            issuer=completed.issuer,
            subject=str(source.user_id),
            email="migrate@example.test",
            email_verified=True,
        )
    )
    assert resolved.user_id == source.user_id and resolved.conflict_id is None


@pytest.mark.parametrize(
    "mutation",
    [
        {"issuer": "https://other.example.test"},
        {"organization": "other"},
        {"subject": "another-subject"},
        {"username": "another-name"},
        {"marker_verified": False},
        {"active": False},
        {"is_admin": True},
        {"is_global_admin": True},
        {"email_verified": False},
        {"email": "other@example.test"},
        {"email": "malformed"},
    ],
)
def test_import_does_not_trust_provider_profile_mismatches(source: Source, mutation):
    source.provider.mutations = mutation
    receipt = source.prepare()
    result = source.service.run_once(receipt.id, cutover=True, now=NOW)
    assert result.status == "conflict"
    with source.sessions() as db:
        user = db.get(GlobalUser, source.user_id)
        assert (user.credential_owner, user.migration_state) == ("legacy", "legacy")
        assert db.scalar(sa.select(sa.func.count()).select_from(IdentityConnection)) == 1
    assert (
        source.passwords.authenticate("migrate@example.test", OLD_PASSWORD, now=NOW)
        == source.user_id
    )


def test_expired_worker_cannot_commit_after_lease_takeover(source: Source):
    receipt = source.prepare()
    old = source.service.claim(receipt.id, now=NOW)
    assert isinstance(old, CredentialImportClaim)
    with pytest.raises(CredentialMigrationError) as busy:
        source.service.claim(receipt.id, now=NOW + timedelta(seconds=1))
    assert busy.value.code == "migration_claim_busy"
    later = NOW + timedelta(minutes=3)
    current = source.service.claim(receipt.id, now=later)
    assert isinstance(current, CredentialImportClaim)
    identity = source.provider.ensure_import(old)
    with pytest.raises(CredentialMigrationError) as stale:
        source.service.finish(old, identity, cutover=True, now=later)
    assert stale.value.code == "migration_claim_stale"
    assert source.service.finish(current, identity, cutover=True, now=later).status == "completed"


def test_password_changed_during_import_keeps_local_authority(source: Source):
    receipt = source.prepare()
    claim = source.service.claim(receipt.id, now=NOW)
    source.passwords.set_password(
        user_id=source.user_id,
        new_password=NEW_PASSWORD,
        current_password=OLD_PASSWORD,
        expected_version=1,
        idempotency_key="changed-during-import",
        now=NOW + timedelta(seconds=1),
    )
    result = source.service.finish(
        claim, source.provider.ensure_import(claim), cutover=True, now=NOW + timedelta(seconds=2)
    )
    assert result.status == "conflict" and result.last_error_code == "source_credential_changed"
    assert (
        source.passwords.authenticate("migrate@example.test", NEW_PASSWORD, now=NOW)
        == source.user_id
    )
    with source.sessions() as db:
        assert db.get(GlobalUser, source.user_id).credential_owner == "legacy"


def test_provider_timeout_is_durable_and_resumable(source: Source):
    receipt = source.prepare()
    source.provider.failure = CredentialMigrationError("provider_unavailable", retryable=True)
    waiting = source.service.run_once(receipt.id, cutover=True, now=NOW)
    assert waiting.status == "pending" and waiting.last_error_code == "provider_unavailable"
    source.provider.failure = None
    assert source.service.run_once(receipt.id, cutover=True, now=NOW).status == "completed"


def test_cutover_transaction_failure_does_not_leave_a_mapping_or_owner_change(
    source: Source,
    monkeypatch: pytest.MonkeyPatch,
):
    import saas.control_plane.credential_migration as module

    receipt = source.prepare()
    claim = source.service.claim(receipt.id, now=NOW)
    identity = source.provider.ensure_import(claim)
    invalidate = module._invalidate_sessions

    def unavailable(*_args):
        raise RuntimeError("injected local commit failure")

    monkeypatch.setattr(module, "_invalidate_sessions", unavailable)
    with pytest.raises(RuntimeError, match="injected local commit"):
        source.service.finish(claim, identity, cutover=True, now=NOW)
    with source.sessions() as db:
        user = db.get(GlobalUser, source.user_id)
        assert (user.credential_owner, user.migration_state) == ("legacy", "pending")
        assert db.scalar(sa.select(sa.func.count()).select_from(IdentityConnection)) == 1
        assert db.get(CredentialMigrationRecord, receipt.id).status == "pending"
    monkeypatch.setattr(module, "_invalidate_sessions", invalidate)
    assert source.service.finish(claim, identity, cutover=True, now=NOW).status == "completed"


def test_native_casdoor_account_cannot_silently_add_a_local_password(source: Source):
    user = source.identities.provision_identity(
        VerifiedIdentityAssertion(
            provider="casdoor",
            issuer="https://auth.example.test",
            subject="native-user",
            email="native@example.test",
            email_verified=True,
        )
    )
    with source.sessions() as db:
        account = db.get(GlobalUser, user)
        assert (account.credential_owner, account.migration_state) == ("casdoor", "native")
    with pytest.raises(LifecycleError) as denied:
        source.passwords.set_password(
            user_id=user,
            new_password=NEW_PASSWORD,
            expected_version=None,
            idempotency_key="forbidden-local",
        )
    assert denied.value.code == "identity_provider_required"
