from __future__ import annotations

from dataclasses import replace
from uuid import uuid4

import pytest
import sqlalchemy as sa
from argon2 import PasswordHasher, Type

from saas.control_plane import (
    CredentialMigrationRecord,
    GlobalUser,
    LifecycleError,
    VerifiedIdentityAssertion,
)
from saas.control_plane.credential_migration import (
    CredentialMigrationError,
    CredentialMigrationService,
    VerifiedLinkedCredentialIdentity,
    VerifiedMigrationIdentity,
)
from saas.control_plane.db_models import (
    ControlPlaneOutboxEvent,
    IdentityConnection,
    PasswordCredential,
)
from tests.saas.test_credential_migration import NOW, OLD_PASSWORD
from tests.saas.test_credential_migration import source as source


class LinkedProvider:
    def __init__(self):
        self.identity = VerifiedMigrationIdentity(
            issuer="https://auth.example.test",
            organization="customers",
            subject=str(uuid4()),
            username="already-existing-customer",
            email="central@example.test",
            email_verified=True,
            active=True,
        )
        self.password_configured = True
        self.reads = []
        self.hook = None

    def ensure_import(self, _claim):
        raise AssertionError("an existing identity must not import or overwrite any credential")

    def read_linked_identity(self, subject):
        self.reads.append(subject)
        if self.hook is not None:
            self.hook()
        return VerifiedLinkedCredentialIdentity(self.identity, self.password_configured)


def linked(source):
    provider = LinkedProvider()
    connection = source.identities.link_identity(
        user_id=source.user_id,
        assertion=VerifiedIdentityAssertion(
            "casdoor",
            provider.identity.issuer,
            provider.identity.subject,
            provider.identity.email,
            True,
        ),
        idempotency_key="user-explicitly-connected-existing-account",
    )
    service = CredentialMigrationService(
        source.sessions, policy=source.service._policy, provider=provider
    )
    return service, provider, connection


def prepare(service, source, connection):
    return service.prepare_existing_link(
        user_id=source.user_id,
        connection_id=connection,
        batch_id="existing-link-v1",
        expected_password_version=1,
        idempotency_key="existing-link-v1",
        now=NOW,
    )


def test_unsupported_hash_switches_through_existing_verified_identity_without_export(source):
    with source.sessions.begin() as db:
        db.get(PasswordCredential, source.user_id).password_hash = PasswordHasher(
            type=Type.I
        ).hash(OLD_PASSWORD)
    with pytest.raises(CredentialMigrationError, match="credential_import_unsupported"):
        source.prepare()
    # The fallback starts with legacy reauthentication; its transparent KDF
    # upgrade must finish before the migration captures the source hash.
    assert (
        source.passwords.authenticate("migrate@example.test", OLD_PASSWORD, now=NOW)
        == source.user_id
    )
    service, provider, connection = linked(source)
    receipt = prepare(service, source, connection)
    assert receipt.mode == "existing_link" and receipt.status == "pending"
    assert receipt.provider_subject != str(source.user_id)
    assert (
        source.passwords.authenticate("migrate@example.test", OLD_PASSWORD, now=NOW)
        == source.user_id
    )
    claim = service.claim(receipt.id, now=NOW)
    assert claim.mode == "existing_link" and claim.password_hash == claim.email == ""
    with pytest.raises(CredentialMigrationError, match="provider_import_claim_invalid"):
        claim.marker_document()
    verified = provider.read_linked_identity(claim.subject)
    assert service.finish(claim, verified, cutover=False, now=NOW).status == "imported"
    assert service.run_once(receipt.id, cutover=True, now=NOW).status == "completed"
    assert prepare(service, source, connection).status == "completed"
    assert provider.reads == [provider.identity.subject] * 3
    with pytest.raises(LifecycleError) as refused:
        source.passwords.authenticate("migrate@example.test", OLD_PASSWORD, now=NOW)
    assert refused.value.code == "invalid_credentials"
    resolved = source.identities.resolve_verified_login(
        VerifiedIdentityAssertion(
            "casdoor",
            provider.identity.issuer,
            provider.identity.subject,
            provider.identity.email,
            True,
        )
    )
    assert resolved.user_id == source.user_id
    with source.sessions() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(GlobalUser)) == 1
        record = db.get(CredentialMigrationRecord, receipt.id)
        assert record.identity_connection_id == connection and record.mode == "existing_link"
        events = list(db.scalars(sa.select(ControlPlaneOutboxEvent)))
        assert any(
            event.event_type == "identity.credential_migration.link_verified" for event in events
        )
        assert not any(
            event.event_type == "identity.credential_migration.imported" for event in events
        )


@pytest.mark.parametrize("kind", ["missing", "foreign", "revoked", "unverified"])
def test_explicit_connection_cannot_be_inferred_or_borrowed_from_another_user(source, kind):
    service, provider, connection = linked(source)
    if kind == "missing":
        connection = uuid4()
    else:
        with source.sessions.begin() as db:
            row = db.get(IdentityConnection, connection)
            if kind == "foreign":
                other = GlobalUser(id=uuid4(), status="active", security_version=1)
                db.add(other)
                db.flush()
                row.user_id = other.id
            elif kind == "revoked":
                row.status = "revoked"
            else:
                row.email_verified = False
    with pytest.raises(CredentialMigrationError, match="migration_existing_link_required"):
        prepare(service, source, connection)
    assert not provider.reads
    with source.sessions() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(CredentialMigrationRecord)) == 0


def test_password_setup_is_required_and_source_version_is_rechecked_after_provider_read(source):
    service, provider, connection = linked(source)
    provider.password_configured = False
    with pytest.raises(CredentialMigrationError, match="provider_password_setup_required"):
        prepare(service, source, connection)
    provider.password_configured = True

    def changed():
        with source.sessions.begin() as db:
            db.get(GlobalUser, source.user_id).security_version += 1

    provider.hook = changed
    with pytest.raises(CredentialMigrationError, match="source_credential_changed"):
        prepare(service, source, connection)
    with source.sessions() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(CredentialMigrationRecord)) == 0
        assert db.get(GlobalUser, source.user_id).credential_owner == "legacy"


def test_provider_contact_drift_prevents_cutover(source):
    service, provider, connection = linked(source)
    receipt = prepare(service, source, connection)
    provider.identity = replace(provider.identity, email="changed@example.test")
    failed = service.run_once(receipt.id, cutover=True, now=NOW)
    assert (
        failed.status == "conflict" and failed.last_error_code == "provider_link_snapshot_changed"
    )
    assert (
        source.passwords.authenticate("migrate@example.test", OLD_PASSWORD, now=NOW)
        == source.user_id
    )


def test_local_revocation_prevents_cutover_before_another_provider_read(source):
    service, provider, connection = linked(source)
    receipt = prepare(service, source, connection)
    source.identities.revoke_identity(
        user_id=source.user_id,
        connection_id=connection,
        idempotency_key="revoke-before-linked-cutover",
        now=NOW,
    )
    failed = service.run_once(receipt.id, cutover=True, now=NOW)
    assert failed.status == "conflict" and provider.reads == [provider.identity.subject]


def test_claim_cannot_retarget_the_persisted_migration_receipt(source):
    receipt = source.prepare()
    claim = source.service.claim(receipt.id, now=NOW)
    forged = replace(claim, subject="other-identity")
    with pytest.raises(CredentialMigrationError, match="migration_claim_stale"):
        source.service.finish(forged, source.provider.ensure_import(forged), cutover=True, now=NOW)
    with source.sessions() as db:
        assert db.get(GlobalUser, source.user_id).credential_owner == "legacy"
