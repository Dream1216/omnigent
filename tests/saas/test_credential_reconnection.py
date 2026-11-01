from __future__ import annotations

import base64
from dataclasses import replace
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa

from saas.control_plane import GlobalUser, LifecycleError
from saas.control_plane.credential_migration import (
    CredentialMigrationError,
    CredentialMigrationService,
    VerifiedLinkedCredentialIdentity,
    VerifiedMigrationIdentity,
)
from saas.control_plane.credential_reconnection import (
    RECONNECTION_SIGNATURE_DOMAIN,
    CredentialReconnectionKeyring,
    CredentialReconnectionService,
)
from saas.control_plane.credential_recovery import recovery_grant_payload
from saas.control_plane.db_models import (
    AuthSessionRecord,
    ControlPlaneOutboxEvent,
    IdentityConnection,
    PasswordCredential,
)
from tests.saas.test_credential_migration import NOW, OLD_PASSWORD
from tests.saas.test_credential_migration import source as source
from tests.saas.test_credential_recovery import RECOVERY_PASSWORD, grant_fixture, signed_grant


def sign(key, request, *, domain=RECONNECTION_SIGNATURE_DOMAIN):
    document = {
        "schema_version": 1,
        "grant_id": str(uuid4()),
        "issued_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
        **request,
    }

    def encode(value):
        return base64.urlsafe_b64encode(value).decode().rstrip("=")

    payload = recovery_grant_payload(document)
    return ".".join(["v1", "offline-return", encode(payload), encode(key.sign(domain + payload))])


class Provider:
    def __init__(self, source, document):
        with source.sessions() as db:
            connection = db.scalar(
                sa.select(IdentityConnection).where(IdentityConnection.provider == "casdoor")
            )
            self.identity = VerifiedMigrationIdentity(
                connection.issuer,
                "customers",
                connection.subject,
                "omnigent-" + source.user_id.hex,
                connection.email_normalized,
                True,
                True,
            )
        self.hook = None
        self.subject = self.identity.subject
        self.configured = True

    def read_linked_identity(self, subject):
        assert subject == self.subject
        if self.hook:
            self.hook()
        return VerifiedLinkedCredentialIdentity(self.identity, self.configured)

    def ensure_import(self, _claim):
        raise AssertionError("a recovered identity must not import any old or recovery password")


def recovered(source):
    recovery, key, document, secret = grant_fixture(source)
    recovery.recover(signed_grant=signed_grant(key, document), secret=secret, now=NOW)
    provider = Provider(source, document)
    service = CredentialReconnectionService(
        source.sessions,
        policy=source.service._policy,
        provider=provider,
        verification_keys=CredentialReconnectionKeyring(
            {"offline-return": key.public_key().public_bytes_raw()}
        ),
    )
    request = service.prepare_request(
        user_id=source.user_id,
        receipt_id=UUID(document["receipt_id"]),
        review_reference="synthetic-review/provider-restored",
    )
    return service, provider, key, request


def test_signed_return_reactivates_only_original_identity_then_uses_readonly_cutover(source):
    service, provider, key, request = recovered(source)
    session = source.lifecycle.issue_auth_session(
        user_id=source.user_id,
        authn_method="password",
        now=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
    token = sign(key, request)
    connection = service.reconnect(signed_grant=token, now=NOW)
    assert str(connection) == request["connection_id"]
    assert service.reconnect(signed_grant=token, now=NOW) == connection
    with source.sessions() as db:
        assert db.get(GlobalUser, source.user_id).credential_owner == "legacy"
        assert db.get(AuthSessionRecord, session.session_id).revoked_at is not None
        events = list(
            db.scalars(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.event_type
                    == "identity.credential_migration.reconnected",
                )
            )
        )
        assert len(events) == 1
    assert (
        source.passwords.authenticate("migrate@example.test", RECOVERY_PASSWORD, now=NOW)
        == source.user_id
    )
    forward = CredentialMigrationService(
        source.sessions, policy=source.service._policy, provider=provider
    )
    receipt = forward.prepare_existing_link(
        user_id=source.user_id,
        connection_id=connection,
        batch_id="return-to-unified-v1",
        expected_password_version=2,
        idempotency_key="return-to-unified-v1",
        now=NOW,
    )
    assert forward.run_once(receipt.id, cutover=True, now=NOW).status == "completed"
    with pytest.raises(LifecycleError):
        source.passwords.authenticate("migrate@example.test", RECOVERY_PASSWORD, now=NOW)
    with pytest.raises(LifecycleError):
        source.passwords.authenticate("migrate@example.test", OLD_PASSWORD, now=NOW)
    source.identities.revoke_identity(
        user_id=source.user_id,
        connection_id=connection,
        idempotency_key="later-deliberate-revocation",
        now=NOW,
    )
    assert service.reconnect(signed_grant=token, now=NOW) == connection
    with source.sessions() as db:
        assert db.get(IdentityConnection, connection).status == "revoked"
        assert db.scalar(sa.select(sa.func.count()).select_from(GlobalUser)) == 1


@pytest.mark.parametrize(
    "change",
    [
        "source_password",
        "source_security",
        "disabled",
        "email_drift",
        "missing_password",
        "foreign_subject",
    ],
)
def test_signed_return_rejects_changed_source_or_provider(source, change):
    service, provider, key, request = recovered(source)
    if change.startswith("source_"):
        with source.sessions.begin() as db:
            if change == "source_password":
                db.get(PasswordCredential, source.user_id).password_version += 1
            else:
                db.get(GlobalUser, source.user_id).security_version += 1
    elif change == "disabled":
        provider.identity = replace(provider.identity, active=False)
    elif change == "email_drift":
        provider.identity = replace(provider.identity, email="changed@example.test")
    elif change == "foreign_subject":
        provider.identity = replace(provider.identity, subject=str(uuid4()))
    else:
        provider.configured = False
    with pytest.raises(CredentialMigrationError):
        service.reconnect(signed_grant=sign(key, request), now=NOW)
    with source.sessions() as db:
        assert db.get(IdentityConnection, UUID(request["connection_id"])).status == "revoked"


def test_return_cannot_reactivate_an_identity_revoked_before_recovery(source):
    recovery, key, document, secret = grant_fixture(source)
    with source.sessions.begin() as db:
        connection = db.scalar(
            sa.select(IdentityConnection).where(IdentityConnection.provider == "casdoor")
        )
        connection.status = "revoked"
    recovery.recover(signed_grant=signed_grant(key, document), secret=secret, now=NOW)
    service = CredentialReconnectionService(
        source.sessions,
        policy=source.service._policy,
        provider=Provider(source, document),
        verification_keys=CredentialReconnectionKeyring(
            {"offline-return": key.public_key().public_bytes_raw()}
        ),
    )
    with pytest.raises(CredentialMigrationError, match="state_conflict"):
        service.prepare_request(
            user_id=source.user_id,
            receipt_id=UUID(document["receipt_id"]),
            review_reference="review/v1",
        )


def test_return_rechecks_source_after_provider_read(source):
    service, provider, key, request = recovered(source)

    def change():
        with source.sessions.begin() as db:
            db.get(GlobalUser, source.user_id).security_version += 1

    provider.hook = change
    with pytest.raises(CredentialMigrationError, match="state_conflict"):
        service.reconnect(signed_grant=sign(key, request), now=NOW)


@pytest.mark.parametrize(
    "mutation",
    [
        {"expected_password_version": True},
        {"source_password_sha256": "invalid"},
        {"reason_code": "migration_rollback"},
        {"connection_id": str(uuid4())},
        {"issued_at": (NOW + timedelta(seconds=1)).isoformat()},
        {"expires_at": (NOW + timedelta(minutes=6)).isoformat()},
        {"unrecognized": "field"},
    ],
)
def test_return_grant_rejects_invalid_or_retargeted_authorization(source, mutation):
    service, _provider, key, request = recovered(source)
    token = sign(key, {**request, **mutation})
    with pytest.raises(CredentialMigrationError):
        service.reconnect(signed_grant=token, now=NOW)


def test_recovery_signature_cannot_authorize_return_even_with_same_key(source):
    from saas.control_plane.credential_recovery import RECOVERY_SIGNATURE_DOMAIN

    service, _provider, key, request = recovered(source)
    with pytest.raises(CredentialMigrationError, match="grant_invalid"):
        service.reconnect(
            signed_grant=sign(key, request, domain=RECOVERY_SIGNATURE_DOMAIN), now=NOW
        )


def test_offline_return_artifact_uses_a_separate_domain_and_private_new_files(source, tmp_path):
    import json
    import stat

    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

    from saas.production.credential_reconnection_grant import issue_grant

    service, _provider, key, request = recovered(source)
    request_file, key_file = tmp_path / "request.json", tmp_path / "offline.pem"
    request_file.write_text(json.dumps(request))
    key_file.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    for path in (request_file, key_file):
        path.chmod(0o600)
    output = tmp_path / "authorization"
    arguments = {
        "request_file": str(request_file),
        "signing_key_file": str(key_file),
        "key_id": "offline-return",
        "output_directory": str(output),
        "now": NOW,
    }
    assert issue_grant(**arguments) == output
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert {path.name for path in output.iterdir()} == {"grant.txt", "request.json"}
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in output.iterdir())
    assert (
        str(service.reconnect(signed_grant=(output / "grant.txt").read_text().strip(), now=NOW))
        == request["connection_id"]
    )
    with pytest.raises(FileExistsError):
        issue_grant(**arguments)
