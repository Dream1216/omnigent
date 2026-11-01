from __future__ import annotations

import base64
import json
from datetime import timedelta
from hashlib import sha256
from uuid import uuid4

import pytest
import sqlalchemy as sa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from omnigent.server.passwords import hash_password
from saas.control_plane import GlobalUser, LifecycleError, VerifiedIdentityAssertion
from saas.control_plane.credential_migration import CredentialMigrationError
from saas.control_plane.credential_recovery import (
    RECOVERY_SIGNATURE_DOMAIN,
    CredentialRecoveryKeyring,
    CredentialRecoverySecret,
    CredentialRecoveryService,
    recovery_grant_payload,
)
from saas.control_plane.db_models import (
    AuthSessionRecord,
    ControlPlaneOutboxEvent,
    IdentityConnection,
    PasswordCredential,
)
from tests.saas.test_credential_migration import NOW, OLD_PASSWORD, Source
from tests.saas.test_credential_migration import source as source

RECOVERY_PASSWORD = "fresh-isolated-recovery-password"


def signed_grant(private_key, document, *, key_id="offline-review"):
    payload = recovery_grant_payload(document)

    def encode(value):
        return base64.urlsafe_b64encode(value).decode().rstrip("=")

    return ".".join(
        [
            "v1",
            key_id,
            encode(payload),
            encode(private_key.sign(RECOVERY_SIGNATURE_DOMAIN + payload)),
        ]
    )


def grant_fixture(source, *, password=RECOVERY_PASSWORD):
    receipt = source.prepare()
    completed = source.service.run_once(receipt.id, cutover=True, now=NOW)
    assert completed.status == "completed"
    key = Ed25519PrivateKey.generate()
    new_hash = hash_password(password)
    with source.sessions() as db:
        version = db.get(GlobalUser, source.user_id).security_version
    document = {
        "schema_version": 1,
        "grant_id": str(uuid4()),
        "user_id": str(source.user_id),
        "receipt_id": str(receipt.id),
        "expected_security_version": version,
        "new_password_hash_sha256": sha256(new_hash.encode()).hexdigest(),
        "issued_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
        "review_reference": "synthetic-review/p3-recovery",
        "reason_code": "migration_rollback",
    }
    service = CredentialRecoveryService(
        source.sessions,
        verification_keys=CredentialRecoveryKeyring(
            {"offline-review": key.public_key().public_bytes_raw()}
        ),
    )
    return service, key, document, CredentialRecoverySecret(password, new_hash)


def test_signed_recovery_uses_fresh_password_and_revokes_provider_and_sessions(source: Source):
    service, key, document, secret = grant_fixture(source)
    session = source.lifecycle.issue_auth_session(
        user_id=source.user_id,
        authn_method="oidc:casdoor",
        now=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
    token = signed_grant(key, document)
    recovered = service.recover(signed_grant=token, secret=secret, now=NOW)
    assert recovered.status == "recovered" and recovered.user_id == source.user_id
    assert service.recover(signed_grant=token, secret=secret, now=NOW) == recovered
    with pytest.raises(LifecycleError, match="invalid"):
        source.passwords.authenticate("migrate@example.test", OLD_PASSWORD, now=NOW)
    assert (
        source.passwords.authenticate("migrate@example.test", RECOVERY_PASSWORD, now=NOW)
        == source.user_id
    )
    with source.sessions() as db:
        user = db.get(GlobalUser, source.user_id)
        assert (user.credential_owner, user.migration_state) == ("legacy", "recovered")
        assert user.security_version == document["expected_security_version"] + 1
        assert db.get(AuthSessionRecord, session.session_id).revoked_at is not None
        assert db.get(PasswordCredential, source.user_id).password_version == 2
        provider = db.scalar(
            sa.select(IdentityConnection).where(IdentityConnection.provider == "casdoor")
        )
        assert provider.status == "revoked"
        events = list(
            db.scalars(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.event_type == "identity.credential_migration.recovered"
                )
            )
        )
        assert len(events) == 1
        assert RECOVERY_PASSWORD not in json.dumps(events[0].payload)
        assert secret.new_password_hash not in json.dumps(events[0].payload)
    with pytest.raises(LifecycleError) as denied:
        source.identities.provision_identity(
            VerifiedIdentityAssertion(
                "casdoor",
                recovered.issuer,
                recovered.provider_subject,
                "migrate@example.test",
                True,
            )
        )
    assert denied.value.code == "identity_revoked"
    assert RECOVERY_PASSWORD not in repr(secret)


def test_retained_old_password_cannot_be_restored_even_with_a_valid_grant(source: Source):
    service, key, document, secret = grant_fixture(source, password=OLD_PASSWORD)
    with pytest.raises(CredentialMigrationError, match="requires_fresh_password"):
        service.recover(signed_grant=signed_grant(key, document), secret=secret, now=NOW)
    with source.sessions() as db:
        assert db.get(GlobalUser, source.user_id).credential_owner == "casdoor"


@pytest.mark.parametrize(
    "mutation",
    [
        {"expires_at": NOW.isoformat()},
        {"issued_at": (NOW + timedelta(seconds=1)).isoformat()},
        {"expires_at": (NOW + timedelta(minutes=6)).isoformat()},
        {"expected_security_version": True},
        {"new_password_hash_sha256": "f" * 64},
        {"user_id": str(uuid4())},
        {"receipt_id": str(uuid4())},
        {"reason_code": "client-requested"},
    ],
)
def test_recovery_grants_are_bounded_and_bound_to_exact_user_receipt_and_secret(
    source: Source, mutation
):
    service, key, document, secret = grant_fixture(source)
    with pytest.raises(CredentialMigrationError):
        service.recover(
            signed_grant=signed_grant(key, {**document, **mutation}), secret=secret, now=NOW
        )
    with source.sessions() as db:
        assert db.get(GlobalUser, source.user_id).credential_owner == "casdoor"


def test_online_worker_cannot_accept_an_untrusted_signer_or_stale_security_version(source: Source):
    service, key, document, secret = grant_fixture(source)
    with pytest.raises(CredentialMigrationError, match="grant_invalid"):
        service.recover(
            signed_grant=signed_grant(Ed25519PrivateKey.generate(), document),
            secret=secret,
            now=NOW,
        )
    with source.sessions.begin() as db:
        db.get(GlobalUser, source.user_id).security_version += 1
    with pytest.raises(CredentialMigrationError, match="state_conflict"):
        service.recover(signed_grant=signed_grant(key, document), secret=secret, now=NOW)


def test_offline_authorization_artifact_is_private_verifiable_and_never_overwrites(
    source: Source, tmp_path
):
    from saas.production.credential_recovery_grant import issue_grant

    service, key, document, _secret = grant_fixture(source)
    request = {
        name: document[name]
        for name in (
            "user_id",
            "receipt_id",
            "expected_security_version",
            "review_reference",
            "reason_code",
        )
    }
    for name, data in (
        ("request.json", json.dumps(request).encode()),
        ("password", RECOVERY_PASSWORD.encode()),
        (
            "offline-key.pem",
            key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
        ),
    ):
        path = tmp_path / name
        path.write_bytes(data)
        path.chmod(0o600)
    arguments = {
        "request_file": str(tmp_path / "request.json"),
        "password_file": str(tmp_path / "password"),
        "signing_key_file": str(tmp_path / "offline-key.pem"),
        "key_id": "offline-review",
        "output_directory": str(tmp_path / "authorization"),
        "now": NOW,
    }
    output = issue_grant(**arguments)
    assert output.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in output.iterdir())
    token = (output / "grant.txt").read_text().strip()
    secret = CredentialRecoverySecret(**json.loads((output / "secret.json").read_text()))
    assert service.recover(signed_grant=token, secret=secret, now=NOW).status == "recovered"
    with pytest.raises(FileExistsError):
        issue_grant(**arguments)
    assert (output / "grant.txt").read_text().strip() == token
