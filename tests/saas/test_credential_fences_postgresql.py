from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.orm import sessionmaker

from omnigent.server.passwords import hash_password
from saas.control_plane import (
    CredentialMigrationRecord,
    GlobalUser,
    IdentityManagementService,
    MembershipLifecycleService,
    PasswordCredentialService,
    VerifiedIdentityAssertion,
)
from saas.control_plane.credential_migration import (
    CredentialMigrationError,
    CredentialMigrationPolicy,
    CredentialMigrationService,
)
from saas.control_plane.credential_recovery import (
    CredentialRecoveryKeyring,
    CredentialRecoverySecret,
    CredentialRecoveryService,
)
from saas.control_plane.db_models import IdentityConnection
from tests.saas.test_casdoor_migration import _config
from tests.saas.test_credential_migration import OLD_PASSWORD, Provider, Source
from tests.saas.test_credential_recovery import signed_grant


@pytest.fixture
def postgres_source(isolated_postgres_url):
    engine = sa.create_engine(isolated_postgres_url)
    with engine.begin() as connection:
        command.upgrade(_config(connection), "head")
        connection.exec_driver_sql(
            (
                Path(__file__).resolve().parents[2] / "saas/control_plane/postgresql_roles.sql"
            ).read_text()
        )
    sessions = sessionmaker(engine, expire_on_commit=False)
    local = threading.local()
    prefix = "credential-" + uuid4().hex

    @sa.event.listens_for(sessions, "after_begin")
    def role(_session, _transaction, connection):
        connection.exec_driver_sql("SET LOCAL ROLE saas_authenticator")
        connection.execute(
            sa.text("SELECT set_config('application_name',:name,true)"),
            {"name": prefix + "-" + getattr(local, "phase", "seed")},
        )

    identities = IdentityManagementService(sessions)
    user = identities.provision_identity(
        VerifiedIdentityAssertion(
            "legacy", "urn:credential-fence", "old-user", "fence@example.test", True
        )
    )
    passwords = PasswordCredentialService(sessions)
    passwords.set_password(user_id=user, new_password=OLD_PASSWORD, idempotency_key="initial")
    provider = Provider()
    service = CredentialMigrationService(
        sessions,
        provider=provider,
        policy=CredentialMigrationPolicy(
            issuer="https://auth.example.test",
            organization="customers",
            policy_sha256="a" * 64,
            lease_duration=timedelta(seconds=10),
        ),
    )
    source = Source(
        sessions,
        user,
        passwords,
        MembershipLifecycleService(sessions),
        identities,
        provider,
        service,
    )

    def invoke(phase, operation):
        local.phase = phase
        return operation()

    try:
        yield engine, source, invoke, prefix
    finally:
        engine.dispose()


def wait_for_lock(engine, label):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        with engine.connect() as connection:
            waiting = connection.scalar(
                sa.text(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() "
                    "AND application_name=:name AND wait_event_type='Lock'"
                ),
                {"name": label},
            )
        if waiting:
            return
        time.sleep(0.02)
    raise AssertionError("the credential operation never reached its expected database lock")


def test_lease_is_checked_after_waiting_for_the_global_user_lock(postgres_source):
    engine, source, invoke, prefix = postgres_source
    receipt = source.prepare()
    claim = source.service.claim(receipt.id)
    verified = source.provider.ensure_import(claim)
    with source.sessions() as db:
        expiry = db.get(CredentialMigrationRecord, receipt.id).lease_expires_at
    with ThreadPoolExecutor(max_workers=1) as pool:
        with engine.begin() as held:
            held.execute(
                sa.text("SELECT id FROM saas_global_users WHERE id=:id FOR UPDATE"),
                {"id": source.user_id},
            )
            future = pool.submit(
                invoke, "finish", lambda: source.service.finish(claim, verified, cutover=True)
            )
            wait_for_lock(engine, prefix + "-finish")
            time.sleep(max(0, (expiry - datetime.now(timezone.utc)).total_seconds()) + 0.1)
        with pytest.raises(CredentialMigrationError, match="migration_claim_stale"):
            future.result(timeout=10)
    with source.sessions() as db:
        assert db.get(GlobalUser, source.user_id).credential_owner == "legacy"
        assert db.get(CredentialMigrationRecord, receipt.id).status == "pending"
    assert source.service.claim(receipt.id).claim_token != claim.claim_token


def test_recovery_grant_expiring_during_database_wait_cannot_change_authority(postgres_source):
    engine, source, invoke, prefix = postgres_source
    receipt = source.prepare()
    assert source.service.run_once(receipt.id, cutover=True).status == "completed"
    key = Ed25519PrivateKey.generate()
    password = "fresh-password-after-credential-fence"
    encoded = hash_password(password)
    with source.sessions() as db:
        version = db.get(GlobalUser, source.user_id).security_version
    now = datetime.now(timezone.utc)
    expiry = now + timedelta(seconds=2)
    document = {
        "schema_version": 1,
        "grant_id": str(uuid4()),
        "user_id": str(source.user_id),
        "receipt_id": str(receipt.id),
        "expected_security_version": version,
        "new_password_hash_sha256": sha256(encoded.encode()).hexdigest(),
        "issued_at": now.isoformat(),
        "expires_at": expiry.isoformat(),
        "review_reference": "synthetic-lock-expiry",
        "reason_code": "migration_rollback",
    }
    token = signed_grant(key, document)
    recovery = CredentialRecoveryService(
        source.sessions,
        verification_keys=CredentialRecoveryKeyring(
            {"offline-review": key.public_key().public_bytes_raw()}
        ),
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        with engine.begin() as held:
            held.execute(
                sa.text("SELECT id FROM saas_global_users WHERE id=:id FOR UPDATE"),
                {"id": source.user_id},
            )
            future = pool.submit(
                invoke,
                "recover",
                lambda: recovery.recover(
                    signed_grant=token, secret=CredentialRecoverySecret(password, encoded)
                ),
            )
            wait_for_lock(engine, prefix + "-recover")
            time.sleep(max(0, (expiry - datetime.now(timezone.utc)).total_seconds()) + 0.1)
        with pytest.raises(CredentialMigrationError, match="credential_recovery_grant_invalid"):
            future.result(timeout=10)
    with source.sessions() as db:
        assert db.get(GlobalUser, source.user_id).credential_owner == "casdoor"
        assert db.get(CredentialMigrationRecord, receipt.id).status == "completed"


@pytest.mark.parametrize("first", ["revoke", "cutover"])
def test_identity_revocation_and_cutover_serialize_without_a_lock_cycle(
    postgres_source, monkeypatch, first
):
    from saas.control_plane import credential_migration, identity

    engine, source, invoke, prefix = postgres_source
    connection_id = source.identities.link_identity(
        user_id=source.user_id,
        assertion=VerifiedIdentityAssertion(
            "casdoor", "https://auth.example.test", str(source.user_id), "fence@example.test", True
        ),
        idempotency_key="explicit-existing-identity",
    )
    receipt = source.prepare()
    claim = source.service.claim(receipt.id)
    verified = source.provider.ensure_import(claim)
    reached, release = threading.Event(), threading.Event()
    original_revoke, original_cutover = (
        identity._invalidate_sessions,
        credential_migration._invalidate_sessions,
    )

    def pause(original, phase, *args):
        if phase == first:
            reached.set()
            assert release.wait(10), "the credential lock-order test was not released"
        return original(*args)

    monkeypatch.setattr(
        identity, "_invalidate_sessions", lambda *args: pause(original_revoke, "revoke", *args)
    )
    monkeypatch.setattr(
        credential_migration,
        "_invalidate_sessions",
        lambda *args: pause(original_cutover, "cutover", *args),
    )
    actions = {
        "revoke": lambda: source.identities.revoke_identity(
            user_id=source.user_id,
            connection_id=connection_id,
            idempotency_key="concurrent-revoke",
        ),
        "cutover": lambda: source.service.finish(claim, verified, cutover=True),
    }
    second = "cutover" if first == "revoke" else "revoke"
    with ThreadPoolExecutor(max_workers=2) as pool:
        initial = pool.submit(invoke, first, actions[first])
        try:
            assert reached.wait(10)
            following = pool.submit(invoke, second, actions[second])
            wait_for_lock(engine, prefix + "-" + second)
        finally:
            release.set()
        results = {first: initial.result(timeout=10), second: following.result(timeout=10)}
    expected = "conflict" if first == "revoke" else "completed"
    assert results["cutover"].status == expected
    with source.sessions() as db:
        assert db.get(IdentityConnection, connection_id).status == "revoked"
        assert db.get(GlobalUser, source.user_id).credential_owner == (
            "legacy" if first == "revoke" else "casdoor"
        )
