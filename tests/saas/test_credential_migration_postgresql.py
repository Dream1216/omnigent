from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane import (
    GlobalUser,
    IdentityManagementService,
    LifecycleError,
    PasswordCredentialService,
    VerifiedIdentityAssertion,
)
from saas.control_plane.credential_migration import (
    CredentialMigrationPolicy,
    CredentialMigrationService,
)
from tests.saas.test_casdoor_migration import _config
from tests.saas.test_credential_migration import NOW, OLD_PASSWORD, Provider


def test_real_restricted_authenticator_cutover_and_immutable_receipt(
    isolated_postgres_url: str,
):
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(isolated_postgres_url)
    with engine.begin() as connection:
        command.upgrade(_config(connection), "head")
        connection.exec_driver_sql((root / "saas/control_plane/postgresql_roles.sql").read_text())
    sessions = sessionmaker(engine, expire_on_commit=False)

    @sa.event.listens_for(sessions, "after_begin")
    def authenticator(_session: Session, _transaction, connection):
        connection.exec_driver_sql("SET LOCAL ROLE saas_authenticator")

    user = IdentityManagementService(sessions).provision_identity(
        VerifiedIdentityAssertion(
            "legacy",
            "urn:legacy-credential-pg",
            "pg-source",
            "pg-source@example.test",
            True,
        )
    )
    passwords = PasswordCredentialService(sessions)
    passwords.set_password(
        user_id=user,
        new_password=OLD_PASSWORD,
        expected_version=None,
        idempotency_key="initial",
        now=NOW,
    )
    service = CredentialMigrationService(
        sessions,
        provider=Provider(),
        policy=CredentialMigrationPolicy(
            issuer="https://auth.example.test",
            organization="customers",
            policy_sha256="a" * 64,
        ),
    )
    receipt = service.prepare(
        user_id=user,
        batch_id="pg-batch",
        expected_password_version=1,
        idempotency_key="pg-claim",
        now=NOW,
    )
    completed = service.run_once(receipt.id, cutover=True, now=NOW + timedelta(seconds=1))
    assert completed.status == "completed" and completed.user_id == user
    with pytest.raises(LifecycleError) as denied:
        passwords.authenticate("pg-source@example.test", OLD_PASSWORD, now=NOW)
    assert denied.value.code == "invalid_credentials"
    with sessions() as db:
        assert db.get(GlobalUser, user).credential_owner == "casdoor"
    for role in ("saas_app", "saas_governance", "saas_registration", "saas_onboarding_status"):
        with pytest.raises(DBAPIError), engine.begin() as connection:
            connection.exec_driver_sql(f"SET LOCAL ROLE {role}")
            connection.exec_driver_sql("SELECT * FROM saas_credential_migration_receipts")
    with pytest.raises(DBAPIError), sessions.begin() as db:
        db.execute(
            sa.text(
                "UPDATE saas_credential_migration_receipts "
                "SET provider_subject='hijack' WHERE id=:id"
            ),
            {"id": receipt.id},
        )
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "GRANT UPDATE (provider_subject) ON saas_credential_migration_receipts "
            "TO saas_authenticator"
        )
    with pytest.raises(DBAPIError, match="immutable"), sessions.begin() as db:
        db.execute(
            sa.text(
                "UPDATE saas_credential_migration_receipts "
                "SET provider_subject='hijack' WHERE id=:id"
            ),
            {"id": receipt.id},
        )
    with pytest.raises(DBAPIError, match="immutable"), sessions.begin() as db:
        db.execute(
            sa.text("UPDATE saas_credential_migration_receipts SET status=status WHERE id=:id"),
            {"id": receipt.id},
        )
    with engine.begin() as connection:
        connection.exec_driver_sql((root / "saas/control_plane/postgresql_roles.sql").read_text())
        assert (
            connection.scalar(
                sa.text(
                    "SELECT has_column_privilege('saas_authenticator',"
                    "'saas_credential_migration_receipts','provider_subject','UPDATE')"
                )
            )
            is False
        )
        assert (
            connection.scalar(
                sa.text(
                    "SELECT has_column_privilege('saas_authenticator',"
                    "'saas_credential_migration_receipts','status','UPDATE')"
                )
            )
            is True
        )
    engine.dispose()
