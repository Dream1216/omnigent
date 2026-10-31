from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.identity import IdentityManagementService
from saas.control_plane.oidc import OidcAuthorizationService, OidcProviderConfig


def _config(connection: sa.Connection) -> Config:
    root = Path(__file__).resolve().parents[2]
    config = Config(root / "saas/control_plane/alembic.ini")
    config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
    config.attributes["connection"] = connection
    return config


def _old_transaction(connection: sa.Connection) -> str:
    transaction_id = uuid4().hex
    connection.execute(
        sa.text(
            "INSERT INTO saas_oidc_login_transactions "
            "(id, provider, state_hash, browser_binding_hash, nonce_hash, "
            "code_verifier_ciphertext, purpose, status, expires_at) "
            "VALUES (:id, 'legacy', :state, :binding, :nonce, 'retained-ciphertext', "
            "'login', 'pending', :expiry)"
        ),
        {
            "id": transaction_id,
            "state": "a" * 64,
            "binding": "b" * 64,
            "nonce": "c" * 64,
            "expiry": datetime.now(timezone.utc) + timedelta(minutes=5),
        },
    )
    return transaction_id


def test_sqlite_expansion_retains_transactions_and_refuses_destructive_rollback() -> None:
    engine = sa.create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            config = _config(connection)
            command.upgrade(config, "lm2t00000001")
            _old_transaction(connection)
            command.upgrade(config, "cd1a00000001")
            row = connection.execute(
                sa.text(
                    "SELECT purpose, return_to, ui_locale, code_verifier_ciphertext "
                    "FROM saas_oidc_login_transactions"
                )
            ).one()
            assert tuple(row) == ("login", "/", "zh-CN", "retained-ciphertext")
            with pytest.raises(RuntimeError, match="application-only rollback"):
                command.downgrade(config, "lm2t00000001")
            assert (
                connection.scalar(sa.text("SELECT count(*) FROM saas_oidc_login_transactions"))
                == 1
            )
    finally:
        engine.dispose()


def test_real_postgresql_expansion_preserves_oidc_authority_and_once_only_state(
    isolated_postgres_url: str,
) -> None:
    from saas.control_plane.lifecycle import LifecycleError

    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(isolated_postgres_url)
    try:
        with engine.begin() as connection:
            config = _config(connection)
            command.upgrade(config, "lm2t00000001")
            _old_transaction(connection)
            policy_before = connection.execute(
                sa.text(
                    "SELECT policyname, qual, with_check FROM pg_policies "
                    "WHERE tablename='saas_oidc_login_transactions' ORDER BY policyname"
                )
            ).all()
            command.upgrade(config, "cd1a00000001")
            assert (
                policy_before
                == connection.execute(
                    sa.text(
                        "SELECT policyname, qual, with_check FROM pg_policies "
                        "WHERE tablename='saas_oidc_login_transactions' ORDER BY policyname"
                    )
                ).all()
            )
            assert connection.execute(
                sa.text(
                    "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                    "WHERE oid='saas_oidc_login_transactions'::regclass"
                )
            ).one() == (True, True)
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_roles.sql").read_text()
            )
        sessions = sessionmaker(engine, expire_on_commit=False)

        @sa.event.listens_for(sessions, "after_begin")
        def _authenticator(
            _session: Session, _transaction: object, connection: sa.Connection
        ) -> None:
            connection.exec_driver_sql("SET LOCAL ROLE saas_authenticator")

        provider = OidcProviderConfig(
            provider="casdoor",
            issuer="https://auth.example.test",
            authorization_endpoint="https://auth.example.test/login/oauth/authorize",
            signup_endpoint="https://auth.example.test/signup/oauth/authorize",
            token_endpoint="https://auth.example.test/api/login/oauth/access_token",
            jwks_uri="https://auth.example.test/.well-known/stbz-next-web/jwks",
            client_id="client",
            client_secret="isolated-test-secret",
            redirect_uri="https://next.example.test/saas/auth/oidc/casdoor/callback",
        )
        oidc = OidcAuthorizationService(
            sessions,
            IdentityManagementService(sessions),
            {"casdoor": provider},
            transaction_encryption_key=b"k" * 32,
        )
        started = oidc.begin("casdoor", purpose="signup", return_to="/setup", ui_locale="en-US")
        state = parse_qs(urlsplit(started.authorization_url).query)["state"][0]
        with pytest.raises(LifecycleError, match="transaction is invalid"):
            oidc.abort("casdoor", state=state, browser_binding="other-browser")
        oidc.abort("casdoor", state=state, browser_binding=started.browser_binding)
        with pytest.raises(LifecycleError, match="transaction is invalid"):
            oidc.abort("casdoor", state=state, browser_binding=started.browser_binding)
        with sessions() as db:
            row = db.execute(
                sa.text(
                    "SELECT purpose, return_to, ui_locale, status "
                    "FROM saas_oidc_login_transactions WHERE id=:id"
                ),
                {"id": started.transaction_id},
            ).one()
            assert tuple(row) == ("signup", "/setup", "en-US", "failed")
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_app")
            with pytest.raises(DBAPIError):
                connection.exec_driver_sql("SELECT * FROM saas_oidc_login_transactions")
    finally:
        engine.dispose()
