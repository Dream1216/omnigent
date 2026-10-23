"""Actual authenticator login resolves only a unique alias through a pinned definer API."""

from uuid import uuid4

import pytest
import sqlalchemy as sa

from omnigent.db.db_models import workspace_scope
from saas.control_plane.db_models import (
    GlobalUser,
    RuntimeIdentityAliasRecord,
    RuntimePartitionRecord,
)
from saas.control_plane.http_auth import SaasAuthProvider, SaasCookieConfig
from saas.control_plane.lifecycle import MembershipLifecycleService
from tests.saas.test_delegated_runner_identity import seed_alias
from tests.saas.test_model_run_credentials_postgresql import _authenticator_login
from tests.saas.test_run_customer_pricing_postgresql import priced_execution as priced_execution


def test_real_authenticator_alias_scope_collision_revocation_and_function_admission(
    priced_execution,
):
    f = priced_execution
    alias, foreign = "runtime-delegated-owner", uuid4()
    _placement, partition = seed_alias(f.factory, f.scope, alias)
    with f.factory.begin() as db:
        db.add(GlobalUser(id=foreign, status="active", security_version=1))
    with _authenticator_login(f) as sessions:
        auth = SaasAuthProvider(MembershipLifecycleService(sessions), SaasCookieConfig())
        with sessions() as db:
            assert db.execute(
                sa.text(
                    "SELECT current_user=session_user,rolsuper,rolbypassrls FROM pg_roles "
                    "WHERE rolname=current_user"
                )
            ).one() == (True, False, False)
            assert not db.scalar(
                sa.text(
                    "SELECT has_table_privilege(current_user,"
                    "'saas_runtime_identity_aliases','SELECT')"
                )
            )
        with workspace_scope(41):
            token = auth.mint_runner_token(alias, 60)
            assert token is not None and auth.validate_token(token).user_id == f.scope.owner_id
            assert auth.mint_runner_token(str(foreign), 60) is None
        with workspace_scope(42):
            assert auth.mint_runner_token(alias, 60) is None
        with f.factory.begin() as db:
            db.get(
                RuntimeIdentityAliasRecord, (partition, f.scope.owner_id)
            ).runtime_user_key = str(foreign)
        with workspace_scope(41):
            token = auth.mint_runner_token(str(foreign), 60)
            assert token is not None and auth.validate_token(token).user_id == f.scope.owner_id
        with f.factory.begin() as db:
            db.get(RuntimeIdentityAliasRecord, (partition, f.scope.owner_id)).status = "suspended"
        with workspace_scope(41):
            assert auth.mint_runner_token(str(foreign), 60) is None
        with f.factory.begin() as db:
            db.get(RuntimeIdentityAliasRecord, (partition, f.scope.owner_id)).status = "active"
        _duplicate_placement, duplicate = seed_alias(f.factory, f.scope, str(foreign))
        with workspace_scope(41):
            assert auth.mint_runner_token(str(foreign), 60) is None
        with f.factory.begin() as db:
            db.get(RuntimePartitionRecord, duplicate).status = "retired"
        with workspace_scope(41):
            assert auth.mint_runner_token(str(foreign), 60) is not None
    with f.app.connect() as db:
        assert not db.scalar(
            sa.text(
                "SELECT has_function_privilege(current_user,"
                "'public.saas_delegated_runner_actor_v1(bigint,text)','EXECUTE')"
            )
        )
    with f.engine.begin() as connection:
        connection.exec_driver_sql(
            "GRANT EXECUTE ON FUNCTION public.saas_delegated_runner_actor_v1(bigint,text) "
            "TO saas_app"
        )
    try:
        with pytest.raises(
            sa.exc.DBAPIError, match="delegated Runner identity lookup contract rejected"
        ):
            with f.engine.begin() as connection:
                connection.exec_driver_sql(f"SET LOCAL ROLE {f.table_owner}")
                connection.exec_driver_sql(f.role_sql.read_text())
    finally:
        with f.engine.begin() as connection:
            connection.exec_driver_sql(
                "REVOKE EXECUTE ON FUNCTION public.saas_delegated_runner_actor_v1(bigint,text) "
                "FROM saas_app"
            )
