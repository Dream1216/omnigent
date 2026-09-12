from __future__ import annotations

import time
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from omnigent.db.db_models import OmnigentBase, SqlHost, workspace_scope
from omnigent.stores.host_store import HostStore, encode_host_status, hash_host_launch_token
from saas.production.external_host_credential import (
    ExternalHostCredentialError,
    arm_external_host_credential,
    revoke_external_host_credential,
)


@pytest.fixture
def credential_engine(tmp_path: Path) -> sa.Engine:
    engine = sa.create_engine(f"sqlite:///{tmp_path / 'credential.db'}")
    OmnigentBase.metadata.create_all(engine)
    with workspace_scope(41), Session(engine) as session, session.begin():
        session.add(
            SqlHost(
                workspace_id=41,
                host_id="ce5bb44730f64f47ac427f216e64bb33",
                user_id="tenant-user",
                name="runner-01",
                status=encode_host_status("offline"),
                created_at=1,
                updated_at=1,
            )
        )
    try:
        yield engine
    finally:
        engine.dispose()


def _stored(engine: sa.Engine) -> SqlHost:
    with workspace_scope(41), Session(engine) as session:
        return session.execute(sa.select(SqlHost)).scalar_one()


def test_arm_is_idempotent_and_rotation_requires_expected_digest(
    credential_engine: sa.Engine,
) -> None:
    first = "a" * 48
    second = "b" * 48
    receipt = arm_external_host_credential(
        credential_engine,
        workspace_id=41,
        host_id="ce5bb44730f64f47ac427f216e64bb33",
        token=first,
        ttl_seconds=3600,
        now=100,
    )
    assert receipt.status == "armed"
    assert _stored(credential_engine).token_hash == hash_host_launch_token(first)

    repeated = arm_external_host_credential(
        credential_engine,
        workspace_id=41,
        host_id="ce5bb44730f64f47ac427f216e64bb33",
        token=first,
        ttl_seconds=7200,
        now=200,
    )
    assert repeated.expires_at == 7400

    with pytest.raises(ExternalHostCredentialError, match="credential_changed"):
        arm_external_host_credential(
            credential_engine,
            workspace_id=41,
            host_id="ce5bb44730f64f47ac427f216e64bb33",
            token=second,
            ttl_seconds=3600,
            now=300,
        )
    rotated = arm_external_host_credential(
        credential_engine,
        workspace_id=41,
        host_id="ce5bb44730f64f47ac427f216e64bb33",
        token=second,
        ttl_seconds=3600,
        expected_token_sha256=hash_host_launch_token(first),
        now=300,
    )
    assert _stored(credential_engine).token_hash == rotated.token_sha256


def test_armed_external_host_can_complete_tunnel_registration(
    db_uri: str,
) -> None:
    """The out-of-band credential must survive the tunnel's atomic upsert.

    External Hosts intentionally have no sandbox provider or sandbox id.  The
    WebSocket route first resolves the token, then calls ``upsert_on_connect``
    with the same token; both checks must accept the same row shape.
    """
    token = "f" * 48
    now = int(time.time())
    engine = sa.create_engine(db_uri)
    try:
        with workspace_scope(41), Session(engine) as session, session.begin():
            session.add(
                SqlHost(
                    workspace_id=41,
                    host_id="ce5bb44730f64f47ac427f216e64bb33",
                    user_id="tenant-user",
                    name="runner-01",
                    status=encode_host_status("offline"),
                    created_at=1,
                    updated_at=1,
                )
            )
        arm_external_host_credential(
            engine,
            workspace_id=41,
            host_id="ce5bb44730f64f47ac427f216e64bb33",
            token=token,
            ttl_seconds=3600,
            now=now,
        )
        store = HostStore(db_uri)
        with workspace_scope(41):
            connected = store.upsert_on_connect(
                host_id="ce5bb44730f64f47ac427f216e64bb33",
                name="runner-01",
                user_id="tenant-user",
                managed_token=token,
            )
    finally:
        engine.dispose()

    assert connected.status == "online"
    assert connected.sandbox_provider is None
    assert connected.sandbox_id is None
    assert connected.terminating_sandbox_id is None


def test_revoke_is_digest_fenced_and_does_not_delete_host(
    credential_engine: sa.Engine,
) -> None:
    token = "c" * 48
    arm_external_host_credential(
        credential_engine,
        workspace_id=41,
        host_id="ce5bb44730f64f47ac427f216e64bb33",
        token=token,
        ttl_seconds=3600,
        now=100,
    )
    with pytest.raises(ExternalHostCredentialError, match="credential_changed"):
        revoke_external_host_credential(
            credential_engine,
            workspace_id=41,
            host_id="ce5bb44730f64f47ac427f216e64bb33",
            expected_token="d" * 48,
            now=200,
        )
    receipt = revoke_external_host_credential(
        credential_engine,
        workspace_id=41,
        host_id="ce5bb44730f64f47ac427f216e64bb33",
        expected_token=token,
        now=200,
    )
    row = _stored(credential_engine)
    assert receipt.status == "revoked"
    assert row.host_id == "ce5bb44730f64f47ac427f216e64bb33"
    assert row.token_hash is None
    assert row.token_expires_at is None


def test_cannot_arm_managed_host(credential_engine: sa.Engine) -> None:
    with workspace_scope(41), Session(credential_engine) as session, session.begin():
        row = session.execute(sa.select(SqlHost)).scalar_one()
        row.sandbox_provider = "modal"
    with pytest.raises(ExternalHostCredentialError, match="managed_host_forbidden"):
        arm_external_host_credential(
            credential_engine,
            workspace_id=41,
            host_id="ce5bb44730f64f47ac427f216e64bb33",
            token="e" * 48,
            ttl_seconds=3600,
            now=100,
        )
