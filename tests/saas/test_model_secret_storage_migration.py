from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config

from saas.control_plane.model_connections import credential_context
from saas.control_plane.model_routing_models import (
    ModelConnectionRecord,
    ModelCredentialVersionRecord,
)
from tests.saas.test_model_connections import _KEY, _fixture


def _config(connection):
    config = Config(Path(__file__).resolve().parents[2] / "saas/control_plane/alembic.ini")
    config.attributes["connection"] = connection
    return config


def _old_database(engine):
    with engine.begin() as connection:
        command.upgrade(_config(connection), "lm2o00000001")
    return _fixture(engine=engine)


def _legacy_credential(engine, actor, cipher, *, ciphertext=None):
    connection_id, identifier = uuid4(), uuid4()
    now = datetime.now(timezone.utc)
    context = credential_context(connection_id, identifier)
    if ciphertext is None:
        ciphertext = cipher.encrypt(_KEY, context=context)
    else:
        cipher.values[ciphertext] = (_KEY, context)
    legacy = sa.table(
        "saas_model_credential_versions",
        sa.column("id", sa.Uuid()),
        sa.column("connection_id", sa.Uuid()),
        sa.column("generation", sa.Integer()),
        sa.column("credential_name", sa.String()),
        sa.column("api_key_ciphertext", sa.Text()),
        sa.column("created_by_principal_id", sa.Uuid()),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    with engine.begin() as connection:
        connection.execute(
            sa.insert(ModelConnectionRecord).values(
                id=connection_id,
                display_name="migration fixture",
                provider_id="deepseek",
                base_url="https://api.deepseek.com",
                version=1,
                credential_generation=1,
                updated_by_principal_id=actor.principal_id,
                created_at=now,
                updated_at=now,
            )
        )
        connection.execute(
            legacy.insert().values(
                id=identifier,
                connection_id=connection_id,
                generation=1,
                credential_name="platform-credential-" + identifier.hex,
                api_key_ciphertext=ciphertext,
                created_by_principal_id=actor.principal_id,
                created_at=now,
            )
        )
    return identifier, ciphertext


def _raw(connection):
    return connection.exec_driver_sql(
        "SELECT api_key_ciphertext FROM saas_model_credential_versions"
    ).scalar_one()


@pytest.fixture
def migration_engine():
    engine = sa.create_engine("sqlite+pysqlite://")

    @sa.event.listens_for(engine, "connect")
    def manual_transactions(dbapi, _record):
        dbapi.isolation_level = None

    @sa.event.listens_for(engine, "begin")
    def begin(connection):
        connection.exec_driver_sql("BEGIN")

    try:
        yield engine
    finally:
        engine.dispose()


def _roundtrip(engine, ciphertext):
    service, factory, actor, cipher, _client, _headers = _old_database(engine)
    identifier, original = _legacy_credential(engine, actor, cipher, ciphertext=ciphertext)
    calls = dict(cipher.values)
    with engine.begin() as connection:
        command.upgrade(_config(connection), "lm2p00000001")
        assert _raw(connection) == b"OGSM\x01\x01\x01" + original.encode()
        command.upgrade(_config(connection), "lm2p00000001")
        assert _raw(connection) == b"OGSM\x01\x01\x01" + original.encode()
    with factory() as db:
        credential = db.get(ModelCredentialVersionRecord, identifier)
        assert credential.api_key_ciphertext == original
        assert service._decrypt(credential) == _KEY
    with engine.begin() as connection:
        command.downgrade(_config(connection), "lm2o00000001")
        assert _raw(connection) == original
        command.upgrade(_config(connection), "lm2p00000001")
        assert _raw(connection) == b"OGSM\x01\x01\x01" + original.encode()
    assert cipher.values == calls


@pytest.mark.parametrize(
    "ciphertext", [None, "x" * 16376, "密" * 5458], ids=["opaque", "max-bytes", "utf8"]
)
def test_migration_roundtrip_preserves_opaque_ciphertext_and_context(migration_engine, ciphertext):
    _roundtrip(migration_engine, ciphertext)


def _oversize_refusal(engine):
    _service, _factory, actor, cipher, _client, _headers = _old_database(engine)
    _identifier, original = _legacy_credential(engine, actor, cipher, ciphertext="x" * 16377)
    before_tables = sa.inspect(engine).get_table_names()
    with pytest.raises(
        (sa.exc.IntegrityError, RuntimeError),
        match=r"ck_model_credential_ciphertext|model secret storage exceeds byte cap",
    ):
        with engine.begin() as connection:
            command.upgrade(_config(connection), "lm2p00000001")
    with engine.connect() as connection:
        assert _raw(connection) == original
        assert connection.exec_driver_sql(
            "SELECT version_num FROM saas_alembic_version"
        ).scalar() == ("lm2o00000001")
    assert sa.inspect(engine).get_table_names() == before_tables


def test_oversize_legacy_payload_refuses_atomically_without_truncation(migration_engine):
    _oversize_refusal(migration_engine)


def test_standard_sqlite_driver_refusal_leaves_no_partial_batch_tables():
    engine = sa.create_engine("sqlite+pysqlite://")
    try:
        _oversize_refusal(engine)
    finally:
        engine.dispose()


@pytest.mark.parametrize("value", [b"OGSM\x01\x00\x01plaintext", b"OGSM\x01\x01\x01\xff"])
def test_downgrade_refuses_unknown_or_invalid_envelopes_without_rewriting(migration_engine, value):
    _service, _factory, actor, cipher, _client, _headers = _old_database(migration_engine)
    _legacy_credential(migration_engine, actor, cipher)
    with migration_engine.begin() as connection:
        command.upgrade(_config(connection), "lm2p00000001")
        connection.execute(
            sa.text("UPDATE saas_model_credential_versions SET api_key_ciphertext=:value"),
            {"value": value},
        )
    with pytest.raises(RuntimeError, match="cannot be downgraded"):
        with migration_engine.begin() as connection:
            command.downgrade(_config(connection), "lm2o00000001")
    with migration_engine.connect() as connection:
        assert _raw(connection) == value
        assert connection.exec_driver_sql(
            "SELECT version_num FROM saas_alembic_version"
        ).scalar() == ("lm2p00000001")
