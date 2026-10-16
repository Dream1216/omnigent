from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa

from saas.production import model_projection as production
from saas.production.service_bindings import render_production_service_role_bindings
from tests.saas.test_model_connections import _Cipher
from tests.saas.test_production_postgresql_migration import (
    _bindings,
    _platform_admin_bindings,
    _platform_bindings,
    _projection_bindings,
)

_MANAGEMENT_KEY = "isolated-litellm-management-test-only"


class _Fallback:
    def __init__(self):
        self.events, self.closed, self.validated = [], False, 0

    def publish(self, **event):
        self.events.append(event)

    def validate_outbox_configuration(self):
        self.validated += 1

    def close(self):
        self.closed = True


def _environment(tmp_path: Path) -> dict[str, str]:
    source = {
        "OMNIGENT_SAAS_MODEL_PROJECTION_ENABLED": "true",
        "OMNIGENT_SAAS_PRODUCT_REVISION": "a" * 40,
        "OMNIGENT_SAAS_SOURCE_SHA": "a" * 40,
        "OMNIGENT_SAAS_OFFICIAL_SCHEMA_REVISION": "mm1a2b3c4d5e",
        "OMNIGENT_SAAS_CONTROL_PLANE_SCHEMA_REVISION": "lm1b00000001",
        "OMNIGENT_SAAS_LITELLM_MANAGEMENT_BASE_URL": "http://omnigent-litellm:4000",
    }
    for name, bindings in (
        ("SERVICE_ROLE_BINDINGS", _bindings()),
        ("PLATFORM_MODEL_SERVICE_ROLE_BINDINGS", _platform_bindings()),
        ("PLATFORM_ADMIN_SERVICE_ROLE_BINDINGS", _platform_admin_bindings()),
        ("MODEL_PROJECTION_SERVICE_ROLE_BINDINGS", _projection_bindings()),
    ):
        path = tmp_path / f"{name}.json"
        path.write_text(render_production_service_role_bindings(bindings.bindings))
        path.chmod(0o400)
        source[f"OMNIGENT_SAAS_{name}_FILE"] = str(path)
    core = production.load_production_service_role_bindings(source)
    graph = production.compose_production_service_role_graph(
        core,
        production.load_platform_model_service_role_bindings(source),
        production.load_platform_admin_service_role_bindings(source),
        production.load_model_projection_service_role_bindings(source),
    )
    path = tmp_path / "receipt.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "status": "pass",
                "phases": ["state:verified"],
                "authorities": [
                    {"kind": kind, "login": kind}
                    for kind in (
                        "principal_operator",
                        "database_owner",
                        "official_owner",
                        "saas_owner",
                    )
                ],
                "product_revision": "a" * 40,
                "official_head": "mm1a2b3c4d5e",
                "saas_head": "lm1b00000001",
                "database_identity_sha256": "1" * 64,
                "catalog_sha256": "2" * 64,
                "service_role_bindings_sha256": core.sha256,
                "service_role_graph_sha256": graph.sha256,
                "runtime_rls_table_count": 1,
            }
        )
    )
    path.chmod(0o400)
    source["OMNIGENT_SAAS_MIGRATION_RECEIPT_FILE"] = str(path)
    for name, value in (
        (
            "MODEL_PROJECTION_DATABASE_URL",
            "postgresql+psycopg://model_projection_login:isolated-db-password@db.example:5432/omnigent?sslmode=verify-full&sslrootcert=/runtime/postgresql-ca.crt",
        ),
        ("LITELLM_MANAGEMENT_KEY", _MANAGEMENT_KEY + "\n"),
    ):
        path = tmp_path / name
        path.write_text(value)
        path.chmod(0o400)
        source[f"OMNIGENT_SAAS_{name}_FILE"] = str(path)
    return source


def test_projection_is_opt_in_without_loading_secrets_or_replacing_fallback():
    fallback = _Fallback()
    assert production.wrap_production_model_projection({}, fallback=fallback) is fallback
    assert not fallback.closed
    for value in ("TRUE", "true ", "1", ""):
        with pytest.raises(production.ProductionModelProjectionError):
            production.wrap_production_model_projection(
                {"OMNIGENT_SAAS_MODEL_PROJECTION_ENABLED": value}, fallback=fallback
            )


def test_projection_loads_one_exact_login_and_never_exposes_secrets(tmp_path):
    config = production.load_production_model_projection_config(_environment(tmp_path))
    assert config.service_role_graph.login_for("model_projection") == "model_projection_login"
    assert len(config.service_role_graph.bindings) == 19
    assert config.management.management_key == _MANAGEMENT_KEY
    assert _MANAGEMENT_KEY not in repr(config)
    assert "isolated-db-password" not in repr(config)


@pytest.mark.parametrize(
    "change",
    (
        "direct_key",
        "key_mode",
        "key_symlink",
        "wrong_login",
        "revision",
        "remote_http",
        "stale_graph",
    ),
)
def test_projection_configuration_rejections_are_redacted(tmp_path, change):
    source = _environment(tmp_path)
    if change == "direct_key":
        source["OMNIGENT_SAAS_LITELLM_MANAGEMENT_KEY"] = _MANAGEMENT_KEY
    elif change == "key_mode":
        Path(source["OMNIGENT_SAAS_LITELLM_MANAGEMENT_KEY_FILE"]).chmod(0o600)
    elif change == "key_symlink":
        target = tmp_path / "key-link"
        target.symlink_to(source["OMNIGENT_SAAS_LITELLM_MANAGEMENT_KEY_FILE"])
        source["OMNIGENT_SAAS_LITELLM_MANAGEMENT_KEY_FILE"] = str(target)
    elif change == "wrong_login":
        path = Path(source["OMNIGENT_SAAS_MODEL_PROJECTION_DATABASE_URL_FILE"])
        path.chmod(0o600)
        path.write_text(path.read_text().replace("model_projection_login", "dispatcher_login"))
        path.chmod(0o400)
    elif change == "revision":
        source["OMNIGENT_SAAS_SOURCE_SHA"] = "b" * 40
    elif change == "remote_http":
        source["OMNIGENT_SAAS_LITELLM_MANAGEMENT_BASE_URL"] = "http://untrusted.example"
    else:
        path = Path(source["OMNIGENT_SAAS_MIGRATION_RECEIPT_FILE"])
        document = json.loads(path.read_text())
        document["service_role_graph_sha256"] = "3" * 64
        path.chmod(0o600)
        path.write_text(json.dumps(document))
        path.chmod(0o400)
    with pytest.raises(production.ProductionModelProjectionError) as rejected:
        production.load_production_model_projection_config(source)
    assert str(rejected.value) == "model_projection_configuration_invalid"
    assert rejected.value.__suppress_context__
    assert _MANAGEMENT_KEY not in str(rejected.value)


def test_projection_wrapper_preserves_unrelated_events_and_checks_database_before_claims(
    tmp_path, monkeypatch
):
    source, fallback, verified = _environment(tmp_path), _Fallback(), []
    engine = sa.create_engine("sqlite://")
    monkeypatch.setattr(
        production,
        "verify_model_projection_postgresql_state",
        lambda **kwargs: verified.append(kwargs),
    )
    wrapped = production.wrap_production_model_projection(
        source,
        fallback=fallback,
        engine_factory=lambda _: engine,
        secret_cipher_loader=lambda _: _Cipher(),
    )
    assert isinstance(wrapped, production.ProductionModelProjectionPublisher)
    assert len(verified) == 1 and verified[0]["engine"] is engine and fallback.validated == 1
    routed = _Fallback()
    wrapped.projection = routed
    envelope = {
        "event_id": uuid4(),
        "aggregate_type": "unrelated",
        "aggregate_key": "untouched",
        "event_type": "unrelated.event",
        "payload": {},
    }
    wrapped.publish(**envelope)
    assert fallback.events == [envelope] and routed.events == []
    envelope = {**envelope, "event_type": "platform.model_projection.requested"}
    wrapped.publish(**envelope)
    assert routed.events == [envelope] and len(fallback.events) == 1
    wrapped.close()
    assert fallback.closed


def test_projection_failed_startup_disposes_only_its_engine_and_redacts_cause(
    tmp_path, monkeypatch
):
    source, fallback, disposed = _environment(tmp_path), _Fallback(), []
    engine = sa.create_engine("sqlite://")
    sa.event.listen(engine, "engine_disposed", lambda _: disposed.append(True))

    def reject(**kwargs):
        raise RuntimeError(_MANAGEMENT_KEY)

    monkeypatch.setattr(production, "verify_model_projection_postgresql_state", reject)
    with pytest.raises(production.ProductionModelProjectionError) as rejected:
        production.wrap_production_model_projection(
            source,
            fallback=fallback,
            engine_factory=lambda _: engine,
            secret_cipher_loader=lambda _: _Cipher(),
        )
    assert disposed == [True] and not fallback.closed
    assert str(rejected.value) == "model_projection_startup_rejected"
    assert rejected.value.__suppress_context__


def _verification_environment(tmp_path):
    from saas.control_plane.schema_revision import CONTROL_PLANE_SCHEMA_REVISION

    source = _environment(tmp_path)
    source["OMNIGENT_SAAS_MODEL_VERIFICATION_ENABLED"] = "true"
    source["OMNIGENT_SAAS_CONTROL_PLANE_SCHEMA_REVISION"] = CONTROL_PLANE_SCHEMA_REVISION
    receipt_path = Path(source["OMNIGENT_SAAS_MIGRATION_RECEIPT_FILE"])
    receipt = json.loads(receipt_path.read_text())
    receipt["saas_head"] = CONTROL_PLANE_SCHEMA_REVISION
    receipt_path.chmod(0o600)
    receipt_path.write_text(json.dumps(receipt))
    receipt_path.chmod(0o400)
    path = tmp_path / "billing-dsn"
    path.write_text(
        "postgresql+psycopg://platform_model_billing_login:isolated-billing-test-only@db.example:5432/omnigent?sslmode=verify-full&sslrootcert=/runtime/postgresql-ca.crt"
    )
    path.chmod(0o400)
    source["OMNIGENT_SAAS_BILLING_DATABASE_URL_FILE"] = str(path)
    return source


def test_verification_consumer_owns_separate_billing_login_and_routes_only_its_domain(
    tmp_path, monkeypatch
):
    source, fallback, calls, inspections, disposed = (
        _verification_environment(tmp_path),
        _Fallback(),
        [],
        [],
        [],
    )
    engines = [sa.create_engine("sqlite://"), sa.create_engine("sqlite://")]
    for index, engine in enumerate(engines):
        sa.event.listen(engine, "engine_disposed", lambda _, index=index: disposed.append(index))

    def engine_factory(url):
        calls.append(sa.make_url(url).username)
        return engines[len(calls) - 1]

    monkeypatch.setattr(production, "verify_model_projection_postgresql_state", lambda **_: None)
    monkeypatch.setattr(
        production,
        "_inspect_service_login",
        lambda engine, **kwargs: inspections.append((engine, kwargs)),
    )
    wrapped = production.wrap_production_model_projection(
        source,
        fallback=fallback,
        engine_factory=engine_factory,
        secret_cipher_loader=lambda _: _Cipher(),
    )
    assert calls == ["model_projection_login", "platform_model_billing_login"]
    assert inspections == [
        (
            engines[1],
            {"expected_login": "platform_model_billing_login", "expected_role": "saas_billing"},
        )
    ]
    assert wrapped.verification is not None and wrapped.billing_engine is engines[1]
    verification = _Fallback()
    wrapped.verification = verification
    event = {
        "event_id": uuid4(),
        "event_type": "platform.model_verification.requested",
        "aggregate_type": "platform_model",
        "aggregate_key": "opaque-operation",
        "payload": {},
    }
    wrapped.publish(**event)
    assert verification.events == [event] and fallback.events == []
    wrapped.publish(**{**event, "event_type": "unrelated"})
    assert len(fallback.events) == 1 and len(verification.events) == 1
    wrapped.close()
    assert sorted(disposed) == [0, 1] and fallback.closed


@pytest.mark.parametrize("change", ("missing_billing", "wrong_login", "billing_inspection"))
def test_verification_consumer_failed_startup_disposes_owned_engines_not_fallback(
    tmp_path, monkeypatch, change
):
    source, fallback, engines, disposed = _verification_environment(tmp_path), _Fallback(), [], []
    if change == "missing_billing":
        del source["OMNIGENT_SAAS_BILLING_DATABASE_URL_FILE"]
    elif change == "wrong_login":
        path = Path(source["OMNIGENT_SAAS_BILLING_DATABASE_URL_FILE"])
        path.chmod(0o600)
        path.write_text(
            path.read_text().replace("platform_model_billing_login", "model_projection_login")
        )
        path.chmod(0o400)

    def engine_factory(_url):
        engine = sa.create_engine("sqlite://")
        engines.append(engine)
        sa.event.listen(engine, "engine_disposed", lambda _: disposed.append(True))
        return engine

    def reject(*_args, **_kwargs):
        raise ValueError("isolated-billing-test-only")

    monkeypatch.setattr(production, "verify_model_projection_postgresql_state", lambda **_: None)
    monkeypatch.setattr(production, "_inspect_service_login", reject)
    with pytest.raises(production.ProductionModelProjectionError) as error:
        production.wrap_production_model_projection(
            source,
            fallback=fallback,
            engine_factory=engine_factory,
            secret_cipher_loader=lambda _: _Cipher(),
        )
    assert (
        str(error.value) == "model_projection_startup_rejected"
        and error.value.__suppress_context__
    )
    assert len(disposed) == len(engines) == (2 if change == "billing_inspection" else 1)
    assert not fallback.closed and not fallback.events


def test_verification_event_cannot_fall_through_when_consumer_is_disabled(tmp_path, monkeypatch):
    from saas.control_plane.outbox import OutboxPublishError

    monkeypatch.setattr(production, "verify_model_projection_postgresql_state", lambda **_: None)
    wrapped = production.wrap_production_model_projection(
        _environment(tmp_path),
        fallback=_Fallback(),
        engine_factory=lambda _: sa.create_engine("sqlite://"),
        secret_cipher_loader=lambda _: _Cipher(),
    )
    with pytest.raises(OutboxPublishError, match="model_verification_unavailable"):
        wrapped.publish(
            event_id=uuid4(),
            event_type="platform.model_verification.requested",
            aggregate_type="platform_model",
            aggregate_key="opaque-operation",
            payload={},
        )
    assert wrapped.fallback.events == []
    wrapped.close()
    with pytest.raises(
        production.ProductionModelProjectionError, match="model_verification_requires_projection"
    ):
        production.wrap_production_model_projection(
            {"OMNIGENT_SAAS_MODEL_VERIFICATION_ENABLED": "true"}, fallback=_Fallback()
        )


def _attestation_environment(tmp_path):
    source = _verification_environment(tmp_path)
    source["OMNIGENT_SAAS_MODEL_CONFIG_ATTESTATION_ENABLED"] = "true"
    for name, value in (
        (
            "LITELLM_ATTESTATION_DATABASE_URL",
            "postgresql+psycopg://omnigent_litellm_attestor:isolated-read-only@db.example:5432/omnigent_litellm?sslmode=verify-full&sslrootcert=/runtime/postgresql-ca.crt",
        ),
        ("LITELLM_SALT_KEY", "isolated-litellm-at-rest-salt-key-only"),
    ):
        path = tmp_path / name
        path.write_text(value)
        path.chmod(0o400)
        source["OMNIGENT_SAAS_" + name + "_FILE"] = str(path)
    return source


class _ReadOnlyAttestor:
    def __init__(self, engine, *, salt_key, expected_database):
        assert salt_key == "isolated-litellm-at-rest-salt-key-only"
        assert expected_database == "omnigent_litellm"
        self.engine, self.validated = engine, 0

    def validate_authority(self):
        self.validated += 1


def test_storage_attestation_is_composed_only_in_trusted_worker_with_separate_database(
    tmp_path, monkeypatch
):
    source, engines, users, disposed = _attestation_environment(tmp_path), [], [], []
    monkeypatch.setattr(production, "verify_model_projection_postgresql_state", lambda **_: None)
    monkeypatch.setattr(production, "_inspect_service_login", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(production, "LiteLLMConfigurationAttestor", _ReadOnlyAttestor)

    def build(url):
        users.append(sa.make_url(url).username)
        engine = sa.create_engine("sqlite://")
        engines.append(engine)
        sa.event.listen(engine, "engine_disposed", lambda _: disposed.append(True))
        return engine

    wrapped = production.wrap_production_model_projection(
        source,
        fallback=_Fallback(),
        engine_factory=build,
        secret_cipher_loader=lambda _: _Cipher(),
    )
    assert isinstance(wrapped, production.ProductionModelProjectionPublisher)
    assert users == [
        "model_projection_login",
        "omnigent_litellm_attestor",
        "platform_model_billing_login",
    ]
    assert wrapped.storage_attestation.validated == 1
    assert wrapped.verification._attestor is wrapped.storage_attestation
    assert "isolated-litellm-at-rest-salt-key-only" not in repr(wrapped)
    wrapped.close()
    assert len(disposed) == 3


@pytest.mark.parametrize(
    "change",
    (
        "no_verification",
        "same_database",
        "wrong_login",
        "salt_mode",
        "direct_salt",
        "invalid_flag",
    ),
)
def test_storage_attestation_configuration_rejects_wrong_or_ambient_authority(
    tmp_path, monkeypatch, change
):
    source, fallback, disposed = _attestation_environment(tmp_path), _Fallback(), []
    engine = sa.create_engine("sqlite://")
    sa.event.listen(engine, "engine_disposed", lambda _: disposed.append(True))
    if change == "no_verification":
        source["OMNIGENT_SAAS_MODEL_VERIFICATION_ENABLED"] = "false"
    elif change in {"same_database", "wrong_login"}:
        path = Path(source["OMNIGENT_SAAS_LITELLM_ATTESTATION_DATABASE_URL_FILE"])
        path.chmod(0o600)
        value = path.read_text()
        path.write_text(
            value.replace("/omnigent_litellm?", "/omnigent?")
            if change == "same_database"
            else value.replace("omnigent_litellm_attestor:", "model_projection_login:")
        )
        path.chmod(0o400)
    elif change == "salt_mode":
        Path(source["OMNIGENT_SAAS_LITELLM_SALT_KEY_FILE"]).chmod(0o600)
    elif change == "direct_salt":
        source["OMNIGENT_SAAS_LITELLM_SALT_KEY"] = "private-must-not-be-in-errors"
    else:
        source["OMNIGENT_SAAS_MODEL_CONFIG_ATTESTATION_ENABLED"] = "TRUE"
    with pytest.raises(production.ProductionModelProjectionError) as error:
        production.wrap_production_model_projection(
            source,
            fallback=fallback,
            engine_factory=lambda _: engine,
            secret_cipher_loader=lambda _: _Cipher(),
        )
    assert str(error.value) == "model_projection_startup_rejected"
    assert error.value.__suppress_context__ and not fallback.closed
    assert disposed == [True]
