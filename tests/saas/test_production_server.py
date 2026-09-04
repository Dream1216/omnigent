from __future__ import annotations

import hashlib
import os
import sys
import threading
import time
import traceback
import types
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
import sqlalchemy as sa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

from omnigent.db.db_models import current_workspace_id
from omnigent.runtime import init as init_runtime
from omnigent.server import app as official_server_app
from saas.compatibility import OmnigentStoreAdapter
from saas.control_plane.client_network import (
    TrustedClientNetworkConfig,
    TrustedClientNetworkResolver,
)
from saas.control_plane.http_auth import SaasAuthContextMiddleware
from saas.production import server as server_module
from saas.production.artifact_store import (
    BuiltProductionS3ArtifactStore,
    ProductionArtifactStoreError,
    build_production_s3_artifact_store,
)
from saas.production.server import (
    OfficialRuntimeDependencies,
    ProductionExternalAdapters,
    ProductionReadiness,
    ProductionServerCompositionError,
    RoleSessionFactories,
    SplitAuthorityApiCredentialService,
    build_production_saas_services,
    build_production_server,
    create_role_session_factories,
    load_external_adapters,
    lock_down_ambient_cloud_file_providers,
    open_private_artifact_cache_directory,
    verify_installed_build_lineage,
)
from saas.production.server_config import (
    ProductionArtifactAdmissionReceipt,
    ProductionDatabaseUrls,
    ProductionMigrationReceipt,
    ProductionS3Credentials,
    ProductionServerConfig,
    ProductionServerSecrets,
)
from saas.production.service_bindings import (
    EXPECTED_PRODUCTION_SERVICE_ROLES,
    ProductionServiceRoleBinding,
    ProductionServiceRoleBindings,
)


def _config(tmp_path: Path, *, capabilities: frozenset[str] | None = None):
    service_logins = {
        "runtime": "runtime_login",
        "authenticator": "auth_login",
        "app": "app_login",
        "governance": "governance_login",
        "public_api": "public_api_login",
        "dispatcher": "dispatcher_login",
        "executor": "executor_login",
        "secret_broker": "secret_broker_login",
        "preview_gateway": "preview_gateway_login",
    }
    for service in EXPECTED_PRODUCTION_SERVICE_ROLES:
        service_logins.setdefault(service, f"{service}_login")
    service_role_bindings = ProductionServiceRoleBindings(
        path=tmp_path / "service-role-bindings.json",
        sha256="6" * 64,
        bindings=tuple(
            ProductionServiceRoleBinding(service, service_logins[service], base_role)
            for service, base_role in sorted(EXPECTED_PRODUCTION_SERVICE_ROLES.items())
        ),
    )
    return ProductionServerConfig(
        product_revision="1" * 40,
        upstream_revision="2" * 40,
        image_digest="sha256:" + "3" * 64,
        release_incarnation="4" * 32,
        runtime_version="0.9.0",
        official_schema_revision="e5d9bc8ac650",
        control_plane_schema_revision="p0s000000007",
        adapter_contract_version="0.2.0",
        public_origin="https://next.example.test",
        capabilities=capabilities or frozenset({"tenant", "run"}),
        artifact_store_uri="s3://omnigent-production/artifacts",
        artifact_endpoint_url="https://objects.example.test",
        artifact_region="production-1",
        artifact_credential_revision="sha256:" + "f" * 64,
        artifact_admission_receipt_revision="sha256:" + "7" * 64,
        artifact_readiness_key="readiness/omnigent-saas-canary-v1",
        artifact_readiness_sha256="e" * 64,
        artifact_cache_dir=tmp_path / "cache",
        host="127.0.0.1",
        port=8000,
        cookie_name="__Host-omnigent_saas_session",
        session_ttl_seconds=3600,
        snapshot_ttl_seconds=60,
        active_key_id="v1",
        official_config_path=None,
        runner_adapter_factory=None,
        preview_adapter_factory=None,
        service_role_bindings=service_role_bindings,
        migration_receipt=ProductionMigrationReceipt(
            path=tmp_path / "migration-receipt.json",
            product_revision="1" * 40,
            official_head="e5d9bc8ac650",
            saas_head="p0s000000007",
            database_identity_sha256="4" * 64,
            catalog_sha256="5" * 64,
            service_role_bindings_sha256=service_role_bindings.sha256,
            runtime_rls_table_count=15,
        ),
        artifact_admission_receipt=ProductionArtifactAdmissionReceipt(
            path=tmp_path / "artifact-admission-receipt.json",
            source_sha256="7" * 64,
            product_revision="1" * 40,
            source_revision="1" * 40,
            image_digest="sha256:" + "3" * 64,
            release_incarnation="4" * 32,
            artifact_store_uri_sha256="8" * 64,
            artifact_endpoint_url_sha256="9" * 64,
            artifact_region="production-1",
            credential_revision="sha256:" + "f" * 64,
            verified_key_spaces=(
                "admission",
                "file_id",
                "agent_bundle",
                "executor_storage",
            ),
            object_key_sha256s=(
                ("admission", "a" * 64),
                ("file_id", "b" * 64),
                ("agent_bundle", "c" * 64),
                ("executor_storage", "d" * 64),
            ),
            operations=("put", "head", "get_hash", "delete"),
            completed_at="2026-09-01T00:00:00+00:00",
        ),
        secrets=ProductionServerSecrets(
            database_urls=ProductionDatabaseUrls(
                runtime="postgresql+psycopg://runtime_login:secret@db/omnigent?sslmode=verify-full",
                authenticator="postgresql+psycopg://auth_login:secret@db/omnigent?sslmode=verify-full",
                app="postgresql+psycopg://app_login:secret@db/omnigent?sslmode=verify-full",
                governance="postgresql+psycopg://governance_login:secret@db/omnigent?sslmode=verify-full",
                public_api="postgresql+psycopg://public_api_login:secret@db/omnigent?sslmode=verify-full",
            ),
            api_credential_pepper=b"a" * 32,
            cursor_hmac_key=b"b" * 32,
            idempotency_hmac_key=b"c" * 32,
            context_snapshot_key=b"d" * 32,
            preview_exchange_hmac_key=b"e" * 32,
            artifact_credentials=ProductionS3Credentials(
                source_path=tmp_path / "artifact-credentials",
                source_sha256="f" * 64,
                profile="omnigent-saas-artifacts",
                access_key_id="access-key-id-123456",
                secret_access_key="secret-access-key-1234567890",
            ),
        ),
    )


def _sessions() -> RoleSessionFactories:
    engines = tuple(sa.create_engine("sqlite://") for _ in range(5))
    return RoleSessionFactories(
        runtime_engine=engines[0],
        authenticator=sessionmaker(engines[1], expire_on_commit=False),
        app=sessionmaker(engines[2], expire_on_commit=False),
        governance=sessionmaker(engines[3], expire_on_commit=False),
        public_api=sessionmaker(engines[4], expire_on_commit=False),
        _engines=engines,
    )


def _official() -> OfficialRuntimeDependencies:
    dependencies: dict[str, Any] = {
        name: object()
        for name in (
            "agent_store",
            "file_store",
            "conversation_store",
            "artifact_store",
            "agent_cache",
            "comment_store",
            "permission_store",
            "policy_store",
            "host_store",
            "scheduled_task_store",
            "project_store",
        )
    }
    return OfficialRuntimeDependencies(
        **dependencies,
        artifact_readiness_check=lambda: None,
    )


def _fake_official_app(*, integration, **_dependencies: Any) -> FastAPI:
    app = FastAPI()
    for router, prefix, tags in integration.extra_routers:
        app.include_router(router, prefix=prefix, tags=tags)
    integration.install_middleware(app)
    app.state.saas_http_integration = integration
    return app


class _OnboardingServiceStub:
    def require_network_rate_limit(self, *_args: object, **_kwargs: object) -> None:
        pass


class _OnboardingHttpServices:
    def __init__(self) -> None:
        self.closed = 0
        self.onboarding = _OnboardingServiceStub()
        self.onboarding_status = object()
        self.onboarding_client_network = TrustedClientNetworkResolver(TrustedClientNetworkConfig())
        self.integration_kwargs = {
            "onboarding": self.onboarding,
            "onboarding_status": self.onboarding_status,
            "onboarding_client_network": self.onboarding_client_network,
        }

    def close(self) -> None:
        self.closed += 1


def test_import_is_side_effect_free_with_no_configuration() -> None:
    # Collection imported the module without config, DB, migration, or app construction.
    assert callable(server_module.main)
    assert not hasattr(server_module, "app")


def test_builds_s3_store_with_only_explicit_validated_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import boto3

    business_client = object()
    readiness_client = object()
    captured: list[dict[str, Any]] = []

    def _client(service: str, **kwargs: Any) -> object:
        captured.append({"service": service, **kwargs})
        return (business_client, readiness_client)[len(captured) - 1]

    monkeypatch.setattr(boto3, "client", _client)
    built = build_production_s3_artifact_store(_config(tmp_path))

    assert built.client is business_client
    assert built.readiness_client is readiness_client
    assert built.store._client is business_client
    assert len(captured) == 2
    for call in captured:
        assert call["service"] == "s3"
        assert call["endpoint_url"] == "https://objects.example.test"
        assert call["region_name"] == "production-1"
        assert call["aws_access_key_id"] == "access-key-id-123456"
        assert call["aws_secret_access_key"] == "secret-access-key-1234567890"
        assert "aws_session_token" not in call
    readiness_config = captured[1]["config"]
    assert readiness_config.connect_timeout == 0.5
    assert readiness_config.read_timeout == 0.75
    assert readiness_config.retries["total_max_attempts"] == 1


def test_s3_client_composition_redacts_provider_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import boto3

    leaked = "access-key-id-123456 secret-access-key-1234567890"

    def fail_client(_service: str, **_kwargs: Any) -> object:
        raise RuntimeError(leaked)

    monkeypatch.setattr(boto3, "client", fail_client)
    with pytest.raises(ProductionArtifactStoreError) as captured:
        build_production_s3_artifact_store(_config(tmp_path))
    rendered = "".join(
        traceback.format_exception(
            type(captured.value), captured.value, captured.value.__traceback__
        )
    )
    assert captured.value.__cause__ is None
    assert leaked not in rendered
    assert "access-key-id-123456" not in rendered
    assert "secret-access-key-1234567890" not in rendered


class _ReadinessBody:
    def __init__(self, payload: bytes, *, error: Exception | None = None) -> None:
        self.payload = payload
        self.error = error
        self.closed = False

    def read(self, amount: int) -> bytes:
        assert amount == 4097
        if self.error is not None:
            raise self.error
        return self.payload

    def close(self) -> None:
        self.closed = True


class _ReadinessClient:
    def __init__(self, payload: bytes, body: _ReadinessBody) -> None:
        self.payload = payload
        self.body = body

    def head_object(self, **kwargs: str) -> dict[str, int]:
        assert kwargs == {"Bucket": "bucket", "Key": "prefix/canary"}
        return {"ContentLength": len(self.payload)}

    def get_object(self, **kwargs: str) -> dict[str, _ReadinessBody]:
        assert kwargs == {
            "Bucket": "bucket",
            "Key": "prefix/canary",
            "Range": f"bytes=0-{len(self.payload) - 1}",
        }
        return {"Body": self.body}


def _readiness_store(
    payload: bytes,
    body: _ReadinessBody,
    *,
    digest: str | None = None,
) -> BuiltProductionS3ArtifactStore:
    client = _ReadinessClient(payload, body)
    return BuiltProductionS3ArtifactStore(
        store=object(),
        client=object(),
        readiness_client=client,
        bucket="bucket",
        readiness_object_key="prefix/canary",
        readiness_sha256=digest or hashlib.sha256(payload).hexdigest(),
    )


def test_artifact_readiness_hashes_bounded_canary_and_closes_body() -> None:
    payload = b"omnigent-saas-readiness-v1\n"
    body = _ReadinessBody(payload)
    _readiness_store(payload, body).assert_ready()
    assert body.closed is True


def test_artifact_readiness_closes_body_and_redacts_provider_failure() -> None:
    payload = b"omnigent-saas-readiness-v1\n"
    leaked = "provider-endpoint-and-secret-must-not-leak"
    body = _ReadinessBody(payload, error=RuntimeError(leaked))
    with pytest.raises(ProductionArtifactStoreError) as captured:
        _readiness_store(payload, body).assert_ready()
    assert body.closed is True
    assert captured.value.__cause__ is None
    assert leaked not in repr(captured.value)


def test_artifact_readiness_rejects_digest_mismatch() -> None:
    payload = b"omnigent-saas-readiness-v1\n"
    body = _ReadinessBody(payload)
    with pytest.raises(ProductionArtifactStoreError, match="digest does not match"):
        _readiness_store(payload, body, digest="0" * 64).assert_ready()
    assert body.closed is True


def test_private_artifact_cache_is_new_fd_pinned_and_cleaned(
    tmp_path: Path,
) -> None:
    root = tmp_path / "cache"
    cache = open_private_artifact_cache_directory(root, product_revision="1" * 40)
    child_name = cache.child_name
    (cache.path / "proof").write_text("derived", encoding="utf-8")
    assert cache.path.stat().st_mode & 0o777 == 0o700
    cache.close()
    assert not (root / child_name).exists()
    assert list(root.iterdir()) == []

    stale = root / ("2" * 12 + "-" + "3" * 32)
    stale.mkdir(mode=0o700)
    (stale / "poisoned-agent").mkdir()
    cache = open_private_artifact_cache_directory(root, product_revision="1" * 40)
    try:
        assert not stale.exists()
        assert list(cache.path.iterdir()) == []
    finally:
        cache.close()


def test_private_artifact_cache_rejects_precreated_writable_or_symlink_root(
    tmp_path: Path,
) -> None:
    writable = tmp_path / "writable"
    writable.mkdir(mode=0o700)
    writable.chmod(0o777)
    with pytest.raises(ProductionServerCompositionError, match="owner-only"):
        open_private_artifact_cache_directory(writable, product_revision="1" * 40)

    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(ProductionServerCompositionError, match="unsafe"):
        open_private_artifact_cache_directory(link, product_revision="1" * 40)


def test_builds_tenant_and_public_run_services_with_version_and_readiness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions = _sessions()
    monkeypatch.setattr(server_module, "create_omnigent_saas_app", _fake_official_app)
    try:
        onboarding = _OnboardingHttpServices()
        services = build_production_saas_services(
            _config(tmp_path),
            sessions,
            onboarding=cast(Any, onboarding),
        )
        assert services.integration.public_api_router is not None
        assert services.integration.onboarding_ui_router is not None
        assert isinstance(services.integration.runtime_store_adapter, OmnigentStoreAdapter)
        assert (
            services.integration.runtime_store_adapter.adapter_contract_version
            == _config(tmp_path).adapter_contract_version
        )
        assert services.integration.cookie_config.secure is True
        assert services.integration.cookie_config.trusted_origins == frozenset(
            {"https://next.example.test"}
        )

        built_onboarding = _OnboardingHttpServices()
        built = build_production_server(
            _config(tmp_path),
            sessions,
            official=_official(),
            onboarding=cast(Any, built_onboarding),
        )
        assert {"/signup", "/signup/verify", "/signup/status"}.issubset(
            {getattr(route, "path", None) for route in built.app.routes}
        )
        runtime_context_middleware = next(
            middleware
            for middleware in built.app.user_middleware
            if middleware.cls is SaasAuthContextMiddleware
        )
        assert (
            runtime_context_middleware.kwargs["runtime_store_adapter"]
            is built.app.state.saas_http_integration.runtime_store_adapter
        )
        with TestClient(built.app, base_url="https://next.example.test") as client:
            ready = client.get("/saas/readyz")
            assert ready.status_code == 200
            assert ready.json() == {"status": "ready"}
            assert ready.headers["cache-control"] == "no-store"

            version = client.get("/saas/version")
            assert version.status_code == 200
            assert version.json() == {
                "product_revision": "1" * 40,
                "upstream_revision": "2" * 40,
                "image_digest": "sha256:" + "3" * 64,
                "release_incarnation": "4" * 32,
                "runtime_version": "0.9.0",
                "official_schema_revision": "e5d9bc8ac650",
                "control_plane_schema_revision": "p0s000000007",
                "adapter_contract_version": "0.2.0",
                "service_role_bindings_sha256": "6" * 64,
                "artifact_credential_revision": "sha256:" + "f" * 64,
                "artifact_admission_receipt_sha256": "7" * 64,
                "capabilities": ["run", "tenant"],
            }
            assert version.headers["cache-control"] == "no-store"
        built.close()
        built.close()
        assert built_onboarding.closed == 1
        services.close()
        assert onboarding.closed == 1
    finally:
        sessions.close()


def test_runtime_database_is_a_mandatory_readiness_dependency(tmp_path: Path) -> None:
    sessions = _sessions()
    runtime_statements: list[str] = []

    @sa.event.listens_for(sessions.runtime_engine, "before_cursor_execute")
    def fail_runtime_probe(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        runtime_statements.append(statement)
        raise RuntimeError("runtime database unavailable")

    try:
        with pytest.raises(ProductionServerCompositionError, match=r"database[.]runtime"):
            build_production_saas_services(_config(tmp_path), sessions)
        assert runtime_statements == ["SELECT 1"]
    finally:
        sessions.close()


class _ReadyAdapter:
    def __init__(self, *, ready: bool = True) -> None:
        self.ready = ready
        self.calls = 0

    def assert_production_ready(self) -> None:
        self.calls += 1
        if not self.ready:
            raise RuntimeError("not ready")


@pytest.mark.parametrize("capability", ("runner", "preview"))
def test_required_external_capability_fails_before_app_construction(
    tmp_path: Path,
    capability: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions = _sessions()
    constructed = False

    def forbidden_app(**_kwargs: Any) -> FastAPI:
        nonlocal constructed
        constructed = True
        return FastAPI()

    monkeypatch.setattr(server_module, "create_omnigent_saas_app", forbidden_app)
    config = _config(tmp_path, capabilities=frozenset({"tenant", "run", capability}))
    try:
        with pytest.raises(ProductionServerCompositionError, match=capability):
            build_production_server(config, sessions, official=_official())
        assert constructed is False
    finally:
        sessions.close()


def test_external_adapter_and_dependency_readiness_are_fail_closed(tmp_path: Path) -> None:
    sessions = _sessions()
    config = _config(tmp_path, capabilities=frozenset({"tenant", "run", "runner"}))
    runner = _ReadyAdapter()
    try:
        services = build_production_saas_services(
            config,
            sessions,
            external=ProductionExternalAdapters(runner=runner),
        )
        assert services.readiness.failures() == ()
        assert runner.calls >= 1

        with pytest.raises(ProductionServerCompositionError, match=r"dependency\.probe"):
            build_production_saas_services(
                config,
                sessions,
                external=ProductionExternalAdapters(runner=runner),
                extra_readiness_checks={
                    "dependency.probe": lambda: (_ for _ in ()).throw(RuntimeError())
                },
            )
        services.readiness.close()
    finally:
        sessions.close()


def test_readiness_is_bounded_single_flight_when_dependency_hangs() -> None:
    gate = threading.Event()
    calls = 0

    def hung() -> None:
        nonlocal calls
        calls += 1
        gate.wait(timeout=2)

    readiness = ProductionReadiness({"hung.dependency": hung}, timeout_seconds=0.05)
    try:
        started = time.monotonic()
        assert readiness.failures() == ("hung.dependency",)
        assert readiness.failures() == ("hung.dependency",)
        assert time.monotonic() - started < 0.2
        assert calls == 1
    finally:
        gate.set()
        readiness.close()


def test_readiness_engines_have_isolated_connect_and_statement_timeouts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    marker = object()

    def capture(url: str, **kwargs: Any) -> object:
        captured["url"] = url
        captured.update(kwargs)
        return marker

    monkeypatch.setattr(sa, "create_engine", capture)
    assert server_module._new_readiness_engine("postgresql+psycopg://service@db/app") is marker
    assert captured["poolclass"] is sa.pool.NullPool
    assert captured["connect_args"] == {
        "connect_timeout": 1,
        "options": "-c statement_timeout=1000 -c lock_timeout=1000",
        "tcp_user_timeout": 1000,
    }


def test_role_factory_verifies_once_and_never_runs_migration(tmp_path: Path) -> None:
    config = _config(tmp_path)
    created: list[Engine] = []
    verified: list[tuple[str, ...]] = []

    def engine_factory(_url: str) -> Engine:
        engine = sa.create_engine("sqlite://")
        # create_role_session_factories checks the deployment dialect before
        # calling the verify-only contract; this controlled engine is otherwise
        # never queried in this test.
        engine.dialect.name = "postgresql"
        created.append(engine)
        return engine

    def verify(engines, supplied_config) -> None:
        assert supplied_config is config
        verified.append(tuple(engines))

    sessions = create_role_session_factories(
        config,
        verify_state=verify,
        engine_factory=engine_factory,
    )
    try:
        assert verified == [("runtime", "authenticator", "app", "governance", "public_api")]
        assert len({id(engine) for engine in sessions.engines.values()}) == 5
        assert len(created) == 10
        assert len({id(engine) for engine in sessions.readiness_engines.values()}) == 5
    finally:
        sessions.close()


def test_role_session_factories_reject_reused_engine() -> None:
    runtime = sa.create_engine("sqlite://")
    shared = sa.create_engine("sqlite://")
    factory = sessionmaker(shared)
    with pytest.raises(ProductionServerCompositionError, match="distinct engines"):
        RoleSessionFactories(
            runtime_engine=runtime,
            authenticator=factory,
            app=factory,
            governance=sessionmaker(sa.create_engine("sqlite://")),
            public_api=sessionmaker(sa.create_engine("sqlite://")),
            _engines=(runtime, shared),
        )


def test_role_session_factories_reject_incomplete_or_reused_readiness_engines() -> None:
    business = tuple(sa.create_engine("sqlite://") for _ in range(5))
    factories = {
        "runtime_engine": business[0],
        "authenticator": sessionmaker(business[1]),
        "app": sessionmaker(business[2]),
        "governance": sessionmaker(business[3]),
        "public_api": sessionmaker(business[4]),
        "_engines": business,
    }
    probe = sa.create_engine("sqlite://")
    with pytest.raises(ProductionServerCompositionError, match="exact five"):
        RoleSessionFactories(
            **factories,
            _readiness_engines={"runtime": probe},
        )
    with pytest.raises(ProductionServerCompositionError, match="distinct from every"):
        RoleSessionFactories(
            **factories,
            _readiness_engines={
                "runtime": business[0],
                "authenticator": probe,
                "app": probe,
                "governance": probe,
                "public_api": probe,
            },
        )
    for engine in (*business, probe):
        engine.dispose()


def test_official_dependency_mapping_never_contains_auth_or_database_url() -> None:
    values = _official().as_app_dependencies()
    assert "auth_provider" not in values
    assert "database_url" not in values
    assert "migration" not in " ".join(values)


def test_official_config_is_nonsecret_integrity_protected_and_never_expands_env(
    tmp_path: Path,
) -> None:
    path = tmp_path / "official.yaml"
    path.write_text(
        "execution_timeout: 600\nllm:\n  model: openai/gpt-5.4\n  max_tokens: 1024\n",
        encoding="utf-8",
    )
    path.chmod(0o644)
    loaded = server_module._load_official_config(path)
    assert loaded["llm"]["model"] == "openai/gpt-5.4"

    for index, unsafe in enumerate(
        (
            "llm:\n  model: bedrock/model\n  connection:\n    aws_secret_access_key: leaked\n",
            "llm:\n  model: openai/model\n  temperature: ${LEAKED_SECRET}\n",
            "sandbox:\n  provider: kubernetes\n",
        )
    ):
        candidate = tmp_path / f"unsafe-{index}.yaml"
        candidate.write_text(unsafe, encoding="utf-8")
        candidate.chmod(0o644)
        with pytest.raises(ProductionServerCompositionError):
            server_module._load_official_config(candidate)

    malformed = tmp_path / "malformed.yaml"
    leaked = "secret-parser-line-must-not-reach-traceback"
    malformed.write_text(f"llm: [ {leaked}\n", encoding="utf-8")
    malformed.chmod(0o644)
    with pytest.raises(ProductionServerCompositionError) as captured:
        server_module._load_official_config(malformed)
    assert captured.value.__cause__ is None
    assert leaked not in repr(captured.value)


@pytest.mark.parametrize(
    "llm_document",
    (
        "llm:\n  model: bedrock/anthropic.claude-v2\n",
        "llm:\n  model: vertex/gemini-pro\n",
        "llm:\n  model: openai/gpt-5.4\n  fallback_models:\n    - databricks/model\n",
        "policies:\n  reviewed:\n    type: prompt\n    llm:\n      model: bedrock/model\n",
    ),
)
def test_official_config_rejects_bedrock_without_reviewed_secret_broker(
    tmp_path: Path,
    llm_document: str,
) -> None:
    path = tmp_path / "bedrock.yaml"
    path.write_text(llm_document, encoding="utf-8")
    path.chmod(0o644)
    with pytest.raises(ProductionServerCompositionError, match="ambient provider"):
        server_module._load_official_config(path)


def test_locks_every_ambient_cloud_file_provider_after_validation() -> None:
    environment = {"AWS_EC2_METADATA_DISABLED": "true", "HOME": "/attacker/home"}
    lock_down_ambient_cloud_file_providers(environment)
    assert environment["AWS_CONFIG_FILE"] == "/dev/null"
    assert environment["AWS_SHARED_CREDENTIALS_FILE"] == "/dev/null"
    assert environment["BOTO_CONFIG"] == "/dev/null"
    assert environment["DATABRICKS_CONFIG_FILE"] == "/dev/null"
    assert environment["GOOGLE_APPLICATION_CREDENTIALS"] == "/dev/null"
    assert environment["HOME"] == "/attacker/home"

    for name in (
        "AWS_CONFIG_FILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "BOTO_CONFIG",
        "DATABRICKS_CONFIG_FILE",
        "GOOGLE_APPLICATION_CREDENTIALS",
    ):
        with pytest.raises(ProductionServerCompositionError, match="not validated"):
            lock_down_ambient_cloud_file_providers(
                {
                    "AWS_EC2_METADATA_DISABLED": "true",
                    name: "/attacker/provider-file",
                }
            )


@pytest.mark.parametrize("provider", ("credential_process", "shared", "legacy_boto"))
def test_locked_boto_chain_never_reads_any_home_file_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    provider: str,
) -> None:
    from botocore.session import Session

    for name in tuple(os.environ):
        if name.startswith("AWS_") or name == "BOTO_CONFIG":
            monkeypatch.delenv(name, raising=False)
    home = tmp_path / provider / "untrusted-home"
    aws = home / ".aws"
    aws.mkdir(parents=True)
    marker = tmp_path / "credential-process-ran"
    if provider == "credential_process":
        process = tmp_path / "credential-process.py"
        process.write_text(
            "#!/usr/bin/env python3\n"
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('ran', encoding='utf-8')\n"
            'print(\'{"Version":1,"AccessKeyId":"from-process",\''
            '\'"SecretAccessKey":"from-process-secret"}\')\n',
            encoding="utf-8",
        )
        process.chmod(0o700)
        (aws / "config").write_text(
            f"[default]\ncredential_process = {process}\n",
            encoding="utf-8",
        )
    elif provider == "shared":
        (aws / "credentials").write_text(
            "[default]\naws_access_key_id = from-home\naws_secret_access_key = from-home-secret\n",
            encoding="utf-8",
        )
    else:
        (home / ".boto").write_text(
            "[Credentials]\naws_access_key_id = from-boto\n"
            "aws_secret_access_key = from-boto-secret\n",
            encoding="utf-8",
        )
    monkeypatch.setenv("HOME", str(home))
    locked_environment = {"AWS_EC2_METADATA_DISABLED": "true"}
    lock_down_ambient_cloud_file_providers(locked_environment)
    for name, value in locked_environment.items():
        monkeypatch.setenv(name, value)

    assert Session().get_credentials() is None
    assert not marker.exists()


def test_official_dependency_repr_never_exposes_raw_server_config() -> None:
    leaked = "nested-secret-must-stay-redacted"
    dependencies = replace(_official(), server_config={"llm": {"connection": leaked}})
    assert leaked not in repr(dependencies)


def test_production_composition_forces_context_free_official_jobs_off(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions = _sessions()
    captured: dict[str, Any] = {}

    def capture_dependencies(*, integration, **dependencies: Any) -> FastAPI:
        captured.update(dependencies)
        return _fake_official_app(integration=integration, **dependencies)

    monkeypatch.setattr(server_module, "create_omnigent_saas_app", capture_dependencies)
    try:
        config = _config(tmp_path)
        assert config.official_builtin_agent_seed_enabled is False
        assert config.official_cross_workspace_scheduler_enabled is False

        build_production_server(config, sessions, official=_official())

        assert captured["suppress_context_free_builtin_seed"] is True
        assert captured["scheduled_task_store"] is None
    finally:
        sessions.close()


class _CrossWorkspaceSchedulerTrap:
    def __init__(self) -> None:
        self.calls = 0

    def list_active_all_workspaces(self) -> list[Any]:
        self.calls += 1
        return []


def test_production_lifespan_never_seeds_workspace_zero_or_advertises_scheduler(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions = _sessions()
    seed_workspace_ids: list[int] = []
    scheduler_store = _CrossWorkspaceSchedulerTrap()
    official = replace(_official(), scheduled_task_store=scheduler_store)
    init_runtime(
        conversation_store=official.conversation_store,
        agent_store=official.agent_store,
        agent_cache=official.agent_cache,
        file_store=official.file_store,
        artifact_store=official.artifact_store,
        comment_store=official.comment_store,
        policy_store=official.policy_store,
    )

    def record_context_free_seed(*_args: Any) -> None:
        seed_workspace_ids.append(current_workspace_id())

    monkeypatch.setattr(official_server_app, "_ensure_default_agents", record_context_free_seed)
    try:
        built = build_production_server(_config(tmp_path), sessions, official=official)
        route_paths = {getattr(route, "path", None) for route in built.app.routes}
        assert "/v1/scheduled-tasks" not in route_paths

        with TestClient(built.app):
            assert getattr(built.app.state, "scheduled_task_scheduler", None) is None

        assert seed_workspace_ids == []
        assert scheduler_store.calls == 0
    finally:
        sessions.close()


def test_official_nonproduction_lifespan_keeps_builtin_seed_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded_workspaces: list[int] = []
    official = replace(
        _official(),
        permission_store=None,
        scheduled_task_store=None,
    )
    init_runtime(
        conversation_store=official.conversation_store,
        agent_store=official.agent_store,
        agent_cache=official.agent_cache,
        file_store=official.file_store,
        artifact_store=official.artifact_store,
        comment_store=official.comment_store,
        policy_store=official.policy_store,
    )

    def record_seed(*_args: Any) -> None:
        seeded_workspaces.append(current_workspace_id())

    monkeypatch.setattr(official_server_app, "_ensure_default_agents", record_seed)
    app = official_server_app.create_app(**official.as_app_dependencies())

    with TestClient(app):
        pass

    assert seeded_workspaces == [0]


class _CredentialAuthority:
    def __init__(self, label: str) -> None:
        self.label = label
        self.calls: list[str] = []

    def authenticate(self, _token: str, *, source_ip: str | None):
        self.calls.append(f"authenticate:{source_ip}")
        return self.label

    def require_permission(self, _principal, **_scope) -> None:
        self.calls.append("require_permission")

    def create_service_account(self, **_command):
        self.calls.append("create_service_account")
        return self.label


def test_api_credential_facade_splits_authentication_from_governance() -> None:
    authenticator = _CredentialAuthority("authenticator")
    governance = _CredentialAuthority("governance")
    facade = SplitAuthorityApiCredentialService(
        authenticator=authenticator,  # type: ignore[arg-type]
        governance=governance,  # type: ignore[arg-type]
    )

    assert facade.authenticate("omk_token", source_ip="192.0.2.1") == "authenticator"
    assert facade.create_service_account() == "governance"
    assert authenticator.calls == ["authenticate:192.0.2.1"]
    assert governance.calls == ["create_service_account"]


def test_external_factory_loader_accepts_config_factory_and_rejects_incomplete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = types.ModuleType("deployment_runtime")
    adapter = _ReadyAdapter()

    def factory(*, config):
        assert config.product_revision == "1" * 40
        assert not hasattr(config, "secrets")
        assert not hasattr(config, "artifact_store_uri")
        assert "password" not in repr(config)
        assert "secret-access-key" not in repr(config)
        return adapter

    module.factory = factory  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "deployment_runtime", module)
    config = replace(
        _config(tmp_path),
        capabilities=frozenset({"tenant", "run", "runner"}),
        runner_adapter_factory="deployment_runtime:factory",
    )
    loaded = load_external_adapters(config)
    assert loaded.runner is adapter

    module.factory = lambda: object()  # type: ignore[attr-defined]
    with pytest.raises(ProductionServerCompositionError, match="incomplete"):
        load_external_adapters(config)


def test_build_lineage_mismatch_prevents_every_database_connection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    connections = 0

    def forbidden_role_factories(*_args, **_kwargs):
        nonlocal connections
        connections += 1
        raise AssertionError("database factory must not be reached")

    from omnigent import _build_info

    monkeypatch.setattr(_build_info, "COMMIT_SHA", "9" * 40)
    monkeypatch.setattr(server_module, "load_production_server_config", lambda: config)
    monkeypatch.setattr(server_module, "create_role_session_factories", forbidden_role_factories)
    with pytest.raises(ProductionServerCompositionError, match="does not match"):
        server_module.main()
    assert connections == 0


def test_main_injects_production_onboarding_before_server_build(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    sessions = _sessions()
    onboarding = _OnboardingHttpServices()
    observed: dict[str, object] = {}

    class StopBuild(RuntimeError):
        pass

    def stop_build(
        supplied_config: ProductionServerConfig,
        supplied_sessions: RoleSessionFactories,
        **kwargs: object,
    ) -> None:
        observed.update(kwargs)
        assert supplied_config is config
        assert supplied_sessions is sessions
        raise StopBuild

    monkeypatch.setattr(server_module, "load_production_server_config", lambda: config)
    monkeypatch.setattr(server_module, "verify_installed_build_lineage", lambda _config: None)
    monkeypatch.setattr(
        server_module,
        "lock_down_ambient_cloud_file_providers",
        lambda _environment: None,
    )
    monkeypatch.setattr(
        server_module,
        "load_external_adapters",
        lambda _config: ProductionExternalAdapters(),
    )
    monkeypatch.setattr(
        server_module,
        "create_role_session_factories",
        lambda *_args, **_kwargs: sessions,
    )
    monkeypatch.setattr(
        server_module,
        "build_production_onboarding_http_services",
        lambda: onboarding,
    )
    monkeypatch.setattr(server_module, "build_production_server", stop_build)

    with pytest.raises(StopBuild):
        server_module.main()

    assert observed["onboarding"] is onboarding


def test_build_lineage_accepts_exact_installed_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    from omnigent import _build_info

    monkeypatch.setattr(_build_info, "COMMIT_SHA", config.product_revision)
    verify_installed_build_lineage(config)
