from __future__ import annotations

import os
import stat
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa

from omnigent.harnesses.codex_native.app_server import resolve_native_codex_launch
from omnigent.harnesses.opencode_native.provider import resolve_databricks_gateway
from omnigent.harnesses.pi_native.credentials import resolve_pi_native_provider
from saas.control_plane.isolation import (
    SandboxLaunchContract,
    ToolPolicy,
    TrustedRunnerLaunchGrant,
)
from saas.control_plane.model_provider import PlatformManagedModelRuntimeConfiguration
from saas.production import platform_model_runtime
from saas.production.platform_model_host import PlatformModelHostProcess
from saas.production.platform_model_sandbox_host import stage_platform_model_key
from saas.production.runner_control import RunnerControlError
from saas.production.runner_executor import _optional_platform_model_projection
from saas.production.service_bindings import (
    EXPECTED_PRODUCTION_SERVICE_ROLES,
    ProductionServiceRoleBinding,
    render_production_service_role_bindings,
)
from saas.runner_adapter import (
    PhysicalWorktree,
    RunnerIsolationAdapter,
    RunnerIsolationAdapterError,
)
from saas.runner_adapter.platform_models import (
    PLATFORM_MODEL_CREDENTIAL_ENV,
    activate_platform_managed_model_runtime,
    activate_platform_managed_model_secret,
    load_platform_managed_model_projection,
    project_platform_managed_model,
    render_platform_managed_model_projection,
    render_platform_model_gateway_config,
)


def _configuration() -> PlatformManagedModelRuntimeConfiguration:
    return PlatformManagedModelRuntimeConfiguration(
        provider_id="deepseek",
        base_url="https://api.deepseek.com",
        api_type="openai_chat_completions",
        allowed_models=("deepseek-flash", "deepseek-v4-pro"),
        default_model="deepseek-flash",
        monthly_budget_microusd=100_000_000,
        per_tenant_daily_token_limit=1_000_000,
        configuration_version=7,
        api_key="not-exported-provider-secret",
    )


def test_managed_sandbox_stages_projected_model_key_owner_only(tmp_path: Path) -> None:
    source = tmp_path / "projection" / "key"
    source.parent.mkdir()
    source.write_bytes(b"k" * 32 + b"\n")
    home = tmp_path / "home"
    environment = {
        "HOME": str(home),
        "OMNIGENT_MANAGED_SERVER_URL": "http://omnigent-saas-server.example.svc",
    }

    target = stage_platform_model_key(environment, source=source)

    assert target.read_bytes() == b"k" * 32
    assert stat.S_IMODE(target.stat().st_mode) == 0o400
    assert environment["OMNIGENT_SAAS_SERVER_URL"] == ("http://omnigent-saas-server.example.svc")
    assert environment["OMNIGENT_SAAS_PLATFORM_MODEL_TOKEN_KEY_FILE"] == str(target)
    assert environment["OMNIGENT_SAAS_PLATFORM_MODEL_TOKEN_TTL_SECONDS"] == "3600"


def test_projection_contains_no_secret_and_pi_defers_to_proxy_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    synthetic_token = "session-bound-gateway-token"
    monkeypatch.setenv(PLATFORM_MODEL_CREDENTIAL_ENV, synthetic_token)
    projection = project_platform_managed_model(_configuration())
    rendered = repr(projection)
    assert "not-exported-provider-secret" not in rendered
    assert projection.secret_binding.host == "api.deepseek.com"
    assert projection.secret_binding.inject_env == (PLATFORM_MODEL_CREDENTIAL_ENV,)
    assert projection.secret_binding.version_ref == "v7"

    provider = resolve_pi_native_provider(
        config_loader=lambda: projection.provider_config,
    )
    assert provider is not None
    assert provider.api_key == synthetic_token
    assert provider.model == "deepseek-flash"
    assert {
        entry["id"] for entry in provider.to_models_config()["providers"]["omnigent"]["models"]
    } == {"deepseek-flash", "deepseek-v4-pro"}


def test_gateway_projection_routes_codex_without_cli_login(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OMNIGENT_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv(PLATFORM_MODEL_CREDENTIAL_ENV, "session-bound-gateway-token")
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "config.yaml").write_text(
        render_platform_model_gateway_config(
            allowed_models=("deepseek-flash", "deepseek-v4-pro"),
            default_model="deepseek-flash",
        ),
        encoding="ascii",
    )

    launch = resolve_native_codex_launch(model=None)

    assert launch.login_required is False
    assert launch.model == "deepseek-flash"
    rendered = "\n".join(launch.config_overrides)
    assert 'base_url="http://omnigent-platform-model-gateway:8090/v1"' in rendered
    assert 'wire_api="responses"' in rendered
    assert "session-bound-gateway-token" in rendered


def test_gateway_projection_routes_opencode_without_cli_login(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OMNIGENT_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv(PLATFORM_MODEL_CREDENTIAL_ENV, "session-bound-gateway-token")
    (tmp_path / "config.yaml").write_text(
        render_platform_model_gateway_config(
            allowed_models=("deepseek-flash", "deepseek-v4-pro"),
            default_model="deepseek-flash",
        ),
        encoding="ascii",
    )

    resolution = resolve_databricks_gateway(None)

    assert resolution is not None
    assert resolution.provider_id == "platform-deepseek"
    assert resolution.api_key == "session-bound-gateway-token"
    assert resolution.model_id == "deepseek-flash"


@pytest.mark.asyncio
async def test_platform_host_promotes_only_codex_auth_readiness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OMNIGENT_CONFIG_HOME", str(tmp_path))
    (tmp_path / "config.yaml").write_text(
        render_platform_model_gateway_config(
            allowed_models=("deepseek-flash", "deepseek-v4-pro"),
            default_model="deepseek-flash",
        ),
        encoding="ascii",
    )

    async def base_probe(
        _self: object,
        *,
        startup: bool,
    ) -> dict[str, bool | str]:
        assert startup is True
        return {
            "codex": "needs-auth",
            "codex-native": "needs-auth",
            "native-codex": "needs-auth",
            "pi": True,
            "claude-native": "needs-auth",
        }

    monkeypatch.setattr(
        "omnigent.host.connect.HostProcess._probe_configured_harnesses", base_probe
    )
    host = object.__new__(PlatformModelHostProcess)

    readiness = await host._probe_configured_harnesses(startup=True)

    assert readiness == {
        "codex": True,
        "codex-native": True,
        "native-codex": True,
        "pi": True,
        "claude-native": "needs-auth",
    }


def test_projection_rejects_endpoint_or_default_model_drift() -> None:
    source = _configuration()
    for changed in (
        replace(source, base_url="https://example.com"),
        replace(source, default_model="deepseek-not-allowed"),
    ):
        try:
            project_platform_managed_model(changed)
        except ValueError:
            pass
        else:  # pragma: no cover - explicit fail-loud branch
            raise AssertionError("invalid managed model projection was accepted")


def test_activation_stages_versioned_secret_atomically_and_idempotently(
    tmp_path: Path,
) -> None:
    root = tmp_path / "runtime-secrets"
    root.mkdir(mode=0o700)
    path = activate_platform_managed_model_secret(_configuration(), secret_root=root)
    assert path == root / "platform-deepseek" / "v7"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_text() == "not-exported-provider-secret"
    assert activate_platform_managed_model_secret(_configuration(), secret_root=root) == path
    assert not tuple(path.parent.glob(".*.tmp"))


def test_activation_rejects_public_root_symlink_and_same_version_conflict(
    tmp_path: Path,
) -> None:
    public = tmp_path / "public"
    public.mkdir(mode=0o755)
    with pytest.raises(ValueError, match="not private"):
        activate_platform_managed_model_secret(_configuration(), secret_root=public)

    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(private, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic link"):
        activate_platform_managed_model_secret(_configuration(), secret_root=link)

    path = activate_platform_managed_model_secret(_configuration(), secret_root=private)
    os.chmod(path, 0o600)
    changed = replace(_configuration(), api_key="another-secret-value")
    with pytest.raises(RuntimeError, match="version conflicts"):
        activate_platform_managed_model_secret(changed, secret_root=private)


def test_projection_file_is_secret_free_canonical_and_digest_pinned(tmp_path: Path) -> None:
    projection = project_platform_managed_model(_configuration())
    rendered = render_platform_managed_model_projection(projection)
    assert "not-exported-provider-secret" not in rendered
    path = tmp_path / "platform-model-projection.json"
    path.write_text(rendered, encoding="ascii")
    path.chmod(0o444)
    digest = sha256(rendered.encode()).hexdigest()

    loaded = load_platform_managed_model_projection(path, expected_sha256=digest)
    assert loaded == projection
    with pytest.raises(ValueError, match="authority is invalid"):
        load_platform_managed_model_projection(path, expected_sha256="0" * 64)


def test_runtime_activation_publishes_only_secret_free_authority(tmp_path: Path) -> None:
    secret_root = tmp_path / "secrets"
    secret_root.mkdir(mode=0o700)
    files = activate_platform_managed_model_runtime(
        _configuration(),
        secret_root=secret_root,
        config_home=tmp_path / "config",
    )

    assert files.projection_sha256_file.read_text().strip() == files.projection_sha256
    assert stat.S_IMODE(files.config_file.stat().st_mode) == 0o444
    assert stat.S_IMODE(files.projection_file.stat().st_mode) == 0o444
    assert stat.S_IMODE(files.projection_sha256_file.stat().st_mode) == 0o444
    public = files.config_file.read_text() + files.projection_file.read_text()
    assert "not-exported-provider-secret" not in public
    assert PLATFORM_MODEL_CREDENTIAL_ENV in public
    assert files.secret_file.read_text() == "not-exported-provider-secret"


def test_official_pi_reads_materialized_config_home(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_root = tmp_path / "secrets"
    secret_root.mkdir(mode=0o700)
    files = activate_platform_managed_model_runtime(
        _configuration(),
        secret_root=secret_root,
        config_home=tmp_path / "config",
    )
    monkeypatch.setenv("OMNIGENT_CONFIG_HOME", str(files.config_home))
    synthetic_token = "session-bound-gateway-token"
    monkeypatch.setenv(PLATFORM_MODEL_CREDENTIAL_ENV, synthetic_token)

    provider = resolve_pi_native_provider()

    assert provider is not None
    assert provider.model == "deepseek-flash"
    assert provider.api_key == synthetic_token


def _owner_file(path: Path, value: str) -> Path:
    path.write_text(value, encoding="ascii")
    path.chmod(0o400)
    return path


def _runtime_environment(tmp_path: Path) -> dict[str, str]:
    bindings = tuple(
        ProductionServiceRoleBinding(
            service=service,
            login=f"svc_{service}",
            base_role=role,
        )
        for service, role in EXPECTED_PRODUCTION_SERVICE_ROLES.items()
    )
    bindings_path = _owner_file(
        tmp_path / "service-bindings.json",
        render_production_service_role_bindings(bindings),
    )
    database_path = _owner_file(
        tmp_path / "secret-broker-database-url",
        "postgresql+psycopg://svc_secret_broker:password@db.example.test/omnigent"
        "?sslmode=verify-full&sslrootcert=/runtime/postgresql-ca.crt",
    )
    config_home = tmp_path / "config"
    return {
        "OMNIGENT_CONFIG_HOME": str(config_home),
        "OMNIGENT_SAAS_RUNNER_SECRET_PROVIDER_ROOT": str(tmp_path / "secrets"),
        "OMNIGENT_SAAS_PLATFORM_MODEL_PROJECTION_FILE": str(
            config_home / "platform-model-projection.json"
        ),
        "OMNIGENT_SAAS_PLATFORM_MODEL_PROJECTION_SHA256_FILE": str(
            config_home / "platform-model-projection.sha256"
        ),
        "OMNIGENT_SAAS_SECRET_BROKER_DATABASE_URL_FILE": str(database_path),
        "OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS_FILE": str(bindings_path),
    }


def test_production_materializer_binds_database_openbao_and_runtime_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Reader:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def load(self) -> PlatformManagedModelRuntimeConfiguration:
            return _configuration()

    monkeypatch.setattr(platform_model_runtime, "ModelProviderConfigurationReader", _Reader)
    environment = _runtime_environment(tmp_path)
    result = platform_model_runtime.reconcile_platform_model_runtime(
        environ=environment,
        engine_factory=lambda _url: sa.create_engine("sqlite+pysqlite:///:memory:"),
        cipher_loader=lambda _source: object(),  # type: ignore[return-value]
        login_inspector=lambda *_args, **_kwargs: None,
    )

    assert result["status"] == "pass"
    assert result["configuration_version"] == 7
    assert result["secret_exported"] is False
    rendered = repr(result) + (tmp_path / "config" / "config.yaml").read_text()
    assert "not-exported-provider-secret" not in rendered
    assert (tmp_path / "secrets" / "platform-deepseek" / "v7").read_text() == (
        "not-exported-provider-secret"
    )


@pytest.mark.parametrize(
    ("name", "value"),
    (
        ("OMNIGENT_PLATFORM_DEEPSEEK_KEY", "ambient-secret-is-forbidden"),
        ("OMNIGENT_SAAS_PLATFORM_MODEL_PROJECTION_SHA256", "0" * 64),
    ),
)
def test_production_materializer_rejects_ambient_secret_or_mutable_digest(
    tmp_path: Path,
    name: str,
    value: str,
) -> None:
    environment = _runtime_environment(tmp_path)
    environment[name] = value
    with pytest.raises(platform_model_runtime.PlatformModelRuntimeError) as rejected:
        platform_model_runtime.reconcile_platform_model_runtime(environ=environment)
    assert rejected.value.code == "runtime_authority_invalid"
    assert value not in str(rejected.value)


def test_runner_loads_paired_projection_digest_file_and_config_home(tmp_path: Path) -> None:
    secret_root = tmp_path / "secrets"
    secret_root.mkdir(mode=0o700)
    files = activate_platform_managed_model_runtime(
        _configuration(),
        secret_root=secret_root,
        config_home=tmp_path / "config",
    )
    source = {
        "OMNIGENT_CONFIG_HOME": str(files.config_home),
        "OMNIGENT_SAAS_PLATFORM_MODEL_PROJECTION_FILE": str(files.projection_file),
        "OMNIGENT_SAAS_PLATFORM_MODEL_PROJECTION_SHA256_FILE": str(files.projection_sha256_file),
    }

    loaded = _optional_platform_model_projection(source)
    assert loaded is not None
    assert sha256(files.projection_file.read_bytes()).hexdigest() == files.projection_sha256
    assert (
        loaded[0].projection_sha256
        == project_platform_managed_model(_configuration()).projection_sha256
    )
    assert loaded[1] == files.config_home

    source["OMNIGENT_SAAS_PLATFORM_MODEL_PROJECTION_SHA256"] = files.projection_sha256
    with pytest.raises(RunnerControlError, match="projection authority"):
        _optional_platform_model_projection(source)


class _Authority:
    def __init__(self, grant: TrustedRunnerLaunchGrant) -> None:
        self.grant = grant

    def redeem_launch_grant(self, **_kwargs: object) -> TrustedRunnerLaunchGrant:
        return self.grant

    def redeem_secret(self, **_kwargs: object) -> object:
        raise AssertionError("Project secret redemption was not expected")


class _PlatformSecretProvider:
    def resolve(self, *, provider: str, vault_ref: str, version_ref: str) -> str:
        assert (provider, vault_ref, version_ref) == (
            "filesystem",
            "platform-deepseek",
            "v7",
        )
        return "not-exported-provider-secret"


class _Containment:
    def require_enforced(self, **_kwargs: object) -> None:
        return None


def _launch_grant(*, egress_rules: tuple[str, ...]) -> TrustedRunnerLaunchGrant:
    now = datetime.now(timezone.utc)
    return TrustedRunnerLaunchGrant(
        grant_id=uuid4(),
        tenant_id=uuid4(),
        space_id=uuid4(),
        project_id=uuid4(),
        run_id=uuid4(),
        runner_id=uuid4(),
        worktree_id=uuid4(),
        worktree_access_mode="writer",
        worktree_lease_generation=1,
        run_fence_token=1,
        runner_connection_generation=1,
        contract=SandboxLaunchContract(
            backend="linux_bwrap",
            network_mode="proxy_only",
            root_read_only=True,
            run_as_uid=65532,
            run_as_gid=65532,
            no_new_privileges=True,
            host_socket_access=False,
            syscall_profile_ref="oci-default-v1",
            cpu_millis=1000,
            memory_bytes=1024 * 1024,
            pids_limit=32,
            tool_policy=ToolPolicy(("sys_os_read",), (), ()),
            egress_rules=egress_rules,
            allow_private_destinations=False,
            required_runner_capabilities=(),
            config_hash="a" * 64,
        ),
        secret_leases=(),
        expires_at=now + timedelta(minutes=1),
    )


def test_runner_injects_platform_key_only_through_exact_host_proxy(tmp_path: Path) -> None:
    grant = _launch_grant(egress_rules=("POST api.deepseek.com/chat/completions",))
    worktree = tmp_path / "worktree"
    worktree.mkdir(mode=0o700)
    staging = tmp_path / "staging"
    staging.mkdir(mode=0o700)
    secret_root = tmp_path / "runtime-secrets"
    secret_root.mkdir(mode=0o700)
    runtime = activate_platform_managed_model_runtime(
        _configuration(),
        secret_root=secret_root,
        config_home=tmp_path / "runtime-config",
    )
    authority = _Authority(grant)
    adapter = RunnerIsolationAdapter(
        staging_root=staging,
        authority=authority,
        secret_provider=_PlatformSecretProvider(),
        containment=_Containment(),
        platform_model_projection=project_platform_managed_model(_configuration()),
        platform_model_config_home=runtime.config_home,
    )
    prepared = adapter.prepare(
        grant_token="grant-token",
        runner_id=grant.runner_id,
        run_id=grant.run_id,
        physical_worktree=PhysicalWorktree(
            worktree_id=grant.worktree_id,
            worktree_path=worktree,
            head_revision="a" * 40,
            actual_bytes=1024,
            readonly=False,
        ),
    )
    proxy = prepared.os_env_spec.sandbox.credential_proxy  # type: ignore[union-attr]
    assert proxy is not None and len(proxy.entries) == 1
    entry = proxy.entries[0]
    assert entry.host == "api.deepseek.com"
    assert entry.inject_env == [PLATFORM_MODEL_CREDENTIAL_ENV]
    assert entry.source.kind == "file"
    assert "not-exported-provider-secret" not in repr(prepared.os_env_spec)
    assert str(runtime.config_home) in prepared.os_env_spec.sandbox.read_paths  # type: ignore[union-attr]
    assert prepared.os_env_spec.sandbox.env_passthrough == ["OMNIGENT_CONFIG_HOME"]  # type: ignore[union-attr]
    prepared.close()


def test_runner_rejects_wildcard_or_missing_platform_model_egress(tmp_path: Path) -> None:
    for index, rules in enumerate(((), ("POST *.deepseek.com/**",))):
        grant = _launch_grant(egress_rules=rules)
        worktree = tmp_path / f"worktree-{index}"
        worktree.mkdir(mode=0o700)
        staging = tmp_path / f"staging-{index}"
        staging.mkdir(mode=0o700)
        secret_root = tmp_path / f"runtime-secrets-{index}"
        secret_root.mkdir(mode=0o700)
        runtime = activate_platform_managed_model_runtime(
            _configuration(),
            secret_root=secret_root,
            config_home=tmp_path / f"runtime-config-{index}",
        )
        adapter = RunnerIsolationAdapter(
            staging_root=staging,
            authority=_Authority(grant),
            secret_provider=_PlatformSecretProvider(),
            containment=_Containment(),
            platform_model_projection=project_platform_managed_model(_configuration()),
            platform_model_config_home=runtime.config_home,
        )
        with pytest.raises(
            RunnerIsolationAdapterError,
            match="exact Provider egress rule",
        ):
            adapter.prepare(
                grant_token="grant-token",
                runner_id=grant.runner_id,
                run_id=grant.run_id,
                physical_worktree=PhysicalWorktree(
                    worktree_id=grant.worktree_id,
                    worktree_path=worktree,
                    head_revision="a" * 40,
                    actual_bytes=1024,
                    readonly=False,
                ),
            )
