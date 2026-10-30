from __future__ import annotations

import os
import stat
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest

from omnigent.host import HOST_FATAL_EXIT_CODE
from omnigent.host.identity import (
    HOST_ID_ENV_VAR,
    HOST_NAME_ENV_VAR,
    HOST_TOKEN_FILE_ENV_VAR,
    HOST_WORKSPACE_ID_ENV_VAR,
)
from saas.production import aliyun_host
from saas.production.aliyun_model_client import AliyunHostModelTokenIssuer
from saas.production.aliyun_model_lease import HostModelLeaseAuthority
from tests.saas.test_tenant_sandbox import _runtime


@pytest.fixture
def launch_files(tmp_path):
    runtime = _runtime()
    host_id, token = uuid4().hex, "h" * 43
    lease = HostModelLeaseAuthority(b"l" * 32).issue(
        host_id=host_id, launch_token=token, runtime=runtime, ttl_seconds=5400
    )
    host_file, lease_file = tmp_path / "host-token", tmp_path / "model-lease"
    host_file.write_text(token)
    lease_file.write_text(lease)
    host_file.chmod(0o400)
    lease_file.chmod(0o400)
    env = {
        HOST_ID_ENV_VAR: host_id,
        HOST_NAME_ENV_VAR: "managed-test",
        HOST_TOKEN_FILE_ENV_VAR: str(host_file),
        HOST_WORKSPACE_ID_ENV_VAR: str(runtime.physical_workspace_id),
        aliyun_host.SERVER_URL_ENV: "https://control.invalid",
        aliyun_host.MODEL_GATEWAY_URL_ENV: "https://control.invalid/platform-model/v1",
        aliyun_host.MODEL_LEASE_FILE_ENV: str(lease_file),
        aliyun_host.MODEL_TENANT_ENV: str(runtime.tenant_id),
    }
    return SimpleNamespace(
        env=env, token=token, lease=lease, host_file=host_file, lease_file=lease_file
    )


def test_cloud_host_composes_the_official_model_host_with_file_only_credentials(
    launch_files, monkeypatch
):
    c = launch_files
    for name in aliyun_host._SERVER_ONLY_ENV:
        monkeypatch.delenv(name, raising=False)
    for name, value in c.env.items():
        monkeypatch.setenv(name, value)
    run = Mock()
    monkeypatch.setattr(aliyun_host, "run_host_with_model_issuer", run)
    aliyun_host.run_aliyun_host()
    server, issuer, ttl = run.call_args.args
    assert server == "https://control.invalid" and ttl == 300
    assert isinstance(issuer, AliyunHostModelTokenIssuer)
    assert issuer._host_token == c.token and issuer._lease == c.lease
    assert run.call_args.kwargs == {
        "gateway_base_url": "https://control.invalid/platform-model/v1"
    }


@pytest.mark.parametrize("name", aliyun_host._SERVER_ONLY_ENV)
def test_cloud_host_rejects_inline_or_server_authority_before_start(launch_files, name):
    c = launch_files
    with pytest.raises(aliyun_host.AliyunHostConfigurationError) as failure:
        aliyun_host.build_aliyun_model_channel({**c.env, name: "server-only-canary"})
    assert "server-only-canary" not in str(failure.value)


@pytest.mark.parametrize("file_key", ["host_file", "lease_file"])
@pytest.mark.parametrize("mode", [0o640, 0o644, 0o660])
def test_cloud_host_rejects_shared_launch_files(launch_files, file_key, mode):
    getattr(launch_files, file_key).chmod(mode)
    with pytest.raises(aliyun_host.AliyunHostConfigurationError):
        aliyun_host.build_aliyun_model_channel(launch_files.env)


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_cloud_host_rejects_launch_file_aliases(launch_files, tmp_path, kind):
    c = launch_files
    alias = tmp_path / "alias"
    if kind == "symlink":
        alias.symlink_to(c.host_file)
    else:
        os.link(c.host_file, alias)
    env = {**c.env, HOST_TOKEN_FILE_ENV_VAR: str(alias)}
    with pytest.raises(aliyun_host.AliyunHostConfigurationError):
        aliyun_host.build_aliyun_model_channel(env)


@pytest.mark.parametrize(
    "name,value",
    [
        (HOST_WORKSPACE_ID_ENV_VAR, "0"),
        (HOST_WORKSPACE_ID_ENV_VAR, "091"),
        (HOST_WORKSPACE_ID_ENV_VAR, "-1"),
        (HOST_ID_ENV_VAR, "0" * 32),
        (HOST_ID_ENV_VAR, "not-a-host-id"),
        (aliyun_host.MODEL_TENANT_ENV, "00000000-0000-0000-0000-000000000000"),
        (aliyun_host.MODEL_GATEWAY_URL_ENV, "http://internal.invalid/v1"),
        (aliyun_host.SERVER_URL_ENV, "http://control.invalid"),
        (HOST_NAME_ENV_VAR, "name\ncommand"),
    ],
)
def test_cloud_host_requires_canonical_scope_and_tls_endpoints(launch_files, name, value):
    with pytest.raises(aliyun_host.AliyunHostConfigurationError):
        aliyun_host.build_aliyun_model_channel({**launch_files.env, name: value})


def test_invalid_cloud_host_configuration_exits_fatally_without_credential_output(
    monkeypatch, capsys
):
    monkeypatch.setenv("E2B_API_KEY", "server-only-canary")
    with pytest.raises(SystemExit) as failure:
        aliyun_host.main()
    assert failure.value.code == HOST_FATAL_EXIT_CODE
    assert "server-only-canary" not in capsys.readouterr().err


def _private_path(home):
    return home / ".omnigent" / "runtime" / ("aliyun-host-" + "a" * 32 + "-" + "b" * 24)


def test_host_credential_directory_is_fresh_and_owner_only(tmp_path):
    private = _private_path(tmp_path)
    aliyun_host.prepare_aliyun_host_directory(private, home=tmp_path)
    for directory in (private, private.parent, private.parent.parent):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    with pytest.raises(FileExistsError):
        aliyun_host.prepare_aliyun_host_directory(private, home=tmp_path)


@pytest.mark.parametrize("kind", ["symlink", "group-write", "outside-home"])
def test_host_credential_directory_rejects_untrusted_parents(tmp_path, kind):
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    private = _private_path(home)
    if kind == "symlink":
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (home / ".omnigent").symlink_to(elsewhere)
    elif kind == "group-write":
        (home / ".omnigent").mkdir()
        (home / ".omnigent").chmod(0o770)
    else:
        private = _private_path(tmp_path)
    with pytest.raises(aliyun_host.AliyunHostConfigurationError):
        aliyun_host.prepare_aliyun_host_directory(private, home=home)
    assert not private.exists()
