from __future__ import annotations

from pathlib import Path

import pytest

from saas.scripts.aliyun_sandbox_probe import host_prerequisites_ready, load_config


def _credentials(tmp_path: Path, *, endpoint: str | None = None) -> Path:
    target = tmp_path / "aliyun.env"
    target.write_text(
        "E2B_API_KEY=e2b_"
        + "x" * 32
        + "\n"
        + "E2B_API_URL="
        + (endpoint or "https://api.cn-hangzhou.sandbox.aliyuncs.com")
        + "\nE2B_DOMAIN=cn-hangzhou.sandbox.aliyuncs.com\n"
        + "E2B_TEMPLATE_ID=0mipsyhtqfvkegns0jbw\n"
    )
    target.chmod(0o600)
    return target


def test_credential_repr_never_contains_key(tmp_path: Path) -> None:
    config = load_config(_credentials(tmp_path))
    assert "e2b_" not in repr(config)
    assert config.sdk_options()["api_key"] == "e2b_" + "x" * 32


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://api.cn-hangzhou.sandbox.aliyuncs.com",
        "https://api.cn-hangzhou.sandbox.aliyuncs.com.attacker.example",
        "https://attacker.example",
        "https://api.cn-hangzhou.sandbox.aliyuncs.com/redirect",
    ],
)
def test_rejects_credentials_sent_to_unreviewed_endpoint(tmp_path: Path, endpoint: str) -> None:
    with pytest.raises(ValueError, match="reviewed Hangzhou"):
        load_config(_credentials(tmp_path, endpoint=endpoint))


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o660])
def test_rejects_shared_credential_file(tmp_path: Path, mode: int) -> None:
    path = _credentials(tmp_path)
    path.chmod(mode)
    with pytest.raises(ValueError, match="owner-only"):
        load_config(path)


def test_rejects_symlink_and_hardlink_credentials(tmp_path: Path) -> None:
    source = _credentials(tmp_path)
    link = tmp_path / "symlink.env"
    link.symlink_to(source)
    with pytest.raises(ValueError, match="unavailable"):
        load_config(link)
    hardlink = tmp_path / "hardlink.env"
    hardlink.hardlink_to(source)
    with pytest.raises(ValueError, match="owner-only"):
        load_config(hardlink)


def test_rejects_duplicate_endpoint_assignment(tmp_path: Path) -> None:
    path = _credentials(tmp_path)
    with path.open("a") as stream:
        stream.write("E2B_API_URL=https://attacker.example\n")
    with pytest.raises(ValueError, match="duplicate"):
        load_config(path)


def test_does_not_evaluate_shell_payload(tmp_path: Path) -> None:
    path = _credentials(tmp_path)
    marker = tmp_path / "shell-executed"
    with path.open("a") as stream:
        stream.write(f"UNUSED=$(touch {marker})\n")
    load_config(path)
    assert not marker.exists()


@pytest.mark.parametrize("template", ["../other", "https://attacker.example", "", "x\nvalue"])
def test_rejects_invalid_template(tmp_path: Path, template: str) -> None:
    with pytest.raises(ValueError, match="template"):
        load_config(_credentials(tmp_path), template)


@pytest.mark.parametrize("node_version", ["v20.20.2", "v22.12.0", "unknown", None])
def test_installed_node_does_not_hide_unsupported_runtime(node_version: str | None) -> None:
    inventory = {
        "python": "3.13.13",
        "node_version": node_version,
        "uid": 1000,
        "omnigent_installed": True,
        "tools": dict.fromkeys(("git", "tmux", "node", "bwrap"), "/usr/bin/tool"),
    }
    assert not host_prerequisites_ready(inventory)
    inventory["node_version"] = "v22.13.0"
    assert host_prerequisites_ready(inventory)
