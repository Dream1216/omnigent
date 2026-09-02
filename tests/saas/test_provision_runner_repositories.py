from __future__ import annotations

import json
from pathlib import Path
from types import MappingProxyType

import pytest

import saas.scripts.provision_runner_repositories as cli
from saas.production.repository_mirror import RepositoryMirrorReceipt


def test_cli_emits_only_secret_free_receipt_hashes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    spec = tmp_path / "provisioning.json"
    receipt = RepositoryMirrorReceipt(
        bindings_file=tmp_path / "bindings.json",
        receipt_file=tmp_path / "receipt.json",
        bindings_sha256="1" * 64,
        receipt_sha256="2" * 64,
        spec_sha256="3" * 64,
        bindings=MappingProxyType({"repository": tmp_path / "mirror.git"}),
    )
    observed: dict[str, object] = {}

    def provision(path: Path, **kwargs: object) -> RepositoryMirrorReceipt:
        observed.update({"path": path, **kwargs})
        return receipt

    monkeypatch.setattr(cli, "provision_repository_mirrors", provision)

    assert cli.main(["--spec", str(spec), "--expected-binding-key", "primary"]) == 0

    output = capsys.readouterr()
    assert output.err == ""
    assert json.loads(output.out) == {
        "bindings_sha256": "1" * 64,
        "receipt_sha256": "2" * 64,
        "schema_version": 1,
        "spec_sha256": "3" * 64,
        "status": "pass",
    }
    assert "mirror.git" not in output.out
    assert observed == {
        "path": spec,
        "expected_binding_keys": ("primary",),
        "expected_credential_files": {
            "primary": Path("/provisioning-private/credentials/primary.credential")
        },
    }


def test_cli_redacts_fetch_and_credential_failures(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    def fail(_path: Path, **_kwargs: object) -> None:
        raise RuntimeError("https://runner:plaintext-secret@example.test/acme/repository.git")

    monkeypatch.setattr(cli, "provision_repository_mirrors", fail)

    assert (
        cli.main(
            [
                "--spec",
                str(tmp_path / "provisioning.json"),
                "--expected-binding-key",
                "primary",
            ]
        )
        == 1
    )

    output = capsys.readouterr()
    assert output.err == ""
    assert json.loads(output.out) == {
        "code": "runner_repository_provisioning_failed",
        "schema_version": 1,
        "status": "fail",
    }
    assert "plaintext-secret" not in output.out
    assert "example.test" not in output.out


def test_cli_rejects_repeated_beta_binding_profile(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        cli,
        "provision_repository_mirrors",
        lambda *_args, **_kwargs: pytest.fail("invalid profile reached provisioning"),
    )

    assert (
        cli.main(
            [
                "--spec",
                str(tmp_path / "provisioning.json"),
                "--expected-binding-key",
                "primary",
                "--expected-binding-key",
                "primary",
            ]
        )
        == 1
    )
    assert json.loads(capsys.readouterr().out) == {
        "code": "runner_repository_provisioning_failed",
        "schema_version": 1,
        "status": "fail",
    }
