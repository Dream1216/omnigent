from __future__ import annotations

import json
import sys
from types import SimpleNamespace
from uuid import uuid4

import pytest

from saas.production import customer_auth_restore as restore_cli
from saas.production.credential_worker_config import load_credential_maintenance_config
from saas.production.server_config import ProductionServerConfigError
from tests.saas.test_credential_worker_config import minimal_environment
from tests.saas.test_customer_auth_restore import REVISION
from tests.saas.test_identity_sync import source as source


def install_cli(monkeypatch, source):
    monkeypatch.setattr(
        restore_cli,
        "load_credential_maintenance_config",
        lambda _: SimpleNamespace(product_revision=REVISION),
    )
    monkeypatch.setattr(restore_cli, "verify_installed_build_lineage", lambda _: None)
    monkeypatch.setattr(
        restore_cli,
        "create_credential_worker_sessions",
        lambda *_a, **_kw: SimpleNamespace(authenticator=source.sessions, close=lambda: None),
    )


def test_private_review_apply_permissions_and_existing_output_are_closed(
    source, monkeypatch, tmp_path, capsys
):
    install_cli(monkeypatch, source)
    output = tmp_path / "review.json"
    command = [
        "customer-restore",
        "review",
        "--restore-id",
        str(uuid4()),
        "--backup-set-sha256",
        "b" * 64,
        "--output",
        str(output),
    ]
    monkeypatch.setattr(sys, "argv", command)
    assert restore_cli.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert output.stat().st_mode & 0o777 == 0o600
    original = output.read_bytes()
    assert restore_cli.main() == 1
    capsys.readouterr()
    assert output.read_bytes() == original
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "customer-restore",
            "apply",
            "--review-file",
            str(output),
            "--review-sha256",
            result["result"]["review_sha256"],
            "--review-reference",
            "owned/RESTORE-123",
        ],
    )
    output.chmod(0o644)
    assert restore_cli.main() == 1
    capsys.readouterr()
    output.chmod(0o600)
    assert restore_cli.main() == 0
    assert not json.loads(capsys.readouterr().out)["result"]["duplicate"]


def test_restore_failure_is_content_blind(monkeypatch, capsys):
    private = "secret-driver-password-and-private-review-content"

    def fail(_source):
        raise RuntimeError(private)

    monkeypatch.setattr(restore_cli, "load_credential_maintenance_config", fail)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "customer-restore",
            "apply",
            "--review-file",
            "/never-read",
            "--review-sha256",
            "b" * 64,
            "--review-reference",
            "owned/RESTORE-123",
        ],
    )
    assert restore_cli.main() == 1
    output = capsys.readouterr()
    assert private not in output.out + output.err
    assert json.loads(output.out)["error"] == "customer_restore_rejected"


def test_maintenance_environment_excludes_provider_and_online_authorities(tmp_path):
    environment = minimal_environment(tmp_path)
    assert load_credential_maintenance_config(environment).product_revision
    for key in (
        "OMNIGENT_SAAS_IDENTITY_READER_SECRET_FILE",
        "OMNIGENT_SAAS_CASDOOR_WEBHOOK_SECRET_FILE",
        "OMNIGENT_SAAS_IDENTITY_REPLAY_KEYS_FILE",
        "OMNIGENT_SAAS_RUNTIME_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_UNKNOWN_RESTORE_SWITCH",
    ):
        with pytest.raises(ProductionServerConfigError, match="unrelated authority"):
            load_credential_maintenance_config(environment | {key: "/never-read"})
