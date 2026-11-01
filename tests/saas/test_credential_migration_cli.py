from __future__ import annotations

import json
from types import SimpleNamespace
from uuid import uuid4

import pytest

from saas.control_plane.credential_migration import CredentialMigrationError
from saas.production.credential_migration_cli import load_batch, main
from tests.saas.test_credential_migration import NOW, OLD_PASSWORD
from tests.saas.test_credential_migration import source as source


def test_batch_manifest_is_bounded_unique_private_and_contains_no_credentials(tmp_path):
    path = tmp_path / "batch.json"
    user_id = str(uuid4())
    item = {
        "user_id": user_id,
        "batch_id": "reviewed-p3-batch",
        "expected_password_version": 1,
        "idempotency_key": "prepare-" + user_id,
    }
    document = {"schema_version": 1, "items": [item]}
    path.write_text(json.dumps(document))
    path.chmod(0o600)
    assert load_batch(str(path), prepare=True) == [item]
    mutations = [
        {"schema_version": True, "items": [item]},
        {"schema_version": 1, "items": []},
        {"schema_version": 1, "items": [item, item]},
        {"schema_version": 1, "items": [{**item, "password": "never accepted"}]},
        {"schema_version": 1, "items": [{**item, "expected_password_version": True}]},
        {"schema_version": 1, "items": [{**item, "batch_id": "invalid/batch"}]},
        {"schema_version": 1, "items": [{**item, "idempotency_key": ""}]},
        {"schema_version": 1, "items": [{**item, "user_id": user_id.replace("-", "")}]},
    ]
    for mutation in mutations:
        path.write_text(json.dumps(mutation))
        with pytest.raises(CredentialMigrationError, match="migration_batch_invalid"):
            load_batch(str(path), prepare=True)
    path.write_text(json.dumps(document))
    path.chmod(0o644)
    with pytest.raises(CredentialMigrationError, match="migration_batch_invalid"):
        load_batch(str(path), prepare=True)


def test_process_manifest_contains_only_explicit_receipt_ids(tmp_path):
    path = tmp_path / "receipts.json"
    items = [{"receipt_id": str(uuid4())} for _ in range(3)]
    path.write_text(json.dumps({"schema_version": 1, "items": items}))
    path.chmod(0o600)
    assert load_batch(str(path), prepare=False) == items
    with pytest.raises(CredentialMigrationError):
        load_batch(str(path), prepare=True)


def test_private_cli_checks_installed_lineage_before_any_database_authority(
    monkeypatch, tmp_path, capsys
):
    import saas.production.credential_migration_cli as cli

    path = tmp_path / "receipts.json"
    path.write_text(json.dumps({"schema_version": 1, "items": [{"receipt_id": str(uuid4())}]}))
    path.chmod(0o600)
    monkeypatch.setattr("sys.argv", ["credential-migration", "process", "--batch-file", str(path)])
    config = object()
    monkeypatch.setattr(cli, "load_production_server_config", lambda: config)
    database_calls = []
    monkeypatch.setattr(
        cli, "create_role_session_factories", lambda *a, **k: database_calls.append(a)
    )

    def refuse(value):
        assert value is config
        raise RuntimeError("private configuration must not appear in stdout")

    monkeypatch.setattr(cli, "verify_installed_build_lineage", refuse)
    with pytest.raises(SystemExit) as stopped:
        main()
    assert stopped.value.code == 1 and not database_calls
    assert json.loads(capsys.readouterr().out) == {
        "error": "credential_migration_execution_failed"
    }


def test_private_batch_cli_stages_by_default_requires_explicit_cutover_and_reports_failures(
    source, monkeypatch, tmp_path, capsys
):
    import saas.production.credential_migration_cli as cli

    receipt = source.prepare()
    batch = tmp_path / "receipts.json"
    batch.write_text(json.dumps({"schema_version": 1, "items": [{"receipt_id": str(receipt.id)}]}))
    batch.chmod(0o600)
    config = SimpleNamespace(identity=object())
    closed = []
    verified = []
    monkeypatch.setattr(cli, "load_production_server_config", lambda: config)
    monkeypatch.setattr(
        cli, "verify_installed_build_lineage", lambda value: verified.append(value)
    )
    monkeypatch.setattr(
        cli, "verify_production_postgresql_state", lambda **values: verified.append(values)
    )

    def factories(value, *, verify_state):
        assert value is config
        verify_state({"authenticator": "test-composition-only"}, value)
        return SimpleNamespace(authenticator=source.sessions, close=lambda: closed.append(True))

    monkeypatch.setattr(cli, "create_role_session_factories", factories)
    monkeypatch.setattr(
        cli,
        "load_casdoor_credential_import_config",
        lambda *args, **kwargs: SimpleNamespace(policy=lambda: source.service._policy),
    )
    monkeypatch.setattr(cli, "CasdoorCredentialImportProvider", lambda _config: source.provider)
    arguments = ["credential-migration", "process", "--batch-file", str(batch)]
    monkeypatch.setattr("sys.argv", arguments)
    main()
    assert json.loads(capsys.readouterr().out)["status"] == "imported"
    assert (
        source.passwords.authenticate("migrate@example.test", OLD_PASSWORD, now=NOW)
        == source.user_id
    )
    monkeypatch.setattr("sys.argv", [*arguments, "--cutover"])
    main()
    output = capsys.readouterr().out
    assert json.loads(output)["status"] == "completed"
    assert OLD_PASSWORD not in output and "migrate@example.test" not in output
    assert len(closed) == 2 and len(verified) == 4
    batch.write_text(json.dumps({"schema_version": 1, "items": [{"receipt_id": str(uuid4())}]}))
    with pytest.raises(SystemExit) as stopped:
        main()
    error = json.loads(capsys.readouterr().out)
    assert stopped.value.code == 1 and error["error"] == "migration_receipt_unavailable"
    assert len(closed) == 3
