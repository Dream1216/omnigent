from __future__ import annotations

import json

import pytest

import saas.scripts.verify_runner_database_fleet as cli


def test_fleet_admission_source_hashes_bind_all_executable_contracts() -> None:
    hashes = cli.runner_database_fleet_source_sha256s()

    assert set(hashes) == {
        "cluster_sql",
        "roles_sql",
        "runner_database_fleet",
        "runner_executor",
        "verify_runner_database_fleet",
    }
    assert all(len(value) == 64 for value in hashes.values())
    assert hashes["runner_database_fleet"] != hashes["verify_runner_database_fleet"]


def test_cli_emits_one_canonical_secret_free_success_receipt(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    receipt = {
        "evidence_context_sha256": "1" * 64,
        "runner_database_fleet_sha256": "2" * 64,
        "schema_version": 1,
        "status": "pass",
    }
    monkeypatch.setattr(cli, "admit_runner_database_fleet", lambda _source: receipt)

    assert cli.main() == 0

    output = capsys.readouterr()
    assert output.err == ""
    assert output.out == json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n"


def test_cli_redacts_all_failure_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(_source: object) -> None:
        raise RuntimeError(
            "postgresql+psycopg://managed_admin:plaintext-secret@database.example.test/db"
        )

    monkeypatch.setattr(cli, "admit_runner_database_fleet", fail)

    assert cli.main() == 1

    output = capsys.readouterr()
    assert output.err == ""
    assert json.loads(output.out) == {
        "code": "runner_database_fleet_admission_failed",
        "schema_version": 1,
        "status": "fail",
    }
    assert "plaintext-secret" not in output.out
    assert "database.example.test" not in output.out
