from __future__ import annotations

import json
import stat
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest

import saas.scripts.stage_runner_database_fleet as stage_module
from saas.production.runner_database_fleet import (
    RUNNER_DATABASE_FLEET_STAGE_TOKEN_OUTPUT_FILE_ENV,
    RunnerDatabaseFleetError,
    StagedRunnerDatabaseFleetMember,
)

_RUNNER_A = UUID("11111111-1111-4111-8111-111111111111")
_RUNNER_B = UUID("22222222-2222-4222-8222-222222222222")


class _Engine:
    disposed = False

    def dispose(self) -> None:
        self.disposed = True


def _staged() -> tuple[StagedRunnerDatabaseFleetMember, StagedRunnerDatabaseFleetMember]:
    return (
        StagedRunnerDatabaseFleetMember(_RUNNER_A, 1, "token-a-secret", "draining"),
        StagedRunnerDatabaseFleetMember(_RUNNER_B, 2, "token-b-secret", "draining"),
    )


def test_stage_writes_tokens_only_to_one_new_owner_only_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path.chmod(0o700)
    output = tmp_path / "runner-tokens.json"
    engine = _Engine()
    monkeypatch.setattr(stage_module, "load_runner_database_fleet_stage_specs", lambda source: ())
    monkeypatch.setattr(
        stage_module,
        "load_runner_database_fleet_stage_admin_database_url",
        lambda source: ("secret-dsn", SimpleNamespace(), Path("/admin")),
    )
    monkeypatch.setattr(
        stage_module,
        "stage_runner_database_fleet",
        lambda factory, *, specs: _staged(),
    )

    result = stage_module.stage_exact_runner_database_fleet(
        {RUNNER_DATABASE_FLEET_STAGE_TOKEN_OUTPUT_FILE_ENV: str(output)},
        engine_factory=lambda database_url: engine,  # type: ignore[arg-type,return-value]
    )

    assert result == (
        (str(_RUNNER_A), 1, "draining"),
        (str(_RUNNER_B), 2, "draining"),
    )
    assert engine.disposed is True
    assert stat.S_IMODE(output.stat().st_mode) == 0o400
    document = json.loads(output.read_text(encoding="ascii"))
    assert document == {
        "runners": [
            {
                "connection_generation": 1,
                "connection_token": "token-a-secret",
                "runner_id": str(_RUNNER_A),
                "status": "draining",
            },
            {
                "connection_generation": 2,
                "connection_token": "token-b-secret",
                "runner_id": str(_RUNNER_B),
                "status": "draining",
            },
        ],
        "schema_version": 1,
    }


def test_stage_refuses_to_replace_an_existing_token_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path.chmod(0o700)
    output = tmp_path / "runner-tokens.json"
    output.write_text("preserve", encoding="ascii")
    output.chmod(0o400)
    monkeypatch.setattr(stage_module, "load_runner_database_fleet_stage_specs", lambda source: ())
    monkeypatch.setattr(
        stage_module,
        "load_runner_database_fleet_stage_admin_database_url",
        lambda source: ("secret-dsn", SimpleNamespace(), Path("/admin")),
    )

    with pytest.raises(RunnerDatabaseFleetError, match="cannot be reserved"):
        stage_module.stage_exact_runner_database_fleet(
            {RUNNER_DATABASE_FLEET_STAGE_TOKEN_OUTPUT_FILE_ENV: str(output)},
            engine_factory=lambda database_url: pytest.fail("engine must not be created"),
        )

    assert output.read_text(encoding="ascii") == "preserve"


def test_stage_failure_envelope_never_echoes_exception_or_token(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        stage_module,
        "stage_exact_runner_database_fleet",
        lambda source: (_ for _ in ()).throw(RuntimeError("token-a-secret")),
    )

    assert stage_module.main() == 1
    assert json.loads(capsys.readouterr().out) == {
        "code": "runner_database_fleet_stage_failed",
        "schema_version": 1,
        "status": "fail",
    }
