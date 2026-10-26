"""Model selection survives a config-sourced harness override."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import httpx
import pytest
import yaml

from omnigent.testing.process_reaper import reap_leaked_omnigent_processes

_REPO_ROOT = Path(__file__).resolve().parents[2]

_MODEL = "e2e-selected-model"
_PROVIDER = "e2e-model-pin-gateway"
_RUN_TIMEOUT_S = 300


def _seed_config_home(config_home: Path, gateway_base_url: str) -> None:
    """Configure a mock gateway and a matching default harness."""
    config_home.mkdir(parents=True, exist_ok=True)
    (config_home / "config.yaml").write_text(
        yaml.safe_dump(
            {
                "harness": "pi",
                "providers": {
                    _PROVIDER: {
                        "kind": "gateway",
                        "openai": {
                            "api_key_ref": "dummy-key-model-pin",
                            "base_url": gateway_base_url,
                            "wire_api": "chat",
                        },
                    }
                },
            }
        ),
        encoding="utf-8",
    )


def _seed_agent_dir(agent_dir: Path, model: str | None) -> None:
    executor: dict[str, object] = {
        "type": "omnigent",
        "auth": {"type": "provider", "name": _PROVIDER},
        "config": {"harness": "pi"},
    }
    if model is not None:
        executor["model"] = model
    agent_dir.mkdir(parents=True, exist_ok=True)
    (agent_dir / "config.yaml").write_text(
        yaml.safe_dump(
            {
                "spec_version": 1,
                "name": "model-pin-agent",
                "description": "regression agent for the spec-model drop",
                "executor": executor,
                "prompt": "You are a terse test agent.\n",
                "os_env": {
                    "type": "caller_process",
                    "cwd": ".",
                    "sandbox": {"type": "none"},
                },
            }
        ),
        encoding="utf-8",
    )


def _gateway_request_models(mock_url: str) -> list[str]:
    """Read the model IDs captured by the mock gateway."""
    resp = httpx.get(f"{mock_url}/mock/requests", timeout=10.0)
    resp.raise_for_status()
    return [r.get("model") for r in resp.json()["requests"] if isinstance(r, dict)]


@pytest.mark.parametrize("model_source", ["spec", "env"])
def test_run_preserves_model_under_config_harness_default(
    tmp_path: Path, isolated_mock_llm_server_url: str, model_source: str
) -> None:
    """The configured harness default preserves the selected model on the wire."""
    mock_url = isolated_mock_llm_server_url
    httpx.post(
        f"{mock_url}/mock/configure",
        json={"key": _MODEL, "responses": [{"text": "hi from mock"}] * 3},
        timeout=10.0,
    ).raise_for_status()
    httpx.post(
        f"{mock_url}/mock/set_fallback",
        json={"key": _MODEL, "response": {"text": "hi from mock"}},
        timeout=10.0,
    ).raise_for_status()

    config_home = tmp_path / "confighome"
    _seed_config_home(config_home, f"{mock_url}/v1")
    agent_dir = tmp_path / "agent"
    _seed_agent_dir(agent_dir, _MODEL if model_source == "spec" else None)
    home = tmp_path / "home"
    home.mkdir()

    session_data_root = Path(os.environ.get("OMNIGENT_DATA_DIR") or tmp_path)
    data_dir = session_data_root / f"model-pin-{uuid.uuid4().hex[:8]}"

    inherited_pythonpath = os.environ.get("PYTHONPATH")
    pythonpath = (
        f"{_REPO_ROOT}{os.pathsep}{inherited_pythonpath}"
        if inherited_pythonpath
        else str(_REPO_ROOT)
    )

    env = os.environ.copy()
    env.update(
        {
            "HOME": str(home),
            "OMNIGENT_CONFIG_HOME": str(config_home),
            "OMNIGENT_DATA_DIR": str(data_dir),
            "PYTHONPATH": pythonpath,
        }
    )
    env.pop("OMNIGENT_MODEL", None)
    if model_source == "env":
        env["OMNIGENT_MODEL"] = _MODEL

    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "omnigent",
                "run",
                str(agent_dir),
                "-p",
                "say hi",
            ],
            capture_output=True,
            text=True,
            env=env,
            cwd=tmp_path,
            timeout=_RUN_TIMEOUT_S,
        )
    finally:
        cleanup_errors: list[str] = []
        survivors: list[str] = []
        try:
            reaped, survivors = reap_leaked_omnigent_processes(data_dir)
            print(f"model-pin cleanup: reaped={reaped!r}; survivors={survivors!r}")
        except Exception as exc:
            cleanup_errors.append(f"reap: {type(exc).__name__}: {exc}")
            print(f"model-pin cleanup error: {cleanup_errors[-1]}", file=sys.stderr)
        try:
            log_root = data_dir / "logs"
            for log in log_root.rglob("*.log"):
                if log.is_symlink() or not log.is_file():
                    continue
                if not log.resolve().is_relative_to(data_dir.resolve()):
                    continue
                destination = tmp_path / ".omnigent" / "logs" / log.relative_to(log_root)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(log, destination)
        except Exception as exc:
            cleanup_errors.append(f"capture: {type(exc).__name__}: {exc}")
            print(f"model-pin capture error: {cleanup_errors[-1]}", file=sys.stderr)

    combined = result.stdout + result.stderr

    assert "No default model resolved" not in combined, (
        f"`omnigent run` lost model {_MODEL!r} from {model_source} "
        f"under the configured harness default:\n{combined}"
    )
    assert result.returncode == 0, (
        f"`omnigent run` with model from {model_source} exited {result.returncode}:\n{combined}"
    )
    models = _gateway_request_models(mock_url)
    assert _MODEL in models, (
        f"No request carrying model {_MODEL!r} from {model_source} reached the gateway "
        f"(captured request models: {models!r}):\n{combined}"
    )

    assert not cleanup_errors, f"Runtime cleanup/capture failed: {cleanup_errors!r}"
    assert not survivors, f"Owned runtime processes survived cleanup: {survivors!r}"
