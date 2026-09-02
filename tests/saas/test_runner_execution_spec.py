from __future__ import annotations

import sys
from uuid import UUID

import pytest

from saas.control_plane.runner_execution_spec import (
    ManagedRunExecutionSpecError,
    managed_run_execution_spec,
    production_run_execution_spec,
    server_owned_preview_run_input,
)
from saas.production.preview_execution import static_web_preview_execution


def test_managed_execution_derives_one_fixed_argv_without_caller_command_surface() -> None:
    spec = managed_run_execution_spec(
        {
            "change_set_id": "10000000-0000-4000-8000-000000000001",
            "execution": {
                "kind": "omnigent.agent.v1",
                "agent_path": "agents/security-review.yaml",
                "prompt": "Review the managed change set",
            },
        }
    )

    assert spec.launch_argv == (
        sys.executable,
        "-P",
        "-m",
        "omnigent.cli",
        "run",
        "agents/security-review.yaml",
        "--no-session",
        "--no-log",
        "--prompt",
        "Review the managed change set",
    )
    assert len(spec.spec_hash) == 64


@pytest.mark.parametrize(
    "payload",
    [
        {
            "change_set_id": "10000000-0000-4000-8000-000000000001",
            "launch_argv": ["sh", "-c", "curl attacker.invalid"],
            "execution": {
                "kind": "omnigent.agent.v1",
                "agent_path": "agents/review.yaml",
                "prompt": "Review",
            },
        },
        {
            "change_set_id": "10000000-0000-4000-8000-000000000001",
            "execution": {
                "kind": "omnigent.agent.v1",
                "agent_path": "../outside.yaml",
                "prompt": "Review",
            },
        },
        {
            "change_set_id": "10000000-0000-4000-8000-000000000001",
            "execution": {
                "kind": "shell.v1",
                "agent_path": "agents/review.yaml",
                "prompt": "Review",
            },
        },
        {
            "change_set_id": "10000000-0000-4000-8000-000000000001",
            "execution": {
                "kind": "omnigent.agent.v1",
                "agent_path": "agents/review.yaml",
                "prompt": " Review ",
            },
        },
    ],
)
def test_managed_execution_rejects_argv_injection_and_ambiguous_inputs(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ManagedRunExecutionSpecError):
        managed_run_execution_spec(payload)


def test_production_execution_derives_closed_static_preview_runtime() -> None:
    spec = production_run_execution_spec(
        {
            "change_set_id": "10000000-0000-4000-8000-000000000001",
            "execution": {
                "checkpoint_revision": "a" * 40,
                "kind": "omnigent.preview.v1",
                "preview_execution_id": "20000000-0000-4000-8000-000000000002",
                "profile": "static_web_v1",
            },
        }
    )

    assert spec.kind == "omnigent.preview.v1"
    assert spec.launch_argv == (
        sys.executable,
        "-P",
        "-m",
        "saas.runner_adapter.static_web_preview",
    )
    assert str(spec.preview_execution_id) == "20000000-0000-4000-8000-000000000002"
    assert spec.checkpoint_revision == "a" * 40
    assert len(spec.spec_hash) == 64


def test_preview_producer_document_and_runner_envelope_share_one_hash_and_argv() -> None:
    document = server_owned_preview_run_input(
        preview_execution_id=UUID("20000000-0000-4000-8000-000000000002"),
        change_set_id=UUID("10000000-0000-4000-8000-000000000001"),
        checkpoint_revision="a" * 40,
    )

    producer = static_web_preview_execution(document)
    runner = production_run_execution_spec(document)

    assert runner.spec_hash == producer.spec_hash
    assert runner.preview_execution_id == producer.preview_execution_id
    assert runner.change_set_id == producer.change_set_id
    assert runner.checkpoint_revision == producer.checkpoint_revision
    assert runner.launch_argv == producer.launch_argv


@pytest.mark.parametrize(
    "mutation",
    [
        {"launch_argv": ["sh", "-c", "curl attacker.invalid"]},
        {"change_set_id": "../writer-worktree"},
        {"execution": {"profile": "dev_server_v1"}},
        {"execution": {"checkpoint_revision": "A" * 40}},
        {"execution": {"path": "../secret", "profile": "static_web_v1"}},
        {"execution": {"argv": ["npm", "run", "dev"]}},
    ],
)
def test_production_execution_rejects_preview_command_and_path_surfaces(
    mutation: dict[str, object],
) -> None:
    payload: dict[str, object] = {
        "change_set_id": "10000000-0000-4000-8000-000000000001",
        "execution": {
            "checkpoint_revision": "a" * 40,
            "kind": "omnigent.preview.v1",
            "preview_execution_id": "20000000-0000-4000-8000-000000000002",
            "profile": "static_web_v1",
        },
    }
    for key, value in mutation.items():
        if key == "execution" and isinstance(value, dict):
            execution = dict(payload["execution"])
            execution.update(value)
            payload["execution"] = execution
        else:
            payload[key] = value

    with pytest.raises(ManagedRunExecutionSpecError):
        production_run_execution_spec(payload)
