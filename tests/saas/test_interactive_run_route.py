from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from omnigent.server.schemas import SessionEventInput
from saas.control_plane.interactive_run_route import (
    MAX_INTERACTIVE_ATTACHMENTS,
    InteractiveRunRouteError,
    decode_interactive_run_route,
    interactive_session_identity,
)
from tests.saas.test_interactive_execution_http import _launch, _message


def _input():
    return {
        "execution": {
            "kind": "omnigent.interactive.v1",
            "runtime_partition_id": str(uuid4()),
            "runtime_partition_generation": 3,
            "runtime_session_id": uuid4().hex,
            "runtime_project_id": uuid4().hex,
            "launch": _launch(),
            "model_publication": {
                "schema_version": 1,
                "public_model_id": "synthetic-public-id",
                "wire_api": "openai_chat_completions",
                "generation": 1,
                "snapshot_sha256": "a" * 64,
            },
            "event": SessionEventInput.model_validate(_message()).model_dump(mode="json"),
        }
    }


def test_interactive_route_keeps_runtime_and_saas_identities_distinct_and_scope_bound():
    payload = _input()
    route = decode_interactive_run_route(payload)
    tenant, space = uuid4(), uuid4()
    identity = interactive_session_identity(tenant, space, route.partition_id, route.session_id)
    assert identity.version == 5 and identity != UUID(route.session_id)
    assert identity == interactive_session_identity(
        tenant, space, route.partition_id, route.session_id
    )
    assert identity != interactive_session_identity(
        uuid4(), space, route.partition_id, route.session_id
    )
    assert identity != interactive_session_identity(
        tenant, uuid4(), route.partition_id, route.session_id
    )
    assert identity != interactive_session_identity(tenant, space, uuid4(), route.session_id)


@pytest.mark.parametrize(
    "path,value",
    [
        (("runtime_partition_generation",), True),
        (("runtime_partition_id",), "0" * 32),
        (("runtime_session_id",), "not-a-runtime-id"),
        (("runtime_project_id",), None),
        (("launch", "host_id"), None),
        (("launch", "host_type"), {}),
        (("launch", "workspace"), "relative/path"),
        (("launch", "workspaces"), ["https://github.com/example/repo.git"]),
        (("launch", "terminal_launch_args"), {"command": "not-accepted"}),
        (("event", "created_by"), "someone-else"),
        (("event", "tools"), []),
        (("event", "model_override"), {}),
        (("event", "data", "stable_id"), "not-stable"),
        (("event", "data", "content"), []),
        (("event", "data", "content"), [{"type": "input_text", "text": "  "}]),
        (
            ("event", "data", "content"),
            [{"type": "input_file", "file_id": "f" * 32, "filename": "owned.txt"}]
            * (MAX_INTERACTIVE_ATTACHMENTS + 1),
        ),
        (("model_publication", "schema_version"), True),
        (("model_publication", "generation"), True),
        (("model_publication", "wire_api"), {}),
        (("model_publication", "snapshot_sha256"), "x" * 64),
    ],
)
def test_interactive_route_rejects_malformed_scope_or_frozen_intent(path, value):
    payload = _input()
    target = payload["execution"]
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(InteractiveRunRouteError):
        decode_interactive_run_route(payload)


def test_interactive_route_rejects_undeclared_execution_fields():
    payload = _input()
    payload["execution"]["argv"] = ["not-an-interactive-command"]
    with pytest.raises(InteractiveRunRouteError):
        decode_interactive_run_route(payload)


@pytest.mark.parametrize("workspace", ["/workspace", "C:/workspace", r"\\server\share\repo"])
def test_interactive_route_preserves_supported_absolute_workspace_formats(workspace):
    payload = _input()
    payload["execution"]["launch"]["workspace"] = workspace
    decode_interactive_run_route(payload)
