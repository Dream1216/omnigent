"""Immutable Runtime routing identity for server-admitted interactive input."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from uuid import UUID, uuid5

INTERACTIVE_EXECUTION_KIND = "omnigent.interactive.v1"
INTERACTIVE_QUEUE_CLASS = "managed_interactive"
_SESSION_NAMESPACE = UUID("bb1402e6-05cb-42a4-9e89-12bfdd0546a8")
_RUNTIME_ID = re.compile(r"^[0-9a-f]{32}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class InteractiveRunRouteError(ValueError):
    """An input does not carry one closed, server-admitted Runtime route."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class InteractiveRunRoute:
    partition_id: UUID
    partition_generation: int
    session_id: str
    project_id: str


def interactive_session_identity(
    tenant_id: UUID, space_id: UUID, partition_id: UUID, runtime_session_id: str
) -> UUID:
    """Derive a separate SaaS identity; this value never grants access by itself."""
    if (
        any(value.int == 0 for value in (tenant_id, space_id, partition_id))
        or _RUNTIME_ID.fullmatch(runtime_session_id) is None
    ):
        raise InteractiveRunRouteError("interactive_session_identity_invalid")
    return uuid5(_SESSION_NAMESPACE, f"{tenant_id}:{space_id}:{partition_id}:{runtime_session_id}")


def interactive_message_intent(event: Mapping[str, object]) -> tuple[str, str]:
    """Validate the frozen user event shared by admission and dispatch."""
    data = event.get("data")
    if (
        set(event) != {"type", "data", "model_override", "tools", "created_by"}
        or event.get("type") != "message"
        or event.get("tools") is not None
        or event.get("created_by") is not None
        or not isinstance(data, dict)
        or data.get("role") != "user"
    ):
        raise InteractiveRunRouteError("interactive_message_invalid")
    stable_id, content = data.get("stable_id"), data.get("content")
    if (
        not isinstance(stable_id, str)
        or _RUNTIME_ID.fullmatch(stable_id) is None
        or not isinstance(content, list)
        or not content
        or any(
            not isinstance(block, dict)
            or set(block) != {"type", "text"}
            or block.get("type") != "input_text"
            or not isinstance(block.get("text"), str)
            for block in content
        )
    ):
        raise InteractiveRunRouteError("interactive_message_invalid")
    text = "\n".join(block["text"] for block in content).strip()
    if not text:
        raise InteractiveRunRouteError("interactive_message_invalid")
    return stable_id, text[:256]


def decode_interactive_run_route(input_payload: object) -> InteractiveRunRoute:
    """Decode the frozen route without treating it as execution authority."""
    if not isinstance(input_payload, dict) or set(input_payload) != {"execution"}:
        raise InteractiveRunRouteError("interactive_run_route_invalid")
    execution = input_payload["execution"]
    if (
        not isinstance(execution, dict)
        or set(execution)
        != {
            "kind",
            "runtime_partition_id",
            "runtime_partition_generation",
            "runtime_session_id",
            "runtime_project_id",
            "model_publication",
            "launch",
            "event",
        }
        or execution.get("kind") != INTERACTIVE_EXECUTION_KIND
    ):
        raise InteractiveRunRouteError("interactive_run_route_invalid")
    raw_partition = execution.get("runtime_partition_id")
    generation = execution.get("runtime_partition_generation")
    session_id = execution.get("runtime_session_id")
    project_id = execution.get("runtime_project_id")
    if (
        not isinstance(raw_partition, str)
        or type(generation) is not int
        or generation < 1
        or not isinstance(session_id, str)
        or _RUNTIME_ID.fullmatch(session_id) is None
        or not isinstance(project_id, str)
        or _RUNTIME_ID.fullmatch(project_id) is None
        or not isinstance(execution.get("model_publication"), dict)
        or not isinstance(execution.get("event"), dict)
    ):
        raise InteractiveRunRouteError("interactive_run_route_invalid")
    try:
        partition_id = UUID(raw_partition)
    except ValueError:
        raise InteractiveRunRouteError("interactive_run_route_invalid") from None
    if partition_id.int == 0 or str(partition_id) != raw_partition:
        raise InteractiveRunRouteError("interactive_run_route_invalid")
    publication = execution["model_publication"]
    event = execution["event"]
    if (
        set(publication)
        != {
            "schema_version",
            "public_model_id",
            "wire_api",
            "generation",
            "snapshot_sha256",
        }
        or type(publication.get("schema_version")) is not int
        or publication.get("schema_version") != 1
        or not isinstance(publication.get("public_model_id"), str)
        or not publication["public_model_id"]
        or len(publication["public_model_id"]) > 128
        or publication.get("wire_api") not in ("openai_chat_completions", "openai_responses")
        or type(publication.get("generation")) is not int
        or publication["generation"] < 1
        or not isinstance(publication.get("snapshot_sha256"), str)
        or _DIGEST.fullmatch(publication["snapshot_sha256"]) is None
        or event.get("model_override") not in (None, publication["public_model_id"])
    ):
        raise InteractiveRunRouteError("interactive_run_route_invalid")
    interactive_message_intent(event)
    from saas.control_plane.interactive_launch import decode_interactive_launch

    decode_interactive_launch(execution["launch"])
    return InteractiveRunRoute(partition_id, generation, session_id, project_id)
