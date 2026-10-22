"""Canonical server-owned launch specification for managed SaaS Runs."""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from hashlib import sha256
from pathlib import PurePosixPath
from typing import cast
from uuid import UUID

_AGENT_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_EXECUTION_KIND = "omnigent.agent.v1"
PREVIEW_EXECUTION_KIND = "omnigent.preview.v1"
STATIC_WEB_PREVIEW_PROFILE = "static_web_v1"
STATIC_WEB_RUNTIME_MODULE = "saas.runner_adapter.static_web_preview"
STATIC_WEB_PUBLISH_DIRECTORY = PurePosixPath("dist")
_FULL_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$")


class ManagedRunExecutionSpecError(ValueError):
    """A public Run input cannot be converted into a production launch."""


@dataclass(frozen=True, slots=True)
class ManagedRunExecutionSpec:
    """Normalized one-shot invocation selected by the server, not the Runner."""

    kind: str
    agent_path: str
    prompt: str
    spec_hash: str
    launch_argv: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PreviewRequestIdentity:
    """Hashed idempotency key and canonical browser request identity."""

    key_hash: str
    request_hash: str


@dataclass(frozen=True, slots=True)
class ProductionRunExecutionSpec:
    """Closed server-derived launch identity for Agent or static Preview Runs."""

    kind: str
    spec_hash: str
    launch_argv: tuple[str, ...]
    change_set_id: UUID | None = None
    preview_execution_id: UUID | None = None
    checkpoint_revision: str | None = None


def preview_request_identity(
    *, run_id: UUID, preview_kind: str, idempotency_key: str
) -> PreviewRequestIdentity:
    """Build the two hashes used by crash-replay-safe Preview API idempotency."""

    if run_id.int == 0 or preview_kind != STATIC_WEB_PREVIEW_PROFILE:
        raise ManagedRunExecutionSpecError("Preview request is invalid")
    if not isinstance(idempotency_key, str) or _IDEMPOTENCY_KEY.fullmatch(idempotency_key) is None:
        raise ManagedRunExecutionSpecError("Preview idempotency key is invalid")
    encoded = _canonical_bytes(
        {
            "preview_kind": STATIC_WEB_PREVIEW_PROFILE,
            "run_id": str(run_id),
        }
    )
    return PreviewRequestIdentity(
        key_hash=sha256(idempotency_key.encode("ascii")).hexdigest(),
        request_hash=sha256(encoded).hexdigest(),
    )


def server_owned_preview_run_input(
    *,
    preview_execution_id: UUID,
    change_set_id: UUID,
    checkpoint_revision: str,
) -> dict[str, object]:
    """Create the sole child Run document accepted by production Runners."""

    document: dict[str, object] = {
        "change_set_id": str(change_set_id),
        "execution": {
            "checkpoint_revision": checkpoint_revision,
            "kind": PREVIEW_EXECUTION_KIND,
            "preview_execution_id": str(preview_execution_id),
            "profile": STATIC_WEB_PREVIEW_PROFILE,
        },
    }
    _ = static_web_preview_execution(document)
    return document


def static_web_preview_execution(
    input_payload: object,
) -> ProductionRunExecutionSpec:
    """Validate and hash the canonical static Preview child Run document."""

    if not isinstance(input_payload, dict) or set(input_payload) != {
        "change_set_id",
        "execution",
    }:
        raise ManagedRunExecutionSpecError("Preview child Run fields are invalid")
    execution = input_payload.get("execution")
    if not isinstance(execution, dict) or set(execution) != {
        "checkpoint_revision",
        "kind",
        "preview_execution_id",
        "profile",
    }:
        raise ManagedRunExecutionSpecError("Preview execution fields are invalid")
    if (
        execution.get("kind") != PREVIEW_EXECUTION_KIND
        or execution.get("profile") != STATIC_WEB_PREVIEW_PROFILE
    ):
        raise ManagedRunExecutionSpecError("Preview execution profile is unsupported")
    preview_execution_id = _canonical_uuid(
        execution.get("preview_execution_id"), field="Preview execution"
    )
    change_set_id = _canonical_uuid(input_payload.get("change_set_id"), field="Preview ChangeSet")
    checkpoint_revision = execution.get("checkpoint_revision")
    if (
        not isinstance(checkpoint_revision, str)
        or _FULL_GIT_SHA.fullmatch(checkpoint_revision) is None
    ):
        raise ManagedRunExecutionSpecError("Preview checkpoint revision is invalid")
    encoded = _canonical_bytes(input_payload)
    return ProductionRunExecutionSpec(
        kind=PREVIEW_EXECUTION_KIND,
        spec_hash=sha256(encoded).hexdigest(),
        launch_argv=(sys.executable, "-P", "-m", STATIC_WEB_RUNTIME_MODULE),
        change_set_id=change_set_id,
        preview_execution_id=preview_execution_id,
        checkpoint_revision=checkpoint_revision,
    )


def production_run_execution_spec(
    input_payload: dict[str, object],
) -> ProductionRunExecutionSpec:
    """Accept exactly one of the two server-owned production execution schemas."""

    try:
        managed = managed_run_execution_spec(input_payload)
    except ManagedRunExecutionSpecError:
        return static_web_preview_execution(input_payload)
    return ProductionRunExecutionSpec(
        kind=managed.kind,
        spec_hash=managed.spec_hash,
        launch_argv=managed.launch_argv,
    )


def managed_run_execution_spec(input_payload: dict[str, object]) -> ManagedRunExecutionSpec:
    """Validate public input and build the only production Runner command shape.

    The public API intentionally accepts general JSON, so execution admission
    must not forward caller-provided argv to a shell.  Production claims accept
    only this versioned, closed schema and derive the argv from fixed literals.
    The exact normalized document and argv are then bound into the claim
    envelope and independently recomputed by the Runner from the immutable Run.
    """

    if set(input_payload) != {"change_set_id", "execution"}:
        raise ManagedRunExecutionSpecError("Run input is not a managed execution document")
    execution = input_payload.get("execution")
    if not isinstance(execution, dict) or set(execution) != {"kind", "agent_path", "prompt"}:
        raise ManagedRunExecutionSpecError("Managed execution fields are invalid")
    document = cast(dict[str, object], execution)
    return managed_execution_spec(
        kind=document.get("kind"),
        agent_path=document.get("agent_path"),
        prompt=document.get("prompt"),
    )


def managed_execution_spec(
    *, kind: object, agent_path: object, prompt: object
) -> ManagedRunExecutionSpec:
    """Normalize one closed execution document and derive its fixed argv."""

    if kind != _EXECUTION_KIND:
        raise ManagedRunExecutionSpecError("Managed execution kind is unsupported")
    if not isinstance(agent_path, str):
        raise ManagedRunExecutionSpecError("Managed execution agent path is invalid")
    normalized_path = _agent_path(agent_path)
    if (
        not isinstance(prompt, str)
        or not prompt
        or prompt != prompt.strip()
        or "\x00" in prompt
        or len(prompt.encode("utf-8")) > 4096
    ):
        raise ManagedRunExecutionSpecError("Managed execution prompt is invalid")
    normalized = {
        "agent_path": normalized_path,
        "kind": _EXECUTION_KIND,
        "prompt": prompt,
    }
    encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    launch_argv = (
        sys.executable,
        "-P",
        "-m",
        "omnigent.cli",
        "run",
        normalized_path,
        "--no-session",
        "--no-log",
        "--prompt",
        prompt,
    )
    return ManagedRunExecutionSpec(
        kind=_EXECUTION_KIND,
        agent_path=normalized_path,
        prompt=prompt,
        spec_hash=sha256(encoded.encode()).hexdigest(),
        launch_argv=launch_argv,
    )


def _agent_path(value: str) -> str:
    if not value or value != value.strip() or "\x00" in value or "\\" in value or len(value) > 512:
        raise ManagedRunExecutionSpecError("Managed execution agent path is invalid")
    path = PurePosixPath(value)
    parts = path.parts
    if (
        path.is_absolute()
        or not 1 <= len(parts) <= 16
        or any(part in {".", ".."} or not _AGENT_COMPONENT.fullmatch(part) for part in parts)
        or path.suffix not in {".yaml", ".yml"}
        or path.as_posix() != value
    ):
        raise ManagedRunExecutionSpecError("Managed execution agent path is invalid")
    return path.as_posix()


def _canonical_uuid(value: object, *, field: str) -> UUID:
    if not isinstance(value, str):
        raise ManagedRunExecutionSpecError(f"{field} identifier is invalid")
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise ManagedRunExecutionSpecError(f"{field} identifier is invalid") from error
    if parsed.int == 0 or str(parsed) != value:
        raise ManagedRunExecutionSpecError(f"{field} identifier is invalid")
    return parsed


def _canonical_bytes(document: object) -> bytes:
    try:
        return json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as error:
        raise ManagedRunExecutionSpecError("Preview execution document is invalid") from error


__all__ = [
    "PREVIEW_EXECUTION_KIND",
    "STATIC_WEB_PREVIEW_PROFILE",
    "STATIC_WEB_PUBLISH_DIRECTORY",
    "STATIC_WEB_RUNTIME_MODULE",
    "ManagedRunExecutionSpec",
    "ManagedRunExecutionSpecError",
    "PreviewRequestIdentity",
    "ProductionRunExecutionSpec",
    "managed_execution_spec",
    "managed_run_execution_spec",
    "preview_request_identity",
    "production_run_execution_spec",
    "server_owned_preview_run_input",
    "static_web_preview_execution",
]
