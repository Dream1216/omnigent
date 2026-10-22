"""Closed server-owned execution contract for durable static Preview Runs.

Browsers select one already-authorized source Run and the single supported
non-secret profile.  They never select a command, module, filesystem path,
environment variable, Runner, Worktree, capability, or lease proof.  The
control plane persists this canonical document on a child Run, and the Runner
derives the fixed process specification below only after it has materialized a
new readonly Worktree from the committed checkpoint.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from saas.control_plane.runner_execution_spec import (
    PREVIEW_EXECUTION_KIND,
    STATIC_WEB_PREVIEW_PROFILE,
    STATIC_WEB_PUBLISH_DIRECTORY,
    STATIC_WEB_RUNTIME_MODULE,
    ManagedRunExecutionSpecError,
    PreviewRequestIdentity,
)
from saas.control_plane.runner_execution_spec import (
    preview_request_identity as _preview_request_identity,
)
from saas.control_plane.runner_execution_spec import (
    server_owned_preview_run_input as _server_owned_preview_run_input,
)
from saas.control_plane.runner_execution_spec import (
    static_web_preview_execution as _static_web_preview_execution,
)
from saas.runner_adapter.preview_supervisor import PreviewProcessSpec


class PreviewExecutionContractError(ValueError):
    """Reject untrusted Preview input without reflecting its value."""


@dataclass(frozen=True, slots=True)
class StaticWebPreviewExecution:
    """Validated child Run input with no caller-controlled process surface."""

    preview_execution_id: UUID
    change_set_id: UUID
    checkpoint_revision: str
    spec_hash: str
    profile: str = STATIC_WEB_PREVIEW_PROFILE

    @property
    def launch_argv(self) -> tuple[str, ...]:
        """Return the argv from the canonical control-plane execution spec."""

        return _static_web_preview_execution(
            {
                "change_set_id": str(self.change_set_id),
                "execution": {
                    "checkpoint_revision": self.checkpoint_revision,
                    "kind": PREVIEW_EXECUTION_KIND,
                    "preview_execution_id": str(self.preview_execution_id),
                    "profile": self.profile,
                },
            }
        ).launch_argv

    def process_spec(self, readonly_worktree_root: Path) -> PreviewProcessSpec:
        """Derive the sole executable and publication directory from constants."""

        root = Path(readonly_worktree_root)
        if not root.is_absolute():
            raise PreviewExecutionContractError("Preview readonly Worktree root must be absolute")
        publish = root / STATIC_WEB_PUBLISH_DIRECTORY.as_posix()
        try:
            root_stat = os.lstat(root)
            publish_stat = os.lstat(publish)
            resolved_root = root.resolve(strict=True)
            resolved_publish = publish.resolve(strict=True)
        except OSError as exc:
            raise PreviewExecutionContractError(
                "Preview static publication directory is unavailable"
            ) from exc
        if (
            not stat.S_ISDIR(root_stat.st_mode)
            or not stat.S_ISDIR(publish_stat.st_mode)
            or stat.S_ISLNK(root_stat.st_mode)
            or stat.S_ISLNK(publish_stat.st_mode)
            or root_stat.st_uid != os.geteuid()
            or publish_stat.st_uid != os.geteuid()
            or stat.S_IMODE(root_stat.st_mode) & 0o022
            or stat.S_IMODE(publish_stat.st_mode) & 0o022
            or resolved_publish.parent != resolved_root
        ):
            raise PreviewExecutionContractError(
                "Preview static publication directory is not an exact readonly child"
            )
        return PreviewProcessSpec(
            argv=self.launch_argv,
            working_directory=resolved_publish,
        )


def preview_request_identity(
    *, run_id: UUID, preview_kind: str, idempotency_key: str
) -> PreviewRequestIdentity:
    """Build the two hashes used by crash-replay-safe API idempotency."""

    try:
        return _preview_request_identity(
            run_id=run_id,
            preview_kind=preview_kind,
            idempotency_key=idempotency_key,
        )
    except ManagedRunExecutionSpecError as error:
        raise PreviewExecutionContractError(str(error)) from error


def server_owned_preview_run_input(
    *,
    preview_execution_id: UUID,
    change_set_id: UUID,
    checkpoint_revision: str,
) -> dict[str, object]:
    """Create the only child Run input accepted for the first Preview profile."""

    try:
        return _server_owned_preview_run_input(
            preview_execution_id=preview_execution_id,
            change_set_id=change_set_id,
            checkpoint_revision=checkpoint_revision,
        )
    except ManagedRunExecutionSpecError as error:
        raise PreviewExecutionContractError(str(error)) from error


def static_web_preview_execution(input_payload: object) -> StaticWebPreviewExecution:
    """Validate a canonical child Run document and derive its immutable hash."""

    try:
        spec = _static_web_preview_execution(input_payload)
    except ManagedRunExecutionSpecError as error:
        raise PreviewExecutionContractError(str(error)) from error
    assert (
        spec.change_set_id is not None
        and spec.preview_execution_id is not None
        and spec.checkpoint_revision is not None
    )
    return StaticWebPreviewExecution(
        preview_execution_id=spec.preview_execution_id,
        change_set_id=spec.change_set_id,
        checkpoint_revision=spec.checkpoint_revision,
        spec_hash=spec.spec_hash,
    )


__all__ = [
    "PREVIEW_EXECUTION_KIND",
    "STATIC_WEB_PREVIEW_PROFILE",
    "STATIC_WEB_PUBLISH_DIRECTORY",
    "STATIC_WEB_RUNTIME_MODULE",
    "PreviewExecutionContractError",
    "PreviewRequestIdentity",
    "StaticWebPreviewExecution",
    "preview_request_identity",
    "server_owned_preview_run_input",
    "static_web_preview_execution",
]
