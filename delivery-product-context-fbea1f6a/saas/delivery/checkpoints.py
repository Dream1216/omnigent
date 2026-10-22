"""Trusted read-only export of a completed Run's content-addressed checkpoint."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any
from uuid import UUID

from fastapi import HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select

from saas.control_plane.authorization import ProjectAuthorizer
from saas.control_plane.execution_models import RunRecord
from saas.control_plane.rls import RlsContext, apply_rls_context
from saas.control_plane.worktree_models import (
    ChangeSetRecord,
    RepositoryRecord,
    WorktreeInstanceRecord,
)
from saas.runner_adapter.worktrees import RecoveryArtifactStore

if TYPE_CHECKING:
    from saas.delivery.authorization import DeliveryAuthorization


class CheckpointExportBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    actor_id: UUID
    tenant_id: UUID
    project_id: UUID
    membership_version: int = Field(ge=1)
    run_id: UUID
    context_path: str = Field(default=".", max_length=512)
    request_nonce: str = Field(pattern=r"^[A-Za-z0-9._:-]{1,128}$")

    @field_validator("context_path")
    @classmethod
    def relative_context(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            not value
            or path.is_absolute()
            or ".." in path.parts
            or path.as_posix() != value
            or "\x00" in value
        ):
            raise ValueError("invalid context path")
        return value


class CheckpointExporter:
    def __init__(
        self,
        authority: DeliveryAuthorization,
        recovery: RecoveryArtifactStore,
        mirrors: dict[str, Path],
    ):
        self.authority, self.recovery, self.mirrors = authority, recovery, mirrors

    def export(self, body: CheckpointExportBody) -> Response:
        project = next(
            (
                p
                for p in self.authority.config.projects
                if p.project_id == body.project_id and p.tenant_id == body.tenant_id
            ),
            None,
        )
        if project is None:
            raise HTTPException(404, detail={"code": "checkpoint_unavailable"})
        current = self.authority.resolver.resolve_request_context(
            actor_id=body.actor_id,
            tenant_id=body.tenant_id,
            space_id=project.space_id,
            trace_id=body.request_nonce,
        )
        for action in ("project.content.read", "run.create"):
            current = ProjectAuthorizer(self.authority.sessions).bind_project_context(
                current, action=action, project_id=project.project_id
            )
        if current.tenant_membership_version != body.membership_version:
            raise HTTPException(403, detail={"code": "checkpoint_authorization_changed"})
        with self.authority.sessions() as db:
            apply_rls_context(
                db,
                RlsContext(
                    actor_id=current.actor_id,
                    tenant_id=current.tenant_id,
                    space_id=current.space_id,
                    project_id=current.project_id,
                ),
            )
            run = db.scalar(
                select(RunRecord).where(
                    RunRecord.id == body.run_id,
                    RunRecord.tenant_id == body.tenant_id,
                    RunRecord.space_id == project.space_id,
                    RunRecord.project_id == body.project_id,
                    RunRecord.created_by == body.actor_id,
                    RunRecord.status == "succeeded",
                )
            )
            if run is None:
                raise HTTPException(404, detail={"code": "checkpoint_run_unavailable"})
            rows = list(
                db.execute(
                    select(WorktreeInstanceRecord, RepositoryRecord)
                    .join(
                        ChangeSetRecord, ChangeSetRecord.id == WorktreeInstanceRecord.change_set_id
                    )
                    .join(RepositoryRecord, RepositoryRecord.id == ChangeSetRecord.repository_id)
                    .where(
                        WorktreeInstanceRecord.run_id == run.id,
                        WorktreeInstanceRecord.tenant_id == body.tenant_id,
                        WorktreeInstanceRecord.space_id == project.space_id,
                        WorktreeInstanceRecord.project_id == body.project_id,
                        WorktreeInstanceRecord.recovery_artifact_ref.is_not(None),
                        WorktreeInstanceRecord.status.not_in(("quarantined", "checkpointing")),
                        WorktreeInstanceRecord.dirty.is_(False),
                    )
                )
            )
            # Multiple repositories require an explicit server-owned build binding.
            unique = {(w.change_set_id, w.recovery_artifact_ref) for w, _ in rows}
            if len(unique) != 1:
                raise HTTPException(409, detail={"code": "checkpoint_ambiguous_or_missing"})
            worktree, repository = max(rows, key=lambda pair: pair[0].lease_generation)
            artifact_ref = worktree.recovery_artifact_ref
            source_key = repository.source_binding_key
            generation = worktree.lease_generation
            session_id = str(run.session_id or run.id)
        assert artifact_ref is not None
        artifact = self.recovery.get(artifact_ref)
        if artifact.repository_binding_digest != hashlib.sha256(source_key.encode()).hexdigest():
            raise HTTPException(409, detail={"code": "checkpoint_repository_mismatch"})
        mirror = self.mirrors.get(source_key)
        if (
            mirror is None
            or not mirror.is_absolute()
            or mirror.is_symlink()
            or not mirror.is_dir()
        ):
            raise HTTPException(503, detail={"code": "checkpoint_mirror_unavailable"})
        with tempfile.TemporaryDirectory(prefix="omnigent-checkpoint-") as directory:
            root = Path(directory)
            repository_path = root / "source.git"
            env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_NO_REPLACE_OBJECTS": "1",
            }

            def git(*args: str) -> bytes:
                return subprocess.run(
                    [
                        "git",
                        "-c",
                        "core.hooksPath=/dev/null",
                        "-c",
                        "protocol.allow=never",
                        "-c",
                        "protocol.file.allow=always",
                        *args,
                    ],
                    cwd=root,
                    env=env,
                    check=True,
                    capture_output=True,
                    timeout=90,
                ).stdout

            keys = (
                git(
                    "--git-dir",
                    str(mirror),
                    "config",
                    "--local",
                    "--no-includes",
                    "--name-only",
                    "--null",
                    "--list",
                )
                .decode()
                .lower()
                .split("\0")
            )
            safe = {
                "core.repositoryformatversion",
                "core.filemode",
                "core.bare",
                "core.logallrefupdates",
                "core.ignorecase",
                "core.precomposeunicode",
                "extensions.objectformat",
            }
            if any(
                key
                and key not in safe
                and not re.fullmatch(r"remote\.[^.]+\.(url|fetch|mirror)", key)
                for key in keys
            ):
                raise HTTPException(409, detail={"code": "checkpoint_mirror_config_unsafe"})
            git("init", "--bare", str(repository_path))
            git(
                "--git-dir",
                str(repository_path),
                "fetch",
                "--no-tags",
                str(mirror),
                artifact.base_revision,
            )
            if artifact.bundle:
                bundle = root / "checkpoint.bundle"
                bundle.write_bytes(artifact.bundle)
                git("--git-dir", str(repository_path), "bundle", "verify", str(bundle))
                git("--git-dir", str(repository_path), "fetch", "--no-tags", str(bundle), "HEAD")
            revision = (
                git("--git-dir", str(repository_path), "rev-parse", "FETCH_HEAD").decode().strip()
            )
            if (
                revision != artifact.head_revision
                or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision) is None
            ):
                raise HTTPException(409, detail={"code": "checkpoint_revision_mismatch"})
            tree = revision if body.context_path == "." else f"{revision}:{body.context_path}"
            inventory = git("--git-dir", str(repository_path), "ls-tree", "-rl", tree).splitlines()
            total = 0
            for line in inventory:
                fields = line.split(b"\t", 1)[0].split()
                if (
                    len(fields) != 4
                    or not fields[3].isdigit()
                    or fields[0] not in {b"100644", b"100755", b"040000"}
                ):
                    raise HTTPException(409, detail={"code": "checkpoint_entry_unsupported"})
                total += int(fields[3])
            if len(inventory) > 20_000 or total > 128 * 1024 * 1024:
                raise HTTPException(413, detail={"code": "checkpoint_too_large"})
            archive = git("--git-dir", str(repository_path), "archive", "--format=tar", tree)
        metadata: dict[str, Any] = {
            "actor_id": str(body.actor_id),
            "tenant_id": str(body.tenant_id),
            "project_id": str(body.project_id),
            "space_id": str(project.space_id),
            "run_id": str(body.run_id),
            "session_id": session_id,
            "membership_version": body.membership_version,
            "request_nonce": body.request_nonce,
            "context_path": body.context_path,
            "workspace_generation": generation,
            "source_revision": revision,
            "checkpoint_digest": artifact_ref.removeprefix("wta_sha256_"),
            "archive_digest": "sha256:" + hashlib.sha256(archive).hexdigest(),
        }
        return Response(
            archive,
            media_type="application/x-tar",
            headers={
                "X-Omnigent-Checkpoint": json.dumps(metadata, separators=(",", ":")),
                "Cache-Control": "no-store",
            },
        )
