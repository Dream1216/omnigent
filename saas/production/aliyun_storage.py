"""Deterministic, session-scoped OSS volume admission for the Aliyun provider."""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Protocol
from uuid import UUID

from saas.compatibility.runtime_partition import RuntimeContext, current_runtime_context

OSS_ENDPOINT = "https://oss-cn-hangzhou.aliyuncs.com"
INPUT_MOUNT = "/home/user/workspace/inputs"
OUTPUT_MOUNT = "/home/user/workspace/artifacts"


class AliyunStorageError(ValueError):
    """Storage identity, authorization or cloud state cannot be admitted."""


@dataclass(frozen=True)
class AliyunOssStorageConfig:
    team_id: UUID
    tenant_id: UUID
    workspace_id: int
    bucket: str
    role_arn: str
    prefix: str = "omnigent/aliyun/v1"
    project_scoped: bool = False

    def __post_init__(self) -> None:
        if (
            any(not isinstance(v, UUID) or v.int == 0 for v in (self.team_id, self.tenant_id))
            or type(self.workspace_id) is not int
            or not 0 < self.workspace_id < 2**63
            or not isinstance(self.bucket, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", self.bucket) is None
            or not isinstance(self.role_arn, str)
            or re.fullmatch(r"acs:ram::[0-9]{10,20}:role/[a-z][a-z0-9-]{2,63}", self.role_arn)
            is None
            or not isinstance(self.prefix, str)
            or len(self.prefix) > 128
            or re.fullmatch(r"[a-z0-9-]+(?:/[a-z0-9-]+)*", self.prefix) is None
            or type(self.project_scoped) is not bool
        ):
            raise AliyunStorageError("Aliyun storage configuration is invalid")

    def session(self, runtime: RuntimeContext, session_id: UUID) -> AliyunOssSession:
        if (
            runtime.tenant_id != self.tenant_id
            or runtime.physical_workspace_id != self.workspace_id
            or not isinstance(session_id, UUID)
            or session_id.int == 0
            or not isinstance(runtime.space_id, UUID)
            or runtime.space_id.int == 0
            or (
                runtime.project_id is not None
                and (not isinstance(runtime.project_id, UUID) or runtime.project_id.int == 0)
            )
        ):
            raise AliyunStorageError("Aliyun storage session scope is invalid")
        path = (
            f"/{self.prefix}/tenants/{self.tenant_id}/spaces/{runtime.space_id}"
            + (f"/projects/{runtime.project_id or 'unbound'}" if self.project_scoped else "")
            + f"/sessions/{session_id}"
        )
        return AliyunOssSession(
            session_id,
            tuple(
                AliyunOssVolumeSpec(
                    team_id=self.team_id,
                    tenant_id=self.tenant_id,
                    workspace_id=self.workspace_id,
                    session_id=session_id,
                    bucket=self.bucket,
                    bucket_path=f"{path}/{directory}/",
                    role_arn=self.role_arn,
                    read_only=read_only,
                    mount_path=mount,
                )
                for directory, read_only, mount in (
                    ("inputs", True, INPUT_MOUNT),
                    ("outputs", False, OUTPUT_MOUNT),
                )
            ),
        )


@dataclass(frozen=True)
class AliyunOssVolumeSpec:
    team_id: UUID
    tenant_id: UUID
    workspace_id: int
    session_id: UUID
    bucket: str
    bucket_path: str
    role_arn: str
    read_only: bool
    mount_path: str

    def __post_init__(self) -> None:
        directory = "inputs" if self.read_only else "outputs"
        match = re.fullmatch(
            rf"/([a-z0-9-]+(?:/[a-z0-9-]+)*)/tenants/{self.tenant_id}"
            rf"/spaces/([0-9a-f]{{8}}(?:-[0-9a-f]{{4}}){{3}}-[0-9a-f]{{12}})"
            rf"(?:/projects/(unbound|[0-9a-f]{{8}}(?:-[0-9a-f]{{4}}){{3}}-[0-9a-f]{{12}}))?"
            rf"/sessions/{self.session_id}/{directory}/",
            self.bucket_path if isinstance(self.bucket_path, str) else "",
        )
        if (
            type(self.read_only) is not bool
            or not isinstance(self.session_id, UUID)
            or self.session_id.int == 0
            or self.mount_path != (INPUT_MOUNT if self.read_only else OUTPUT_MOUNT)
            or match is None
            or UUID(match[2]).int == 0
            or (match[3] not in (None, "unbound") and UUID(match[3]).int == 0)
        ):
            raise AliyunStorageError("Aliyun volume specification is invalid")
        AliyunOssStorageConfig(
            self.team_id,
            self.tenant_id,
            self.workspace_id,
            self.bucket,
            self.role_arn,
            match[1],
            project_scoped=match[3] is not None,
        )

    @property
    def space_id(self) -> UUID:
        return UUID(self.bucket_path.rsplit("/spaces/", 1)[1].split("/", 1)[0])

    @property
    def project_scoped(self) -> bool:
        return self.bucket_path.rsplit(f"/spaces/{self.space_id}/", 1)[1].startswith("projects/")

    @property
    def project_id(self) -> UUID | None:
        if not self.project_scoped:
            return None
        value = self.bucket_path.rsplit(f"/spaces/{self.space_id}/projects/", 1)[1].split("/", 1)[
            0
        ]
        return None if value == "unbound" else UUID(value)

    @property
    def name(self) -> str:
        document = asdict(self)
        encoded = json.dumps(document, default=str, sort_keys=True, separators=(",", ":")).encode()
        kind = "in" if self.read_only else "out"
        return f"omni-{kind}-{hashlib.sha256(encoded).hexdigest()[:40]}"

    def verify(self, volume: Mapping[str, object]) -> str:
        oss = volume.get("ossVolumeConfig")
        mount = volume.get("mountConfig")
        identifier = volume.get("volumeID")
        if (
            not isinstance(identifier, str)
            or re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", identifier) is None
            or volume.get("volumeName") != self.name
            or volume.get("teamID") != str(self.team_id)
            or volume.get("storageClass") != "OSS"
            or not isinstance(oss, dict)
            or oss.get("bucketName") != self.bucket
            or oss.get("bucketPath") != self.bucket_path
            or oss.get("endpoint") != OSS_ENDPOINT
            or type(oss.get("readOnly")) is not bool
            or oss.get("readOnly") != self.read_only
            or not isinstance(mount, dict)
            or mount.get("role") != self.role_arn
            or mount.get("vpcConfig") not in (None, {})
            or volume.get("status") not in {"CREATING", "AVAILABLE"}
        ):
            raise AliyunStorageError("Aliyun volume does not match its admitted session")
        return identifier


@dataclass(frozen=True)
class AliyunOssSession:
    session_id: UUID
    volumes: tuple[AliyunOssVolumeSpec, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.volumes, tuple)
            or len(self.volumes) != 2
            or any(not isinstance(v, AliyunOssVolumeSpec) for v in self.volumes)
            or any(v.session_id != self.session_id for v in self.volumes)
            or tuple(v.mount_path for v in self.volumes) != (INPUT_MOUNT, OUTPUT_MOUNT)
            or len(
                {
                    (v.team_id, v.tenant_id, v.workspace_id, v.bucket, v.role_arn)
                    for v in self.volumes
                }
            )
            != 1
            or len({v.bucket_path.rsplit("/", 2)[0] for v in self.volumes}) != 1
        ):
            raise AliyunStorageError("Aliyun session mounts are invalid")

    @property
    def mount_points(self) -> dict[str, str]:
        return {volume.mount_path: volume.name for volume in self.volumes}

    @property
    def metadata(self) -> dict[str, str]:
        encoded = json.dumps(self.mount_points, sort_keys=True, separators=(",", ":")).encode()
        return {
            "omnigent-storage-session": str(self.session_id),
            "omnigent-storage-bindings": hashlib.sha256(encoded).hexdigest(),
            "fc.sandbox.auth.role": self.volumes[0].role_arn,
        }

    @property
    def ram_policy(self) -> dict[str, object]:
        """Draft one role policy restricted to this session's two OSS prefixes."""

        source, output = self.volumes
        bucket = f"acs:oss:*:*:{source.bucket}"
        return {
            "Version": "1",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["oss:ListObjects"],
                    "Resource": [bucket],
                    "Condition": {
                        "StringLike": {
                            "oss:Prefix": [v.bucket_path.lstrip("/") + "*" for v in self.volumes]
                        }
                    },
                },
                {
                    "Effect": "Allow",
                    "Action": ["oss:GetObject"],
                    "Resource": [bucket + source.bucket_path + "*"],
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "oss:GetObject",
                        "oss:PutObject",
                        "oss:DeleteObject",
                        "oss:AbortMultipartUpload",
                        "oss:ListParts",
                    ],
                    "Resource": [bucket + output.bucket_path + "*"],
                },
            ],
        }


class AliyunVolumeControl:
    """Server-only control plane; implementations must not retry a create blindly."""

    def find(self, *, team_id: UUID, name: str) -> Sequence[Mapping[str, object]]:
        raise NotImplementedError

    def create(self, spec: AliyunOssVolumeSpec) -> Mapping[str, object]:
        raise NotImplementedError

    def read(self, *, team_id: UUID, volume_id: str) -> Mapping[str, object]:
        raise NotImplementedError


class AliyunStorageMounts(Protocol):
    def admit(self) -> AliyunOssSession: ...

    def ensure(self) -> AliyunOssSession: ...


class AliyunSessionVolumeManager:
    """Reuse immutable metadata after scope checks; retain OSS data on VM cleanup."""

    def __init__(
        self,
        config: AliyunOssStorageConfig,
        control: AliyunVolumeControl,
        *,
        authorize: Callable[[UUID], RuntimeContext],
        wait: Callable[[float], None] = time.sleep,
    ) -> None:
        self.config = config
        self._control = control
        self._authorize = authorize
        self._wait = wait

    def admit(self, session_id: UUID) -> AliyunOssSession:
        runtime = self._authorize(session_id)
        if runtime != current_runtime_context():
            raise AliyunStorageError("Aliyun storage authorization changed")
        return self.config.session(runtime, session_id)

    def ensure(self, session_id: UUID) -> AliyunOssSession:
        runtime = self._authorize(session_id)

        def revalidate() -> None:
            if runtime != current_runtime_context() or self._authorize(session_id) != runtime:
                raise AliyunStorageError("Aliyun storage authorization changed")

        revalidate()
        admitted = self.config.session(runtime, session_id)
        for spec in admitted.volumes:
            revalidate()
            matches = self._control.find(team_id=spec.team_id, name=spec.name)
            if len(matches) > 1:
                raise AliyunStorageError("Aliyun volume lookup is ambiguous")
            if matches:
                volume = matches[0]
            else:
                revalidate()
                try:
                    volume = self._control.create(spec)
                except Exception:  # noqa: BLE001 - never echo credentials or replay a create.
                    revalidate()
                    matches = self._control.find(team_id=spec.team_id, name=spec.name)
                    if len(matches) != 1:
                        raise AliyunStorageError("Aliyun volume creation is unconfirmed") from None
                    volume = matches[0]
            identifier = spec.verify(volume)
            for _ in range(3):
                if volume.get("status") == "AVAILABLE":
                    break
                self._wait(0.5)
                revalidate()
                volume = self._control.read(team_id=spec.team_id, volume_id=identifier)
                if spec.verify(volume) != identifier:
                    raise AliyunStorageError("Aliyun volume identity changed")
            if volume.get("status") != "AVAILABLE":
                raise AliyunStorageError("Aliyun volume is not ready")
        revalidate()
        return admitted
