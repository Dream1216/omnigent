"""Host-owned model channel identity consumed before agent processes exist."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from uuid import UUID

from omnigent.inner.sandbox import SandboxPolicy, with_additional_read_roots

SESSION_MODEL_CHANNEL_ENV = "OMNIGENT_RUNNER_SESSION_MODEL_CHANNEL"
SESSION_MODEL_CREDENTIAL_ENV = "OMNIGENT_PLATFORM_DEEPSEEK_KEY"


def session_ids_match(left: str, right: str) -> bool:
    """Compare legal UUID representations without rewriting protocol identifiers."""

    def parse(value: str) -> UUID:
        parsed = UUID(value)
        if value.lower() not in (parsed.hex, str(parsed)):
            raise ValueError("Invalid Session UUID representation")
        return parsed

    return parse(left) == parse(right)


def verify_session_socket(path: Path, *, device: int, inode: int) -> None:
    """Check a private endpoint before connecting to its fixed Session owner."""
    parent = path.parent.lstat()
    current = path.lstat()
    if (
        not path.is_absolute()
        or path.resolve() != path
        or parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
        or not stat.S_ISDIR(parent.st_mode)
        or current.st_uid != os.getuid()
        or stat.S_IMODE(current.st_mode) != 0o600
        or not stat.S_ISSOCK(current.st_mode)
        or (current.st_dev, current.st_ino) != (device, inode)
    ):
        raise ValueError("Session channel endpoint changed")


@dataclass(frozen=True)
class SessionRelayChannel:
    """Non-secret, immutable transport binding; credentials stay in the Host relay."""

    session_id: str
    runner_id: str
    generation: str
    socket_path: str
    relay_port: int
    device: int
    inode: int
    role: str = "model"

    def verify(self, *, session_id: str, runner_id: str) -> None:
        if (
            not session_ids_match(self.session_id, session_id)
            or self.runner_id != runner_id
            or not runner_id
            or runner_id.strip() != runner_id
            or "\x00" in runner_id
            or len(self.generation) != 32
            or any(c not in "0123456789abcdef" for c in self.generation)
            or type(self.relay_port) is not int
            or not 1 <= self.relay_port <= 65535
            or self.role not in ("model", "policy")
            or type(self.device) is not int
            or type(self.inode) is not int
        ):
            raise ValueError("Invalid session model channel identity")
        verify_session_socket(Path(self.socket_path), device=self.device, inode=self.inode)

    def to_json(self) -> str:
        self.verify(session_id=self.session_id, runner_id=self.runner_id)
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, raw: str, *, session_id: str, runner_id: str) -> SessionRelayChannel:
        data = json.loads(raw)
        if not isinstance(data, dict) or set(data) != set(cls.__dataclass_fields__):
            raise ValueError("Invalid session model channel metadata")
        for field in ("session_id", "runner_id", "generation", "socket_path", "role"):
            if not isinstance(data[field], str):
                raise ValueError("Invalid session model channel metadata")
        for field in ("relay_port", "device", "inode"):
            if type(data[field]) is not int:
                raise ValueError("Invalid session model channel metadata")
        channel = cls(**data)
        if channel.role != "model":
            raise ValueError("Host must supply a model channel")
        channel.verify(session_id=session_id, runner_id=runner_id)
        return channel

    def apply(self, policy: SandboxPolicy, *, session_id: str) -> SandboxPolicy:
        self.verify(session_id=session_id, runner_id=self.runner_id)
        if self.role == "model":
            policy = replace(
                policy, model_relay_port=self.relay_port, model_relay_socket_path=self.socket_path
            )
        else:
            policy = replace(
                policy,
                policy_relay_port=self.relay_port,
                policy_relay_socket_path=self.socket_path,
            )
        policy.session_relay_pairs()
        return with_additional_read_roots(policy, [Path(self.socket_path).parent])
