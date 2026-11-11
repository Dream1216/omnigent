"""Narrow app-server launcher using the already approved Session environment."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import tempfile
import tomllib
from copy import deepcopy
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
from uuid import UUID

from omnigent.harnesses.codex_native.executor_transport import SessionExecutorEndpoint
from omnigent.inner.datamodel import OSEnvSpec
from omnigent.inner.os_env import CallerProcessOSEnvironment, build_helper_env
from omnigent.inner.sandbox import (
    SandboxPolicy,
    create_exec_launcher,
    with_additional_read_roots,
    with_additional_write_roots,
)
from omnigent.inner.terminal import terminal_pane_environment
from omnigent.runner.session_channels import (
    SESSION_MODEL_CREDENTIAL_ENV,
    SessionRelayChannel,
    verify_session_socket,
)

SYSTEM_CODEX_REQUIREMENTS = Path("/etc/codex/requirements.toml")


@dataclass
class CodexPrivateRuntime:
    """Generated Session files, separated from Runner/server credentials."""

    session_id: str
    generation: str
    original_bridge: Path
    root: Path
    required_hooks: dict[str, str]
    executor: SessionExecutorEndpoint
    codex_binary: Path | None = None
    mcp_overrides: tuple[str, ...] | None = None
    _root_identity: tuple[int, int] = field(default=(0, 0), init=False)

    @property
    def bridge(self) -> Path:
        return self.root / "bridge"

    @property
    def home(self) -> Path:
        return self.root / "home"

    @property
    def control(self) -> Path:
        return self.root / "control" / "app.sock"

    @property
    def history(self) -> Path:
        return self.original_bridge.resolve() / ("required-history-" + UUID(self.session_id).hex)

    def _bind_history(self) -> None:
        """Keep only rollout state stable while credentials/config remain per generation."""
        for directory in (self.history, self.history / "sessions"):
            directory.mkdir(mode=0o700, exist_ok=True)
            identity = directory.lstat()
            if (
                directory.is_symlink()
                or not directory.is_dir()
                or directory.resolve() != directory
                or identity.st_uid != os.getuid()
                or identity.st_mode & 0o077
            ):
                raise ValueError("Required native history directory is not private")
        (self.home / "sessions").symlink_to(self.history / "sessions", target_is_directory=True)

    @classmethod
    def create(
        cls,
        model: SessionRelayChannel,
        policy: SessionRelayChannel,
        original_bridge: Path,
        *,
        executor: SessionExecutorEndpoint,
    ) -> CodexPrivateRuntime:
        import sys

        import tomlkit

        from omnigent.harnesses.codex_native.app_server import (
            _codex_policy_hooks_settings,
            _object_list,
            _string_object_dict,
        )

        model.verify(session_id=model.session_id, runner_id=model.runner_id)
        policy.verify(session_id=model.session_id, runner_id=model.runner_id)
        if policy.role != "policy" or policy.generation != model.generation:
            raise ValueError("Native runtime channel binding differs")
        executor.verify(model)
        root = Path(tempfile.mkdtemp(prefix="om-codex-", dir="/tmp")).resolve()
        runtime = cls(model.session_id, model.generation, original_bridge, root, {}, executor)
        identity = root.lstat()
        runtime._root_identity = (identity.st_dev, identity.st_ino)
        try:
            for directory in (
                runtime.bridge,
                runtime.home,
                runtime.control.parent,
                runtime.root / "mcp",
            ):
                directory.mkdir(mode=0o700)
            system = SYSTEM_CODEX_REQUIREMENTS
            requirements: dict[str, Any] = (
                tomllib.loads(system.read_text()) if system.exists() else {}
            )
            if "features" in requirements and "feature_requirements" in requirements:
                raise ValueError("Ambiguous administrator feature requirements")
            features = requirements.setdefault(
                "features", requirements.pop("feature_requirements", {})
            )
            if not isinstance(features, dict):
                raise ValueError("Invalid administrator feature requirements")
            for name, value in (("hooks", True), ("use_legacy_landlock", False)):
                if name in features and features[name] is not value:
                    raise ValueError("Administrator requirements reject required native features")
                features[name] = value
            allowed = requirements.get("allowed_sandbox_modes", ["read-only", "workspace-write"])
            narrowed = [mode for mode in allowed if mode in ("read-only", "workspace-write")]
            if "read-only" not in narrowed:
                raise ValueError("Administrator sandbox requirements are incompatible")
            requirements["allowed_sandbox_modes"] = narrowed
            requirements["allow_managed_hooks_only"] = True
            managed = requirements.setdefault("hooks", {})
            source = managed.setdefault("managed_dir", str(system))
            if not isinstance(source, str) or not Path(source).is_absolute():
                raise ValueError("Managed hook source must be an absolute administrator path")
            settings = _codex_policy_hooks_settings(
                runtime.bridge,
                sys.executable,
                required_session_id=model.session_id,
                required_generation=model.generation,
            )
            generated = _string_object_dict(settings.get("hooks")) or {}
            for event, event_key in (
                ("PreToolUse", "pre_tool_use"),
                ("PostToolUse", "post_tool_use"),
                ("UserPromptSubmit", "user_prompt_submit"),
            ):
                groups = managed.setdefault(event, [])
                group_index = len(groups)
                new_groups = _object_list(generated.get(event)) or []
                new_group = _string_object_dict(new_groups[0]) if new_groups else None
                if new_group is None:
                    raise ValueError("Required native hook generation failed")
                for index, raw_hook in enumerate(_object_list(new_group.get("hooks")) or []):
                    hook = _string_object_dict(raw_hook) or {}
                    command = hook.get("command")
                    if not isinstance(command, str):
                        raise ValueError("Required native hook command is invalid")
                    runtime.required_hooks[f"{source}:{event_key}:{group_index}:{index}"] = command
                groups.append(new_group)
            target = root / "requirements.toml"
            target.write_text(tomlkit.dumps(requirements))
            target.chmod(0o600)
            config = executor.environment_config(model)
            for path in (root / "environments.toml", runtime.home / "environments.toml"):
                path.write_text(config)
                path.chmod(0o600)
            runtime.refresh_projection(policy)
            runtime._bind_history()
            from omnigent.harnesses.codex_native.bridge import write_mcp_bridge_config

            write_mcp_bridge_config(runtime.bridge)
            return runtime
        except BaseException:
            shutil.rmtree(root)
            raise

    def refresh_projection(
        self, policy: SessionRelayChannel, *, publish_state: bool = False
    ) -> None:
        from omnigent.harnesses.codex_native.bridge import read_bridge_state, write_bridge_state

        advertisement = json.loads((self.original_bridge / "tool_relay.json").read_text())
        if (
            not isinstance(advertisement, dict)
            or advertisement.get("session_id") != self.session_id
            or advertisement.get("generation") != self.generation
            or advertisement.get("socket_path") != policy.socket_path
        ):
            raise ValueError("Native relay projection binding differs")
        selected = {
            key: advertisement[key]
            for key in ("url", "token", "session_id", "generation", "socket_path", "tools")
        }
        target = self.bridge / "tool_relay.json"
        temporary = self.bridge / ".relay-next.json"
        temporary.write_text(json.dumps(selected))
        temporary.chmod(0o600)
        temporary.replace(target)
        state = read_bridge_state(self.original_bridge) if publish_state else None
        if state is not None:
            if state.session_id != self.session_id:
                raise ValueError("Native bridge projection belongs to another Session")
            write_bridge_state(
                self.bridge,
                replace(state, codex_home=str(self.home), socket_path=f"unix://{self.control}"),
            )

    def apply(self, policy: SandboxPolicy) -> SandboxPolicy:
        policy = with_additional_read_roots(policy, [self.bridge, self.root / "requirements.toml"])
        policy = with_additional_write_roots(
            policy, [self.home, self.control.parent, self.history]
        )
        policy.codex_requirements_path = str(self.root / "requirements.toml")
        verify_session_socket(
            self.executor.socket_path, device=self.executor.device, inode=self.executor.inode
        )
        policy = with_additional_read_roots(policy, [self.executor.socket_path.parent])
        policy.codex_environments_path = str(self.root / "environments.toml")
        policy.env_passthrough = [
            *(policy.env_passthrough or []),
            "CODEX_HOME",
            SESSION_MODEL_CREDENTIAL_ENV,
        ]
        return policy

    def close(self) -> None:
        """Retire owned transport projections, preserving Codex history for recovery."""
        try:
            identity = self.root.lstat()
        except FileNotFoundError:
            return
        if (identity.st_dev, identity.st_ino) != self._root_identity:
            raise ValueError("Native runtime projection ownership changed")
        for directory in (self.bridge, self.control.parent, self.root / "mcp"):
            with contextlib.suppress(FileNotFoundError):
                shutil.rmtree(directory)
        (self.root / "requirements.toml").unlink(missing_ok=True)
        (self.root / "environments.toml").unlink(missing_ok=True)


@dataclass
class CodexSandboxLaunch:
    """Own launchers, without owning or changing the shared OSEnv or relays."""

    session_id: str
    required_spec: OSEnvSpec
    environment: CallerProcessOSEnvironment
    model_channel: SessionRelayChannel
    policy_channel: SessionRelayChannel
    runtime: CodexPrivateRuntime | None = None
    _launchers: list[tuple[Path, int, int]] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        self.required_spec = deepcopy(self.required_spec)
        self._verify()

    def _verify(self) -> None:
        policy = self.environment.sandbox
        required = self.required_spec.sandbox
        if (
            required is None
            or required.type != "linux_bwrap"
            or required.allow_network is not False
        ):
            raise ValueError("Codex requires the server's network-isolated linux_bwrap spec")
        if self.environment.spec != self.required_spec:
            raise ValueError("Codex environment differs from the required Session sandbox")
        for channel, role in ((self.model_channel, "model"), (self.policy_channel, "policy")):
            channel.verify(session_id=self.session_id, runner_id=self.model_channel.runner_id)
            if channel.role != role or channel.generation != self.model_channel.generation:
                raise ValueError("Codex channel role or generation differs")
        expected = [
            (self.model_channel.relay_port, self.model_channel.socket_path),
            (self.policy_channel.relay_port, self.policy_channel.socket_path),
        ]
        if policy.session_relay_pairs() != expected:
            raise ValueError("Codex environment does not contain its Session channels")

    def prepare_spawn(
        self, executable: str, parent_env: dict[str, str]
    ) -> tuple[str, dict[str, str], str]:
        """Prepare one existing launcher with the original grants and COW ownership."""
        self._verify()
        policy = replace(self.environment.sandbox)
        env = terminal_pane_environment(inherit_env=False, env=parent_env, env_unset=())
        env = build_helper_env(env, policy)
        home = env.get("CODEX_HOME")
        if not home or home != parent_env.get("CODEX_HOME"):
            raise ValueError("Required Codex environment does not grant CODEX_HOME")
        path = Path(home)
        if (
            not path.is_absolute()
            or path.resolve() != path
            or not any(path.is_relative_to(root.resolve()) for root in policy.write_roots)
        ):
            raise ValueError("Required Codex environment does not grant its private home")
        binary = shutil.which(executable, path=env.get("PATH"))
        if binary is None:
            raise FileNotFoundError("Required Codex executable is unavailable")
        policy.spawn_env_allowlist = sorted(env)
        self.environment.prepare_sandbox(policy)
        launcher = Path(
            create_exec_launcher(
                str(Path(binary).resolve()), policy, cwd=str(self.environment.cwd)
            )
        )
        identity = launcher.lstat()
        self._launchers.append((launcher, identity.st_dev, identity.st_ino))
        return (
            str(launcher),
            env,
            "/" if policy.copy_on_write_namespace else str(self.environment.cwd),
        )

    def close(self) -> None:
        """Unlink only launcher files still owned by this execution composition."""
        for path, device, inode in self._launchers:
            try:
                current = path.lstat()
                if (current.st_dev, current.st_ino) == (device, inode):
                    path.unlink()
            except FileNotFoundError:
                pass
        self._launchers.clear()
