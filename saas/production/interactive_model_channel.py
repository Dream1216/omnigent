"""Session-stable model-only transport for trusted Controller-owned Run relays."""

from __future__ import annotations

import asyncio
import base64
import copy
import hmac
import json
import re
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field, replace
from hashlib import sha256
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from starlette.types import ASGIApp, Receive, Scope, Send

from omnigent.harness_aliases import canonicalize_harness
from omnigent.host.frames import HostLaunchRunnerFrame
from omnigent.inference_config import parse_inference_config, validate_inference_credentials
from saas.production.platform_model_relay import PlatformModelRelay
from saas.runner_adapter.platform_models import PLATFORM_MODEL_CREDENTIAL_ENV

CHANNEL_CONTROL_KEY = "saas_model_channel"
_CAPABILITY = re.compile(r"[A-Za-z0-9_-]{43}")
_SESSION = re.compile(r"[0-9a-f]{32}")
_ROUTE = re.compile(
    r"/internal/v1/model-channels/([0-9a-f-]{36})/(v1/(?:responses|chat/completions))"
)


@dataclass(frozen=True, slots=True)
class ModelChannelScope:
    tenant_id: UUID
    space_id: UUID
    project_id: UUID
    actor_id: UUID
    session_id: UUID
    partition_id: UUID
    official_session_id: str
    publication_sha256: str

    def __post_init__(self) -> None:
        identifiers = (
            self.tenant_id,
            self.space_id,
            self.project_id,
            self.actor_id,
            self.session_id,
            self.partition_id,
        )
        if (
            any(not isinstance(value, UUID) or not value.int for value in identifiers)
            or not isinstance(self.official_session_id, str)
            or _SESSION.fullmatch(self.official_session_id) is None
            or not isinstance(self.publication_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", self.publication_sha256) is None
        ):
            raise ValueError("interactive_model_channel_scope_invalid")


@dataclass(frozen=True, slots=True)
class HostModelChannel:
    session_id: str
    base_url: str
    secret_value: str = field(repr=False)


def model_channel_origin(value: str) -> str:
    try:
        if not isinstance(value, str) or any(char.isspace() for char in value):
            raise ValueError
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or parsed.port not in {None, 443}
        ):
            raise ValueError
    except (ValueError, TypeError):
        raise ValueError("interactive_model_channel_origin_invalid") from None
    return value.rstrip("/")


def channel_url(public_origin: str, session_id: UUID) -> str:
    if not isinstance(session_id, UUID) or not session_id.int:
        raise ValueError("interactive_model_channel_session_invalid")
    return f"{model_channel_origin(public_origin)}/internal/v1/model-channels/{session_id}/v1"


def model_channel_configuration(
    *, public_origin: str, session_id: UUID, harness: str, publication: dict[str, Any]
) -> dict[str, Any]:
    """Project only the frozen public model and limits, never deployment aliases or prices."""
    wire = publication.get("wire_api")
    supported = (
        {"codex", "codex-native", "openai-agents"}
        if wire == "openai_responses"
        else {"qwen", "jcode", "opencode-native", "openai-agents"}
        if wire == "openai_chat_completions"
        else set()
    )
    name, model, maximum = (
        canonicalize_harness(harness),
        publication.get("public_model_id"),
        publication.get("max_output_tokens"),
    )
    if (
        name not in supported
        or not isinstance(model, str)
        or not 1 <= len(model) <= 128
        or type(maximum) is not int
        or maximum < 1
    ):
        raise ValueError("interactive_model_channel_publication_invalid")
    return {
        "providers": {
            "platform-deepseek": {
                "kind": "gateway",
                "openai": {
                    "base_url": channel_url(public_origin, session_id),
                    "api_key_ref": "env:" + PLATFORM_MODEL_CREDENTIAL_ENV,
                    "wire_api": "responses" if wire == "openai_responses" else "chat_completions",
                    "max_output_tokens": maximum,
                    "models": {"default": model},
                },
            }
        },
        "inference": {
            "harnesses": {
                harness: {
                    "provider": "platform-deepseek",
                    "default_model": model,
                    "model_allowlist": [model],
                }
            }
        },
    }


def _capability(frame: HostLaunchRunnerFrame, base_url: str) -> str:
    # Domain-separated: the official Runner binding token never reaches a model.
    if (
        not isinstance(frame.binding_token, str)
        or _CAPABILITY.fullmatch(frame.binding_token) is None
        or not isinstance(frame.session_id, str)
        or _SESSION.fullmatch(frame.session_id) is None
    ):
        raise ValueError("interactive_model_channel_launch_invalid")
    digest = hmac.new(
        frame.binding_token.encode(),
        ("omnigent.saas.model-channel.v1\0" + frame.session_id + "\0" + base_url).encode(),
        sha256,
    ).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def host_model_channel(
    frame: HostLaunchRunnerFrame, *, scope: ModelChannelScope, public_origin: str
) -> HostModelChannel:
    """Called only after the existing Runtime authorizes the exact Host launch."""
    if frame.session_id != scope.official_session_id:
        raise ValueError("interactive_model_channel_scope_changed")
    base_url = channel_url(public_origin, scope.session_id)
    return HostModelChannel(scope.official_session_id, base_url, _capability(frame, base_url))


def prepare_host_model_channel(
    frame: HostLaunchRunnerFrame, *, channel: HostModelChannel
) -> HostLaunchRunnerFrame:
    """Only add non-secret metadata; the existing top-level binding token stays redacted."""
    if (
        frame.session_id != channel.session_id
        or frame.inference_config is None
        or not hmac.compare_digest(_capability(frame, channel.base_url), channel.secret_value)
    ):
        raise ValueError("interactive_model_channel_launch_invalid")
    configuration = copy.deepcopy(frame.inference_config)
    if CHANNEL_CONTROL_KEY in configuration:
        raise ValueError("interactive_model_channel_launch_invalid")
    _validate_configuration(configuration, channel.base_url)
    configuration[CHANNEL_CONTROL_KEY] = {
        "schema_version": 1,
        "session_id": channel.session_id,
        "base_url": channel.base_url,
    }
    return replace(frame, inference_config=configuration)


def _validate_configuration(configuration: dict[str, Any], base_url: str) -> None:
    validate_inference_credentials(configuration)
    bindings = parse_inference_config(configuration)
    if not bindings:
        raise ValueError("interactive_model_channel_binding_invalid")
    providers = configuration.get("providers", {})
    for binding in bindings.values():
        provider = providers.get(binding.provider)
        api = provider.get("openai") if isinstance(provider, dict) else None
        if (
            binding.provider != "platform-deepseek"
            or not isinstance(api, dict)
            or api.get("base_url") != base_url
            or api.get("api_key_ref") != "env:" + PLATFORM_MODEL_CREDENTIAL_ENV
        ):
            raise ValueError("interactive_model_channel_binding_invalid")


def consume_host_model_channel(
    frame: HostLaunchRunnerFrame, *, server_url: str
) -> tuple[HostLaunchRunnerFrame, HostModelChannel]:
    """Remove the downstream metadata before the official Host persists inference config."""
    configuration = copy.deepcopy(frame.inference_config)
    if not isinstance(configuration, dict):
        raise ValueError("interactive_model_channel_launch_invalid")
    control = configuration.pop(CHANNEL_CONTROL_KEY, None)
    if (
        not isinstance(control, dict)
        or set(control) != {"schema_version", "session_id", "base_url"}
        or type(control["schema_version"]) is not int
        or control["schema_version"] != 1
        or control["session_id"] != frame.session_id
        or not isinstance(control["base_url"], str)
    ):
        raise ValueError("interactive_model_channel_launch_invalid")
    try:
        base = urlsplit(control["base_url"])
        origin = urlsplit(model_channel_origin(server_url))
        if (
            base.scheme != "https"
            or base.netloc != origin.netloc
            or base.query
            or base.fragment
            or re.fullmatch(r"/internal/v1/model-channels/[0-9a-f-]{36}/v1", base.path) is None
        ):
            raise ValueError
        session = base.path.split("/")[-2]
        if str(UUID(session)) != session or not UUID(session).int:
            raise ValueError
    except ValueError:
        raise ValueError("interactive_model_channel_endpoint_invalid") from None
    _validate_configuration(configuration, control["base_url"])
    assert frame.session_id is not None
    return replace(frame, inference_config=configuration), HostModelChannel(
        frame.session_id, control["base_url"], _capability(frame, control["base_url"])
    )


@dataclass(slots=True)
class _BoundRelay:
    run_id: UUID
    fence_token: int
    relay: PlatformModelRelay = field(repr=False)
    lifespan: AbstractAsyncContextManager = field(repr=False)
    active: int = 0
    accepting: bool = True
    idle: asyncio.Event = field(default_factory=asyncio.Event)


class SessionModelChannels:
    """No refresh/control API; each request pins a Run until its stream finishes."""

    def __init__(self, *, public_origin: str):
        self.public_origin = model_channel_origin(public_origin)
        self._scopes: dict[UUID, ModelChannelScope] = {}
        self._secrets: dict[UUID, str] = {}
        self._bound: dict[UUID, _BoundRelay] = {}
        self._lock = asyncio.Lock()

    def restore(self, scope: ModelChannelScope, secret_value: str) -> HostModelChannel:
        """The Controller loads the original private grant; this never resumes user input."""
        if not isinstance(secret_value, str) or _CAPABILITY.fullmatch(secret_value) is None:
            raise ValueError("interactive_model_channel_capability_invalid")
        if scope.session_id in self._scopes and (
            replace(self._scopes[scope.session_id], actor_id=scope.actor_id) != scope
            or (
                self._scopes[scope.session_id].actor_id != scope.actor_id
                and scope.session_id in self._bound
            )
            or not hmac.compare_digest(self._secrets[scope.session_id], secret_value)
        ):
            raise ValueError("interactive_model_channel_scope_changed")
        self._scopes[scope.session_id], self._secrets[scope.session_id] = scope, secret_value
        return HostModelChannel(
            scope.official_session_id,
            channel_url(self.public_origin, scope.session_id),
            secret_value,
        )

    async def bind(
        self,
        scope: ModelChannelScope,
        *,
        secret_value: str,
        run_id: UUID,
        fence_token: int,
        relay: PlatformModelRelay,
        accepting: bool = True,
    ) -> HostModelChannel:
        async with self._lock:
            if scope.session_id in self._bound:
                raise ValueError("interactive_model_channel_busy")
            if (
                not isinstance(run_id, UUID)
                or not run_id.int
                or type(fence_token) is not int
                or fence_token < 1
                or relay.run_id != run_id
                or relay.metering_run_id != run_id
                or relay.fence_token != fence_token
                or not hmac.compare_digest(relay.capability, secret_value)
            ):
                raise ValueError("interactive_model_channel_run_invalid")
            channel = self.restore(scope, secret_value)
            lifespan = relay.app.router.lifespan_context(relay.app)
            await lifespan.__aenter__()
            bound = _BoundRelay(run_id, fence_token, relay, lifespan, accepting=accepting)
            bound.idle.set()
            self._bound[scope.session_id] = bound
            return channel

    async def activate(self, session_id: UUID, *, run_id: UUID, fence_token: int) -> None:
        async with self._lock:
            bound = self._bound.get(session_id)
            if bound is None or (bound.run_id, bound.fence_token) != (run_id, fence_token):
                raise ValueError("interactive_model_channel_fence_changed")
            bound.accepting = True

    async def forget(self, session_id: UUID) -> None:
        """The Controller calls this only after an exact physical stop acknowledgement."""
        async with self._lock:
            if session_id in self._bound:
                raise ValueError("interactive_model_channel_busy")
            self._scopes.pop(session_id, None)
            self._secrets.pop(session_id, None)

    async def suspend(
        self, session_id: UUID, *, run_id: UUID, fence_token: int, timeout: float = 10
    ) -> bool:
        """Timeout keeps the slot closed and occupied; a later drain may finish the barrier."""
        async with self._lock:
            bound = self._bound.get(session_id)
            if bound is None:
                return True
            if bound.run_id != run_id or bound.fence_token != fence_token:
                raise ValueError("interactive_model_channel_fence_changed")
            bound.accepting = False
        try:
            await asyncio.wait_for(bound.idle.wait(), timeout=timeout)
        except TimeoutError:
            return False
        async with self._lock:
            if self._bound.get(session_id) is not bound:
                return True
            # Keep the slot until all renewal/client resources have actually closed.
            await bound.lifespan.__aexit__(None, None, None)
            del self._bound[session_id]
        return True

    async def serve(self, scope: Scope, receive: Receive, send: Send) -> None:
        match = _ROUTE.fullmatch(scope.get("path", ""))
        if match is None:
            await self._error(send, 404, "interactive_model_channel_unavailable")
            return
        headers: dict[bytes, list[bytes]] = {}
        for key, value in scope.get("headers", []):
            headers.setdefault(key.lower(), []).append(value)
        try:
            session_id = UUID(match[1])
            if str(session_id) != match[1]:
                raise ValueError
            expected = self._secrets[session_id]
            authorization = headers.get(b"authorization", [])
            if (
                scope.get("method") != "POST"
                or scope.get("query_string")
                or b"cookie" in headers
                or len(authorization) != 1
                or headers.get(b"origin", []) not in ([], [self.public_origin.encode()])
                or not hmac.compare_digest(authorization[0], ("Bearer " + expected).encode())
            ):
                raise ValueError
        except (ValueError, KeyError):
            await self._error(send, 403, "interactive_model_channel_unavailable")
            return
        async with self._lock:
            bound = self._bound.get(session_id)
            if bound is not None and bound.accepting:
                bound.active += 1
                bound.idle.clear()
            else:
                bound = None
        if bound is None:
            await self._error(send, 503, "interactive_model_run_unavailable")
            return
        try:
            inner = dict(scope)
            inner.update(
                path="/" + match[2],
                raw_path=("/" + match[2]).encode(),
                root_path="",
                path_params={},
            )
            await bound.relay.app(inner, receive, send)
        finally:
            bound.active -= 1
            if bound.active == 0:
                bound.idle.set()

    @staticmethod
    async def _error(send: Send, status: int, code: str) -> None:
        body = json.dumps(
            {"error": {"code": code, "message": "模型任务通道暂不可用；未重放任务"}}
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"cache-control", b"no-store"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


class SessionModelChannelMiddleware:
    def __init__(self, app: ASGIApp, *, channels: SessionModelChannels):
        self.app, self.channels = app, channels

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope.get("path", "").startswith(
            "/internal/v1/model-channels/"
        ):
            await self.channels.serve(scope, receive, send)
        else:
            await self.app(scope, receive, send)
