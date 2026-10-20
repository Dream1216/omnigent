"""Observe an accepted Run's live fence while provider network I/O is waiting."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any, NoReturn, TypeVar

import anyio
from fastapi.responses import StreamingResponse
from starlette.types import Receive, Scope, Send

from saas.runner_adapter.platform_model_gateway import PlatformModelGatewayTokenError

_T = TypeVar("_T")


class ModelRunAuthorityLost(RuntimeError):
    def __init__(self, *, status_code: int, code: str) -> None:
        self.status_code, self.code = status_code, code
        super().__init__(code)


class ModelRunAuthorityWatch:
    def __init__(self, check: Callable[[], None], *, interval: float, timeout: float):
        if not 0 < interval <= 5 or not 0 < timeout <= 10:
            raise ValueError("model_run_authority_watch_policy_invalid")
        self._check, self._interval, self._timeout = check, interval, timeout
        self.interrupted = False
        self._task = asyncio.create_task(self._watch(), name="model-run-authority")

    async def _watch(self) -> NoReturn:
        while True:
            await asyncio.sleep(self._interval)
            try:
                await asyncio.wait_for(asyncio.to_thread(self._check), timeout=self._timeout)
            except PlatformModelGatewayTokenError:
                self.interrupted = True
                raise ModelRunAuthorityLost(
                    status_code=403, code="platform_model_run_authority_unavailable"
                ) from None
            except Exception:  # noqa: BLE001 - database/clock diagnostics remain private.
                self.interrupted = True
                raise ModelRunAuthorityLost(
                    status_code=503, code="platform_model_gateway_unavailable"
                ) from None

    async def wait(self, operation: Awaitable[_T]) -> _T:
        pending = asyncio.ensure_future(operation)
        try:
            done, _ = await asyncio.wait(
                (pending, self._task), return_when=asyncio.FIRST_COMPLETED
            )
            if self._task in done:
                await self._task
            return await pending
        finally:
            if not pending.done():
                pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)

    async def stream(self, source: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
        while True:
            try:
                chunk = await self.wait(anext(source))
            except (StopAsyncIteration, ModelRunAuthorityLost):
                return
            yield chunk

    async def close(self) -> None:
        if not self._task.done():
            self._task.cancel()
        await asyncio.gather(self._task, return_exceptions=True)


class GuardedModelRunResponse(StreamingResponse):
    """Also close the provider when ASGI exits before consuming the iterator."""

    def __init__(
        self,
        content: AsyncIterator[bytes],
        *,
        cleanup: Callable[[], Awaitable[None]],
        **kwargs: Any,
    ) -> None:
        super().__init__(content, **kwargs)
        self._cleanup = cleanup

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            with anyio.CancelScope(shield=True):
                try:
                    close = getattr(self.body_iterator, "aclose", None)
                    if close is not None:
                        await close()
                finally:
                    await self._cleanup()
