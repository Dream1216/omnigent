"""Fixed UDS-only static server for the ``static_web_v1`` Preview profile.

The Runner starts this trusted module with ``-P`` from the fixed ``dist``
directory. It accepts no CLI argument, network host, document root, executable,
or import path from the Worktree. Every requested path component is opened
relative to a pinned root descriptor with ``O_NOFOLLOW``; a bounded file is
fully read and its identity rechecked before any response bytes are emitted.
"""

from __future__ import annotations

import asyncio
import os
import re
import stat
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

import uvicorn
from starlette.types import Receive, Scope, Send

_HEALTH_PATH = re.compile(r"^/[A-Za-z0-9_./-]{1,255}$")
_MAX_PATH_BYTES = 1_024
_MAX_COMPONENTS = 32
_MAX_FILE_BYTES = 10 * 1024 * 1024
_MAX_CONCURRENT_READS = 4
_READ_CHUNK_BYTES = 64 * 1024
_CONTENT_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".gif": "image/gif",
    ".htm": "text/html; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".ico": "image/x-icon",
    ".jpeg": "image/jpeg",
    ".jpg": "image/jpeg",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".map": "application/json; charset=utf-8",
    ".mjs": "application/javascript; charset=utf-8",
    ".png": "image/png",
    ".svg": "image/svg+xml; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".wasm": "application/wasm",
    ".webp": "image/webp",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
}
_SECURITY_HEADERS = (
    (b"cache-control", b"no-store"),
    (
        b"content-security-policy",
        b"sandbox allow-scripts allow-forms allow-modals allow-same-origin; "
        b"default-src 'self'; connect-src 'none'; frame-src 'none'; "
        b"worker-src 'none'; object-src 'none'; base-uri 'none'; "
        b"frame-ancestors 'none'",
    ),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"accept-ranges", b"none"),
)


class StaticWebPreviewRuntimeError(RuntimeError):
    """Fail closed without reflecting filesystem or environment values."""


@dataclass(frozen=True, slots=True)
class _OpenedStaticFile:
    content: bytes
    content_type: str


class _StaticWebPreviewApp:
    def __init__(self, *, root: Path, health_path: str) -> None:
        if _HEALTH_PATH.fullmatch(health_path) is None or any(
            component in {".", ".."} for component in health_path.split("/")
        ):
            raise StaticWebPreviewRuntimeError("Preview health path is invalid")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(root, flags)
            facts = os.fstat(descriptor)
        except OSError as exc:
            raise StaticWebPreviewRuntimeError("Preview publication root is unavailable") from exc
        if not stat.S_ISDIR(facts.st_mode):
            os.close(descriptor)
            raise StaticWebPreviewRuntimeError("Preview publication root is unavailable")
        self._root_fd = descriptor
        self._health_path = health_path
        self._closed = False
        # Each read is bounded to the Edge's default 10 MiB response ceiling.
        # Four reads cap in-process static payload memory at 40 MiB.
        self._capacity = asyncio.Semaphore(_MAX_CONCURRENT_READS)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
            return
        if scope["type"] != "http":
            return
        method = str(scope.get("method", ""))
        path = str(scope.get("path", ""))
        if self._closed:
            await _plain(send, status=503, body=b"unavailable\n")
            return
        if method not in {"GET", "HEAD"}:
            await _plain(send, status=405, body=b"method not allowed\n")
            return
        if path == self._health_path:
            await _plain(send, status=200, body=b"ok\n", head=method == "HEAD")
            return
        if any(name.lower() == b"range" for name, _value in scope.get("headers", ())):
            await _plain(send, status=416, body=b"range not supported\n", head=method == "HEAD")
            return
        try:
            components = _path_components(path)
            async with self._capacity:
                opened = await asyncio.to_thread(_read_static_file, self._root_fd, components)
        except (OSError, StaticWebPreviewRuntimeError, UnicodeError):
            await _plain(send, status=404, body=b"not found\n", head=method == "HEAD")
            return
        headers = (
            *_SECURITY_HEADERS,
            (b"content-type", opened.content_type.encode("ascii")),
            (b"content-length", str(len(opened.content)).encode("ascii")),
        )
        await send({"type": "http.response.start", "status": 200, "headers": list(headers)})
        await send(
            {
                "type": "http.response.body",
                "body": b"" if method == "HEAD" else opened.content,
                "more_body": False,
            }
        )

    async def _lifespan(self, receive: Receive, send: Send) -> None:
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                self.close()
                await send({"type": "lifespan.shutdown.complete"})
                return

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            os.close(self._root_fd)


def _path_components(path: str) -> tuple[str, ...]:
    if (
        not path.startswith("/")
        or "\x00" in path
        or "\\" in path
        or len(path.encode("utf-8")) > _MAX_PATH_BYTES
    ):
        raise StaticWebPreviewRuntimeError("Preview path is invalid")
    raw = path.split("/")[1:]
    if raw and raw[-1] == "":
        raw.pop()
        raw.append("index.html")
    if not raw:
        raw = ["index.html"]
    if len(raw) > _MAX_COMPONENTS or any(
        not component
        or component in {".", ".."}
        or component.startswith(".")
        or len(component.encode("utf-8")) > 255
        for component in raw
    ):
        raise StaticWebPreviewRuntimeError("Preview path is invalid")
    return tuple(raw)


def _read_static_file(root_fd: int, components: tuple[str, ...]) -> _OpenedStaticFile:
    directory_fd = os.dup(root_fd)
    file_fd: int | None = None
    try:
        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        for component in components[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            facts = os.fstat(next_fd)
            if not stat.S_ISDIR(facts.st_mode):
                os.close(next_fd)
                raise StaticWebPreviewRuntimeError("Preview path is invalid")
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(
            components[-1],
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        before = os.fstat(file_fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 0
            or before.st_size > _MAX_FILE_BYTES
        ):
            raise StaticWebPreviewRuntimeError("Preview file is invalid")
        remaining = before.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(file_fd, min(_READ_CHUNK_BYTES, remaining))
            if not chunk:
                raise StaticWebPreviewRuntimeError("Preview file changed during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(file_fd, 1):
            raise StaticWebPreviewRuntimeError("Preview file changed during read")
        after = os.fstat(file_fd)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise StaticWebPreviewRuntimeError("Preview file changed during read")
        suffix = Path(components[-1]).suffix.lower()
        normalized_type = _CONTENT_TYPES.get(suffix, "application/octet-stream")
        return _OpenedStaticFile(b"".join(chunks), normalized_type)
    finally:
        if file_fd is not None:
            with suppress(OSError):
                os.close(file_fd)
        with suppress(OSError):
            os.close(directory_fd)


async def _plain(send: Send, *, status: int, body: bytes, head: bool = False) -> None:
    headers = (
        *_SECURITY_HEADERS,
        (b"content-type", b"text/plain; charset=utf-8"),
        (b"content-length", str(len(body)).encode("ascii")),
    )
    await send({"type": "http.response.start", "status": status, "headers": list(headers)})
    await send(
        {
            "type": "http.response.body",
            "body": b"" if head else body,
            "more_body": False,
        }
    )


def create_static_web_preview_app(*, root: Path, health_path: str) -> _StaticWebPreviewApp:
    """Build a pinned-root static ASGI app with no directory listing or Range."""

    return _StaticWebPreviewApp(root=root, health_path=health_path)


def main() -> int:
    """Run only on the supervisor-selected private Unix-domain socket."""

    socket_path = os.environ.get("OMNIGENT_PREVIEW_SOCKET_PATH", "")
    health_path = os.environ.get("OMNIGENT_PREVIEW_HEALTH_PATH", "")
    if (
        not socket_path
        or not Path(socket_path).is_absolute()
        or "\x00" in socket_path
        or len(os.fsencode(socket_path)) > 100
    ):
        raise StaticWebPreviewRuntimeError("Preview socket path is invalid")
    app = create_static_web_preview_app(root=Path.cwd(), health_path=health_path)
    config = uvicorn.Config(
        app=app,
        uds=socket_path,
        access_log=False,
        server_header=False,
        date_header=False,
        proxy_headers=False,
        log_level="warning",
    )
    uvicorn.Server(config).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["StaticWebPreviewRuntimeError", "create_static_web_preview_app", "main"]
