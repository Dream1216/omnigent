"""Authenticated, read-only access to persisted Session output objects."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import re
import time
import unicodedata
from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote_to_bytes
from uuid import UUID

import anyio
import httpx
from defusedxml.ElementTree import fromstring
from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.types import Receive, Scope, Send

from omnigent.server.routes._sessions.helpers import _attachment_disposition
from saas.compatibility.runtime_partition import RuntimeContext, current_runtime_context
from saas.control_plane.http_auth import SaasAuthProvider
from saas.control_plane.lifecycle import LifecycleError
from saas.production.aliyun_storage import AliyunOssStorageConfig, AliyunOssVolumeSpec
from saas.production.aliyun_sts import read_sts_document

_CHUNK_BYTES = 65536
_XML_BYTES = 524288
_HEADERS = {"Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff"}
_ETAG = re.compile(r'"[\x21\x23-\x7e]{1,128}"')


class ArtifactAccessDenied(PermissionError):
    """The caller no longer owns the admitted output scope."""

    def __init__(self, message: str, *, status: int = 403) -> None:
        super().__init__(message)
        self.status = status


class ArtifactUnavailable(RuntimeError):
    """Provider failures are deliberately free of requests and credential diagnostics."""

    def __init__(self, status: int = 503) -> None:
        super().__init__("Saved outputs are unavailable")
        self.status = status


def _relative_path(value: str, *, directory: bool = False) -> str:
    if not isinstance(value, str):
        raise ArtifactAccessDenied("Saved output path is invalid")
    if value.startswith("/"):
        raise ArtifactAccessDenied("Saved output path is invalid")
    if directory and value.endswith("/"):
        value = value[:-1]
    if (
        len(value.encode("utf-8")) > 1024
        or "\\" in value
        or any(unicodedata.category(c).startswith("C") for c in value)
        or (value and any(part in {"", ".", ".."} for part in value.split("/")))
    ):
        raise ArtifactAccessDenied("Saved output path is invalid")
    return value


def _decoded(value: str | None) -> str:
    if value is None or re.search(r"%(?![0-9a-fA-F]{2})", value):
        raise ArtifactUnavailable(502)
    return unquote_to_bytes(value).decode("utf-8", errors="strict")


async def _close(client: httpx.AsyncClient | None, response: httpx.Response | None) -> None:
    with anyio.CancelScope(shield=True):
        await asyncio.gather(
            *([response.aclose()] if response is not None else []),
            *([client.aclose()] if client is not None else []),
            return_exceptions=True,
        )


class _OutputStream(StreamingResponse):
    def __init__(
        self,
        body: AsyncIterator[bytes],
        *,
        upstream: httpx.Response,
        client: httpx.AsyncClient,
        headers: Mapping[str, str],
        expires_at: int,
        clock: Callable[[], float],
    ) -> None:
        super().__init__(body, headers=headers)
        self._upstream, self._client = upstream, client
        self._expires_at, self._clock = expires_at, clock

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            async with asyncio.timeout(max(0, self._expires_at - self._clock() - 5)):
                await super().__call__(scope, receive, send)
        except TimeoutError:
            raise ArtifactAccessDenied("Saved output stream authority expired") from None
        finally:
            await _close(self._client, self._upstream)


class AliyunArtifactReader:
    """Only list and GET the output prefix derived from fresh Session authority."""

    def __init__(
        self,
        configs: tuple[AliyunOssStorageConfig, ...],
        *,
        credential_file: Path,
        authorize: Callable[[UUID], RuntimeContext],
        clock: Callable[[], float] = time.time,
        client_factory: Callable[[], httpx.AsyncClient] | None = None,
    ) -> None:
        if (
            not configs
            or len({c.tenant_id for c in configs}) != len(configs)
            or any(not c.project_scoped for c in configs)
        ):
            raise ValueError("Aliyun output tenant allowlist is invalid")
        self._configs = {c.tenant_id: c for c in configs}
        self._credential_file = credential_file
        self._authorize = authorize
        self._clock = clock
        self._client_factory = client_factory or (
            lambda: httpx.AsyncClient(
                timeout=httpx.Timeout(30.0, connect=5.0),
                trust_env=False,
                follow_redirects=False,
            )
        )

    def prepare(self) -> dict[str, Any]:
        try:
            if version("alibabacloud-oss-v2") != "1.4.0":
                raise ValueError
            return read_sts_document(self._credential_file, now=self._clock())
        except Exception:  # noqa: BLE001 - redact SDK and credential-file diagnostics.
            raise ArtifactUnavailable() from None

    async def admit(self, session_id: UUID) -> AliyunOssVolumeSpec:
        try:
            runtime = await asyncio.to_thread(self._authorize, session_id)
            config = self._configs.get(runtime.tenant_id)
            requested = current_runtime_context()
            if (
                config is None
                or replace(runtime, project_id=requested.project_id) != requested
                or (
                    requested.project_id is not None and runtime.project_id != requested.project_id
                )
            ):
                raise ValueError
            return config.session(runtime, session_id).volumes[1]
        except Exception:  # noqa: BLE001 - deny without disclosing stores or scope facts.
            raise ArtifactAccessDenied("Saved output access is denied") from None

    @staticmethod
    def scope_key(spec: AliyunOssVolumeSpec) -> str:
        runtime = current_runtime_context()
        data = (
            spec.name,
            str(runtime.actor_id),
            runtime.user_security_version,
            runtime.tenant_membership_version,
            runtime.space_membership_version,
        )
        return hashlib.sha256(json.dumps(data, separators=(",", ":")).encode()).hexdigest()

    def _check_scope(self, spec: AliyunOssVolumeSpec, scope_key: str | None) -> None:
        if scope_key is not None and not hmac.compare_digest(self.scope_key(spec), scope_key):
            raise ArtifactAccessDenied("Saved output scope changed")

    async def _request(
        self,
        spec: AliyunOssVolumeSpec,
        *,
        key: str | None,
        params: Mapping[str, str] | None = None,
        etag: str | None = None,
    ) -> tuple[httpx.AsyncClient, httpx.Response, int]:
        client: httpx.AsyncClient | None = None
        response: httpx.Response | None = None
        try:
            credential = self.prepare()
            from alibabacloud_oss_v2.signer.v4 import SignerV4
            from alibabacloud_oss_v2.types import Credentials, HttpRequest, SigningContext

            if key is not None and (
                not key.startswith(spec.bucket_path.lstrip("/")) or len(key.encode("utf-8")) > 1024
            ):
                raise ArtifactAccessDenied("Saved output path is invalid")
            if etag is not None and _ETAG.fullmatch(etag) is None:
                raise ArtifactAccessDenied("Saved output identity is invalid")
            client = self._client_factory()
            host = f"{spec.bucket}.oss-cn-hangzhou.aliyuncs.com"
            outbound = client.build_request(
                "GET",
                f"https://{host}/{quote(key or '', safe='/')}",
                params=params,
                headers={
                    "Accept-Encoding": "identity",
                    **({"If-Match": etag} if etag is not None else {}),
                },
            )
            signed = HttpRequest("GET", str(outbound.url), headers=dict(outbound.headers))
            SignerV4().sign(
                SigningContext(
                    product="oss",
                    region="cn-hangzhou",
                    bucket=spec.bucket,
                    key=key,
                    request=signed,
                    credentials=Credentials(
                        credential["access_key_id"],
                        credential["access_key_secret"],
                        credential["security_token"],
                    ),
                    signing_time=datetime.fromtimestamp(self._clock(), UTC),
                    additional_headers={"if-match"} if etag is not None else None,
                )
            )
            outbound.headers.update(signed.headers)
            response = await client.send(outbound, stream=True, follow_redirects=False)
            if response.status_code != 200:
                raise ArtifactUnavailable(
                    response.status_code if response.status_code in {404, 412} else 503
                )
            if response.headers.get("content-encoding", "identity") != "identity":
                raise ArtifactUnavailable(502)
            return client, response, credential["expires_at"]
        except BaseException as error:
            await _close(client, response)
            if not isinstance(error, Exception):
                raise
            if isinstance(
                error, (ArtifactAccessDenied, ArtifactUnavailable, asyncio.CancelledError)
            ):
                raise
            raise ArtifactUnavailable() from None

    async def list(
        self,
        session_id: UUID,
        *,
        prefix: str = "",
        cursor: str | None = None,
        limit: int = 50,
        check_auth: Callable[[], None],
        scope_key: str | None = None,
    ) -> dict[str, Any]:
        relative = _relative_path(prefix, directory=True)
        if not 1 <= limit <= 200 or (
            cursor is not None
            and (not 1 <= len(cursor) <= 4096 or any(ord(c) < 33 or ord(c) > 126 for c in cursor))
        ):
            raise ArtifactAccessDenied("Saved output cursor is invalid")
        await asyncio.to_thread(check_auth)
        spec = await self.admit(session_id)
        self._check_scope(spec, scope_key)
        namespace = spec.bucket_path.lstrip("/")
        directory = namespace + (relative + "/" if relative else "")
        params = {
            "list-type": "2",
            "encoding-type": "url",
            "delimiter": "/",
            "prefix": directory,
            "max-keys": str(limit),
        }
        if cursor is not None:
            params["continuation-token"] = cursor
        client, response, expires_at = await self._request(spec, key=None, params=params)
        try:
            payload = bytearray()
            async for chunk in response.aiter_raw(chunk_size=_CHUNK_BYTES):
                if len(payload) + len(chunk) > _XML_BYTES or self._clock() >= expires_at - 5:
                    raise ArtifactUnavailable(502)
                payload.extend(chunk)
            result = self._listing(bytes(payload), namespace, directory, limit)
            if cursor is not None and result["next_cursor"] == cursor:
                raise ArtifactUnavailable(502)
            await asyncio.to_thread(check_auth)
            if await self.admit(session_id) != spec:
                raise ArtifactAccessDenied("Saved output scope changed")
            return result
        except (ArtifactAccessDenied, ArtifactUnavailable, asyncio.CancelledError):
            raise
        except Exception:  # noqa: BLE001 - redact provider and XML diagnostics.
            raise ArtifactUnavailable(502) from None
        finally:
            await _close(client, response)

    @staticmethod
    def _listing(payload: bytes, namespace: str, directory: str, limit: int) -> dict[str, Any]:
        root = fromstring(payload)
        for element in root.iter():
            element.tag = element.tag.rsplit("}", 1)[-1]
        if (
            root.tag != "ListBucketResult"
            or root.findtext("EncodingType") != "url"
            or _decoded(root.findtext("Prefix")) != directory
            or root.findtext("IsTruncated") not in {"true", "false"}
        ):
            raise ArtifactUnavailable(502)
        entries = []
        seen: set[tuple[str, str]] = set()
        for item in root:
            if item.tag not in {"Contents", "CommonPrefixes"}:
                continue
            folder = item.tag == "CommonPrefixes"
            key = _decoded(item.findtext("Prefix" if folder else "Key"))
            if key == directory:
                continue
            if not key.startswith(directory):
                raise ArtifactUnavailable(502)
            child = key[len(directory) :]
            name = child[:-1] if folder and child.endswith("/") else child
            if not name or "/" in name or (folder and not child.endswith("/")):
                raise ArtifactUnavailable(502)
            path = _relative_path(key[len(namespace) :], directory=folder)
            etag = None if folder else item.findtext("ETag")
            size = None if folder else int(item.findtext("Size", "-1"))
            if not folder and (
                size is None
                or not 0 <= size < 2**63
                or etag is None
                or _ETAG.fullmatch(etag) is None
            ):
                raise ArtifactUnavailable(502)
            identity = ("directory" if folder else "file", path)
            if identity in seen:
                raise ArtifactUnavailable(502)
            seen.add(identity)
            entries.append(
                {"path": path, "name": name, "type": identity[0], "bytes": size, "etag": etag}
            )
        cursor = root.findtext("NextContinuationToken")
        truncated = root.findtext("IsTruncated") == "true"
        if len(entries) > limit or (
            truncated
            and (
                not cursor
                or len(cursor) > 4096
                or any(ord(c) < 33 or ord(c) > 126 for c in cursor)
            )
        ):
            raise ArtifactUnavailable(502)
        return {
            "object": "session.artifacts",
            "data": entries,
            "next_cursor": cursor if truncated else None,
        }

    async def download(
        self,
        session_id: UUID,
        *,
        path: str,
        etag: str,
        check_auth: Callable[[], None],
        scope_key: str | None = None,
    ) -> StreamingResponse:
        relative = _relative_path(path)
        if not relative or _ETAG.fullmatch(etag) is None:
            raise ArtifactAccessDenied("Saved output identity is invalid")
        await asyncio.to_thread(check_auth)
        spec = await self.admit(session_id)
        self._check_scope(spec, scope_key)
        client, response, expires_at = await self._request(
            spec, key=spec.bucket_path.lstrip("/") + relative, etag=etag
        )
        try:
            raw_length = response.headers.get("content-length", "")
            if (
                not raw_length.isascii()
                or not raw_length.isdigit()
                or not 0 <= int(raw_length) < 2**63
                or response.headers.get("etag") != etag
            ):
                raise ArtifactUnavailable(502)
            length = int(raw_length)
            await asyncio.to_thread(check_auth)
            if await self.admit(session_id) != spec:
                raise ArtifactAccessDenied("Saved output scope changed")
        except BaseException:
            await _close(client, response)
            raise

        async def body() -> AsyncIterator[bytes]:
            transferred = 0
            pending = b""
            try:
                async for chunk in response.aiter_raw(chunk_size=_CHUNK_BYTES):
                    await asyncio.to_thread(check_auth)
                    if (
                        self._clock() >= expires_at - 5
                        or await self.admit(session_id) != spec
                        or transferred + len(chunk) > length
                    ):
                        raise ArtifactAccessDenied("Saved output stream authority changed")
                    transferred += len(chunk)
                    if pending:
                        yield pending
                    pending = chunk
                if transferred != length:
                    raise ArtifactUnavailable(502)
                await asyncio.to_thread(check_auth)
                if self._clock() >= expires_at - 5 or await self.admit(session_id) != spec:
                    raise ArtifactAccessDenied("Saved output stream authority changed")
                if pending:
                    yield pending
            except (ArtifactAccessDenied, ArtifactUnavailable, asyncio.CancelledError):
                raise
            except Exception:  # noqa: BLE001 - never expose signed-request diagnostics.
                raise ArtifactUnavailable() from None

        return _OutputStream(
            body(),
            upstream=response,
            client=client,
            expires_at=expires_at,
            clock=self._clock,
            headers={
                **_HEADERS,
                "Content-Type": "application/octet-stream",
                "Content-Length": str(length),
                "Content-Disposition": _attachment_disposition(relative.rsplit("/", 1)[-1]),
                "ETag": etag,
            },
        )


def create_aliyun_artifact_router(
    reader: AliyunArtifactReader, auth_provider: SaasAuthProvider
) -> APIRouter:
    router = APIRouter()

    def checker(request: Request) -> Callable[[], None]:
        token, source = auth_provider.extract_token(request)
        if token is None or source == "ambiguous" or auth_provider.is_machine_token(token):
            raise ArtifactAccessDenied("Saved output authentication is required", status=401)
        try:
            runtime = current_runtime_context()
        except RuntimeError:
            raise ArtifactAccessDenied("Saved output scope is required") from None

        def check() -> None:
            try:
                session = auth_provider.validate_token(token)
                if (session.user_id, session.security_version) != (
                    runtime.actor_id,
                    runtime.user_security_version,
                ):
                    raise ValueError
            except (LifecycleError, ValueError):
                raise ArtifactAccessDenied("Saved output authentication was revoked") from None
            except Exception:  # noqa: BLE001 - redact authentication dependency diagnostics.
                raise ArtifactUnavailable() from None

        return check

    def error_response(error: Exception) -> JSONResponse:
        status = (
            error.status if isinstance(error, (ArtifactUnavailable, ArtifactAccessDenied)) else 403
        )
        code = (
            "saved_outputs_unavailable" if isinstance(error, ArtifactUnavailable) else "forbidden"
        )
        return JSONResponse({"error": {"code": code}}, status_code=status, headers=_HEADERS)

    @router.get("/sessions/{session_id}/artifacts/availability", include_in_schema=False)
    async def available(request: Request, session_id: UUID):
        try:
            await asyncio.to_thread(checker(request))
            spec = await reader.admit(session_id)
            return JSONResponse(
                {
                    "object": "session.artifacts.availability",
                    "available": True,
                    "scope_key": reader.scope_key(spec),
                    "tenant_id": str(spec.tenant_id),
                    "space_id": str(spec.space_id),
                },
                headers=_HEADERS,
            )
        except (ArtifactAccessDenied, ArtifactUnavailable) as error:
            return error_response(error)

    @router.get("/sessions/{session_id}/artifacts", include_in_schema=False)
    async def listing(
        request: Request,
        session_id: UUID,
        prefix: str = Query(default="", max_length=1024),
        cursor: str | None = Query(default=None, max_length=4096),
        limit: int = Query(default=50, ge=1, le=200),
        scope: str | None = Query(default=None, pattern="^[0-9a-f]{64}$"),
    ):
        try:
            return JSONResponse(
                await reader.list(
                    session_id,
                    prefix=prefix,
                    cursor=cursor,
                    limit=limit,
                    check_auth=checker(request),
                    scope_key=scope,
                ),
                headers=_HEADERS,
            )
        except (ArtifactAccessDenied, ArtifactUnavailable) as error:
            return error_response(error)

    @router.get("/sessions/{session_id}/artifacts/content", include_in_schema=False)
    async def content(
        request: Request,
        session_id: UUID,
        path: str = Query(min_length=1, max_length=1024),
        etag: str = Query(min_length=3, max_length=130),
        scope: str | None = Query(default=None, pattern="^[0-9a-f]{64}$"),
    ):
        try:
            return await reader.download(
                session_id, path=path, etag=etag, check_auth=checker(request), scope_key=scope
            )
        except (ArtifactAccessDenied, ArtifactUnavailable) as error:
            return error_response(error)

    return router
