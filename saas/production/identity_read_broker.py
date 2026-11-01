"""Fixed-subject state reads; the product worker receives no provider credential."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from saas.control_plane.identity_events import IdentityStateProvider
from saas.control_plane.identity_inbox import IdentitySyncPolicy
from saas.control_plane.identity_private_channel import PrivateIdentityKeys, private_identity_https
from saas.control_plane.identity_read_protocol import (
    IDENTITY_READ_KEY_ID,
    IDENTITY_READ_PATH,
    IDENTITY_READ_SECRET,
    encode_identity_read,
    validate_provider_state,
)


class QualifiedIdentityReader(IdentityStateProvider, Protocol):
    def verify_organization(self) -> None: ...


@dataclass(frozen=True, slots=True)
class IdentityReadBrokerPins:
    issuer: str
    organization: str
    broker_revision: str
    provider_source_lock_sha256: str
    allow_insecure_loopback: bool = False

    def __post_init__(self) -> None:
        url = urlsplit(self.issuer)
        port = url.port
        IdentitySyncPolicy(
            issuer=self.issuer,
            organization=self.organization,
            allow_insecure_loopback=self.allow_insecure_loopback,
        )
        if (
            self.issuer != f"{url.scheme}://{url.netloc}"
            or (port is not None and not 1 <= port <= 65535)
            or re.fullmatch(r"[0-9a-f]{40}", self.broker_revision) is None
            or re.fullmatch(r"[0-9a-f]{64}", self.provider_source_lock_sha256) is None
        ):
            raise ValueError("identity reader source pins are invalid")


def create_identity_read_broker(
    provider: QualifiedIdentityReader,
    *,
    pins: IdentityReadBrokerPins,
    keys: PrivateIdentityKeys,
    concurrency: int = 4,
) -> FastAPI:
    if type(concurrency) is not int or not 1 <= concurrency <= 16:
        raise ValueError("identity reader concurrency is invalid")
    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
    capacity = asyncio.Semaphore(concurrency)

    def response(status: int, document: dict[str, object]):
        return JSONResponse(document, status_code=status, headers={"Cache-Control": "no-store"})

    @app.get("/healthz")
    async def health():
        return response(200, {"status": "ok"})

    @app.get(IDENTITY_READ_PATH)
    async def read(request: Request):
        if not private_identity_https(
            request,
            allow_insecure_loopback=keys.allow_insecure_loopback and pins.allow_insecure_loopback,
        ):
            return response(403, {"error": "identity_reader_https_required"})
        if (
            len(request.headers.getlist(IDENTITY_READ_KEY_ID)) != 1
            or len(request.headers.getlist(IDENTITY_READ_SECRET)) != 1
            or not keys.accepts(
                request.headers.get(IDENTITY_READ_KEY_ID, ""),
                request.headers.get(IDENTITY_READ_SECRET, ""),
            )
        ):
            return response(401, {"error": "identity_reader_authentication_required"})
        values = list(request.query_params.multi_items())
        if (
            len(request.url.query) > 2048
            or len(values) != 1
            or values[0][0] != "subject"
            or not 1 <= len(values[0][1]) <= 512
            or any(ord(char) < 32 for char in values[0][1])
        ):
            return response(400, {"error": "identity_reader_request_invalid"})
        async for chunk in request.stream():
            if chunk:
                return response(400, {"error": "identity_reader_request_invalid"})
        subject = values[0][1]

        def read_verified():
            # Policy is rechecked for each read, not cached across organization changes.
            provider.verify_organization()
            state = provider.read_identity(subject)
            observed = datetime.now(timezone.utc)
            validate_provider_state(
                state,
                issuer=pins.issuer,
                organization=pins.organization,
                subject=subject,
                now=observed,
            )
            return encode_identity_read(
                state,
                observed_at=observed,
                broker_revision=pins.broker_revision,
                provider_source_lock_sha256=pins.provider_source_lock_sha256,
            )

        try:
            if capacity.locked():
                return response(503, {"error": "identity_reader_busy"})
            async with capacity:
                document = await run_in_threadpool(read_verified)
        except Exception:  # noqa: BLE001 - never expose upstream payloads or credentials.
            return response(503, {"error": "identity_reader_unavailable"})
        return response(200, document)

    return app
