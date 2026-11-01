"""Private authenticated notification ingress; browser sessions confer no authority."""

from __future__ import annotations

import hmac
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from saas.control_plane.identity_events import (
    IdentityNotificationIgnored,
    IdentitySyncError,
    parse_casdoor_notification,
)
from saas.control_plane.identity_inbox import IdentityEventInboxService


@dataclass(frozen=True, slots=True)
class IdentityEventIngressKeys:
    keys: Mapping[str, str] = field(repr=False)
    allow_insecure_loopback: bool = False

    def __post_init__(self) -> None:
        if not 1 <= len(self.keys) <= 8 or any(
            not isinstance(key_id, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", key_id)
            or not isinstance(secret, str)
            or not 32 <= len(secret) <= 256
            or not secret.isascii()
            or any(ord(char) < 33 or ord(char) > 126 for char in secret)
            for key_id, secret in self.keys.items()
        ):
            raise ValueError("identity event ingress keys are invalid")
        object.__setattr__(self, "keys", MappingProxyType(dict(self.keys)))

    def accepts(self, key_id: str, secret: str) -> bool:
        expected = self.keys.get(key_id)
        candidate = expected or "x" * 43
        if len(secret) > 256 or not secret.isascii():
            return False
        matched = hmac.compare_digest(secret, candidate)
        return expected is not None and matched


def create_identity_event_router(
    inbox: IdentityEventInboxService,
    *,
    keys: IdentityEventIngressKeys,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> APIRouter:
    router = APIRouter()

    def response(status: int, document: dict[str, object]) -> JSONResponse:
        return JSONResponse(document, status_code=status, headers={"Cache-Control": "no-store"})

    @router.post("/saas/identity-events/casdoor")
    async def receive(request: Request):
        loopback = (
            request.client is not None
            and request.client.host in {"127.0.0.1", "::1"}
            and request.url.hostname in {"localhost", "127.0.0.1", "::1"}
        )
        if request.url.scheme != "https" and not (keys.allow_insecure_loopback and loopback):
            return response(403, {"error": "identity_event_https_required"})
        if not keys.accepts(
            request.headers.get("X-Omnigent-Identity-Event-Key-Id", ""),
            request.headers.get("X-Omnigent-Identity-Event-Secret", ""),
        ):
            return response(401, {"error": "identity_event_authentication_required"})
        if (
            request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            != "application/json"
            or request.headers.get("content-encoding", "identity") != "identity"
        ):
            return response(415, {"error": "identity_event_content_type_invalid"})
        body = bytearray()
        try:
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 65536:
                    return response(413, {"error": "identity_event_payload_too_large"})
            received_at = now()
            event = parse_casdoor_notification(
                bytes(body), organization=inbox.policy.organization, now=received_at
            )
            receipt = await run_in_threadpool(inbox.ingest, event, now=received_at)
        except IdentityNotificationIgnored:
            return response(200, {"status": "ignored"})
        except IdentitySyncError as error:
            status = 409 if error.code == "identity_notification_idempotency_conflict" else 400
            return response(status, {"error": error.code})
        except Exception:  # noqa: BLE001 - neither DB details nor raw notifications leave ingress.
            return response(503, {"error": "identity_event_unavailable"})
        # The pinned provider retries any status other than 200. The transaction
        # has committed before acknowledging this asynchronous receipt.
        return response(
            200,
            {
                "receipt_id": str(receipt.id),
                "status": receipt.status,
                "duplicate": receipt.duplicate,
            },
        )

    return router
