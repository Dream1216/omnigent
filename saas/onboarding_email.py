"""Content-blind production email delivery for self-service verification."""

from __future__ import annotations

import ipaddress
import re
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import timezone
from typing import TYPE_CHECKING
from urllib.parse import quote, urlsplit
from uuid import UUID

import httpx

if TYPE_CHECKING:
    from saas.control_plane.onboarding import EmailVerificationMessage


RESEND_EMAIL_ENDPOINT = "https://api.resend.com/emails"
_SAFE_ERROR_CODE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_EMAIL_LOCAL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}")
_TRANSIENT_HTTP_STATUSES = frozenset({408, 425, 429})
_CONCURRENT_IDEMPOTENCY_ERROR = "concurrent_idempotent_requests"
_INVALID_IDEMPOTENCY_ERROR = "invalid_idempotent_request"
_MAX_PROVIDER_RESPONSE_BYTES = 4096


class EmailVerificationDeliveryError(RuntimeError):
    """Stable delivery failure safe for Outbox retry classification and logs."""

    def __init__(self, code: str, *, retryable: bool, pre_side_effect: bool) -> None:
        if _SAFE_ERROR_CODE.fullmatch(code) is None:
            raise ValueError("email verification delivery error code is invalid")
        if type(retryable) is not bool or type(pre_side_effect) is not bool:
            raise TypeError("email verification delivery disposition is invalid")
        self.code = code
        self.retryable = retryable
        self.pre_side_effect = pre_side_effect
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ResendEmailVerificationConfig:
    """Validated non-ambient configuration for one Resend sender."""

    public_origin: str
    from_address: str
    provider_token: str = field(repr=False)
    timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        origin = _public_origin(self.public_origin)
        sender = _email_address(self.from_address)
        token = self.provider_token
        if (
            not isinstance(token, str)
            or not 1 <= len(token) <= 4096
            or token != token.strip()
            or any(
                character.isspace() or ord(character) < 33 or ord(character) > 126
                for character in token
            )
            or isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not 0 < float(self.timeout_seconds) <= 30
        ):
            raise ValueError("Resend email verification configuration is invalid")
        object.__setattr__(self, "public_origin", origin)
        object.__setattr__(self, "from_address", sender)
        object.__setattr__(self, "timeout_seconds", float(self.timeout_seconds))


class ResendEmailVerificationSender:
    """Deliver a text-only verification link through Resend's HTTPS API.

    The origin, sender, and copy form the provider's idempotency contract. A
    deployment must drain their outstanding events before changing that
    contract while Resend can still retain an event ID.
    """

    __slots__ = ("_client", "_config")

    def __init__(
        self,
        config: ResendEmailVerificationConfig,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not isinstance(config, ResendEmailVerificationConfig):
            raise TypeError("Resend email verification configuration is invalid")
        self._config = config
        self._client = httpx.Client(
            transport=transport,
            timeout=httpx.Timeout(config.timeout_seconds),
            follow_redirects=False,
            trust_env=False,
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(endpoint={RESEND_EMAIL_ENDPOINT!r})"

    def close(self) -> None:
        self._client.close()

    def send_verification(
        self,
        *,
        event_id: UUID,
        message: EmailVerificationMessage,
    ) -> None:
        if not isinstance(event_id, UUID):
            raise EmailVerificationDeliveryError(
                "email_verification_message_invalid",
                retryable=False,
                pre_side_effect=True,
            )
        payload = self._payload(message)
        response: httpx.Response | None = None
        with suppress(httpx.HTTPError):
            response = self._client.post(
                RESEND_EMAIL_ENDPOINT,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {self._config.provider_token}",
                    "Content-Type": "application/json",
                    "Idempotency-Key": str(event_id),
                    "User-Agent": "omnigent-saas-onboarding/1",
                },
                json=payload,
            )
        if response is None:
            # A transport failure can happen after Resend accepted the request.
            # The immutable event id makes the retry safe. Raising after the
            # suppression scope also avoids retaining its cause or context.
            raise EmailVerificationDeliveryError(
                "email_verification_provider_unavailable",
                retryable=True,
                pre_side_effect=False,
            )
        self._validate_response(response)

    def _payload(self, message: EmailVerificationMessage) -> dict[str, object]:
        try:
            recipient = _email_address(message.email)
            if (
                not isinstance(message.registration_id, UUID)
                or not isinstance(message.verification_token, str)
                or not 1 <= len(message.verification_token) <= 1024
                or any(
                    ord(character) < 33 or ord(character) > 126 or character.isspace()
                    for character in message.verification_token
                )
                or message.expires_at.tzinfo is None
                or message.expires_at.utcoffset() is None
            ):
                raise ValueError("invalid verification message")
            token = quote(message.verification_token, safe="")
            registration_id = quote(str(message.registration_id), safe="")
            verification_url = (
                f"{self._config.public_origin}/signup/verify"
                f"?registration_id={registration_id}#token={token}"
            )
            expiry = message.expires_at.astimezone(timezone.utc).isoformat()
        except (AttributeError, TypeError, ValueError, OverflowError):
            raise EmailVerificationDeliveryError(
                "email_verification_message_invalid",
                retryable=False,
                pre_side_effect=True,
            ) from None
        return {
            "from": self._config.from_address,
            "to": [recipient],
            "subject": "Verify your Omnigent workspace",
            "text": (
                "Verify your email address to finish creating your Omnigent workspace.\n\n"
                f"{verification_url}\n\n"
                f"This one-time link expires at {expiry}. If you did not request this, "
                "you can ignore this email."
            ),
        }

    @staticmethod
    def _validate_response(response: httpx.Response) -> None:
        status = response.status_code
        if 200 <= status <= 299:
            if _provider_message_id(response) is None:
                raise EmailVerificationDeliveryError(
                    "email_verification_provider_protocol_invalid",
                    retryable=True,
                    pre_side_effect=False,
                )
            return
        if status == 409:
            provider_error = _provider_error_name(response)
            if provider_error == _CONCURRENT_IDEMPOTENCY_ERROR:
                raise EmailVerificationDeliveryError(
                    "email_verification_provider_concurrent",
                    retryable=True,
                    pre_side_effect=False,
                )
            if provider_error == _INVALID_IDEMPOTENCY_ERROR:
                raise EmailVerificationDeliveryError(
                    "email_verification_provider_idempotency_conflict",
                    retryable=False,
                    # The conflicting key can name an earlier accepted request.
                    pre_side_effect=False,
                )
            # An undocumented conflict is not evidence of a poison event. Keep
            # it on the bounded retry path because a send may already exist.
            raise EmailVerificationDeliveryError(
                "email_verification_provider_protocol_invalid",
                retryable=True,
                pre_side_effect=False,
            )
        if status in _TRANSIENT_HTTP_STATUSES or 500 <= status <= 599:
            raise EmailVerificationDeliveryError(
                (
                    "email_verification_provider_rate_limited"
                    if status == 429
                    else "email_verification_provider_unavailable"
                ),
                retryable=True,
                pre_side_effect=False,
            )
        if 300 <= status <= 399:
            raise EmailVerificationDeliveryError(
                "email_verification_provider_redirect_rejected",
                retryable=False,
                pre_side_effect=True,
            )
        if 400 <= status <= 499:
            raise EmailVerificationDeliveryError(
                "email_verification_provider_rejected",
                retryable=False,
                pre_side_effect=True,
            )
        raise EmailVerificationDeliveryError(
            "email_verification_provider_protocol_invalid",
            retryable=True,
            pre_side_effect=False,
        )


def _provider_message_id(response: httpx.Response) -> UUID | None:
    payload = _bounded_json_object(response)
    if payload is None:
        return None
    value = payload.get("id")
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        return None
    try:
        return UUID(value)
    except ValueError:
        return None


def _provider_error_name(response: httpx.Response) -> str | None:
    payload = _bounded_json_object(response)
    if payload is None:
        return None
    value = payload.get("name")
    if not isinstance(value, str) or _SAFE_ERROR_CODE.fullmatch(value) is None:
        return None
    return value


def _bounded_json_object(response: httpx.Response) -> dict[str, object] | None:
    content = response.content
    if len(content) > _MAX_PROVIDER_RESPONSE_BYTES:
        return None
    try:
        value = response.json()
    except ValueError:
        return None
    if not isinstance(value, dict):
        return None
    return value


def _public_origin(value: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 2048
        or value != value.strip()
        or "\\" in value
        or any(ord(character) < 33 or ord(character) > 126 for character in value)
    ):
        raise ValueError("verification public Origin is invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("verification public Origin is invalid") from error
    hostname = parsed.hostname
    if (
        parsed.scheme != "https"
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.path not in {"", "/"}
        or bool(parsed.query)
        or bool(parsed.fragment)
        or not _dns_name(hostname)
    ):
        raise ValueError("verification public Origin is invalid")
    return f"https://{hostname.lower()}"


def _email_address(value: str) -> str:
    if (
        not isinstance(value, str)
        or not 3 <= len(value) <= 320
        or value != value.strip()
        or value.count("@") != 1
        or any(ord(character) > 127 for character in value)
    ):
        raise ValueError("email address is invalid")
    local, domain = value.rsplit("@", 1)
    if (
        _EMAIL_LOCAL.fullmatch(local) is None
        or local.startswith(".")
        or local.endswith(".")
        or ".." in local
        or not _dns_name(domain)
    ):
        raise ValueError("email address is invalid")
    return f"{local}@{domain.lower()}"


def _dns_name(value: str) -> bool:
    if (
        not 1 <= len(value) <= 253
        or value.startswith(".")
        or value.endswith(".")
        or "." not in value
        or any(_DNS_LABEL.fullmatch(label) is None for label in value.split("."))
    ):
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return True
    return False


__all__ = [
    "RESEND_EMAIL_ENDPOINT",
    "EmailVerificationDeliveryError",
    "ResendEmailVerificationConfig",
    "ResendEmailVerificationSender",
]
