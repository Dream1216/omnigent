"""Stable SDK exception hierarchy."""

from __future__ import annotations

from collections.abc import Mapping


class OmnigentSaasError(RuntimeError):
    """Base class for every SDK-owned failure."""


class TransportError(OmnigentSaasError):
    """The request could not be completed at the HTTP transport boundary."""


class ApiTimeoutError(TransportError):
    """A configured connect/read/write/pool deadline expired."""


class ProtocolError(OmnigentSaasError):
    """The server returned a response that does not match the frozen contract."""


class ApiError(OmnigentSaasError):
    def __init__(
        self,
        *,
        status_code: int,
        code: str,
        message: str,
        request_id: str | None,
        details: Mapping[str, object] | None = None,
        retry_after: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.request_id = request_id
        self.details = dict(details or {})
        self.retry_after = retry_after


class AuthenticationError(ApiError):
    pass


class AuthorizationError(ApiError):
    pass


class NotFoundError(ApiError):
    pass


class ConflictError(ApiError):
    pass


class PreconditionFailedError(ApiError):
    pass


class ValidationError(ApiError):
    pass


class RateLimitError(ApiError):
    pass


__all__ = [
    "ApiError",
    "ApiTimeoutError",
    "AuthenticationError",
    "AuthorizationError",
    "ConflictError",
    "NotFoundError",
    "OmnigentSaasError",
    "PreconditionFailedError",
    "ProtocolError",
    "RateLimitError",
    "TransportError",
    "ValidationError",
]
