"""Streaming gateway for the Platform-managed DeepSeek Provider.

The gateway is the only Runtime component allowed to decrypt the real Provider
credential.  Runners authenticate with a short-lived session bearer, while the
gateway reserves budget before egress and settles the same durable reservation
from the final OpenAI-compatible usage frame.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import stat
from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Protocol, cast
from uuid import UUID, uuid4

import anyio
import httpx
import sqlalchemy as sa
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.model_budget import (
    ModelProviderBudgetAdmissionService,
    ModelProviderBudgetError,
    ModelProviderBudgetReservationView,
)
from saas.control_plane.model_pricing import (
    PlatformModelPrice,
    PlatformModelPricingPolicy,
    token_cost_microusd,
)
from saas.control_plane.model_provider import (
    ModelProviderConfigurationReader,
    PlatformManagedModelRuntimeConfiguration,
)
from saas.control_plane.model_usage import ModelTokenUsage, normalize_model_usage
from saas.production.onboarding import build_production_secret_cipher
from saas.production.postgresql_migration import _inspect_service_login
from saas.production.server_config import (
    ProductionServerConfigError,
    load_production_database_url_file,
)
from saas.production.service_bindings import (
    ProductionServiceRoleBindingsError,
    load_platform_model_service_role_bindings,
)
from saas.runner_adapter.platform_model_gateway import (
    PlatformModelGatewayClaims,
    PlatformModelGatewayTokenAuthority,
    PlatformModelGatewayTokenError,
    PlatformModelGatewayTokenExpired,
)
from saas.runner_adapter.platform_models import PLATFORM_MODEL_MAX_OUTPUT_TOKENS

_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_MAX_SSE_LINE_BYTES = 256 * 1024
_TENANT_ID_ENV = "OMNIGENT_SAAS_PLATFORM_MODEL_TENANT_ID"
_TOKEN_KEY_FILE_ENV = "OMNIGENT_SAAS_PLATFORM_MODEL_TOKEN_KEY_FILE"
_PRICING_FILE_ENV = "OMNIGENT_SAAS_PLATFORM_MODEL_PRICING_FILE"
_LOG = logging.getLogger(__name__)


class ConfigurationReader(Protocol):
    def load(self) -> PlatformManagedModelRuntimeConfiguration | None: ...


class BudgetAuthority(Protocol):
    def reserve(
        self,
        *,
        tenant_id: UUID,
        run_id: UUID,
        operation_key: str,
        requested_microusd: int,
        requested_tokens: int,
        ttl: timedelta,
        now: datetime | None = None,
    ) -> ModelProviderBudgetReservationView: ...

    def begin_attempt(
        self, *, reservation_id: UUID, now: datetime | None = None
    ) -> ModelProviderBudgetReservationView: ...

    def mark_uncertain(
        self, *, reservation_id: UUID, now: datetime | None = None
    ) -> ModelProviderBudgetReservationView: ...

    def resolve_attempt(
        self,
        *,
        reservation_id: UUID,
        actual_microusd: int,
        actual_tokens: int,
        evidence_sha256: str,
        now: datetime | None = None,
    ) -> ModelProviderBudgetReservationView: ...

    def release(
        self,
        *,
        reservation_id: UUID,
        now: datetime | None = None,
    ) -> ModelProviderBudgetReservationView: ...


def _streaming_document(document: dict[str, object], *, responses: bool) -> dict[str, object]:
    outbound = dict(document)
    outbound["stream"] = True
    if responses:
        outbound.pop("stream_options", None)
        outbound["max_output_tokens"] = _output_token_limit(document, responses=True)
    else:
        # DeepSeek receives one concrete bound, including null/omitted SDK defaults.
        outbound.pop("max_completion_tokens", None)
        outbound["max_tokens"] = _output_token_limit(document, responses=False)
        outbound["stream_options"] = {"include_usage": True}
    return outbound


class PlatformModelGateway:
    """Authenticate, admit, proxy and settle one OpenAI-compatible stream."""

    def __init__(
        self,
        *,
        tokens: PlatformModelGatewayTokenAuthority,
        configurations: ConfigurationReader,
        budgets: BudgetAuthority,
        pricing: PlatformModelPricingPolicy,
        reservation_ttl: timedelta = timedelta(minutes=30),
        client_factory: Callable[[], httpx.AsyncClient] | None = None,
        readiness_check: Callable[[], None] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if reservation_ttl <= timedelta(0) or reservation_ttl > timedelta(hours=24):
            raise ValueError("Platform model reservation TTL is invalid")
        self._tokens = tokens
        self._configurations = configurations
        self._budgets = budgets
        self._pricing = pricing
        self._reservation_ttl = reservation_ttl
        self._client_factory = client_factory or (
            lambda: httpx.AsyncClient(timeout=httpx.Timeout(120.0, connect=10.0), trust_env=False)
        )
        self._readiness_check = readiness_check
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def require_ready(self) -> None:
        if self._readiness_check is not None:
            self._readiness_check()

    async def chat_completions(self, request: Request):
        return await self._proxy_stream(request, upstream_path="chat/completions")

    async def responses(self, request: Request):
        return await self._proxy_stream(request, upstream_path="responses")

    async def _proxy_stream(self, request: Request, *, upstream_path: str):
        claims = self._authenticate(request.headers.get("authorization", ""))
        raw = await request.body()
        try:
            document = _request_document(raw, responses=upstream_path == "responses")
        except ValueError:
            return _error(400, "platform_model_request_invalid")
        model = cast(str, document["model"])
        try:
            configuration = await asyncio.to_thread(self._configurations.load)
        except Exception:  # noqa: BLE001 - redact KMS and database adapter details.
            return _error(503, "platform_model_provider_unavailable")
        if configuration is None:
            return _error(503, "platform_model_provider_unavailable")
        if model not in configuration.allowed_models:
            return _error(400, "platform_model_not_allowed")
        try:
            price = self._pricing.for_catalog(configuration.allowed_models).get(model)
        except ValueError:
            return _error(503, "platform_model_pricing_unavailable")
        if price is None:
            return _error(503, "platform_model_pricing_unavailable")

        requested_tokens = _requested_tokens(
            raw,
            document,
            responses=upstream_path == "responses",
        )
        requested_microusd = _microusd(requested_tokens, price.reservation_rate)
        request_id = uuid4()
        requested_at = self._clock()
        if requested_at.tzinfo is None or requested_at.utcoffset() is None:
            return _error(503, "platform_model_pricing_unavailable")
        try:
            reservation = await asyncio.to_thread(
                self._budgets.reserve,
                tenant_id=claims.tenant_id,
                run_id=claims.session_id,
                operation_key=(
                    f"model-gateway:{self._pricing.revision}:{claims.session_id}:{request_id}"
                ),
                requested_microusd=requested_microusd,
                requested_tokens=requested_tokens,
                ttl=self._reservation_ttl,
                now=requested_at,
            )
        except ModelProviderBudgetError as error:
            return _error(429, error.code)
        except Exception:  # noqa: BLE001 - redact database adapter details.
            return _error(503, "platform_model_budget_unavailable")
        if reservation.status != "reserved":
            return _error(429, reservation.rejection_code or "platform_model_budget_rejected")
        if reservation.configuration_version != configuration.configuration_version:
            await self._release(reservation)
            return _error(409, "platform_model_configuration_changed")

        outbound = _streaming_document(document, responses=upstream_path == "responses")
        client: httpx.AsyncClient | None = None
        try:
            client = self._client_factory()
            outbound_request = client.build_request(
                "POST",
                f"{configuration.base_url.rstrip('/')}/{upstream_path}",
                headers={
                    "Authorization": f"Bearer {configuration.api_key}",
                    "Content-Type": "application/json",
                    "Accept": "text/event-stream",
                },
                json=outbound,
            )
        except Exception:  # noqa: BLE001 - local transport setup has not sent inference.
            await self._release(reservation)
            await self._close_transport(client)
            return _error(503, "platform_model_transport_unavailable")
        try:
            attempt = await asyncio.to_thread(
                self._budgets.begin_attempt, reservation_id=reservation.id
            )
            if attempt.id != reservation.id or attempt.status != "in_flight":
                raise ValueError("Invalid budget attempt fence")
        except Exception:  # noqa: BLE001 - a lost fence acknowledgement never permits egress.
            await self._release(reservation)
            await self._close_transport(client)
            return _error(503, "platform_model_budget_attempt_unavailable")
        try:
            upstream = await client.send(outbound_request, stream=True)
        except httpx.HTTPError:
            await self._retain_uncertain(reservation)
            await self._close_transport(client)
            return _error(502, "platform_model_provider_unreachable")
        except BaseException:
            with anyio.CancelScope(shield=True):
                await self._retain_uncertain(reservation)
                await self._close_transport(client)
            raise
        if upstream.status_code != 200:
            await self._retain_uncertain(reservation)
            await self._close_transport(client, upstream)
            return _error(502, "platform_model_provider_rejected")

        return StreamingResponse(
            self._stream_and_settle(
                client=client,
                upstream=upstream,
                reservation=reservation,
                price=price,
                requested_at=requested_at,
                model=model,
                responses=upstream_path == "responses",
            ),
            status_code=200,
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-store",
                "X-Accel-Buffering": "no",
                "X-Platform-Model-Pricing-Revision": self._pricing.revision,
            },
        )

    def _authenticate(self, header: str) -> PlatformModelGatewayClaims:
        scheme, separator, token = header.partition(" ")
        if not separator or scheme.lower() != "bearer" or not token or token != token.strip():
            raise PlatformModelGatewayTokenError("model gateway bearer is required")
        return self._tokens.validate(token)

    async def _stream_and_settle(
        self,
        *,
        client: httpx.AsyncClient,
        upstream: httpx.Response,
        reservation: ModelProviderBudgetReservationView,
        price: PlatformModelPrice,
        requested_at: datetime,
        model: str,
        responses: bool,
    ) -> AsyncIterator[bytes]:
        parser = _UsageParser(responses=responses)
        try:
            async for chunk in upstream.aiter_bytes():
                if chunk:
                    parser.feed(chunk)
                    yield chunk
            parser.finish()
        finally:
            with anyio.CancelScope(shield=True):
                try:
                    usage = parser.final_usage
                    if usage is None:
                        await self._retain_uncertain(reservation)
                    else:
                        await self._resolve_usage(
                            reservation,
                            usage,
                            price=price,
                            requested_at=requested_at,
                            model=model,
                            responses=responses,
                        )
                finally:
                    await self._close_transport(client, upstream)

    async def _resolve_usage(
        self,
        reservation: ModelProviderBudgetReservationView,
        usage: ModelTokenUsage,
        *,
        price: PlatformModelPrice,
        requested_at: datetime,
        model: str,
        responses: bool,
    ) -> None:
        try:
            actual = price.cost(usage, at=requested_at)
            if (
                actual > reservation.admitted_microusd
                or usage.total_tokens > reservation.admitted_tokens
            ):
                raise ValueError("Usage exceeds admitted budget")
            evidence = {
                "contract": "platform-model-gateway-usage-v1",
                "reservation_id": str(reservation.id),
                "tenant_id": str(reservation.tenant_id),
                "session_id": str(reservation.run_id),
                "provider_id": reservation.provider_id,
                "configuration_version": reservation.configuration_version,
                "public_model_id": model,
                "wire_api": "openai_responses" if responses else "openai_chat_completions",
                "pricing_revision": self._pricing.revision,
                "model_price": asdict(price),
                "requested_at": requested_at.isoformat(),
                "usage": asdict(usage),
                "actual_microusd": actual,
            }
            witness = sha256(
                json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("ascii")
            ).hexdigest()
            await asyncio.to_thread(
                self._budgets.resolve_attempt,
                reservation_id=reservation.id,
                actual_microusd=actual,
                actual_tokens=usage.total_tokens,
                evidence_sha256=witness,
            )
        except Exception:  # noqa: BLE001 - retain the hold rather than inventing a cost.
            await self._retain_uncertain(reservation)

    async def _retain_uncertain(self, reservation: ModelProviderBudgetReservationView) -> None:
        try:
            await asyncio.to_thread(self._budgets.mark_uncertain, reservation_id=reservation.id)
        except Exception:  # noqa: BLE001 - in-flight fences remain held if storage is unavailable.
            _LOG.warning(
                "platform_model_budget_reconciliation_required",
                extra={"reservation_id": str(reservation.id)},
            )

    @staticmethod
    async def _close_transport(
        client: httpx.AsyncClient | None, upstream: httpx.Response | None = None
    ) -> None:
        for value in (upstream, client):
            if value is not None:
                try:
                    await value.aclose()
                except Exception:  # noqa: BLE001 - cleanup cannot override a retained budget outcome.
                    _LOG.warning("platform_model_transport_cleanup_pending")

    async def _release(self, reservation: ModelProviderBudgetReservationView) -> None:
        try:
            await asyncio.to_thread(self._budgets.release, reservation_id=reservation.id)
        except Exception:  # noqa: BLE001 - a possibly committed attempt must never be released.
            return


def _chat_usage_has_no_output(value: object) -> bool:
    if not isinstance(value, list) or len(value) > 1:
        return False
    for choice in value:
        if (
            not isinstance(choice, dict)
            or type(choice.get("index", 0)) is not int
            or choice.get("index", 0) != 0
            or choice.get("message")
            or choice.get("finish_reason")
            not in {None, "stop", "length", "tool_calls", "function_call", "content_filter"}
        ):
            return False
        delta = choice.get("delta", {})
        if not isinstance(delta, dict) or delta.get("role") not in {None, "assistant"}:
            return False
        if any(value not in (None, "", [], {}) for key, value in delta.items() if key != "role"):
            return False
    return True


class _UsageParser:
    def __init__(self, *, responses: bool = False) -> None:
        self._pending = bytearray()
        self._responses, self._terminal, self._invalid = responses, False, False
        self._usage: ModelTokenUsage | None = None
        self.prompt_tokens: int | None = None
        self.prompt_cache_hit_tokens: int | None = None
        self.prompt_cache_miss_tokens: int | None = None
        self.completion_tokens: int | None = None
        self.total_tokens: int | None = None

    @property
    def final_usage(self) -> ModelTokenUsage | None:
        return self._usage if self._terminal and not self._invalid else None

    def feed(self, chunk: bytes) -> None:
        self._pending.extend(chunk)
        if len(self._pending) > _MAX_SSE_LINE_BYTES and b"\n" not in self._pending:
            self._invalid = True
            raise ValueError("Provider stream line exceeds the gateway limit")
        while b"\n" in self._pending:
            line, _, remainder = self._pending.partition(b"\n")
            self._pending = bytearray(remainder)
            self._line(bytes(line).rstrip(b"\r"))

    def finish(self) -> None:
        if self._pending:
            self._line(bytes(self._pending).rstrip(b"\r"))
            self._pending.clear()

    def _line(self, line: bytes) -> None:
        if len(line) > _MAX_SSE_LINE_BYTES:
            self._invalid = True
            raise ValueError("Provider stream line exceeds the gateway limit")
        if not line.startswith(b"data:"):
            return
        payload = line[5:].strip()
        if not payload:
            return
        if payload == b"[DONE]":
            if not self._responses:
                self._terminal = True
            return
        try:
            document = json.loads(payload)
            if not isinstance(document, dict) or self._terminal or self._usage is not None:
                raise ValueError("Invalid provider stream ordering")
            if self._responses:
                if document.get("type") not in {
                    "response.completed",
                    "response.incomplete",
                    "response.failed",
                }:
                    return
                self._terminal = True
            usage = document.get("usage")
            if self._responses:
                response = document.get("response")
                usage = response.get("usage") if isinstance(response, dict) else None
            if usage is None:
                return
            # LiteLLM retains an empty choice in the final usage-only chunk.
            if not self._responses and not _chat_usage_has_no_output(document.get("choices", [])):
                raise ValueError("Usage must be in the final Chat usage frame")
            normalized = normalize_model_usage(usage, responses=self._responses)
            self._usage = normalized
            self.prompt_tokens = normalized.input_tokens
            self.prompt_cache_hit_tokens = normalized.input_cache_hit_tokens
            self.prompt_cache_miss_tokens = normalized.input_cache_miss_tokens
            self.completion_tokens = normalized.output_tokens
            self.total_tokens = normalized.total_tokens
        except (UnicodeError, json.JSONDecodeError, ValueError, TypeError):
            self._invalid = True
            self._usage = None
            self.total_tokens = None
            return


def create_platform_model_gateway_app(gateway: PlatformModelGateway) -> FastAPI:
    app = FastAPI(
        title="Omnigent Platform Model Gateway",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.exception_handler(PlatformModelGatewayTokenError)
    async def invalid_token(_request: Request, _error: PlatformModelGatewayTokenError):
        if isinstance(_error, PlatformModelGatewayTokenExpired):
            return JSONResponse(
                status_code=401,
                content={
                    "error": {
                        "code": "platform_model_authentication_expired",
                        "message": "会话认证过期，正在恢复",
                    }
                },
                headers={"Cache-Control": "no-store"},
            )
        return _error_response(401, "platform_model_authentication_invalid")

    @app.get("/healthz")
    async def healthz():
        try:
            await asyncio.to_thread(gateway.require_ready)
        except Exception:  # noqa: BLE001 - health output must redact dependency detail.
            return _error_response(503, "platform_model_gateway_unavailable")
        return {"status": "ok", "provider_secret_exported": False}

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request):
        return await gateway.chat_completions(request)

    @app.post("/v1/responses")
    async def responses(request: Request):
        return await gateway.responses(request)

    return app


def build_platform_model_gateway(
    environ: Mapping[str, str],
) -> tuple[FastAPI, tuple[Engine, Engine]]:
    """Compose the standalone gateway with exact Billing and Secret Broker logins."""

    try:
        tenant_id = UUID(_required(environ, _TENANT_ID_ENV))
        bindings = load_platform_model_service_role_bindings(environ)
        secret_url, secret_parsed, _ = load_production_database_url_file(environ, "secret_broker")
        billing_url, billing_parsed, _ = load_production_database_url_file(environ, "billing")
    except (
        ValueError,
        ProductionServerConfigError,
        ProductionServiceRoleBindingsError,
    ):
        raise ValueError("Platform model gateway database authority is invalid") from None
    if (
        tenant_id.int == 0
        or secret_parsed.username != bindings.login_for("secret_broker")
        or billing_parsed.username != bindings.login_for("billing")
    ):
        raise ValueError("Platform model gateway database authority is invalid")
    secret_engine = sa.create_engine(secret_url, pool_pre_ping=True)
    billing_engine = sa.create_engine(billing_url, pool_pre_ping=True)
    try:
        _inspect_service_login(
            secret_engine,
            expected_login=bindings.login_for("secret_broker"),
            expected_role="saas_secret_broker",
        )
        _inspect_service_login(
            billing_engine,
            expected_login=bindings.login_for("billing"),
            expected_role="saas_billing",
        )
        cipher = build_production_secret_cipher(environ)
        if cipher is None:
            raise ValueError("Platform model gateway cipher is unavailable")
        secret_sessions = sessionmaker(secret_engine, expire_on_commit=False, class_=Session)
        billing_sessions = sessionmaker(billing_engine, expire_on_commit=False, class_=Session)
        reader = ModelProviderConfigurationReader(secret_sessions, secret_cipher=cipher)
        budgets = ModelProviderBudgetAdmissionService(billing_sessions)
        pricing = load_platform_model_pricing(environ)
        tokens = PlatformModelGatewayTokenAuthority(
            signing_key=_owner_secret(environ, _TOKEN_KEY_FILE_ENV),
            tenant_id=tenant_id,
        )

        def readiness() -> None:
            with secret_engine.connect() as connection:
                connection.execute(sa.text("SELECT 1"))
            with billing_engine.connect() as connection:
                connection.execute(sa.text("SELECT 1"))
            configuration = reader.load()
            if configuration is not None:
                pricing.for_catalog(configuration.allowed_models)

        gateway = PlatformModelGateway(
            tokens=tokens,
            configurations=reader,
            budgets=budgets,
            pricing=pricing,
            readiness_check=readiness,
        )
        app = create_platform_model_gateway_app(gateway)

        @app.on_event("shutdown")
        def close_engines() -> None:
            secret_engine.dispose()
            billing_engine.dispose()

        return app, (secret_engine, billing_engine)
    except Exception:
        secret_engine.dispose()
        billing_engine.dispose()
        raise


def load_platform_model_pricing(environ: Mapping[str, str]) -> PlatformModelPricingPolicy:
    """Load one canonical, non-secret pricing policy from a read-only file."""

    path = Path(_required(environ, _PRICING_FILE_ENV))
    try:
        metadata = path.lstat()
        raw = path.read_text(encoding="ascii")
        document = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ValueError("Platform model pricing policy is unavailable") from None
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not 0 < metadata.st_size <= 64 * 1024
        or not isinstance(document, dict)
        or set(document) != {"schema_version", "revision", "catalog_sha256", "rates"}
        or document.get("schema_version") != 2
        or not isinstance(document.get("revision"), str)
        or not isinstance(document.get("catalog_sha256"), str)
        or not isinstance(document.get("rates"), list)
    ):
        raise ValueError("Platform model pricing policy is invalid")
    prices: list[PlatformModelPrice] = []
    rate_rows = cast(list[object], document["rates"])
    for value in rate_rows:
        if not isinstance(value, dict) or set(value) != {
            "model_sha256",
            "peak_input_cache_hit_microusd_per_million_tokens",
            "peak_input_cache_miss_microusd_per_million_tokens",
            "peak_output_microusd_per_million_tokens",
            "off_peak_input_cache_hit_microusd_per_million_tokens",
            "off_peak_input_cache_miss_microusd_per_million_tokens",
            "off_peak_output_microusd_per_million_tokens",
        }:
            raise ValueError("Platform model pricing policy is invalid")
        model_sha256 = value["model_sha256"]
        rates = {str(key): item for key, item in value.items() if key != "model_sha256"}
        if not isinstance(model_sha256, str) or any(
            isinstance(item, bool) or not isinstance(item, int) for item in rates.values()
        ):
            raise ValueError("Platform model pricing policy is invalid")
        prices.append(PlatformModelPrice(model_sha256=model_sha256, **rates))
    revision = document["revision"]
    catalog_sha256 = document["catalog_sha256"]
    assert isinstance(revision, str)
    assert isinstance(catalog_sha256, str)
    policy = PlatformModelPricingPolicy(
        revision=revision,
        catalog_sha256=catalog_sha256,
        prices=tuple(prices),
    )
    canonical = (
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    )
    if raw != canonical:
        raise ValueError("Platform model pricing policy must be canonical JSON")
    return policy


def _required(source: Mapping[str, str], name: str) -> str:
    value = source.get(name, "")
    if not value or value != value.strip() or "\x00" in value:
        raise ValueError(f"{name} is invalid")
    return value


def _owner_secret(source: Mapping[str, str], name: str) -> bytes:
    path = Path(_required(source, name))
    try:
        metadata = path.lstat()
        value = path.read_bytes().rstrip(b"\r\n")
    except OSError:
        raise ValueError(f"{name} is unavailable") from None
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or not 32 <= len(value) <= 4096
        or b"\x00" in value
    ):
        raise ValueError(f"{name} is invalid")
    return value


def main() -> None:
    app, _engines = build_platform_model_gateway(os.environ)
    host = os.environ.get("OMNIGENT_SAAS_PLATFORM_MODEL_GATEWAY_HOST", "0.0.0.0")
    try:
        port = int(os.environ.get("OMNIGENT_SAAS_PLATFORM_MODEL_GATEWAY_PORT", "8090"))
    except ValueError:
        raise ValueError("Platform model gateway bind authority is invalid") from None
    if host not in {"0.0.0.0", "127.0.0.1", "::"} or not 1 <= port <= 65_535:
        raise ValueError("Platform model gateway bind authority is invalid")
    import uvicorn

    uvicorn.run(app, host=host, port=port, proxy_headers=False, server_header=False)


def _request_document(raw: bytes, *, responses: bool = False) -> dict[str, object]:
    if not 0 < len(raw) <= _MAX_REQUEST_BYTES:
        raise ValueError("Platform model request size is invalid")
    try:
        document = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError("Platform model request is invalid") from None
    if not isinstance(document, dict):
        raise ValueError("Platform model request is invalid")
    model = document.get("model")
    if not isinstance(model, str) or not model or len(model) > 128:
        raise ValueError("Platform model request model is invalid")
    if document.get("stream") is not True:
        raise ValueError("Platform model gateway requires streaming")
    if "n" in document and (responses or type(document["n"]) is not int or document["n"] != 1):
        raise ValueError("Platform model gateway requires one completion")
    _output_token_limit(document, responses=responses)
    return document


def _requested_tokens(
    raw: bytes,
    document: Mapping[str, object],
    *,
    responses: bool = False,
) -> int:
    max_tokens = _output_token_limit(document, responses=responses)
    # UTF-8 byte length is a conservative upper bound for ordinary BPE input;
    # the fixed allowance covers protocol/tool framing not present in messages.
    return len(raw) + max_tokens + 1024


def _output_token_limit(document: Mapping[str, object], *, responses: bool) -> int:
    """Return the validated reservation limit for either OpenAI wire shape."""

    if not responses and "max_tokens" in document and "max_completion_tokens" in document:
        first, second = document["max_tokens"], document["max_completion_tokens"]
        if type(first) is not type(second) or first != second:
            raise ValueError("Platform model output limits conflict")
    value = (
        document.get("max_output_tokens", 4096)
        if responses
        else document.get("max_tokens", document.get("max_completion_tokens", 4096))
    )
    # The same effective default is materialized in the outbound request.
    if value is None:
        return 4096
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("Platform model output limit is invalid")
    if not 1 <= value <= PLATFORM_MODEL_MAX_OUTPUT_TOKENS:
        raise ValueError("Platform model output limit is invalid")
    return value


def _microusd(tokens: int, rate_per_million: int) -> int:
    return token_cost_microusd(tokens, rate_per_million)


def _error(status: int, code: str) -> JSONResponse:
    return _error_response(status, code)


def _error_response(status: int, code: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": "Platform model request rejected"}},
        headers={"Cache-Control": "no-store"},
    )


__all__ = [
    "PlatformModelGateway",
    "PlatformModelPrice",
    "PlatformModelPricingPolicy",
    "build_platform_model_gateway",
    "create_platform_model_gateway_app",
    "load_platform_model_pricing",
    "main",
]


if __name__ == "__main__":
    main()
