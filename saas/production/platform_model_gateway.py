"""Streaming gateway for the Platform-managed DeepSeek Provider.

The gateway is the only Runtime component allowed to decrypt the real Provider
credential.  Runners authenticate with a short-lived session bearer, while the
gateway reserves budget before egress and settles the same durable reservation
from the final OpenAI-compatible usage frame.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import stat
from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Protocol, cast
from uuid import UUID, uuid4

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
from saas.control_plane.model_provider import (
    ModelProviderConfigurationReader,
    PlatformManagedModelRuntimeConfiguration,
)
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
)

_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_MAX_SSE_LINE_BYTES = 256 * 1024
_MAX_OUTPUT_TOKENS = 65_536
_TENANT_ID_ENV = "OMNIGENT_SAAS_PLATFORM_MODEL_TENANT_ID"
_TOKEN_KEY_FILE_ENV = "OMNIGENT_SAAS_PLATFORM_MODEL_TOKEN_KEY_FILE"
_PRICING_FILE_ENV = "OMNIGENT_SAAS_PLATFORM_MODEL_PRICING_FILE"


@dataclass(frozen=True, slots=True)
class PlatformModelPrice:
    model_sha256: str
    peak_input_cache_hit_microusd_per_million_tokens: int
    peak_input_cache_miss_microusd_per_million_tokens: int
    peak_output_microusd_per_million_tokens: int
    off_peak_input_cache_hit_microusd_per_million_tokens: int
    off_peak_input_cache_miss_microusd_per_million_tokens: int
    off_peak_output_microusd_per_million_tokens: int

    def __post_init__(self) -> None:
        if len(self.model_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.model_sha256
        ):
            raise ValueError("Platform model price is invalid")
        for value in (
            self.peak_input_cache_hit_microusd_per_million_tokens,
            self.peak_input_cache_miss_microusd_per_million_tokens,
            self.peak_output_microusd_per_million_tokens,
            self.off_peak_input_cache_hit_microusd_per_million_tokens,
            self.off_peak_input_cache_miss_microusd_per_million_tokens,
            self.off_peak_output_microusd_per_million_tokens,
        ):
            if isinstance(value, bool) or not 1 <= value <= 10**12:
                raise ValueError("Platform model price is invalid")

    @property
    def reservation_rate(self) -> int:
        """Return the maximum possible rate for fail-closed pre-egress admission."""

        return max(
            self.peak_input_cache_hit_microusd_per_million_tokens,
            self.peak_input_cache_miss_microusd_per_million_tokens,
            self.peak_output_microusd_per_million_tokens,
            self.off_peak_input_cache_hit_microusd_per_million_tokens,
            self.off_peak_input_cache_miss_microusd_per_million_tokens,
            self.off_peak_output_microusd_per_million_tokens,
        )

    def rates_at(self, at: datetime) -> tuple[int, int, int]:
        """Resolve the pinned DeepSeek weekday UTC peak-window contract."""

        normalized = at.astimezone(timezone.utc)
        peak = normalized.weekday() < 5 and (1 <= normalized.hour < 4 or 6 <= normalized.hour < 10)
        if peak:
            return (
                self.peak_input_cache_hit_microusd_per_million_tokens,
                self.peak_input_cache_miss_microusd_per_million_tokens,
                self.peak_output_microusd_per_million_tokens,
            )
        return (
            self.off_peak_input_cache_hit_microusd_per_million_tokens,
            self.off_peak_input_cache_miss_microusd_per_million_tokens,
            self.off_peak_output_microusd_per_million_tokens,
        )


@dataclass(frozen=True, slots=True)
class PlatformModelPricingPolicy:
    revision: str
    catalog_sha256: str
    prices: tuple[PlatformModelPrice, ...]

    def __post_init__(self) -> None:
        if (
            not self.revision
            or len(self.revision) > 32
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in self.revision)
            or len(self.catalog_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.catalog_sha256)
            or not self.prices
        ):
            raise ValueError("Platform model pricing policy is invalid")
        sealed_models = tuple(price.model_sha256 for price in self.prices)
        if len(set(sealed_models)) != len(sealed_models):
            raise ValueError("Platform model pricing policy is invalid")

    def for_catalog(self, models: tuple[str, ...]) -> Mapping[str, PlatformModelPrice]:
        """Return rates for a unique configured subset of the sealed catalog."""

        indexed = {price.model_sha256: price for price in self.prices}
        model_hashes = tuple(hashlib.sha256(model.encode("utf-8")).hexdigest() for model in models)
        if (
            not models
            or len(set(models)) != len(models)
            or any(model_hash not in indexed for model_hash in model_hashes)
        ):
            raise ValueError("Platform model pricing catalog is unavailable")
        if len(models) == len(self.prices):
            canonical = json.dumps(list(models), separators=(",", ":"), ensure_ascii=True).encode()
            if hashlib.sha256(canonical).hexdigest() != self.catalog_sha256:
                raise ValueError("Platform model pricing catalog is unavailable")
        return {
            model: indexed[model_hash]
            for model, model_hash in zip(models, model_hashes, strict=True)
        }


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

    def settle(
        self,
        *,
        reservation_id: UUID,
        actual_microusd: int,
        actual_tokens: int,
        now: datetime | None = None,
    ) -> ModelProviderBudgetReservationView: ...

    def release(
        self,
        *,
        reservation_id: UUID,
        now: datetime | None = None,
    ) -> ModelProviderBudgetReservationView: ...


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
        claims = self._authenticate(request.headers.get("authorization", ""))
        raw = await request.body()
        try:
            document = _request_document(raw)
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

        requested_tokens = _requested_tokens(raw, document)
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

        outbound = dict(document)
        outbound["stream"] = True
        outbound["stream_options"] = {"include_usage": True}
        client = self._client_factory()
        try:
            upstream = await client.send(
                client.build_request(
                    "POST",
                    f"{configuration.base_url.rstrip('/')}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {configuration.api_key}",
                        "Content-Type": "application/json",
                        "Accept": "text/event-stream",
                    },
                    json=outbound,
                ),
                stream=True,
            )
        except httpx.HTTPError:
            await client.aclose()
            await self._release(reservation)
            return _error(502, "platform_model_provider_unreachable")
        if upstream.status_code != 200:
            await upstream.aclose()
            await client.aclose()
            await self._release(reservation)
            return _error(502, "platform_model_provider_rejected")

        return StreamingResponse(
            self._stream_and_settle(
                client=client,
                upstream=upstream,
                reservation=reservation,
                price=price,
                requested_at=requested_at,
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
    ) -> AsyncIterator[bytes]:
        parser = _UsageParser()
        output_observed = False
        completed = False
        try:
            async for chunk in upstream.aiter_bytes():
                if chunk:
                    output_observed = True
                    parser.feed(chunk)
                    yield chunk
            parser.finish()
            completed = True
        finally:
            await upstream.aclose()
            await client.aclose()
            if completed and parser.total_tokens is not None:
                actual_tokens = max(1, parser.total_tokens)
                cache_hit_rate, cache_miss_rate, output_rate = price.rates_at(requested_at)
                actual_cost = max(
                    1,
                    _microusd(parser.prompt_cache_hit_tokens or 0, cache_hit_rate)
                    + _microusd(parser.prompt_cache_miss_tokens or 0, cache_miss_rate)
                    + _microusd(parser.completion_tokens or 0, output_rate),
                )
                # The reservation uses the maximum configured rate and a byte-
                # bounded token ceiling. A malformed Provider usage frame can
                # never expand authority after egress.
                if (
                    actual_tokens <= reservation.admitted_tokens
                    and actual_cost <= reservation.admitted_microusd
                ):
                    await self._settle(reservation, actual_cost, actual_tokens)
                else:
                    await self._settle_full(reservation)
            elif output_observed:
                # A disconnect after output is financially ambiguous. Charge
                # the admitted ceiling instead of silently releasing spend.
                await self._settle_full(reservation)
            else:
                await self._release(reservation)

    async def _settle(
        self,
        reservation: ModelProviderBudgetReservationView,
        actual_microusd: int,
        actual_tokens: int,
    ) -> None:
        await asyncio.to_thread(
            self._budgets.settle,
            reservation_id=reservation.id,
            actual_microusd=actual_microusd,
            actual_tokens=actual_tokens,
        )

    async def _settle_full(self, reservation: ModelProviderBudgetReservationView) -> None:
        await self._settle(
            reservation,
            reservation.admitted_microusd,
            reservation.admitted_tokens,
        )

    async def _release(self, reservation: ModelProviderBudgetReservationView) -> None:
        try:
            await asyncio.to_thread(self._budgets.release, reservation_id=reservation.id)
        except Exception:  # noqa: BLE001 - expiry recovery is the durable fallback.
            # Expiry recovery remains the durable fallback. Never mask the
            # original Provider/configuration error with database detail.
            return


class _UsageParser:
    def __init__(self) -> None:
        self._pending = bytearray()
        self.prompt_tokens: int | None = None
        self.prompt_cache_hit_tokens: int | None = None
        self.prompt_cache_miss_tokens: int | None = None
        self.completion_tokens: int | None = None
        self.total_tokens: int | None = None

    def feed(self, chunk: bytes) -> None:
        self._pending.extend(chunk)
        if len(self._pending) > _MAX_SSE_LINE_BYTES and b"\n" not in self._pending:
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
        if not line.startswith(b"data:"):
            return
        payload = line[5:].strip()
        if not payload or payload == b"[DONE]":
            return
        try:
            document = json.loads(payload)
            usage = document.get("usage") if isinstance(document, dict) else None
            if not isinstance(usage, dict):
                return
            prompt = _usage_integer(usage.get("prompt_tokens"))
            completion = _usage_integer(usage.get("completion_tokens"))
            total = _usage_integer(usage.get("total_tokens"))
            if total != prompt + completion:
                raise ValueError("Provider usage total is inconsistent")
            cache_hit_value = usage.get("prompt_cache_hit_tokens")
            cache_miss_value = usage.get("prompt_cache_miss_tokens")
            if cache_hit_value is None and cache_miss_value is None:
                cache_hit = 0
                cache_miss = prompt
            else:
                cache_hit = _usage_integer(cache_hit_value)
                cache_miss = _usage_integer(cache_miss_value)
                if cache_hit + cache_miss != prompt:
                    raise ValueError("Provider prompt cache usage is inconsistent")
            self.prompt_tokens = prompt
            self.prompt_cache_hit_tokens = cache_hit
            self.prompt_cache_miss_tokens = cache_miss
            self.completion_tokens = completion
            self.total_tokens = total
        except (UnicodeError, json.JSONDecodeError, ValueError, TypeError):
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


def _request_document(raw: bytes) -> dict[str, object]:
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
    max_tokens = document.get("max_tokens", document.get("max_completion_tokens", 4096))
    if isinstance(max_tokens, bool) or not isinstance(max_tokens, int):
        raise ValueError("Platform model output limit is invalid")
    if not 1 <= max_tokens <= _MAX_OUTPUT_TOKENS:
        raise ValueError("Platform model output limit is invalid")
    return document


def _requested_tokens(raw: bytes, document: Mapping[str, object]) -> int:
    max_tokens = cast(int, document.get("max_tokens", document.get("max_completion_tokens", 4096)))
    # UTF-8 byte length is a conservative upper bound for ordinary BPE input;
    # the fixed allowance covers protocol/tool framing not present in messages.
    return len(raw) + max_tokens + 1024


def _usage_integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("Provider usage value is invalid")
    return value


def _microusd(tokens: int, rate_per_million: int) -> int:
    if tokens <= 0:
        return 0
    return math.ceil(tokens * rate_per_million / 1_000_000)


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
