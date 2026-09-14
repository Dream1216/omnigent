"""Governed platform-managed LLM provider configuration and live verification."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Protocol
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from omnigent.stores.credential_store.secret_cipher import SecretCipher
from saas.control_plane.platform_models import (
    ModelProviderConfigurationReceiptRecord,
    ModelProviderConfigurationRecord,
)
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformSecurityError,
    ValidatedPlatformPrincipal,
)
from saas.control_plane.rls import PlatformRlsContext, apply_platform_rls_context

_PROVIDER_ID = "deepseek"
_API_TYPE = "openai_chat_completions"
_BASE_URL = "https://api.deepseek.com"
_FRESH_AUTH_WINDOW = timedelta(minutes=5)
_MODEL_ID = re.compile(r"^deepseek-[a-z0-9][a-z0-9.-]{0,118}$")
_MAX_MODELS = 16
_MAX_STREAM_BYTES = 256 * 1024
_SECRET_CONTEXT = {
    "workspace_id": "platform",
    "user_id": "system",
    "provider": _PROVIDER_ID,
    "account_id": "managed_model",
}


@dataclass(frozen=True, slots=True)
class ModelProviderConfigurationUpdate:
    """One CAS-protected update; ``api_key=None`` preserves the current key."""

    enabled: bool
    base_url: str
    api_type: str
    allowed_models: tuple[str, ...]
    default_model: str
    monthly_budget_microusd: int
    per_tenant_daily_token_limit: int
    api_key: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class ModelProviderConfigurationView:
    provider_id: str
    configured: bool
    enabled: bool
    state: str
    base_url: str | None
    api_type: str | None
    allowed_models: tuple[str, ...]
    default_model: str | None
    monthly_budget_microusd: int | None
    per_tenant_daily_token_limit: int | None
    api_key_configured: bool
    verification_status: str
    last_verified_model: str | None
    last_verified_at: datetime | None
    version: int
    updated_by_principal_id: UUID | None
    updated_at: datetime | None


@dataclass(frozen=True, slots=True)
class ManagedModelProbeResult:
    provider_request_id: str | None
    response_model: str
    latency_millis: int
    output_observed: bool


@dataclass(frozen=True, slots=True)
class PlatformManagedModelRuntimeConfiguration:
    """Trusted Host-only projection; API key is always omitted from repr."""

    provider_id: str
    base_url: str
    api_type: str
    allowed_models: tuple[str, ...]
    default_model: str
    monthly_budget_microusd: int
    per_tenant_daily_token_limit: int
    configuration_version: int
    api_key: str = field(repr=False)


class ManagedModelProbe(Protocol):
    def __call__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
    ) -> ManagedModelProbeResult: ...


def deepseek_streaming_probe(
    *,
    base_url: str,
    api_key: str,
    model: str,
) -> ManagedModelProbeResult:
    """Perform a bounded real streaming call without retaining response content."""

    import httpx

    started = time.monotonic()
    observed = False
    response_model = model
    provider_request_id: str | None = None
    total_bytes = 0
    try:
        with (
            httpx.Client(timeout=20.0, follow_redirects=False, trust_env=False) as client,
            client.stream(
                "POST",
                f"{base_url.rstrip('/')}/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "Accept": "text/event-stream",
                },
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": "Reply with OK."}],
                    "max_tokens": 8,
                    "stream": True,
                    "temperature": 0,
                },
            ) as response,
        ):
            provider_request_id = response.headers.get("x-request-id")
            if response.status_code != 200:
                raise RuntimeError("managed model probe was rejected")
            for line in response.iter_lines():
                total_bytes += len(line.encode("utf-8", errors="ignore"))
                if total_bytes > _MAX_STREAM_BYTES:
                    raise RuntimeError("managed model probe response is oversized")
                if not line.startswith("data:"):
                    continue
                payload = line[5:].strip()
                if not payload or payload == "[DONE]":
                    continue
                value = json.loads(payload)
                if not isinstance(value, dict):
                    continue
                raw_model = value.get("model")
                if isinstance(raw_model, str) and raw_model:
                    response_model = raw_model[:128]
                choices = value.get("choices")
                if not isinstance(choices, list):
                    continue
                for choice in choices:
                    if not isinstance(choice, dict):
                        continue
                    delta = choice.get("delta")
                    if not isinstance(delta, dict):
                        continue
                    observed = observed or any(
                        isinstance(delta.get(name), str) and bool(delta.get(name))
                        for name in ("content", "reasoning_content")
                    )
    except Exception:  # noqa: BLE001 - redact Provider and transport details.
        raise RuntimeError("managed model probe failed") from None
    if not observed:
        raise RuntimeError("managed model probe returned no streamed output")
    return ManagedModelProbeResult(
        provider_request_id=provider_request_id,
        response_model=response_model,
        latency_millis=max(0, int((time.monotonic() - started) * 1000)),
        output_observed=True,
    )


class ModelProviderConfigurationService:
    """Platform Provider policy with encrypted credentials and append-only receipts."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        authorization: PlatformAuthorizationService,
        secret_cipher: SecretCipher,
        probe: ManagedModelProbe = deepseek_streaming_probe,
    ) -> None:
        self._sessions = session_factory
        self._authorization = authorization
        self._cipher = secret_cipher
        self._probe = probe

    def get(self, actor: ValidatedPlatformPrincipal) -> ModelProviderConfigurationView:
        self._authorization.require(actor, "platform.model_provider.read")
        with self._sessions.begin() as db:
            self._apply_actor(db, actor)
            self._authorization.require_current(
                db, actor, "platform.model_provider.read", now=_utcnow()
            )
            return _view(db.get(ModelProviderConfigurationRecord, _PROVIDER_ID))

    def update(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        expected_version: int,
        configuration: ModelProviderConfigurationUpdate,
        now: datetime | None = None,
    ) -> ModelProviderConfigurationView:
        changed_at = _stored_time(now or _utcnow())
        self._authorization.require(actor, "platform.model_provider.manage")
        _require_fresh(actor, changed_at)
        if isinstance(expected_version, bool) or not isinstance(expected_version, int):
            raise _invalid()
        normalized = _validated(configuration)
        with self._sessions.begin() as db:
            self._apply_actor(db, actor)
            self._authorization.require_current(
                db, actor, "platform.model_provider.manage", now=changed_at
            )
            current = db.execute(
                sa.select(ModelProviderConfigurationRecord)
                .where(ModelProviderConfigurationRecord.provider_id == _PROVIDER_ID)
                .with_for_update()
            ).scalar_one_or_none()
            current_version = current.version if current is not None else 0
            if expected_version != current_version:
                raise PlatformSecurityError(
                    "platform_model_provider_conflict",
                    "Model Provider configuration changed; reload before saving",
                )
            existing_ciphertext = current.api_key_ciphertext if current is not None else None
            if normalized.api_key is None and existing_ciphertext is None:
                raise PlatformSecurityError(
                    "platform_model_provider_invalid",
                    "API key is required for the first Provider configuration",
                )
            try:
                ciphertext = (
                    self._cipher.encrypt(normalized.api_key, context=_SECRET_CONTEXT)
                    if normalized.api_key is not None
                    else existing_ciphertext
                )
            except Exception:  # noqa: BLE001 - redact KMS/Vault backend details.
                raise PlatformSecurityError(
                    "platform_model_provider_secret_unavailable",
                    "Model Provider secret encryption is unavailable",
                ) from None
            if not ciphertext:
                raise PlatformSecurityError(
                    "platform_model_provider_secret_unavailable",
                    "Model Provider secret encryption is unavailable",
                )
            next_version = current_version + 1
            values = {
                "enabled": normalized.enabled,
                "base_url": normalized.base_url,
                "api_type": normalized.api_type,
                "api_key_ciphertext": ciphertext,
                "allowed_models": list(normalized.allowed_models),
                "default_model": normalized.default_model,
                "monthly_budget_microusd": normalized.monthly_budget_microusd,
                "per_tenant_daily_token_limit": normalized.per_tenant_daily_token_limit,
                "verification_status": "never",
                "last_verified_model": None,
                "last_verified_at": None,
                "version": next_version,
                "updated_by_principal_id": actor.principal_id,
                "updated_at": changed_at,
            }
            if current is None:
                current = ModelProviderConfigurationRecord(provider_id=_PROVIDER_ID, **values)
                db.add(current)
            else:
                for name, value in values.items():
                    setattr(current, name, value)
            db.flush()
            config_hash = _configuration_hash(current)
            db.add(
                ModelProviderConfigurationReceiptRecord(
                    id=uuid4(),
                    provider_id=_PROVIDER_ID,
                    configuration_version=next_version,
                    actor_principal_id=actor.principal_id,
                    action="configured" if normalized.enabled else "disabled",
                    configuration_hash=config_hash,
                    api_key_rotated=normalized.api_key is not None,
                    model_id=None,
                    provider_request_id_hash=None,
                    latency_millis=None,
                    occurred_at=changed_at,
                )
            )
            return _view(current)

    def verify(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        expected_version: int,
        model: str | None = None,
        now: datetime | None = None,
    ) -> ModelProviderConfigurationView:
        tested_at = _stored_time(now or _utcnow())
        self._authorization.require(actor, "platform.model_provider.test")
        _require_fresh(actor, tested_at)
        with self._sessions.begin() as db:
            self._apply_actor(db, actor)
            self._authorization.require_current(
                db, actor, "platform.model_provider.test", now=tested_at
            )
            record = db.get(ModelProviderConfigurationRecord, _PROVIDER_ID)
            if record is None or record.version != expected_version:
                raise PlatformSecurityError(
                    "platform_model_provider_conflict",
                    "Model Provider configuration changed; reload before testing",
                )
            if not record.enabled:
                raise PlatformSecurityError(
                    "platform_model_provider_disabled", "Model Provider is disabled"
                )
            selected_model = model or record.default_model
            if selected_model not in record.allowed_models:
                raise _invalid()
            config_hash = _configuration_hash(record)
            try:
                api_key = self._cipher.decrypt(record.api_key_ciphertext, context=_SECRET_CONTEXT)
            except Exception:  # noqa: BLE001 - redact KMS/Vault backend details.
                api_key = None
            if not api_key:
                raise PlatformSecurityError(
                    "platform_model_provider_secret_unavailable",
                    "Model Provider secret decryption is unavailable",
                )
            base_url = record.base_url
            version = record.version
        result: ManagedModelProbeResult | None = None
        action = "verification_failed"
        try:
            result = self._probe(base_url=base_url, api_key=api_key, model=selected_model)
            if not result.output_observed or result.response_model != selected_model:
                raise RuntimeError("streamed output missing")
            action = "verification_succeeded"
        except Exception:  # noqa: BLE001 - expose only a governed probe verdict.
            result = None
        finally:
            api_key = ""
        with self._sessions.begin() as db:
            self._apply_actor(db, actor)
            self._authorization.require_current(
                db, actor, "platform.model_provider.test", now=tested_at
            )
            record = db.execute(
                sa.select(ModelProviderConfigurationRecord)
                .where(ModelProviderConfigurationRecord.provider_id == _PROVIDER_ID)
                .with_for_update()
            ).scalar_one_or_none()
            if record is None or record.version != version:
                raise PlatformSecurityError(
                    "platform_model_provider_conflict",
                    "Model Provider configuration changed while testing",
                )
            record.verification_status = "verified" if result is not None else "failed"
            record.last_verified_model = selected_model
            record.last_verified_at = tested_at
            db.add(
                ModelProviderConfigurationReceiptRecord(
                    id=uuid4(),
                    provider_id=_PROVIDER_ID,
                    configuration_version=version,
                    actor_principal_id=actor.principal_id,
                    action=action,
                    configuration_hash=config_hash,
                    api_key_rotated=False,
                    model_id=selected_model,
                    provider_request_id_hash=(
                        sha256(result.provider_request_id.encode()).hexdigest()
                        if result is not None and result.provider_request_id
                        else None
                    ),
                    latency_millis=result.latency_millis if result is not None else None,
                    occurred_at=tested_at,
                )
            )
            db.flush()
            view = _view(record)
        if result is None:
            raise PlatformSecurityError(
                "platform_model_provider_test_unavailable",
                "Model Provider live verification failed",
            )
        return view

    @staticmethod
    def _apply_actor(db: Session, actor: ValidatedPlatformPrincipal) -> None:
        apply_platform_rls_context(db, PlatformRlsContext(principal_id=actor.principal_id))


class ModelProviderConfigurationReader:
    """Trusted runtime reader that exposes only an enabled, verified configuration."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        secret_cipher: SecretCipher,
    ) -> None:
        self._sessions = session_factory
        self._cipher = secret_cipher

    def load(self) -> PlatformManagedModelRuntimeConfiguration | None:
        with self._sessions.begin() as db:
            record = db.get(ModelProviderConfigurationRecord, _PROVIDER_ID)
            if record is None or not record.enabled or record.verification_status != "verified":
                return None
            values = {
                "provider_id": record.provider_id,
                "base_url": record.base_url,
                "api_type": record.api_type,
                "allowed_models": tuple(record.allowed_models),
                "default_model": record.default_model,
                "monthly_budget_microusd": record.monthly_budget_microusd,
                "per_tenant_daily_token_limit": record.per_tenant_daily_token_limit,
                "configuration_version": record.version,
                "api_key_ciphertext": record.api_key_ciphertext,
            }
        try:
            api_key = self._cipher.decrypt(
                str(values.pop("api_key_ciphertext")), context=_SECRET_CONTEXT
            )
        except Exception:  # noqa: BLE001 - redact KMS/Vault backend details.
            api_key = None
        if not api_key:
            raise RuntimeError("managed model Provider secret is unavailable")
        return PlatformManagedModelRuntimeConfiguration(api_key=api_key, **values)  # type: ignore[arg-type]


def _validated(
    value: ModelProviderConfigurationUpdate,
) -> ModelProviderConfigurationUpdate:
    if value.api_type != _API_TYPE:
        raise _invalid()
    parsed = urlsplit(value.base_url)
    if (
        value.base_url.rstrip("/") != _BASE_URL
        or parsed.scheme != "https"
        or parsed.hostname != "api.deepseek.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise _invalid()
    models = tuple(dict.fromkeys(value.allowed_models))
    if (
        not 1 <= len(models) <= _MAX_MODELS
        or any(_MODEL_ID.fullmatch(model) is None for model in models)
        or value.default_model not in models
        or isinstance(value.monthly_budget_microusd, bool)
        or not 1 <= value.monthly_budget_microusd <= 10**15
        or isinstance(value.per_tenant_daily_token_limit, bool)
        or not 1 <= value.per_tenant_daily_token_limit <= 10**12
    ):
        raise _invalid()
    if value.api_key is not None and (
        not 16 <= len(value.api_key) <= 4096
        or value.api_key != value.api_key.strip()
        or any(ord(character) < 0x21 for character in value.api_key)
    ):
        raise _invalid()
    return ModelProviderConfigurationUpdate(
        enabled=value.enabled,
        base_url=_BASE_URL,
        api_type=_API_TYPE,
        allowed_models=models,
        default_model=value.default_model,
        monthly_budget_microusd=value.monthly_budget_microusd,
        per_tenant_daily_token_limit=value.per_tenant_daily_token_limit,
        api_key=value.api_key,
    )


def _view(record: ModelProviderConfigurationRecord | None) -> ModelProviderConfigurationView:
    if record is None:
        return ModelProviderConfigurationView(
            provider_id=_PROVIDER_ID,
            configured=False,
            enabled=False,
            state="not_configured",
            base_url=_BASE_URL,
            api_type=_API_TYPE,
            allowed_models=(),
            default_model=None,
            monthly_budget_microusd=None,
            per_tenant_daily_token_limit=None,
            api_key_configured=False,
            verification_status="never",
            last_verified_model=None,
            last_verified_at=None,
            version=0,
            updated_by_principal_id=None,
            updated_at=None,
        )
    state = (
        "disabled"
        if not record.enabled
        else "verified"
        if record.verification_status == "verified"
        else "verification_failed"
        if record.verification_status == "failed"
        else "configured"
    )
    return ModelProviderConfigurationView(
        provider_id=record.provider_id,
        configured=True,
        enabled=record.enabled,
        state=state,
        base_url=record.base_url,
        api_type=record.api_type,
        allowed_models=tuple(record.allowed_models),
        default_model=record.default_model,
        monthly_budget_microusd=record.monthly_budget_microusd,
        per_tenant_daily_token_limit=record.per_tenant_daily_token_limit,
        api_key_configured=True,
        verification_status=record.verification_status,
        last_verified_model=record.last_verified_model,
        last_verified_at=(
            _stored_time(record.last_verified_at) if record.last_verified_at else None
        ),
        version=record.version,
        updated_by_principal_id=record.updated_by_principal_id,
        updated_at=_stored_time(record.updated_at),
    )


def _configuration_hash(record: ModelProviderConfigurationRecord) -> str:
    document = {
        "provider_id": record.provider_id,
        "enabled": record.enabled,
        "base_url": record.base_url,
        "api_type": record.api_type,
        "allowed_models": list(record.allowed_models),
        "default_model": record.default_model,
        "monthly_budget_microusd": record.monthly_budget_microusd,
        "per_tenant_daily_token_limit": record.per_tenant_daily_token_limit,
        "version": record.version,
    }
    return sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _invalid() -> PlatformSecurityError:
    return PlatformSecurityError(
        "platform_model_provider_invalid", "Model Provider configuration is invalid"
    )


def _require_fresh(actor: ValidatedPlatformPrincipal, changed_at: datetime) -> None:
    authenticated_at = _stored_time(actor.authenticated_at)
    if authenticated_at > changed_at or changed_at - authenticated_at > _FRESH_AUTH_WINDOW:
        raise PlatformSecurityError(
            "platform_fresh_auth_required", "fresh Staff authentication is required"
        )


def _stored_time(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


__all__ = [
    "ManagedModelProbeResult",
    "ModelProviderConfigurationReader",
    "ModelProviderConfigurationService",
    "ModelProviderConfigurationUpdate",
    "ModelProviderConfigurationView",
    "PlatformManagedModelRuntimeConfiguration",
    "deepseek_streaming_probe",
]
