"""Fail-closed production composition for self-service Tenant onboarding.

This module is deliberately independent from the downstream production server
entrypoint.  The HTTP process receives only the registration and status
authorities.  The Outbox process receives the registration, onboarding and
execution authorities plus the verification delivery and Runtime Provider
adapters.  The restricted dispatcher login remains owned by
``saas.outbox_worker`` and is never passed into this composition.

No configuration is read at import time.  Secret material is accepted only
through owner-only files staged by the deployment.  The zero-argument
``build_production_onboarding_outbox_publisher`` function is the supported
``OMNIGENT_SAAS_OUTBOX_PUBLISHER`` target.
"""

from __future__ import annotations

import base64
import importlib
import inspect
import ipaddress
import json
import os
import re
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Any, cast
from urllib.parse import urlsplit

import sqlalchemy as sa
from sqlalchemy.engine import URL, Engine, make_url
from sqlalchemy.orm import Session, sessionmaker

from omnigent.stores.credential_store.secret_cipher import (
    SecretCipher,
    build_secret_cipher,
)
from saas.control_plane.client_network import (
    TrustedClientNetworkConfig,
    TrustedClientNetworkResolver,
)
from saas.control_plane.email_provider import (
    ConfiguredSmtpEmailVerificationSender,
    EmailProviderConfigurationReader,
)
from saas.control_plane.onboarding import (
    OnboardingPlan,
    OnboardingPolicy,
    RegistrationRateLimitSubjectKeyring,
    SelfServiceOnboardingService,
    SharedRegistrationRateLimiter,
    VerificationEnvelopeKeyring,
)
from saas.control_plane.onboarding_status import OnboardingStatusService
from saas.control_plane.outbox import OutboxPublisher
from saas.control_plane.runtime_provider import ProductionRuntimePartitionAdapter
from saas.onboarding_composition import (
    TenantOnboardingComposition,
    TenantOnboardingDependencies,
    TenantOnboardingWorkflowConfig,
    create_tenant_onboarding_composition,
    verify_onboarding_database_authority,
)
from saas.onboarding_email import (
    ResendEmailVerificationConfig,
    ResendEmailVerificationSender,
)
from saas.production.service_bindings import (
    ProductionServiceRoleBindingsError,
    load_production_service_role_bindings,
)

_MAX_CONFIG_BYTES = 64 * 1024
_MAX_SECRET_BYTES = 16 * 1024
_FACTORY_REFERENCE = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*:[A-Za-z][A-Za-z0-9_]*$"
)
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_FORBIDDEN_LOGIN_FRAGMENTS = ("admin", "migration", "owner", "postgres", "root")
_ONBOARDING_BASE_ROLES: Mapping[str, str] = MappingProxyType(
    {
        "registration": "saas_registration",
        "onboarding": "saas_onboarding",
        "onboarding_status": "saas_onboarding_status",
        # Executor already belongs to the production profile, but the worker
        # must bind it from the same canonical manifest instead of trusting a
        # free-standing DSN username.
        "executor": "saas_executor",
    }
)
_DIRECT_SECRET_ENVIRONMENT = frozenset(
    {
        "DATABASE_URL",
        "OMNIGENT_SAAS_EMAIL_PROVIDER_TOKEN",
        "OMNIGENT_SAAS_REGISTRATION_DATABASE_URL",
        "OMNIGENT_SAAS_ONBOARDING_DATABASE_URL",
        "OMNIGENT_SAAS_EXECUTOR_DATABASE_URL",
        "OMNIGENT_SAAS_ONBOARDING_STATUS_DATABASE_URL",
        "OMNIGENT_SAAS_VERIFICATION_ENVELOPE_KEYS",
        "OMNIGENT_SAAS_REGISTRATION_RATE_LIMIT_KEYS",
    }
)


class ProductionOnboardingConfigError(ValueError):
    """Stable startup rejection that never includes secret values."""


@dataclass(frozen=True, slots=True)
class ProductionOnboardingServiceRoleBindings:
    """Canonical projection for three new roles plus the existing executor."""

    path: Path
    sha256: str
    logins: Mapping[str, str]

    def login_for(self, service: str) -> str:
        try:
            return self.logins[service]
        except KeyError:
            raise ProductionOnboardingConfigError(
                f"service-role manifest does not contain {service}"
            ) from None


@dataclass(frozen=True, slots=True)
class ProductionOnboardingCommonConfig:
    """Shared immutable policy and cryptographic configuration."""

    public_origin: str
    policy: OnboardingPolicy
    envelope_keyring: VerificationEnvelopeKeyring = field(repr=False)
    rate_limit_keyring: RegistrationRateLimitSubjectKeyring = field(repr=False)
    bindings: ProductionOnboardingServiceRoleBindings


@dataclass(frozen=True, slots=True)
class ProductionOnboardingHttpConfig:
    """Least-privilege configuration for the public HTTP server."""

    common: ProductionOnboardingCommonConfig
    registration_database_url: str = field(repr=False)
    status_database_url: str = field(repr=False)
    trusted_client_network: TrustedClientNetworkConfig


@dataclass(frozen=True, slots=True)
class ProductionOnboardingWorkerConfig:
    """Configuration for the onboarding-aware Outbox worker."""

    common: ProductionOnboardingCommonConfig
    registration_database_url: str = field(repr=False)
    onboarding_database_url: str = field(repr=False)
    execution_database_url: str = field(repr=False)
    email_delivery_mode: str
    email_from_address: str | None
    email_provider_token: str | None = field(repr=False)
    email_timeout_seconds: float
    runtime_provider_factory: str
    workflow: TenantOnboardingWorkflowConfig


@dataclass(slots=True)
class ProductionOnboardingHttpServices:
    """Objects injected into ``create_saas_http_integration`` by the server."""

    onboarding: SelfServiceOnboardingService
    onboarding_status: OnboardingStatusService
    onboarding_client_network: TrustedClientNetworkResolver
    _engines: tuple[Engine, ...] = field(repr=False)

    @property
    def integration_kwargs(self) -> Mapping[str, object]:
        """Return the exact all-or-none HTTP integration keyword set."""

        return MappingProxyType(
            {
                "onboarding": self.onboarding,
                "onboarding_status": self.onboarding_status,
                "onboarding_client_network": self.onboarding_client_network,
            }
        )

    def close(self) -> None:
        for engine in self._engines:
            engine.dispose()


@dataclass(slots=True)
class ProductionOnboardingOutboxPublisher:
    """Validated publisher plus lifecycle of its non-dispatcher authorities."""

    composition: TenantOnboardingComposition
    email_sender: ResendEmailVerificationSender | ConfiguredSmtpEmailVerificationSender = field(
        repr=False
    )
    runtime: ProductionRuntimePartitionAdapter = field(repr=False)
    _engines: tuple[Engine, ...] = field(repr=False)

    def validate_outbox_configuration(self) -> None:
        self.composition.validate_outbox_configuration()
        self.runtime.assert_production_ready()

    def publish(self, **event: Any) -> None:
        self.composition.publish(**event)

    def close(self) -> None:
        self.email_sender.close()
        for engine in self._engines:
            engine.dispose()


def _required(source: Mapping[str, str], name: str) -> str:
    value = source.get(name)
    if value is None or not value.strip():
        raise ProductionOnboardingConfigError(f"{name} is required")
    if value != value.strip() or "\x00" in value:
        raise ProductionOnboardingConfigError(f"{name} is malformed")
    return value


def _reject_direct_secret_environment(source: Mapping[str, str]) -> None:
    present = sorted(name for name in _DIRECT_SECRET_ENVIRONMENT if source.get(name))
    if present:
        raise ProductionOnboardingConfigError(
            "direct secret environment variables are forbidden: " + ", ".join(present)
        )


def _regular_file(
    source: Mapping[str, str],
    name: str,
    *,
    maximum_bytes: int,
) -> Path:
    raw = _required(source, name)
    path = Path(raw)
    if not path.is_absolute():
        raise ProductionOnboardingConfigError(f"{name} must be an absolute path")
    try:
        metadata = path.lstat()
    except OSError:
        raise ProductionOnboardingConfigError(f"{name} cannot be inspected") from None
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o400
        or not 0 < metadata.st_size <= maximum_bytes
    ):
        raise ProductionOnboardingConfigError(
            f"{name} must be an owner-readable, owner-only, read-only regular file"
        )
    return path


def _read_bytes(path: Path, name: str, *, maximum_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or not 0 < metadata.st_size <= maximum_bytes
        ):
            raise ProductionOnboardingConfigError(f"{name} changed during inspection")
        raw = os.read(descriptor, maximum_bytes + 1)
    except ProductionOnboardingConfigError:
        raise
    except OSError:
        raise ProductionOnboardingConfigError(f"{name} cannot be read") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if not 0 < len(raw) <= maximum_bytes:
        raise ProductionOnboardingConfigError(f"{name} has an invalid size")
    return raw


def _json_document(
    source: Mapping[str, str],
    name: str,
    *,
    secret: bool,
) -> tuple[Path, bytes, dict[str, object]]:
    maximum = _MAX_SECRET_BYTES if secret else _MAX_CONFIG_BYTES
    path = _regular_file(source, name, maximum_bytes=maximum)
    raw = _read_bytes(path, name, maximum_bytes=maximum)
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError):
        raise ProductionOnboardingConfigError(f"{name} is not valid JSON") from None
    if not isinstance(value, dict):
        raise ProductionOnboardingConfigError(f"{name} must contain one JSON object")
    return path, raw, cast(dict[str, object], value)


def load_production_onboarding_service_role_bindings(
    source: Mapping[str, str],
) -> ProductionOnboardingServiceRoleBindings:
    """Project onboarding logins from the shared exact 13-service authority."""

    name = "OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS_FILE"
    try:
        bindings = load_production_service_role_bindings(source)
    except ProductionServiceRoleBindingsError as error:
        raise ProductionOnboardingConfigError(
            f"{name} must contain the exact 13-service production profile, including "
            "registration, onboarding, onboarding_status, and executor roles"
        ) from error
    return ProductionOnboardingServiceRoleBindings(
        path=bindings.path,
        sha256=bindings.sha256,
        logins=MappingProxyType(
            {service: bindings.login_for(service) for service in _ONBOARDING_BASE_ROLES}
        ),
    )


def _database_url(
    source: Mapping[str, str],
    *,
    service: str,
    bindings: ProductionOnboardingServiceRoleBindings,
) -> str:
    name = f"OMNIGENT_SAAS_{service.upper()}_DATABASE_URL_FILE"
    path = _regular_file(source, name, maximum_bytes=_MAX_SECRET_BYTES)
    raw = _read_bytes(path, name, maximum_bytes=_MAX_SECRET_BYTES).rstrip(b"\r\n")
    try:
        value = raw.decode("utf-8")
        parsed: URL = make_url(value)
    except (UnicodeError, ValueError):
        raise ProductionOnboardingConfigError(f"{name} is malformed") from None
    if (
        not value
        or value != value.strip()
        or "\n" in value
        or "\r" in value
        or parsed.drivername != "postgresql+psycopg"
        or parsed.username != bindings.login_for(service)
        or parsed.password is None
        or not parsed.host
        or not parsed.database
    ):
        raise ProductionOnboardingConfigError(
            f"{name} must contain the exact postgresql+psycopg service login"
        )
    username = parsed.username
    if username is None:  # Kept explicit for static narrowing after the compound guard.
        raise ProductionOnboardingConfigError(f"{name} is missing a service login")
    login = username.lower()
    if any(fragment in login for fragment in _FORBIDDEN_LOGIN_FRAGMENTS):
        raise ProductionOnboardingConfigError(f"{name} must not contain an owner login")
    query = {str(key).lower(): str(value) for key, value in parsed.query.items()}
    if "role" in query or "options" in query:
        raise ProductionOnboardingConfigError(f"{name} must not request SET ROLE or options")
    if query.get("sslmode") != "verify-full":
        raise ProductionOnboardingConfigError(f"{name} must require sslmode=verify-full")
    if query.get("sslrootcert") != "/runtime/postgresql-ca.crt":
        raise ProductionOnboardingConfigError(
            f"{name} must pin sslrootcert=/runtime/postgresql-ca.crt"
        )
    return value


def _decode_key(value: object, *, name: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ProductionOnboardingConfigError(f"{name} contains an invalid key")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise ProductionOnboardingConfigError(f"{name} contains an invalid key") from None
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        raise ProductionOnboardingConfigError(f"{name} keys must be canonical 256-bit base64")
    return decoded


def _key_document(
    source: Mapping[str, str],
    name: str,
) -> tuple[dict[str, object], dict[str, bytes]]:
    _path, _raw, document = _json_document(source, name, secret=True)
    keys = document.get("keys")
    if document.get("schema_version") != 1 or not isinstance(keys, dict) or not keys:
        raise ProductionOnboardingConfigError(f"{name} has an invalid key document")
    if any(not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None for key_id in keys):
        raise ProductionOnboardingConfigError(f"{name} has an invalid key identifier")
    decoded = {key_id: _decode_key(value, name=name) for key_id, value in keys.items()}
    if len(set(decoded.values())) != len(decoded):
        raise ProductionOnboardingConfigError(f"{name} contains duplicate key material")
    return document, decoded


def _envelope_keyring(source: Mapping[str, str]) -> VerificationEnvelopeKeyring:
    name = "OMNIGENT_SAAS_VERIFICATION_ENVELOPE_KEYS_FILE"
    document, keys = _key_document(source, name)
    if set(document) != {"schema_version", "active_key_id", "keys"}:
        raise ProductionOnboardingConfigError(f"{name} has an invalid document shape")
    active = document.get("active_key_id")
    if not isinstance(active, str):
        raise ProductionOnboardingConfigError(f"{name} has an invalid active key")
    try:
        return VerificationEnvelopeKeyring(active_key_id=active, keys=keys)
    except ValueError:
        raise ProductionOnboardingConfigError(f"{name} has an invalid key rotation") from None


def _rate_limit_keyring(source: Mapping[str, str]) -> RegistrationRateLimitSubjectKeyring:
    name = "OMNIGENT_SAAS_REGISTRATION_RATE_LIMIT_KEYS_FILE"
    document, keys = _key_document(source, name)
    expected = {
        "schema_version",
        "active_key_id",
        "previous_key_id",
        "anchor_key_id",
        "write_key_id",
        "previous_writers_drained",
        "keys",
    }
    if set(document) != expected:
        raise ProductionOnboardingConfigError(f"{name} has an invalid document shape")
    try:
        return RegistrationRateLimitSubjectKeyring(
            keys=keys,
            active_key_id=cast(str, document["active_key_id"]),
            previous_key_id=cast(str | None, document["previous_key_id"]),
            anchor_key_id=cast(str | None, document["anchor_key_id"]),
            write_key_id=cast(str | None, document["write_key_id"]),
            previous_writers_drained=cast(bool, document["previous_writers_drained"]),
        )
    except (TypeError, ValueError, KeyError):
        raise ProductionOnboardingConfigError(f"{name} has an invalid key rotation") from None


def _policy(source: Mapping[str, str]) -> OnboardingPolicy:
    name = "OMNIGENT_SAAS_ONBOARDING_POLICY_FILE"
    _path, raw, document = _json_document(source, name, secret=False)
    expected = {
        "schema_version",
        "plans",
        "home_regions",
        "reserved_slugs",
        "verification_ttl_seconds",
    }
    if set(document) != expected or document.get("schema_version") != 1:
        raise ProductionOnboardingConfigError(f"{name} has an invalid document shape")
    canonical = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if raw != canonical:
        raise ProductionOnboardingConfigError(f"{name} must contain canonical JSON")
    plans = document.get("plans")
    regions = document.get("home_regions")
    reserved = document.get("reserved_slugs")
    ttl = document.get("verification_ttl_seconds")
    if (
        not isinstance(plans, list)
        or not plans
        or not isinstance(regions, list)
        or not isinstance(reserved, list)
        or isinstance(ttl, bool)
        or not isinstance(ttl, int)
    ):
        raise ProductionOnboardingConfigError(f"{name} has invalid policy values")
    plan_fields = {
        "key",
        "policy_revision",
        "trial_days",
        "currency",
        "trial_run_limit",
        "trial_concurrency_limit",
        "runtime_type",
        "capacity_class",
        "default_project_name",
        "default_project_visibility",
        "quota_resource",
        "quota_limit",
    }
    try:
        parsed_plans = tuple(
            OnboardingPlan(**cast(dict[str, Any], plan))
            for plan in plans
            if isinstance(plan, dict) and set(plan) == plan_fields
        )
        if len(parsed_plans) != len(plans):
            raise ValueError
        return OnboardingPolicy(
            plans=parsed_plans,
            home_regions=frozenset(cast(list[str], regions)),
            reserved_slugs=frozenset(cast(list[str], reserved)),
            verification_ttl=timedelta(seconds=ttl),
        )
    except (TypeError, ValueError):
        raise ProductionOnboardingConfigError(f"{name} has invalid policy values") from None


def _public_origin(source: Mapping[str, str]) -> str:
    value = _required(source, "OMNIGENT_SAAS_PUBLIC_ORIGIN")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ProductionOnboardingConfigError("OMNIGENT_SAAS_PUBLIC_ORIGIN is invalid") from None
    hostname = parsed.hostname
    if (
        parsed.scheme != "https"
        or not hostname
        or hostname != hostname.lower()
        or "." not in hostname
        or any(_DNS_LABEL.fullmatch(label) is None for label in hostname.split("."))
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ProductionOnboardingConfigError("OMNIGENT_SAAS_PUBLIC_ORIGIN is invalid")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ProductionOnboardingConfigError("OMNIGENT_SAAS_PUBLIC_ORIGIN is invalid")
    return f"https://{hostname}"


def _common_config(source: Mapping[str, str]) -> ProductionOnboardingCommonConfig:
    _reject_direct_secret_environment(source)
    return ProductionOnboardingCommonConfig(
        public_origin=_public_origin(source),
        policy=_policy(source),
        envelope_keyring=_envelope_keyring(source),
        rate_limit_keyring=_rate_limit_keyring(source),
        bindings=load_production_onboarding_service_role_bindings(source),
    )


def _trusted_network(source: Mapping[str, str]) -> TrustedClientNetworkConfig:
    raw = _required(source, "OMNIGENT_SAAS_TRUSTED_PROXY_CIDRS")
    cidrs = tuple(raw.split(","))
    if any(not value or value != value.strip() for value in cidrs):
        raise ProductionOnboardingConfigError("OMNIGENT_SAAS_TRUSTED_PROXY_CIDRS is malformed")
    try:
        return TrustedClientNetworkConfig(trusted_proxy_cidrs=cidrs)
    except ValueError:
        raise ProductionOnboardingConfigError(
            "OMNIGENT_SAAS_TRUSTED_PROXY_CIDRS is invalid"
        ) from None


def _bounded_number(
    source: Mapping[str, str],
    name: str,
    *,
    default: str,
    minimum: float,
    maximum: float,
    integer: bool = False,
) -> float | int:
    raw = source.get(name, default)
    try:
        value = int(raw) if integer else float(raw)
    except (TypeError, ValueError):
        raise ProductionOnboardingConfigError(f"{name} must be a number") from None
    if not minimum <= value <= maximum:
        raise ProductionOnboardingConfigError(f"{name} is outside the supported range")
    return value


def load_production_onboarding_http_config(
    environ: Mapping[str, str] | None = None,
) -> ProductionOnboardingHttpConfig:
    source = os.environ if environ is None else environ
    common = _common_config(source)
    return ProductionOnboardingHttpConfig(
        common=common,
        registration_database_url=_database_url(
            source, service="registration", bindings=common.bindings
        ),
        status_database_url=_database_url(
            source, service="onboarding_status", bindings=common.bindings
        ),
        trusted_client_network=_trusted_network(source),
    )


def load_production_onboarding_worker_config(
    environ: Mapping[str, str] | None = None,
) -> ProductionOnboardingWorkerConfig:
    source = os.environ if environ is None else environ
    common = _common_config(source)
    runtime_factory = _required(source, "OMNIGENT_SAAS_RUNTIME_PROVIDER_FACTORY")
    module_name, separator, attribute = runtime_factory.partition(":")
    if (
        not separator
        or _FACTORY_REFERENCE.fullmatch(runtime_factory) is None
        or any(part.startswith("_") for part in module_name.split("."))
        or attribute.startswith("_")
    ):
        raise ProductionOnboardingConfigError("OMNIGENT_SAAS_RUNTIME_PROVIDER_FACTORY is invalid")
    email_delivery_mode = source.get("OMNIGENT_SAAS_EMAIL_DELIVERY_MODE", "resend")
    if email_delivery_mode not in {"resend", "platform_smtp"}:
        raise ProductionOnboardingConfigError(
            "OMNIGENT_SAAS_EMAIL_DELIVERY_MODE must be resend or platform_smtp"
        )
    provider_token: str | None = None
    email_from_address: str | None = None
    if email_delivery_mode == "resend":
        token_name = "OMNIGENT_SAAS_EMAIL_PROVIDER_TOKEN_FILE"
        token_path = _regular_file(source, token_name, maximum_bytes=_MAX_SECRET_BYTES)
        token_bytes = _read_bytes(
            token_path,
            token_name,
            maximum_bytes=_MAX_SECRET_BYTES,
        ).rstrip(b"\r\n")
        try:
            provider_token = token_bytes.decode("ascii")
        except UnicodeError:
            raise ProductionOnboardingConfigError(f"{token_name} is invalid") from None
        if not provider_token or provider_token != provider_token.strip():
            raise ProductionOnboardingConfigError(f"{token_name} is invalid")
        email_from_address = _required(source, "OMNIGENT_SAAS_EMAIL_FROM")
    return ProductionOnboardingWorkerConfig(
        common=common,
        registration_database_url=_database_url(
            source, service="registration", bindings=common.bindings
        ),
        onboarding_database_url=_database_url(
            source, service="onboarding", bindings=common.bindings
        ),
        execution_database_url=_database_url(source, service="executor", bindings=common.bindings),
        email_delivery_mode=email_delivery_mode,
        email_from_address=email_from_address,
        email_provider_token=provider_token,
        email_timeout_seconds=cast(
            float,
            _bounded_number(
                source,
                "OMNIGENT_SAAS_EMAIL_TIMEOUT_SECONDS",
                default="10",
                minimum=0.1,
                maximum=30,
            ),
        ),
        runtime_provider_factory=runtime_factory,
        workflow=TenantOnboardingWorkflowConfig(
            lease_duration=timedelta(
                seconds=cast(
                    int,
                    _bounded_number(
                        source,
                        "OMNIGENT_SAAS_ONBOARDING_LEASE_SECONDS",
                        default="120",
                        minimum=30,
                        maximum=900,
                        integer=True,
                    ),
                )
            ),
            max_attempts=cast(
                int,
                _bounded_number(
                    source,
                    "OMNIGENT_SAAS_ONBOARDING_MAX_ATTEMPTS",
                    default="3",
                    minimum=1,
                    maximum=16,
                    integer=True,
                ),
            ),
            retry_base=timedelta(
                seconds=cast(
                    int,
                    _bounded_number(
                        source,
                        "OMNIGENT_SAAS_ONBOARDING_RETRY_BASE_SECONDS",
                        default="5",
                        minimum=1,
                        maximum=300,
                        integer=True,
                    ),
                )
            ),
        ),
    )


def _new_engine(database_url: str) -> Engine:
    return sa.create_engine(database_url, pool_pre_ping=True)


def _session(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False, class_=Session)


def build_production_onboarding_http_services(
    environ: Mapping[str, str] | None = None,
    *,
    engine_factory: Callable[[str], Engine] = _new_engine,
) -> ProductionOnboardingHttpServices:
    """Build the three HTTP dependencies without worker-only authority."""

    config = load_production_onboarding_http_config(environ)
    registration_engine = engine_factory(config.registration_database_url)
    status_engine = engine_factory(config.status_database_url)
    engines = (registration_engine, status_engine)
    try:
        if len({id(engine) for engine in engines}) != 2:
            raise ProductionOnboardingConfigError(
                "registration and onboarding status require distinct engines"
            )
        registration_sessions = _session(registration_engine)
        status_sessions = _session(status_engine)
        verify_onboarding_database_authority(registration_engine, authority="registration")
        limiter = SharedRegistrationRateLimiter(
            registration_sessions,
            subject_keyring=config.common.rate_limit_keyring,
        )
        return ProductionOnboardingHttpServices(
            onboarding=SelfServiceOnboardingService(
                registration_sessions,
                policy=config.common.policy,
                envelope_keyring=config.common.envelope_keyring,
                rate_limiter=limiter,
            ),
            onboarding_status=OnboardingStatusService(status_sessions),
            onboarding_client_network=TrustedClientNetworkResolver(config.trusted_client_network),
            _engines=engines,
        )
    except Exception:
        for engine in engines:
            engine.dispose()
        raise


def _load_runtime_adapter(reference: str) -> ProductionRuntimePartitionAdapter:
    module_name, _, attribute = reference.partition(":")
    try:
        factory = getattr(importlib.import_module(module_name), attribute)
        signature = inspect.signature(factory)
        if (
            isinstance(factory, type)
            or not callable(factory)
            or any(
                parameter.default is inspect.Parameter.empty
                and parameter.kind
                in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
                for parameter in signature.parameters.values()
            )
        ):
            raise TypeError
        adapter = factory()
    except Exception:  # noqa: BLE001 - redact deployment adapter details.
        raise ProductionOnboardingConfigError("Runtime Provider factory failed") from None
    if type(adapter) is not ProductionRuntimePartitionAdapter:
        raise ProductionOnboardingConfigError(
            "Runtime Provider factory returned an unsupported adapter"
        )
    adapter.assert_production_ready()
    return cast(ProductionRuntimePartitionAdapter, adapter)


def build_production_onboarding_outbox_composition(
    environ: Mapping[str, str] | None = None,
    *,
    engine_factory: Callable[[str], Engine] = _new_engine,
    runtime_loader: Callable[[str], ProductionRuntimePartitionAdapter] = _load_runtime_adapter,
    secret_cipher_loader: Callable[[], SecretCipher | None] = build_secret_cipher,
) -> ProductionOnboardingOutboxPublisher:
    """Build the worker publisher without acquiring the dispatcher login."""

    config = load_production_onboarding_worker_config(environ)
    registration_engine = engine_factory(config.registration_database_url)
    onboarding_engine = engine_factory(config.onboarding_database_url)
    execution_engine = engine_factory(config.execution_database_url)
    engines = (registration_engine, onboarding_engine, execution_engine)
    sender: ResendEmailVerificationSender | ConfiguredSmtpEmailVerificationSender | None = None
    try:
        if len({id(engine) for engine in engines}) != 3:
            raise ProductionOnboardingConfigError(
                "registration, onboarding, and execution require distinct engines"
            )
        registration_sessions = _session(registration_engine)
        onboarding_sessions = _session(onboarding_engine)
        execution_sessions = _session(execution_engine)
        limiter = SharedRegistrationRateLimiter(
            registration_sessions,
            subject_keyring=config.common.rate_limit_keyring,
        )
        if config.email_delivery_mode == "platform_smtp":
            try:
                secret_cipher = secret_cipher_loader()
            except Exception:  # noqa: BLE001 - redact deployment cipher details.
                raise ProductionOnboardingConfigError(
                    "Platform SMTP secret cipher is unavailable"
                ) from None
            if secret_cipher is None:
                raise ProductionOnboardingConfigError(
                    "Platform SMTP requires a configured KMS or Vault secret cipher"
                )
            sender = ConfiguredSmtpEmailVerificationSender(
                EmailProviderConfigurationReader(
                    onboarding_sessions,
                    secret_cipher=secret_cipher,
                    public_origin=config.common.public_origin,
                )
            )
        else:
            if config.email_from_address is None or config.email_provider_token is None:
                raise ProductionOnboardingConfigError("Resend email configuration is incomplete")
            sender = ResendEmailVerificationSender(
                ResendEmailVerificationConfig(
                    public_origin=config.common.public_origin,
                    from_address=config.email_from_address,
                    provider_token=config.email_provider_token,
                    timeout_seconds=config.email_timeout_seconds,
                )
            )
        runtime = runtime_loader(config.runtime_provider_factory)
        composition = create_tenant_onboarding_composition(
            TenantOnboardingDependencies(
                registration_sessions=registration_sessions,
                onboarding_sessions=onboarding_sessions,
                execution_sessions=execution_sessions,
                policy=config.common.policy,
                envelopes=config.common.envelope_keyring,
                rate_limiter=limiter,
                email_sender=sender,
                runtime=runtime,
            ),
            config=config.workflow,
        )
        publisher = ProductionOnboardingOutboxPublisher(
            composition=composition,
            email_sender=sender,
            runtime=runtime,
            _engines=engines,
        )
        publisher.validate_outbox_configuration()
        return publisher
    except Exception:
        if sender is not None:
            sender.close()
        for engine in engines:
            engine.dispose()
        raise


def build_production_onboarding_outbox_publisher() -> OutboxPublisher:
    """Zero-argument factory used by ``saas.outbox_worker`` in production."""

    return cast(OutboxPublisher, build_production_onboarding_outbox_composition())


__all__ = [
    "ProductionOnboardingConfigError",
    "ProductionOnboardingHttpConfig",
    "ProductionOnboardingHttpServices",
    "ProductionOnboardingOutboxPublisher",
    "ProductionOnboardingServiceRoleBindings",
    "ProductionOnboardingWorkerConfig",
    "build_production_onboarding_http_services",
    "build_production_onboarding_outbox_composition",
    "build_production_onboarding_outbox_publisher",
    "load_production_onboarding_http_config",
    "load_production_onboarding_service_role_bindings",
    "load_production_onboarding_worker_config",
]
