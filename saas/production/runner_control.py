"""Authenticated production Runner control transport.

This module exposes the existing durable scheduling and execution authorities to
managed Runners without duplicating either state machine.  A request is accepted
only when TLS 1.3 mutual authentication derives one canonical Runner identity,
the deployment certificate authority accepts that leaf for ``runner_control``,
and the current PostgreSQL Runner connection generation/token also matches.

The wire contract is deliberately small: one bounded canonical JSON frame per
TLS connection, no automatic retry, no caller-selected Tenant/Project scope,
capability actions, lease duration, or recovery behavior.  Unknown-result
mutations are therefore visible to the Runner, which must reconcile by reading
durable Run state rather than silently replaying a transition.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import inspect
import json
import os
import re
import signal
import ssl
import stat
import struct
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Protocol, cast
from uuid import UUID

import sqlalchemy as sa
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from omnigent.runner.identity import token_bound_runner_id
from saas.control_plane.certificates import RunnerCertificateAuthority
from saas.control_plane.execution import (
    ExecutionControlPlane,
    ExecutionControlPlaneError,
    RunLease,
    RunMutation,
)
from saas.control_plane.preview_tunnel_registration import (
    PreviewTunnelRegistrationError,
    PreviewTunnelRegistrationGrant,
    PreviewTunnelRegistrationIssuer,
)
from saas.control_plane.runner_execution_spec import (
    ManagedRunExecutionSpecError,
    managed_execution_spec,
    production_run_execution_spec,
)
from saas.control_plane.scheduling import (
    FairRunLease,
    RunnerExecutionEnvelope,
    SchedulingControlPlane,
    SchedulingError,
    VerifiedCapability,
)
from saas.onboarding_composition import verify_onboarding_database_authority
from saas.preview_relay_transport import PreviewRelayEndpointPolicy
from saas.production.runner_readiness import assert_postgresql_runner_fleet_ready
from saas.production.server_config import (
    ProductionMigrationReceipt,
    ProductionServerConfigError,
    load_production_database_url_file,
    load_production_migration_receipt,
)
from saas.production.service_bindings import (
    ProductionServiceRoleBindings,
    ProductionServiceRoleBindingsError,
    load_production_service_role_bindings,
)

_PROTOCOL_VERSION = 1
_MAGIC = b"OMNIRC1\x00"
_FRAME_PREFIX = struct.Struct("!8sI")
_MAX_FRAME_BYTES = 16_384
_READINESS_REQUEST = b"OMNIGENT_RUNNER_CONTROL_READY_V1\n"
_READINESS_RESPONSE = b"READY\n"
_MAX_ERROR_CODE = 64
_FULL_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REVISION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_FACTORY_REFERENCE = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*:[A-Za-z][A-Za-z0-9_]*$"
)
_INTERNAL_HOST = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\."
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
_ERROR_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_RUNNER_SPIFFE_ID = re.compile(
    r"^spiffe://omnigent/runner/"
    r"(?P<runner>[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$"
)
_TERMINAL_STATUSES = frozenset({"cancelled", "succeeded", "failed", "timed_out", "orphaned"})
_RUNNER_TRANSITIONS = (
    frozenset({"starting", "running", "waiting_input", "waiting_approval", "cancelling"})
    | _TERMINAL_STATUSES
)
_CAPABILITY_ACTIONS = (
    "preview.serve",
    "run.execute",
    "sandbox.launch",
    "worktree.read",
    "worktree.write",
)
_CAPABILITY_SCOPE = {"control_plane": "runner_control"}
_FORBIDDEN_DATABASE_ENVIRONMENTS = frozenset(
    {
        "DATABASE_URL",
        "OMNIGENT_SAAS_CONTROL_PLANE_DATABASE_URL",
        "OMNIGENT_SAAS_PRINCIPAL_OPERATOR_DATABASE_URL",
        "OMNIGENT_SAAS_DATABASE_OWNER_DATABASE_URL",
        "OMNIGENT_SAAS_OFFICIAL_MIGRATION_DATABASE_URL",
        "OMNIGENT_SAAS_CONTROL_PLANE_MIGRATION_DATABASE_URL",
        "OMNIGENT_SAAS_PRINCIPAL_OPERATOR_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_DATABASE_OWNER_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_OFFICIAL_MIGRATION_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_CONTROL_PLANE_MIGRATION_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_RUNTIME_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_AUTHENTICATOR_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_APP_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_GOVERNANCE_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_PUBLIC_API_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_DISPATCHER_DATABASE_URL_FILE",
    }
)


class RunnerControlError(RuntimeError):
    """Stable fail-closed authority or transport error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class RunnerMachineCertificateAuthorizer(Protocol):
    """Deployment PKI/revocation authority for one presented Runner leaf."""

    def is_runner_machine_certificate_authorized(
        self,
        *,
        runner_id: UUID,
        certificate_der: bytes,
        purpose: str,
    ) -> bool: ...


class DurableRunnerControlCertificateAuthorizer:
    """Adapt the shared PostgreSQL certificate lifecycle to Runner control."""

    def __init__(self, authority: RunnerCertificateAuthority) -> None:
        self._authority = authority

    def is_runner_machine_certificate_authorized(
        self,
        *,
        runner_id: UUID,
        certificate_der: bytes,
        purpose: str,
    ) -> bool:
        if purpose != "runner_control":
            return False
        return self._authority.is_runner_certificate_authorized(
            runner_id=runner_id,
            certificate_der=certificate_der,
            purpose="runner_control",
        )


class RunnerMachineAuthority(Protocol):
    """Narrow server-side surface used by the authenticated transport."""

    def heartbeat_runner(
        self,
        *,
        runner_id: UUID,
        connection_generation: int,
        connection_token: str,
    ) -> str: ...

    def claim_run(
        self,
        *,
        runner_id: UUID,
        connection_generation: int,
        connection_token: str,
    ) -> FairRunLease | None: ...

    def heartbeat_run(
        self,
        *,
        runner_id: UUID,
        connection_generation: int,
        connection_token: str,
        run_id: UUID,
        lease_token: UUID,
        fence_token: int,
        capability_token: str,
    ) -> RunLease: ...

    def transition_run(
        self,
        *,
        runner_id: UUID,
        connection_generation: int,
        connection_token: str,
        run_id: UUID,
        lease_token: UUID,
        fence_token: int,
        capability_token: str,
        target_status: str,
    ) -> RunMutation: ...

    def release_run(
        self,
        *,
        runner_id: UUID,
        connection_generation: int,
        connection_token: str,
        run_id: UUID,
        fence_token: int,
    ) -> bool: ...

    def mint_preview_tunnel(
        self,
        *,
        runner_id: UUID,
        connection_generation: int,
        connection_token: str,
        certificate_fingerprint_sha256: str,
    ) -> PreviewTunnelRegistrationGrant: ...


class _SchedulingAuthority(Protocol):
    def heartbeat_runner(
        self,
        *,
        runner_id: UUID,
        connection_generation: int,
        connection_token: str,
        now: datetime | None = None,
    ) -> str: ...

    def claim_fair_run(
        self,
        *,
        runner_id: UUID,
        connection_generation: int,
        connection_token: str,
        lease_duration: timedelta,
        capability_actions: tuple[str, ...] | list[str],
        capability_resource_scope: dict[str, str],
        expected_product_revision: str | None = None,
        product_image_digest: str | None = None,
        heartbeat_timeout: timedelta = timedelta(seconds=30),
        now: datetime | None = None,
    ) -> FairRunLease | None: ...

    def verify_capability(
        self,
        *,
        capability_token: str,
        runner_id: UUID,
        run_id: UUID,
        action: str,
        required_resource_scope: dict[str, str],
        now: datetime | None = None,
    ) -> VerifiedCapability: ...

    def release_dispatch(
        self,
        *,
        run_id: UUID,
        runner_id: UUID,
        connection_generation: int,
        connection_token: str,
        fence_token: int,
        requeue: bool,
        now: datetime | None = None,
    ) -> bool: ...

    def authenticated_run_heartbeat(
        self,
        execution: ExecutionControlPlane,
        *,
        runner_id: UUID,
        connection_generation: int,
        connection_token: str,
        run_id: UUID,
        lease_token: UUID,
        fence_token: int,
        capability_token: str,
        lease_duration: timedelta,
    ) -> RunLease: ...

    def authenticated_run_transition(
        self,
        execution: ExecutionControlPlane,
        *,
        runner_id: UUID,
        connection_generation: int,
        connection_token: str,
        run_id: UUID,
        lease_token: UUID,
        fence_token: int,
        capability_token: str,
        target_status: str,
        trace_id: str,
    ) -> RunMutation: ...


class _ExecutionAuthority(Protocol):
    def heartbeat(
        self,
        *,
        run_id: UUID,
        lease_token: UUID,
        fence_token: int,
        lease_duration: timedelta,
        now: datetime | None = None,
    ) -> RunLease: ...

    def transition_run(
        self,
        *,
        run_id: UUID,
        lease_token: UUID,
        fence_token: int,
        target_status: str,
        payload: dict[str, object] | None = None,
        trace_id: str,
        now: datetime | None = None,
    ) -> RunMutation: ...


@dataclass(frozen=True, slots=True)
class RunnerControlPolicy:
    """Server-owned lease and liveness bounds; never accepted on the wire."""

    lease_duration: timedelta = timedelta(seconds=45)
    heartbeat_timeout: timedelta = timedelta(seconds=30)

    def __post_init__(self) -> None:
        if (
            self.lease_duration < timedelta(seconds=5)
            or self.lease_duration > timedelta(minutes=5)
            or self.heartbeat_timeout < timedelta(seconds=5)
            or self.heartbeat_timeout >= self.lease_duration
        ):
            raise ValueError("Runner control lease policy is invalid")


class ProductionRunnerMachineAuthority:
    """Delegate every state change to the existing durable domain authorities."""

    def __init__(
        self,
        scheduling: _SchedulingAuthority,
        execution: _ExecutionAuthority,
        *,
        policy: RunnerControlPolicy | None = None,
        product_revision: str | None = None,
        image_digest: str | None = None,
        preview_tunnel_issuer: PreviewTunnelRegistrationIssuer | None = None,
    ) -> None:
        self._scheduling = scheduling
        self._execution = execution
        self._policy = policy or RunnerControlPolicy()
        self._product_revision = product_revision
        self._image_digest = image_digest
        self._preview_tunnel_issuer = preview_tunnel_issuer

    def heartbeat_runner(
        self,
        *,
        runner_id: UUID,
        connection_generation: int,
        connection_token: str,
    ) -> str:
        return self._scheduling.heartbeat_runner(
            runner_id=runner_id,
            connection_generation=connection_generation,
            connection_token=connection_token,
        )

    def claim_run(
        self,
        *,
        runner_id: UUID,
        connection_generation: int,
        connection_token: str,
    ) -> FairRunLease | None:
        # Actions, resource scope, and TTL are entirely server-selected.  The
        # scheduler itself adds the authoritative Tenant/Space/Project/Run/Runner
        # scope while holding the dispatch and Run locks.
        return self._scheduling.claim_fair_run(
            runner_id=runner_id,
            connection_generation=connection_generation,
            connection_token=connection_token,
            lease_duration=self._policy.lease_duration,
            heartbeat_timeout=self._policy.heartbeat_timeout,
            capability_actions=_CAPABILITY_ACTIONS,
            capability_resource_scope=dict(_CAPABILITY_SCOPE),
            expected_product_revision=self._product_revision,
            product_image_digest=self._image_digest,
        )

    def heartbeat_run(
        self,
        *,
        runner_id: UUID,
        connection_generation: int,
        connection_token: str,
        run_id: UUID,
        lease_token: UUID,
        fence_token: int,
        capability_token: str,
    ) -> RunLease:
        return self._scheduling.authenticated_run_heartbeat(
            self._execution,  # type: ignore[arg-type]
            runner_id=runner_id,
            connection_generation=connection_generation,
            connection_token=connection_token,
            run_id=run_id,
            lease_token=lease_token,
            fence_token=fence_token,
            capability_token=capability_token,
            lease_duration=self._policy.lease_duration,
        )

    def transition_run(
        self,
        *,
        runner_id: UUID,
        connection_generation: int,
        connection_token: str,
        run_id: UUID,
        lease_token: UUID,
        fence_token: int,
        capability_token: str,
        target_status: str,
    ) -> RunMutation:
        if target_status not in _RUNNER_TRANSITIONS:
            raise RunnerControlError(
                "runner_control_transition_denied", "Runner transition target is denied"
            )
        return self._scheduling.authenticated_run_transition(
            self._execution,  # type: ignore[arg-type]
            runner_id=runner_id,
            connection_generation=connection_generation,
            connection_token=connection_token,
            run_id=run_id,
            lease_token=lease_token,
            fence_token=fence_token,
            capability_token=capability_token,
            target_status=target_status,
            trace_id=f"runner:{runner_id}",
        )

    def release_run(
        self,
        *,
        runner_id: UUID,
        connection_generation: int,
        connection_token: str,
        run_id: UUID,
        fence_token: int,
    ) -> bool:
        # A Runner can release only terminal capacity.  It cannot request a
        # requeue; lease expiry/requeue belongs solely to the scheduler recovery
        # loop, which also reconciles a terminal transition followed by a crash.
        return self._scheduling.release_dispatch(
            run_id=run_id,
            runner_id=runner_id,
            connection_generation=connection_generation,
            connection_token=connection_token,
            fence_token=fence_token,
            requeue=False,
        )

    def mint_preview_tunnel(
        self,
        *,
        runner_id: UUID,
        connection_generation: int,
        connection_token: str,
        certificate_fingerprint_sha256: str,
    ) -> PreviewTunnelRegistrationGrant:
        if self._preview_tunnel_issuer is None:
            raise RunnerControlError(
                "runner_preview_tunnel_unavailable",
                "Preview tunnel registration is unavailable",
            )
        return self._preview_tunnel_issuer.issue(
            runner_id=runner_id,
            connection_generation=connection_generation,
            connection_token=connection_token,
            certificate_fingerprint_sha256=certificate_fingerprint_sha256,
        )


def _require_tls13(context: ssl.SSLContext, *, server: bool) -> None:
    if (
        context.minimum_version != ssl.TLSVersion.TLSv1_3
        or context.maximum_version != ssl.TLSVersion.TLSv1_3
        or context.verify_mode != ssl.CERT_REQUIRED
        or (not server and not context.check_hostname)
    ):
        raise ValueError("Runner control TLS must use mutual TLS 1.3 with hostname verification")


def runner_identity_from_certificate(certificate_bytes: bytes) -> UUID:
    """Validate one ClientAuth leaf and return its sole Runner SPIFFE identity."""

    try:
        if certificate_bytes.startswith(b"-----BEGIN CERTIFICATE-----"):
            certificate = x509.load_pem_x509_certificate(certificate_bytes)
        else:
            certificate = x509.load_der_x509_certificate(certificate_bytes)
        basic_constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        extended_usage = certificate.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = list(san)
    except (TypeError, ValueError, x509.ExtensionNotFound) as error:
        raise RunnerControlError(
            "runner_control_identity_invalid", "Runner control identity is invalid"
        ) from error
    if (
        basic_constraints.ca
        or not key_usage.digital_signature
        or key_usage.key_cert_sign
        or key_usage.crl_sign
        or set(extended_usage) != {ExtendedKeyUsageOID.CLIENT_AUTH}
        or len(names) != 1
        or not isinstance(names[0], x509.UniformResourceIdentifier)
    ):
        raise RunnerControlError(
            "runner_control_identity_invalid", "Runner control identity is invalid"
        )
    matched = _RUNNER_SPIFFE_ID.fullmatch(names[0].value)
    if matched is None:
        raise RunnerControlError(
            "runner_control_identity_invalid", "Runner control identity is invalid"
        )
    return UUID(matched.group("runner"))


def _runner_certificate(writer: asyncio.StreamWriter) -> tuple[UUID, bytes]:
    ssl_object = writer.get_extra_info("ssl_object")
    if not isinstance(ssl_object, ssl.SSLObject | ssl.SSLSocket):
        raise RunnerControlError("runner_control_mtls_required", "Runner control requires mTLS")
    certificate_der = ssl_object.getpeercert(binary_form=True)
    if not isinstance(certificate_der, bytes) or not certificate_der:
        raise RunnerControlError(
            "runner_control_identity_invalid", "Runner control identity is invalid"
        )
    return runner_identity_from_certificate(certificate_der), certificate_der


def _strict_document(encoded: bytes) -> dict[str, object]:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result

    value = json.loads(encoded.decode("utf-8"), object_pairs_hook=unique_object)
    if not isinstance(value, dict):
        raise ValueError("frame is not an object")
    return value


def _canonical_uuid(value: object) -> UUID:
    if not isinstance(value, str):
        raise ValueError("UUID is invalid")
    parsed = UUID(value)
    if parsed.int == 0 or str(parsed) != value:
        raise ValueError("UUID is not canonical")
    return parsed


def _positive_integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value < (1 << 63):
        raise ValueError("integer is invalid")
    return value


def _secret(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 32 <= len(value) <= 512
        or value != value.strip()
        or any(ord(character) < 33 for character in value)
    ):
        raise ValueError("secret is invalid")
    return value


def _exact(document: Mapping[str, object], fields: set[str]) -> None:
    if set(document) != fields or document.get("version") != _PROTOCOL_VERSION:
        raise ValueError("frame fields are invalid")


def _request(document: Mapping[str, object]) -> tuple[str, dict[str, object]]:
    action = document.get("action")
    common = {"action", "connection_generation", "connection_token", "version"}
    if action in {"heartbeat_runner", "claim_run", "mint_preview_tunnel"}:
        _exact(document, common)
    elif action in {"heartbeat_run", "transition_run"}:
        fields = common | {"capability_token", "fence_token", "lease_token", "run_id"}
        if action == "transition_run":
            fields.add("target_status")
        _exact(document, fields)
    elif action == "release_run":
        _exact(document, common | {"fence_token", "run_id"})
    else:
        raise ValueError("action is invalid")
    values: dict[str, object] = {
        "connection_generation": _positive_integer(document["connection_generation"]),
        "connection_token": _secret(document["connection_token"]),
    }
    if "run_id" in document:
        values["run_id"] = _canonical_uuid(document["run_id"])
    if "lease_token" in document:
        values["lease_token"] = _canonical_uuid(document["lease_token"])
    if "fence_token" in document:
        values["fence_token"] = _positive_integer(document["fence_token"])
    if "capability_token" in document:
        values["capability_token"] = _secret(document["capability_token"])
    if "target_status" in document:
        target = document["target_status"]
        if not isinstance(target, str) or target not in _RUNNER_TRANSITIONS:
            raise ValueError("target status is invalid")
        values["target_status"] = target
    return cast(str, action), values


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("authority returned a naive timestamp")
    return value.astimezone(timezone.utc).isoformat()


def _lease_document(lease: FairRunLease | None) -> dict[str, object]:
    if lease is None:
        return {"lease": None, "version": _PROTOCOL_VERSION}
    envelope = lease.execution_envelope
    if envelope is None:
        raise RunnerControlError(
            "runner_control_execution_envelope_missing",
            "Production claim has no execution envelope",
        )
    return {
        "lease": {
            "capability_id": str(lease.capability_id),
            "capability_token": lease.capability_token,
            "dispatch_generation": lease.dispatch_generation,
            "expires_at": _timestamp(lease.expires_at),
            "failure_domain": lease.failure_domain,
            "fence_token": lease.fence_token,
            "lease_token": str(lease.lease_token),
            "run_id": str(lease.run_id),
            "execution_envelope": {
                "change_set_id": str(envelope.change_set_id),
                "egress_policy_hash": envelope.egress_policy_hash,
                "egress_policy_id": str(envelope.egress_policy_id),
                "execution_profile_hash": envelope.execution_profile_hash,
                "execution_profile_id": str(envelope.execution_profile_id),
                "execution_spec_hash": envelope.execution_spec_hash,
                "execution_kind": envelope.execution_kind,
                "fence_token": envelope.fence_token,
                "image_digest": envelope.image_digest,
                "launch_argv": list(envelope.launch_argv),
                "preview_execution_id": (
                    str(envelope.preview_execution_id)
                    if envelope.preview_execution_id is not None
                    else None
                ),
                "checkpoint_revision": envelope.checkpoint_revision,
                "product_revision": envelope.product_revision,
                "project_id": str(envelope.project_id),
                "run_id": str(envelope.run_id),
                "runner_id": str(envelope.runner_id),
                "space_id": str(envelope.space_id),
                "tenant_id": str(envelope.tenant_id),
            },
        },
        "version": _PROTOCOL_VERSION,
    }


def _preview_tunnel_document(
    grant: PreviewTunnelRegistrationGrant,
) -> dict[str, object]:
    return {
        "preview_tunnel": {
            "audience": grant.audience,
            "connection_generation": grant.connection_generation,
            "endpoint_host": grant.endpoint_host,
            "endpoint_port": grant.endpoint_port,
            "expires_at": _timestamp(grant.expires_at),
            "official_runner_id": grant.official_runner_id,
            "registration_id": str(grant.registration_id),
            "registration_token": grant.registration_token,
            "runner_id": str(grant.runner_id),
            "server_name": grant.server_name,
        },
        "version": _PROTOCOL_VERSION,
    }


def _dispatch(
    authority: RunnerMachineAuthority,
    *,
    runner_id: UUID,
    action: str,
    values: dict[str, object],
) -> dict[str, object]:
    kwargs = {"runner_id": runner_id, **values}
    if action == "heartbeat_runner":
        status = authority.heartbeat_runner(**kwargs)  # type: ignore[arg-type]
        return {"status": status, "version": _PROTOCOL_VERSION}
    if action == "claim_run":
        return _lease_document(authority.claim_run(**kwargs))  # type: ignore[arg-type]
    if action == "mint_preview_tunnel":
        return _preview_tunnel_document(
            authority.mint_preview_tunnel(**kwargs)  # type: ignore[arg-type]
        )
    if action == "heartbeat_run":
        lease = authority.heartbeat_run(**kwargs)  # type: ignore[arg-type]
        return {
            "expires_at": _timestamp(lease.expires_at),
            "fence_token": lease.fence_token,
            "run_id": str(lease.run_id),
            "run_version": lease.version,
            "status": lease.status,
            "version": _PROTOCOL_VERSION,
        }
    if action == "transition_run":
        mutation = authority.transition_run(**kwargs)  # type: ignore[arg-type]
        return {
            "event_sequence": mutation.event_sequence,
            "run_id": str(mutation.run_id),
            "run_version": mutation.version,
            "status": mutation.status,
            "version": _PROTOCOL_VERSION,
        }
    if action == "release_run":
        replayed = authority.release_run(**kwargs)  # type: ignore[arg-type]
        return {"replayed": replayed, "version": _PROTOCOL_VERSION}
    raise AssertionError("unreachable Runner control action")


def _encoded(document: Mapping[str, object]) -> bytes:
    body = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    if not 1 <= len(body) <= _MAX_FRAME_BYTES:
        raise RunnerControlError("runner_control_frame_invalid", "Runner control frame is invalid")
    return _FRAME_PREFIX.pack(_MAGIC, len(body)) + body


async def _read_frame(reader: asyncio.StreamReader, *, timeout: float) -> dict[str, object]:
    try:
        prefix = await asyncio.wait_for(reader.readexactly(_FRAME_PREFIX.size), timeout=timeout)
        magic, length = _FRAME_PREFIX.unpack(prefix)
        if magic != _MAGIC or not 1 <= length <= _MAX_FRAME_BYTES:
            raise ValueError("frame prefix is invalid")
        body = await asyncio.wait_for(reader.readexactly(length), timeout=timeout)
        return _strict_document(body)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, UnicodeError, ValueError) as error:
        raise RunnerControlError(
            "runner_control_frame_invalid", "Runner control frame is invalid"
        ) from error


class MutualTlsRunnerControlServer:
    """One-frame mTLS server deriving Runner identity before reading commands."""

    def __init__(
        self,
        authority: RunnerMachineAuthority,
        tls_context: ssl.SSLContext,
        certificate_authorizer: RunnerMachineCertificateAuthorizer,
        *,
        request_timeout_seconds: float = 5.0,
    ) -> None:
        _require_tls13(tls_context, server=True)
        if request_timeout_seconds <= 0 or request_timeout_seconds > 60:
            raise ValueError("Runner control request timeout is invalid")
        self._authority = authority
        self._tls_context = tls_context
        self._certificate_authorizer = certificate_authorizer
        self._timeout = request_timeout_seconds
        self._server: asyncio.Server | None = None

    @property
    def port(self) -> int:
        if self._server is None or not self._server.sockets:
            raise RuntimeError("Runner control server is not started")
        return int(self._server.sockets[0].getsockname()[1])

    async def start(self, *, host: str = "127.0.0.1", port: int = 0) -> None:
        if self._server is not None:
            raise RuntimeError("Runner control server is already started")
        self._server = await asyncio.start_server(
            self._handle,
            host,
            port,
            ssl=self._tls_context,
            ssl_handshake_timeout=self._timeout,
            start_serving=True,
        )

    async def aclose(self) -> None:
        server = self._server
        self._server = None
        if server is not None:
            server.close()
            await server.wait_closed()

    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            runner_id, certificate_der = _runner_certificate(writer)
            allowed = await asyncio.to_thread(
                self._certificate_authorizer.is_runner_machine_certificate_authorized,
                runner_id=runner_id,
                certificate_der=certificate_der,
                purpose="runner_control",
            )
            if not allowed:
                raise RunnerControlError(
                    "runner_control_certificate_denied", "Runner control certificate is denied"
                )
            document = await _read_frame(reader, timeout=self._timeout)
            try:
                action, values = _request(document)
            except (KeyError, TypeError, ValueError) as error:
                raise RunnerControlError(
                    "runner_control_request_invalid", "Runner control request is invalid"
                ) from error
            if action == "mint_preview_tunnel":
                values["certificate_fingerprint_sha256"] = hashlib.sha256(
                    certificate_der
                ).hexdigest()
            response = await asyncio.to_thread(
                _dispatch,
                self._authority,
                runner_id=runner_id,
                action=action,
                values=values,
            )
        except RunnerControlError as error:
            response = {"error": {"code": error.code}, "version": _PROTOCOL_VERSION}
        except (
            ExecutionControlPlaneError,
            PreviewTunnelRegistrationError,
            SchedulingError,
        ) as error:
            code = error.code if _ERROR_CODE.fullmatch(error.code) else "runner_control_denied"
            response = {"error": {"code": code}, "version": _PROTOCOL_VERSION}
        except Exception:  # noqa: BLE001 - provider/database details must remain secret.
            response = {
                "error": {"code": "runner_control_internal_error"},
                "version": _PROTOCOL_VERSION,
            }
        try:
            writer.write(_encoded(response))
            await asyncio.wait_for(writer.drain(), timeout=self._timeout)
        except (ConnectionError, OSError, RuntimeError, asyncio.TimeoutError):
            pass
        finally:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()


class TlsRunnerControlReadinessServer:
    """Content-blind TLS endpoint with no Runner or database identity surface."""

    def __init__(
        self,
        tls_context: ssl.SSLContext,
        readiness_probe: Callable[[], None],
        *,
        timeout_seconds: float = 2.0,
    ) -> None:
        if (
            tls_context.minimum_version != ssl.TLSVersion.TLSv1_3
            or tls_context.maximum_version != ssl.TLSVersion.TLSv1_3
            or tls_context.verify_mode != ssl.CERT_NONE
        ):
            raise ValueError("Runner readiness must not request a client identity")
        if not 0.1 <= timeout_seconds <= 10:
            raise ValueError("Runner readiness timeout is invalid")
        self._tls_context = tls_context
        self._readiness_probe = readiness_probe
        self._timeout = timeout_seconds
        self._server: asyncio.Server | None = None

    @property
    def port(self) -> int:
        if self._server is None or not self._server.sockets:
            raise RuntimeError("Runner readiness server is not started")
        return int(self._server.sockets[0].getsockname()[1])

    async def start(self, *, host: str = "127.0.0.1", port: int = 0) -> None:
        if self._server is not None:
            raise RuntimeError("Runner readiness server is already started")
        self._server = await asyncio.start_server(
            self._handle,
            host,
            port,
            ssl=self._tls_context,
            ssl_handshake_timeout=self._timeout,
            start_serving=True,
        )

    async def aclose(self) -> None:
        server = self._server
        self._server = None
        if server is not None:
            server.close()
            await server.wait_closed()

    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            request = await asyncio.wait_for(
                reader.readexactly(len(_READINESS_REQUEST)),
                timeout=self._timeout,
            )
            if request == _READINESS_REQUEST:
                await asyncio.wait_for(
                    asyncio.to_thread(self._readiness_probe),
                    timeout=self._timeout,
                )
                writer.write(_READINESS_RESPONSE)
                await asyncio.wait_for(writer.drain(), timeout=self._timeout)
        except Exception:  # noqa: BLE001 - readiness never returns database or fleet details.
            pass
        finally:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()


@dataclass(frozen=True, slots=True)
class RunnerControlClientLease:
    run_id: UUID
    lease_token: UUID = field(repr=False)
    fence_token: int
    dispatch_generation: int
    failure_domain: str
    expires_at: datetime
    capability_id: UUID
    capability_token: str = field(repr=False)
    execution_envelope: RunnerExecutionEnvelope | None = None


@dataclass(frozen=True, slots=True)
class RunnerPreviewTunnelRegistration:
    registration_id: UUID
    runner_id: UUID
    connection_generation: int
    official_runner_id: str
    endpoint_host: str
    endpoint_port: int
    server_name: str
    audience: str
    registration_token: str = field(repr=False)
    expires_at: datetime


class MutualTlsRunnerControlClient:
    """Runner client with no transparent retry for unknown-result mutations."""

    def __init__(
        self,
        *,
        connect_host: str,
        port: int,
        server_name: str,
        tls_context: ssl.SSLContext,
        connection_generation: int,
        connection_token: str,
        timeout_seconds: float = 5.0,
    ) -> None:
        _require_tls13(tls_context, server=False)
        if (
            not _INTERNAL_HOST.fullmatch(connect_host.lower())
            or not _INTERNAL_HOST.fullmatch(server_name.lower())
            or isinstance(port, bool)
            or not 1 <= port <= 65_535
            or timeout_seconds <= 0
        ):
            raise ValueError("Runner control endpoint is invalid")
        self._connect_host = connect_host
        self._port = port
        self._server_name = server_name
        self._tls_context = tls_context
        self._generation = _positive_integer(connection_generation)
        self._token = _secret(connection_token)
        self._timeout = timeout_seconds

    async def _request(self, action: str, values: Mapping[str, object]) -> dict[str, object]:
        document = {
            "action": action,
            "connection_generation": self._generation,
            "connection_token": self._token,
            "version": _PROTOCOL_VERSION,
            **values,
        }
        reader: asyncio.StreamReader
        writer: asyncio.StreamWriter
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self._connect_host,
                    self._port,
                    ssl=self._tls_context,
                    server_hostname=self._server_name,
                    ssl_handshake_timeout=self._timeout,
                ),
                timeout=self._timeout,
            )
        except Exception as error:
            raise RunnerControlError(
                "runner_control_transport_unavailable", "Runner control is unavailable"
            ) from error
        try:
            writer.write(_encoded(document))
            await asyncio.wait_for(writer.drain(), timeout=self._timeout)
            response = await _read_frame(reader, timeout=self._timeout)
        except RunnerControlError:
            raise
        except Exception as error:
            raise RunnerControlError(
                "runner_control_transport_unavailable", "Runner control is unavailable"
            ) from error
        finally:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()
        if response.get("version") != _PROTOCOL_VERSION:
            raise RunnerControlError(
                "runner_control_response_invalid", "Runner control response is invalid"
            )
        if set(response) == {"error", "version"}:
            error = response["error"]
            code = error.get("code") if isinstance(error, dict) else None
            if not isinstance(code, str) or _ERROR_CODE.fullmatch(code) is None:
                raise RunnerControlError(
                    "runner_control_response_invalid", "Runner control response is invalid"
                )
            raise RunnerControlError(code, "Runner control request was denied")
        return response

    async def heartbeat_runner(self) -> str:
        response = await self._request("heartbeat_runner", {})
        if set(response) != {"status", "version"} or response["status"] not in {
            "online",
            "draining",
        }:
            raise RunnerControlError(
                "runner_control_response_invalid", "Runner control response is invalid"
            )
        return cast(str, response["status"])

    async def claim_run(self) -> RunnerControlClientLease | None:
        response = await self._request("claim_run", {})
        if set(response) != {"lease", "version"}:
            raise RunnerControlError(
                "runner_control_response_invalid", "Runner control response is invalid"
            )
        value = response["lease"]
        if value is None:
            return None
        try:
            if not isinstance(value, dict) or set(value) != {
                "capability_id",
                "capability_token",
                "dispatch_generation",
                "expires_at",
                "failure_domain",
                "fence_token",
                "lease_token",
                "run_id",
                "execution_envelope",
            }:
                raise ValueError("lease fields invalid")
            expiry = datetime.fromisoformat(cast(str, value["expires_at"]))
            if expiry.tzinfo is None or expiry.utcoffset() is None:
                raise ValueError("lease expiry invalid")
            failure_domain = value["failure_domain"]
            if (
                not isinstance(failure_domain, str)
                or not failure_domain
                or len(failure_domain) > 128
            ):
                raise ValueError("failure domain invalid")
            raw_envelope = value["execution_envelope"]
            if not isinstance(raw_envelope, dict) or set(raw_envelope) != {
                "change_set_id",
                "egress_policy_hash",
                "egress_policy_id",
                "execution_profile_hash",
                "execution_profile_id",
                "execution_kind",
                "execution_spec_hash",
                "fence_token",
                "image_digest",
                "launch_argv",
                "preview_execution_id",
                "checkpoint_revision",
                "product_revision",
                "project_id",
                "run_id",
                "runner_id",
                "space_id",
                "tenant_id",
            }:
                raise ValueError("execution envelope fields invalid")
            image_digest = raw_envelope["image_digest"]
            product_revision = raw_envelope["product_revision"]
            profile_hash = raw_envelope["execution_profile_hash"]
            egress_hash = raw_envelope["egress_policy_hash"]
            execution_spec_hash = raw_envelope["execution_spec_hash"]
            execution_kind = raw_envelope["execution_kind"]
            launch_argv = raw_envelope["launch_argv"]
            if (
                not isinstance(image_digest, str)
                or _IMAGE_DIGEST.fullmatch(image_digest) is None
                or not isinstance(product_revision, str)
                or _FULL_GIT_SHA.fullmatch(product_revision) is None
                or not isinstance(profile_hash, str)
                or re.fullmatch(r"[0-9a-f]{64}", profile_hash) is None
                or not isinstance(egress_hash, str)
                or re.fullmatch(r"[0-9a-f]{64}", egress_hash) is None
                or not isinstance(execution_spec_hash, str)
                or re.fullmatch(r"[0-9a-f]{64}", execution_spec_hash) is None
                or execution_kind not in {"omnigent.agent.v1", "omnigent.preview.v1"}
                or not isinstance(launch_argv, list)
                or any(not isinstance(value, str) for value in launch_argv)
            ):
                raise ValueError("execution envelope release identity invalid")
            preview_execution_id: UUID | None = None
            checkpoint_revision: str | None = None
            if execution_kind == "omnigent.agent.v1":
                if (
                    len(launch_argv) != 10
                    or raw_envelope["preview_execution_id"] is not None
                    or raw_envelope["checkpoint_revision"] is not None
                ):
                    raise ValueError("execution envelope Agent fields invalid")
                normalized_spec = managed_execution_spec(
                    kind=execution_kind,
                    agent_path=launch_argv[5],
                    prompt=launch_argv[9],
                )
            else:
                preview_execution_id = _canonical_uuid(raw_envelope["preview_execution_id"])
                raw_checkpoint = raw_envelope["checkpoint_revision"]
                if (
                    not isinstance(raw_checkpoint, str)
                    or _FULL_GIT_SHA.fullmatch(raw_checkpoint) is None
                ):
                    raise ValueError("execution envelope Preview fields invalid")
                checkpoint_revision = raw_checkpoint
                normalized_spec = production_run_execution_spec(
                    {
                        "change_set_id": raw_envelope["change_set_id"],
                        "execution": {
                            "checkpoint_revision": checkpoint_revision,
                            "kind": execution_kind,
                            "preview_execution_id": str(preview_execution_id),
                            "profile": "static_web_v1",
                        },
                    }
                )
            if (
                tuple(launch_argv) != normalized_spec.launch_argv
                or execution_spec_hash != normalized_spec.spec_hash
            ):
                raise ValueError("execution envelope launch specification invalid")
            envelope = RunnerExecutionEnvelope(
                change_set_id=_canonical_uuid(raw_envelope["change_set_id"]),
                tenant_id=_canonical_uuid(raw_envelope["tenant_id"]),
                space_id=_canonical_uuid(raw_envelope["space_id"]),
                project_id=_canonical_uuid(raw_envelope["project_id"]),
                run_id=_canonical_uuid(raw_envelope["run_id"]),
                runner_id=_canonical_uuid(raw_envelope["runner_id"]),
                fence_token=_positive_integer(raw_envelope["fence_token"]),
                execution_profile_id=_canonical_uuid(raw_envelope["execution_profile_id"]),
                execution_profile_hash=profile_hash,
                egress_policy_id=_canonical_uuid(raw_envelope["egress_policy_id"]),
                egress_policy_hash=egress_hash,
                product_revision=product_revision,
                image_digest=image_digest,
                execution_spec_hash=execution_spec_hash,
                launch_argv=normalized_spec.launch_argv,
                execution_kind=execution_kind,
                preview_execution_id=preview_execution_id,
                checkpoint_revision=checkpoint_revision,
            )
            run_id = _canonical_uuid(value["run_id"])
            fence_token = _positive_integer(value["fence_token"])
            if (
                envelope.run_id != run_id
                or envelope.runner_id.int == 0
                or envelope.fence_token != fence_token
            ):
                raise ValueError("execution envelope lease binding invalid")
            return RunnerControlClientLease(
                run_id=run_id,
                lease_token=_canonical_uuid(value["lease_token"]),
                fence_token=fence_token,
                dispatch_generation=_positive_integer(value["dispatch_generation"]),
                failure_domain=failure_domain,
                expires_at=expiry.astimezone(timezone.utc),
                capability_id=_canonical_uuid(value["capability_id"]),
                capability_token=_secret(value["capability_token"]),
                execution_envelope=envelope,
            )
        except (ManagedRunExecutionSpecError, TypeError, ValueError) as error:
            raise RunnerControlError(
                "runner_control_response_invalid", "Runner control response is invalid"
            ) from error

    async def mint_preview_tunnel(self) -> RunnerPreviewTunnelRegistration:
        """Mint a fresh one-use registration for each official WS reconnect."""

        response = await self._request("mint_preview_tunnel", {})
        if set(response) != {"preview_tunnel", "version"}:
            raise RunnerControlError(
                "runner_control_response_invalid", "Runner control response is invalid"
            )
        value = response["preview_tunnel"]
        try:
            if not isinstance(value, dict) or set(value) != {
                "audience",
                "connection_generation",
                "endpoint_host",
                "endpoint_port",
                "expires_at",
                "official_runner_id",
                "registration_id",
                "registration_token",
                "runner_id",
                "server_name",
            }:
                raise ValueError("Preview tunnel response fields invalid")
            token = _secret(value["registration_token"])
            official_runner_id = value["official_runner_id"]
            endpoint_host = value["endpoint_host"]
            server_name = value["server_name"]
            audience = value["audience"]
            port = _positive_integer(value["endpoint_port"])
            generation = _positive_integer(value["connection_generation"])
            expires_at = datetime.fromisoformat(cast(str, value["expires_at"]))
            if (
                not isinstance(official_runner_id, str)
                or token_bound_runner_id(token) != official_runner_id
                or not isinstance(endpoint_host, str)
                or _INTERNAL_HOST.fullmatch(endpoint_host) is None
                or not isinstance(server_name, str)
                or _INTERNAL_HOST.fullmatch(server_name) is None
                or not isinstance(audience, str)
                or audience != server_name
                or port > 65_535
                or expires_at.tzinfo is None
                or expires_at <= datetime.now(timezone.utc)
            ):
                raise ValueError("Preview tunnel response binding invalid")
            return RunnerPreviewTunnelRegistration(
                registration_id=_canonical_uuid(value["registration_id"]),
                runner_id=_canonical_uuid(value["runner_id"]),
                connection_generation=generation,
                official_runner_id=official_runner_id,
                endpoint_host=endpoint_host,
                endpoint_port=port,
                server_name=server_name,
                audience=audience,
                registration_token=token,
                expires_at=expires_at.astimezone(timezone.utc),
            )
        except (TypeError, ValueError) as error:
            raise RunnerControlError(
                "runner_control_response_invalid", "Runner control response is invalid"
            ) from error

    def _run_values(self, lease: RunnerControlClientLease) -> dict[str, object]:
        return {
            "capability_token": lease.capability_token,
            "fence_token": lease.fence_token,
            "lease_token": str(lease.lease_token),
            "run_id": str(lease.run_id),
        }

    async def heartbeat_run(self, lease: RunnerControlClientLease) -> dict[str, object]:
        response = await self._request("heartbeat_run", self._run_values(lease))
        required = {"expires_at", "fence_token", "run_id", "run_version", "status", "version"}
        if set(response) != required or response["run_id"] != str(lease.run_id):
            raise RunnerControlError(
                "runner_control_response_invalid", "Runner control response is invalid"
            )
        return response

    async def transition_run(
        self,
        lease: RunnerControlClientLease,
        *,
        target_status: str,
    ) -> dict[str, object]:
        response = await self._request(
            "transition_run", {**self._run_values(lease), "target_status": target_status}
        )
        required = {"event_sequence", "run_id", "run_version", "status", "version"}
        if (
            set(response) != required
            or response["run_id"] != str(lease.run_id)
            or response["status"] != target_status
        ):
            raise RunnerControlError(
                "runner_control_response_invalid", "Runner control response is invalid"
            )
        return response

    async def release_run(self, lease: RunnerControlClientLease) -> bool:
        response = await self._request(
            "release_run",
            {"fence_token": lease.fence_token, "run_id": str(lease.run_id)},
        )
        if set(response) != {"replayed", "version"} or not isinstance(response["replayed"], bool):
            raise RunnerControlError(
                "runner_control_response_invalid", "Runner control response is invalid"
            )
        return cast(bool, response["replayed"])


@dataclass(frozen=True, slots=True)
class ProductionRunnerControlConfig:
    product_revision: str
    image_digest: str
    official_schema_revision: str
    control_plane_schema_revision: str
    adapter_contract_version: str
    executor_database_url: str = field(repr=False)
    service_role_bindings: ProductionServiceRoleBindings = field(repr=False)
    migration_receipt: ProductionMigrationReceipt
    certificate_authorizer_factory: str
    trust_bundle_version: str
    ca_certificate_path: Path
    server_certificate_path: Path
    server_key_path: Path = field(repr=False)
    bind_host: str
    bind_port: int
    readiness_port: int
    lease_seconds: int
    heartbeat_timeout_seconds: int
    request_timeout_seconds: float
    preview_tunnel_endpoint_policy: PreviewRelayEndpointPolicy
    preview_tunnel_port: int


def _required(source: Mapping[str, str], name: str) -> str:
    value = source.get(name)
    if value is None or not value.strip() or value != value.strip() or "\x00" in value:
        raise RunnerControlError("runner_control_config_invalid", f"{name} is invalid")
    return value


def _revision(source: Mapping[str, str], name: str) -> str:
    value = _required(source, name)
    if _REVISION.fullmatch(value) is None:
        raise RunnerControlError("runner_control_config_invalid", f"{name} is invalid")
    return value


def _integer(
    source: Mapping[str, str], name: str, *, default: int, minimum: int, maximum: int
) -> int:
    raw = source.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as error:
        raise RunnerControlError("runner_control_config_invalid", f"{name} is invalid") from error
    if not minimum <= value <= maximum:
        raise RunnerControlError("runner_control_config_invalid", f"{name} is invalid")
    return value


def _csv(source: Mapping[str, str], name: str) -> tuple[str, ...]:
    raw = source.get(name, "")
    values = tuple(value.strip() for value in raw.split(","))
    if (
        not raw
        or any(not value or "\x00" in value for value in values)
        or len(values) != len(set(values))
    ):
        raise RunnerControlError("runner_control_config_invalid", f"{name} is invalid")
    return values


def _preview_endpoint_policy(
    source: Mapping[str, str],
) -> PreviewRelayEndpointPolicy:
    try:
        ports = tuple(
            int(value) for value in _csv(source, "OMNIGENT_SAAS_PREVIEW_RELAY_ALLOWED_PORTS")
        )
        return PreviewRelayEndpointPolicy.from_strings(
            allowed_dns_suffixes=_csv(source, "OMNIGENT_SAAS_PREVIEW_RELAY_ALLOWED_DNS_SUFFIXES"),
            allowed_cidrs=_csv(source, "OMNIGENT_SAAS_PREVIEW_RELAY_ALLOWED_CIDRS"),
            allowed_ports=ports,
        )
    except (TypeError, ValueError) as error:
        raise RunnerControlError(
            "runner_control_config_invalid", "Preview tunnel endpoint policy is invalid"
        ) from error


def _secure_file(source: Mapping[str, str], name: str, *, secret: bool) -> Path:
    path = Path(_required(source, name))
    if not path.is_absolute():
        raise RunnerControlError("runner_control_config_invalid", f"{name} is invalid")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise RunnerControlError("runner_control_config_invalid", f"{name} is invalid") from error
    forbidden = 0o077 if secret else 0o022
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & forbidden
        or not 1 <= metadata.st_size <= 1_048_576
    ):
        raise RunnerControlError("runner_control_config_invalid", f"{name} is invalid")
    return path


def load_production_runner_control_config(
    environ: Mapping[str, str] | None = None,
) -> ProductionRunnerControlConfig:
    source: Mapping[str, str] = os.environ if environ is None else environ
    if any(source.get(name, "").strip() for name in _FORBIDDEN_DATABASE_ENVIRONMENTS):
        raise RunnerControlError(
            "runner_control_config_invalid",
            "Runner control must not receive ambient, owner, server, or dispatcher DSNs",
        )
    product_revision = _required(source, "OMNIGENT_SAAS_PRODUCT_REVISION")
    source_sha = _required(source, "OMNIGENT_SAAS_SOURCE_SHA")
    image_digest = _required(source, "OMNIGENT_SAAS_IMAGE_DIGEST")
    if (
        _FULL_GIT_SHA.fullmatch(product_revision) is None
        or _FULL_GIT_SHA.fullmatch(source_sha) is None
        or product_revision != source_sha
        or _IMAGE_DIGEST.fullmatch(image_digest) is None
    ):
        raise RunnerControlError(
            "runner_control_config_invalid", "Runner control release identity is invalid"
        )
    official_head = _revision(source, "OMNIGENT_SAAS_OFFICIAL_SCHEMA_REVISION")
    saas_head = _revision(source, "OMNIGENT_SAAS_CONTROL_PLANE_SCHEMA_REVISION")
    try:
        bindings = load_production_service_role_bindings(source)
        database_url, parsed, _path = load_production_database_url_file(source, "executor")
        receipt = load_production_migration_receipt(
            source,
            product_revision=product_revision,
            official_head=official_head,
            saas_head=saas_head,
            service_role_bindings_sha256=bindings.sha256,
        )
    except (ProductionServerConfigError, ProductionServiceRoleBindingsError) as error:
        raise RunnerControlError("runner_control_config_invalid", str(error)) from error
    if parsed.username != bindings.login_for("executor"):
        raise RunnerControlError(
            "runner_control_config_invalid",
            "Runner control executor login does not match service-role bindings",
        )
    factory = _required(source, "OMNIGENT_SAAS_RUNNER_CONTROL_CERTIFICATE_AUTHORIZER_FACTORY")
    if _FACTORY_REFERENCE.fullmatch(factory) is None or any(
        part.startswith("_") for part in factory.replace(":", ".").split(".")
    ):
        raise RunnerControlError(
            "runner_control_config_invalid", "Runner control authorizer factory is invalid"
        )
    bind_host = _required(source, "OMNIGENT_SAAS_RUNNER_CONTROL_BIND_HOST")
    if bind_host not in {"0.0.0.0", "::"} and _INTERNAL_HOST.fullmatch(bind_host.lower()) is None:
        raise RunnerControlError(
            "runner_control_config_invalid", "Runner control bind host is invalid"
        )
    lease_seconds = _integer(
        source, "OMNIGENT_SAAS_RUNNER_CONTROL_LEASE_SECONDS", default=45, minimum=5, maximum=300
    )
    heartbeat_timeout = _integer(
        source,
        "OMNIGENT_SAAS_RUNNER_CONTROL_HEARTBEAT_TIMEOUT_SECONDS",
        default=30,
        minimum=5,
        maximum=299,
    )
    if heartbeat_timeout >= lease_seconds:
        raise RunnerControlError(
            "runner_control_config_invalid", "Runner control heartbeat must be below lease TTL"
        )
    bind_port = _integer(
        source,
        "OMNIGENT_SAAS_RUNNER_CONTROL_BIND_PORT",
        default=9444,
        minimum=1,
        maximum=65535,
    )
    readiness_port = _integer(
        source,
        "OMNIGENT_SAAS_RUNNER_CONTROL_READINESS_PORT",
        default=9445,
        minimum=1,
        maximum=65535,
    )
    if readiness_port == bind_port:
        raise RunnerControlError(
            "runner_control_config_invalid",
            "Runner control and readiness ports must be distinct",
        )
    preview_tunnel_port = _integer(
        source,
        "OMNIGENT_SAAS_PREVIEW_RUNNER_TUNNEL_PORT",
        default=9442,
        minimum=1,
        maximum=65535,
    )
    preview_endpoint_policy = _preview_endpoint_policy(source)
    try:
        preview_endpoint_policy.require_allowed_port(preview_tunnel_port)
    except RuntimeError as error:
        raise RunnerControlError(
            "runner_control_config_invalid", "Preview tunnel port is not allowed"
        ) from error
    if preview_tunnel_port in {bind_port, readiness_port}:
        raise RunnerControlError(
            "runner_control_config_invalid", "Runner control ports must be distinct"
        )
    return ProductionRunnerControlConfig(
        product_revision=product_revision,
        image_digest=image_digest,
        official_schema_revision=official_head,
        control_plane_schema_revision=saas_head,
        adapter_contract_version=_revision(source, "OMNIGENT_SAAS_ADAPTER_CONTRACT_VERSION"),
        executor_database_url=database_url,
        service_role_bindings=bindings,
        migration_receipt=receipt,
        certificate_authorizer_factory=factory,
        trust_bundle_version=_revision(
            source, "OMNIGENT_SAAS_RUNNER_CONTROL_TRUST_BUNDLE_VERSION"
        ),
        ca_certificate_path=_secure_file(
            source, "OMNIGENT_SAAS_RUNNER_CONTROL_CA_CERTIFICATE_FILE", secret=False
        ),
        server_certificate_path=_secure_file(
            source, "OMNIGENT_SAAS_RUNNER_CONTROL_SERVER_CERTIFICATE_FILE", secret=False
        ),
        server_key_path=_secure_file(
            source, "OMNIGENT_SAAS_RUNNER_CONTROL_SERVER_KEY_FILE", secret=True
        ),
        bind_host=bind_host,
        bind_port=bind_port,
        readiness_port=readiness_port,
        lease_seconds=lease_seconds,
        heartbeat_timeout_seconds=heartbeat_timeout,
        request_timeout_seconds=float(
            _integer(
                source,
                "OMNIGENT_SAAS_RUNNER_CONTROL_REQUEST_TIMEOUT_SECONDS",
                default=5,
                minimum=1,
                maximum=60,
            )
        ),
        preview_tunnel_endpoint_policy=preview_endpoint_policy,
        preview_tunnel_port=preview_tunnel_port,
    )


def verify_installed_runner_control_lineage(
    config: ProductionRunnerControlConfig,
) -> None:
    """Bind Runner control to the wheel/image commit before opening PostgreSQL."""

    try:
        from omnigent import _build_info

        installed_revision = _build_info.COMMIT_SHA
    except (AttributeError, ImportError) as error:
        raise RunnerControlError(
            "runner_control_config_invalid",
            "installed build revision is unavailable",
        ) from error
    if installed_revision != config.product_revision:
        raise RunnerControlError(
            "runner_control_config_invalid",
            "installed build revision does not match Runner control release identity",
        )


def _call_factory(
    factory: Callable[..., object],
    config: ProductionRunnerControlConfig,
    session_factory: sessionmaker[Session] | None,
) -> object:
    signature = inspect.signature(factory)
    parameters = signature.parameters
    accepts_keywords = any(
        parameter.kind == inspect.Parameter.VAR_KEYWORD for parameter in parameters.values()
    )
    keyword_arguments: dict[str, object] = {}
    if "config" in parameters or accepts_keywords:
        keyword_arguments["config"] = config
    if "session_factory" in parameters or accepts_keywords:
        if session_factory is None:
            raise RunnerControlError(
                "runner_control_config_invalid",
                "Runner control authorizer requires a database authority",
            )
        keyword_arguments["session_factory"] = session_factory
    if keyword_arguments:
        return factory(**keyword_arguments)
    required = [
        parameter
        for parameter in parameters.values()
        if parameter.default is inspect.Parameter.empty
        and parameter.kind
        in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    if required:
        raise RunnerControlError(
            "runner_control_config_invalid", "Runner control authorizer factory is invalid"
        )
    return factory()


def build_durable_runner_control_certificate_authorizer(
    *,
    config: ProductionRunnerControlConfig,
    session_factory: sessionmaker[Session],
) -> DurableRunnerControlCertificateAuthorizer:
    """Build the production authorizer over the existing executor transaction pool."""

    return DurableRunnerControlCertificateAuthorizer(
        RunnerCertificateAuthority(
            session_factory,
            accepted_trust_bundle_versions=(config.trust_bundle_version,),
        )
    )


def load_runner_machine_certificate_authorizer(
    config: ProductionRunnerControlConfig,
    *,
    session_factory: sessionmaker[Session] | None = None,
) -> RunnerMachineCertificateAuthorizer:
    module_name, attribute = config.certificate_authorizer_factory.split(":", 1)
    try:
        candidate = getattr(importlib.import_module(module_name), attribute)
        value = (
            _call_factory(candidate, config, session_factory) if callable(candidate) else candidate
        )
    except Exception as error:
        raise RunnerControlError(
            "runner_control_config_invalid", "Runner control authorizer cannot be loaded"
        ) from error
    if not callable(getattr(value, "is_runner_machine_certificate_authorized", None)):
        raise RunnerControlError(
            "runner_control_config_invalid", "Runner control authorizer is incomplete"
        )
    return cast(RunnerMachineCertificateAuthorizer, value)


def build_server_tls_context(config: ProductionRunnerControlConfig) -> ssl.SSLContext:
    context = ssl.create_default_context(
        ssl.Purpose.CLIENT_AUTH, cafile=str(config.ca_certificate_path)
    )
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(
        certfile=str(config.server_certificate_path), keyfile=str(config.server_key_path)
    )
    return context


def build_readiness_server_tls_context(
    config: ProductionRunnerControlConfig,
) -> ssl.SSLContext:
    """Build server-auth-only TLS for the content-blind readiness listener."""

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(
        certfile=str(config.server_certificate_path), keyfile=str(config.server_key_path)
    )
    return context


async def _run(config: ProductionRunnerControlConfig) -> None:
    engine: Engine = sa.create_engine(config.executor_database_url, pool_pre_ping=True)
    try:
        if engine.dialect.name != "postgresql":
            raise RunnerControlError(
                "runner_control_config_invalid", "Runner control requires PostgreSQL"
            )
        verify_onboarding_database_authority(engine, authority="execution")
        factory = sessionmaker(engine, expire_on_commit=False, class_=Session)
        domain = ProductionRunnerMachineAuthority(
            SchedulingControlPlane(factory),
            ExecutionControlPlane(factory),
            policy=RunnerControlPolicy(
                lease_duration=timedelta(seconds=config.lease_seconds),
                heartbeat_timeout=timedelta(seconds=config.heartbeat_timeout_seconds),
            ),
            product_revision=config.product_revision,
            image_digest=config.image_digest,
            preview_tunnel_issuer=PreviewTunnelRegistrationIssuer(
                factory,
                endpoint_policy=config.preview_tunnel_endpoint_policy,
                runner_tunnel_port=config.preview_tunnel_port,
            ),
        )
        server = MutualTlsRunnerControlServer(
            domain,
            build_server_tls_context(config),
            load_runner_machine_certificate_authorizer(config, session_factory=factory),
            request_timeout_seconds=config.request_timeout_seconds,
        )
        readiness = TlsRunnerControlReadinessServer(
            build_readiness_server_tls_context(config),
            lambda: assert_postgresql_runner_fleet_ready(
                engine,
                product_revision=config.product_revision,
                official_schema_revision=config.official_schema_revision,
                adapter_contract_version=config.adapter_contract_version,
            ),
        )
        await server.start(host=config.bind_host, port=config.bind_port)
        try:
            await readiness.start(host=config.bind_host, port=config.readiness_port)
        except Exception:
            await server.aclose()
            raise
        stopped = asyncio.Event()
        loop = asyncio.get_running_loop()
        for value in (signal.SIGTERM, signal.SIGINT):
            with suppress(NotImplementedError):
                loop.add_signal_handler(value, stopped.set)
        try:
            await stopped.wait()
        finally:
            await readiness.aclose()
            await server.aclose()
    finally:
        engine.dispose()


def main(_argv: Sequence[str] | None = None) -> int:
    """Fail closed before socket bind when release, PKI, or DB authority is absent."""

    config = load_production_runner_control_config()
    verify_installed_runner_control_lineage(config)
    asyncio.run(_run(config))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "DurableRunnerControlCertificateAuthorizer",
    "MutualTlsRunnerControlClient",
    "MutualTlsRunnerControlServer",
    "ProductionRunnerControlConfig",
    "ProductionRunnerMachineAuthority",
    "RunnerControlClientLease",
    "RunnerControlError",
    "RunnerControlPolicy",
    "RunnerMachineCertificateAuthorizer",
    "TlsRunnerControlReadinessServer",
    "build_durable_runner_control_certificate_authorizer",
    "build_readiness_server_tls_context",
    "build_server_tls_context",
    "load_production_runner_control_config",
    "load_runner_machine_certificate_authorizer",
    "main",
    "runner_identity_from_certificate",
    "verify_installed_runner_control_lineage",
]
