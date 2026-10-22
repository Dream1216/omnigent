"""Production composition loop for lease-fenced Privacy execution."""

from __future__ import annotations

import importlib
import logging
import os
import signal
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal, Protocol, cast
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.platform_security import PlatformSecurityError
from saas.control_plane.privacy_attestation import PrivacyDsseEnvelope
from saas.control_plane.privacy_execution import (
    PRIVACY_EXECUTION_ERROR_CODES,
    ClaimedPrivacyBackupItem,
    ClaimedPrivacyWorkItem,
    PrivacyBackupCatalogEntry,
    PrivacyDestructiveAuthorization,
    PrivacyEvidenceOutcome,
    PrivacyExecutionCompletion,
    PrivacyExecutionFailure,
    PrivacyExecutionService,
    PrivacyTargetType,
    WorkloadIdentity,
)

_LOGGER = logging.getLogger("omnigent-saas-privacy")
_MISSING_SURFACE_ADAPTER = "privacy surface adapter is not registered"
_MISSING_BACKUP_ADAPTER = "privacy Backup adapter is not registered"
_INVALID_ADAPTER_RESULT = "privacy adapter returned an invalid result"
_UNCLASSIFIED_ADAPTER_FAILURE = "privacy adapter raised an unclassified exception"
_INVALID_SIGNER_RESULT = "privacy evidence signer returned an invalid envelope"
_UNCLASSIFIED_SIGNER_FAILURE = "privacy evidence signer raised an unclassified exception"
_INVALID_DEPENDENCY_CODE = "privacy dependency returned an unsupported error code"

PrivacyWorkKind = Literal["surface", "backup"]
PrivacyWorkerStatus = Literal[
    "no_work",
    "succeeded",
    "purged",
    "retry",
    "dead_letter",
    "lease_lost",
    "blocked",
]


@dataclass(frozen=True, slots=True)
class PrivacyExecutionScope:
    """Content-blind queue directive identifying one exact RLS claim scope."""

    kind: PrivacyWorkKind
    target_type: PrivacyTargetType
    target_id: UUID
    manifest_id: UUID


@dataclass(frozen=True, slots=True)
class PrivacySurfaceAdapterResult:
    """Signed-observation inputs returned after a surface adapter call."""

    outcome: PrivacyEvidenceOutcome
    backup_catalog: tuple[PrivacyBackupCatalogEntry, ...] = ()


@dataclass(frozen=True, slots=True)
class PrivacyBackupAdapterResult:
    """Opaque evidence digest returned after a provider Backup purge."""

    evidence_sha256: str


class PrivacyDependencyError(RuntimeError):
    """Allowlisted failure whose raw detail is hash-only input, never log text."""

    def __init__(self, error_code: str, raw_error: str) -> None:
        self.error_code = error_code
        self._raw_error = raw_error
        super().__init__(error_code)

    @property
    def raw_error(self) -> str:
        return self._raw_error

    def __repr__(self) -> str:
        return f"{type(self).__name__}(error_code={self.error_code!r})"


class PrivacyWorkloadIdentityProvider(Protocol):
    """Verify and return the dedicated machine identity for one claim."""

    def identity(self, *, now: datetime) -> WorkloadIdentity: ...


class PrivacyExecutionScopeProvider(Protocol):
    """Return one queue-delivered exact scope, or ``None`` when idle."""

    def next_scope(self) -> PrivacyExecutionScope | None: ...


class PrivacySurfaceAdapter(Protocol):
    """Execute one idempotent deletion before the authorization deadline."""

    def execute(
        self,
        *,
        claim: ClaimedPrivacyWorkItem,
        identity: WorkloadIdentity,
        authorization: PrivacyDestructiveAuthorization,
    ) -> PrivacySurfaceAdapterResult: ...


class PrivacyBackupAdapter(Protocol):
    """Purge one due Backup before the authorization deadline."""

    def execute(
        self,
        *,
        claim: ClaimedPrivacyBackupItem,
        identity: WorkloadIdentity,
        authorization: PrivacyDestructiveAuthorization,
    ) -> PrivacyBackupAdapterResult: ...


class PrivacyAdapterRegistry(Protocol):
    """Resolve configured adapters without supplying fallback implementations."""

    def surface_adapter(self, adapter_type: str) -> PrivacySurfaceAdapter | None: ...

    def backup_adapter(self, provider: str) -> PrivacyBackupAdapter | None: ...


class PrivacyEvidenceSigner(Protocol):
    """Issue externally backed DSSE evidence and immutable-storage receipts."""

    def sign_surface(
        self,
        *,
        identity: WorkloadIdentity,
        claim: ClaimedPrivacyWorkItem,
        result: PrivacySurfaceAdapterResult,
        observed_at: datetime,
    ) -> PrivacyDsseEnvelope: ...

    def sign_backup(
        self,
        *,
        identity: WorkloadIdentity,
        claim: ClaimedPrivacyBackupItem,
        result: PrivacyBackupAdapterResult,
        observed_at: datetime,
    ) -> PrivacyDsseEnvelope: ...


class _PrivacyExecutionAuthority(Protocol):
    def claim_work_item(
        self,
        identity: WorkloadIdentity,
        *,
        target_type: PrivacyTargetType,
        target_id: UUID,
        manifest_id: UUID,
        now: datetime | None = None,
    ) -> ClaimedPrivacyWorkItem | None: ...

    def claim_backup_item(
        self,
        identity: WorkloadIdentity,
        *,
        target_type: PrivacyTargetType,
        target_id: UUID,
        manifest_id: UUID,
        now: datetime | None = None,
    ) -> ClaimedPrivacyBackupItem | None: ...

    def authorize_destructive_execution(
        self,
        identity: WorkloadIdentity,
        claim: ClaimedPrivacyWorkItem | ClaimedPrivacyBackupItem,
        *,
        now: datetime | None = None,
    ) -> PrivacyDestructiveAuthorization: ...

    def complete_work_item(
        self,
        identity: WorkloadIdentity,
        claim: ClaimedPrivacyWorkItem,
        *,
        outcome: PrivacyEvidenceOutcome,
        envelope: PrivacyDsseEnvelope,
        backup_catalog: tuple[PrivacyBackupCatalogEntry, ...] = (),
        now: datetime | None = None,
    ) -> PrivacyExecutionCompletion: ...

    def fail_work_item(
        self,
        identity: WorkloadIdentity,
        claim: ClaimedPrivacyWorkItem,
        *,
        error_code: str,
        raw_error: str,
        now: datetime | None = None,
    ) -> PrivacyExecutionFailure: ...

    def complete_backup_item(
        self,
        identity: WorkloadIdentity,
        claim: ClaimedPrivacyBackupItem,
        *,
        evidence_sha256: str,
        envelope: PrivacyDsseEnvelope,
        now: datetime | None = None,
    ) -> PrivacyExecutionCompletion: ...

    def fail_backup_item(
        self,
        identity: WorkloadIdentity,
        claim: ClaimedPrivacyBackupItem,
        *,
        error_code: str,
        raw_error: str,
        now: datetime | None = None,
    ) -> PrivacyExecutionFailure: ...


class _StopSignal(Protocol):
    def is_set(self) -> bool: ...

    def wait(self, timeout: float | None = None) -> bool: ...


@dataclass(frozen=True, slots=True)
class PrivacyWorkerCycleResult:
    kind: PrivacyWorkKind
    status: PrivacyWorkerStatus
    claimed: bool


@dataclass(frozen=True, slots=True)
class PrivacyWorkerStats:
    cycles: int
    scopes: int
    claimed: int
    succeeded: int
    retries: int
    dead_lettered: int
    lease_lost: int
    blocked: int
    infrastructure_failures: int


class PrivacyWorker:
    """Run bounded Privacy work while keeping network calls outside DB locks."""

    def __init__(
        self,
        authority: _PrivacyExecutionAuthority,
        *,
        identity_provider: PrivacyWorkloadIdentityProvider,
        scope_provider: PrivacyExecutionScopeProvider,
        adapter_registry: PrivacyAdapterRegistry,
        evidence_signer: PrivacyEvidenceSigner,
        idle_interval: float = 0.5,
        error_backoff: float = 1.0,
        max_error_backoff: float = 30.0,
        clock: Callable[[], datetime] | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        if min(idle_interval, error_backoff, max_error_backoff) <= 0:
            raise ValueError("Privacy worker intervals must be positive")
        if max_error_backoff < error_backoff:
            raise ValueError("Privacy maximum backoff must not be smaller than initial backoff")
        self._authority = authority
        self._identity_provider = identity_provider
        self._scope_provider = scope_provider
        self._adapter_registry = adapter_registry
        self._evidence_signer = evidence_signer
        self._idle_interval = idle_interval
        self._error_backoff = error_backoff
        self._max_error_backoff = max_error_backoff
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._logger = logger or _LOGGER

    def run_once(
        self,
        scope: PrivacyExecutionScope,
        *,
        now: datetime | None = None,
    ) -> PrivacyWorkerCycleResult:
        """Claim and settle at most one exact-scope surface or Backup item."""

        claimed_at = self._time(now)
        identity = self._identity_provider.identity(now=claimed_at)
        if scope.kind == "surface":
            return self._run_surface(scope, identity, fixed_now=now)
        if scope.kind == "backup":
            return self._run_backup(scope, identity, fixed_now=now)
        raise ValueError("Privacy scope kind is invalid")

    def run(self, stop: _StopSignal) -> PrivacyWorkerStats:
        """Poll content-blind scopes until stopped, with bounded error backoff."""

        counters = {
            "cycles": 0,
            "scopes": 0,
            "claimed": 0,
            "succeeded": 0,
            "retries": 0,
            "dead_lettered": 0,
            "lease_lost": 0,
            "blocked": 0,
            "infrastructure_failures": 0,
        }
        consecutive_errors = 0
        while not stop.is_set():
            try:
                scope = self._scope_provider.next_scope()
                if scope is None:
                    counters["cycles"] += 1
                    delay = self._idle_interval
                else:
                    counters["scopes"] += 1
                    result = self.run_once(scope)
                    counters["cycles"] += 1
                    counters["claimed"] += int(result.claimed)
                    if result.status in ("succeeded", "purged"):
                        counters["succeeded"] += 1
                    elif result.status == "retry":
                        counters["retries"] += 1
                    elif result.status == "dead_letter":
                        counters["dead_lettered"] += 1
                    elif result.status == "lease_lost":
                        counters["lease_lost"] += 1
                    elif result.status == "blocked":
                        counters["blocked"] += 1
                    delay = 0.0 if result.claimed else self._idle_interval
                consecutive_errors = 0
            except Exception as error:  # noqa: BLE001 - process boundary must survive faults
                counters["infrastructure_failures"] += 1
                consecutive_errors += 1
                delay = min(
                    self._max_error_backoff,
                    self._error_backoff * (2 ** min(consecutive_errors - 1, 10)),
                )
                self._logger.error(
                    "Privacy worker cycle failed (%s); retrying in %.3fs",
                    type(error).__name__,
                    delay,
                )
            if delay > 0 and stop.wait(delay):
                break
        return PrivacyWorkerStats(**counters)

    def _run_surface(
        self,
        scope: PrivacyExecutionScope,
        identity: WorkloadIdentity,
        *,
        fixed_now: datetime | None,
    ) -> PrivacyWorkerCycleResult:
        claim = self._authority.claim_work_item(
            identity,
            target_type=scope.target_type,
            target_id=scope.target_id,
            manifest_id=scope.manifest_id,
            now=self._time(fixed_now),
        )
        if claim is None:
            return PrivacyWorkerCycleResult(kind="surface", status="no_work", claimed=False)
        try:
            adapter = self._adapter_registry.surface_adapter(claim.adapter_type)
        except Exception:  # noqa: BLE001 - registry contract failures settle the lease
            return self._fail_surface(
                identity,
                claim,
                error_code="privacy_adapter_contract_invalid",
                raw_error=_UNCLASSIFIED_ADAPTER_FAILURE,
                fixed_now=fixed_now,
            )
        if adapter is None:
            return self._fail_surface(
                identity,
                claim,
                error_code="privacy_adapter_contract_invalid",
                raw_error=_MISSING_SURFACE_ADAPTER,
                fixed_now=fixed_now,
            )
        try:
            authorization = self._authority.authorize_destructive_execution(
                identity,
                claim,
                now=self._time(fixed_now),
            )
        except PlatformSecurityError as error:
            return self._authorization_error(
                error,
                identity=identity,
                claim=claim,
                fixed_now=fixed_now,
            )
        try:
            result = adapter.execute(
                claim=claim,
                identity=identity,
                authorization=authorization,
            )
        except PrivacyDependencyError as error:
            code, raw_error = self._dependency_failure(error)
            return self._fail_surface(
                identity,
                claim,
                error_code=code,
                raw_error=raw_error,
                fixed_now=fixed_now,
            )
        except Exception:  # noqa: BLE001 - adapter faults are normalized content-blind
            return self._fail_surface(
                identity,
                claim,
                error_code="privacy_adapter_contract_invalid",
                raw_error=_UNCLASSIFIED_ADAPTER_FAILURE,
                fixed_now=fixed_now,
            )
        if not isinstance(result, PrivacySurfaceAdapterResult):
            return self._fail_surface(
                identity,
                claim,
                error_code="privacy_adapter_contract_invalid",
                raw_error=_INVALID_ADAPTER_RESULT,
                fixed_now=fixed_now,
            )
        try:
            envelope = self._evidence_signer.sign_surface(
                identity=identity,
                claim=claim,
                result=result,
                observed_at=self._time(fixed_now),
            )
        except PrivacyDependencyError as error:
            code, raw_error = self._dependency_failure(error)
            return self._fail_surface(
                identity,
                claim,
                error_code=code,
                raw_error=raw_error,
                fixed_now=fixed_now,
            )
        except Exception:  # noqa: BLE001 - signer faults are normalized content-blind
            return self._fail_surface(
                identity,
                claim,
                error_code="privacy_evidence_rejected",
                raw_error=_UNCLASSIFIED_SIGNER_FAILURE,
                fixed_now=fixed_now,
            )
        if not isinstance(envelope, PrivacyDsseEnvelope):
            return self._fail_surface(
                identity,
                claim,
                error_code="privacy_evidence_rejected",
                raw_error=_INVALID_SIGNER_RESULT,
                fixed_now=fixed_now,
            )
        try:
            completion = self._authority.complete_work_item(
                identity,
                claim,
                outcome=result.outcome,
                envelope=envelope,
                backup_catalog=result.backup_catalog,
                now=self._time(fixed_now),
            )
        except PlatformSecurityError as error:
            handled = self._completion_error(
                error,
                identity=identity,
                claim=claim,
                fixed_now=fixed_now,
            )
            if handled is not None:
                return handled
            raise
        return PrivacyWorkerCycleResult(kind="surface", status=completion.status, claimed=True)

    def _run_backup(
        self,
        scope: PrivacyExecutionScope,
        identity: WorkloadIdentity,
        *,
        fixed_now: datetime | None,
    ) -> PrivacyWorkerCycleResult:
        claim = self._authority.claim_backup_item(
            identity,
            target_type=scope.target_type,
            target_id=scope.target_id,
            manifest_id=scope.manifest_id,
            now=self._time(fixed_now),
        )
        if claim is None:
            return PrivacyWorkerCycleResult(kind="backup", status="no_work", claimed=False)
        try:
            adapter = self._adapter_registry.backup_adapter(claim.provider)
        except Exception:  # noqa: BLE001 - registry contract failures settle the lease
            return self._fail_backup(
                identity,
                claim,
                error_code="privacy_adapter_contract_invalid",
                raw_error=_UNCLASSIFIED_ADAPTER_FAILURE,
                fixed_now=fixed_now,
            )
        if adapter is None:
            return self._fail_backup(
                identity,
                claim,
                error_code="privacy_adapter_contract_invalid",
                raw_error=_MISSING_BACKUP_ADAPTER,
                fixed_now=fixed_now,
            )
        try:
            authorization = self._authority.authorize_destructive_execution(
                identity,
                claim,
                now=self._time(fixed_now),
            )
        except PlatformSecurityError as error:
            return self._authorization_error(
                error,
                identity=identity,
                claim=claim,
                fixed_now=fixed_now,
            )
        try:
            result = adapter.execute(
                claim=claim,
                identity=identity,
                authorization=authorization,
            )
        except PrivacyDependencyError as error:
            code, raw_error = self._dependency_failure(error)
            return self._fail_backup(
                identity,
                claim,
                error_code=code,
                raw_error=raw_error,
                fixed_now=fixed_now,
            )
        except Exception:  # noqa: BLE001 - adapter faults are normalized content-blind
            return self._fail_backup(
                identity,
                claim,
                error_code="privacy_adapter_contract_invalid",
                raw_error=_UNCLASSIFIED_ADAPTER_FAILURE,
                fixed_now=fixed_now,
            )
        if not isinstance(result, PrivacyBackupAdapterResult):
            return self._fail_backup(
                identity,
                claim,
                error_code="privacy_adapter_contract_invalid",
                raw_error=_INVALID_ADAPTER_RESULT,
                fixed_now=fixed_now,
            )
        try:
            envelope = self._evidence_signer.sign_backup(
                identity=identity,
                claim=claim,
                result=result,
                observed_at=self._time(fixed_now),
            )
        except PrivacyDependencyError as error:
            code, raw_error = self._dependency_failure(error)
            return self._fail_backup(
                identity,
                claim,
                error_code=code,
                raw_error=raw_error,
                fixed_now=fixed_now,
            )
        except Exception:  # noqa: BLE001 - signer faults are normalized content-blind
            return self._fail_backup(
                identity,
                claim,
                error_code="privacy_evidence_rejected",
                raw_error=_UNCLASSIFIED_SIGNER_FAILURE,
                fixed_now=fixed_now,
            )
        if not isinstance(envelope, PrivacyDsseEnvelope):
            return self._fail_backup(
                identity,
                claim,
                error_code="privacy_evidence_rejected",
                raw_error=_INVALID_SIGNER_RESULT,
                fixed_now=fixed_now,
            )
        try:
            completion = self._authority.complete_backup_item(
                identity,
                claim,
                evidence_sha256=result.evidence_sha256,
                envelope=envelope,
                now=self._time(fixed_now),
            )
        except PlatformSecurityError as error:
            handled = self._completion_error(
                error,
                identity=identity,
                claim=claim,
                fixed_now=fixed_now,
            )
            if handled is not None:
                return handled
            raise
        return PrivacyWorkerCycleResult(kind="backup", status=completion.status, claimed=True)

    def _authorization_error(
        self,
        error: PlatformSecurityError,
        *,
        identity: WorkloadIdentity,
        claim: ClaimedPrivacyWorkItem | ClaimedPrivacyBackupItem,
        fixed_now: datetime | None,
    ) -> PrivacyWorkerCycleResult:
        kind: PrivacyWorkKind = (
            "backup" if isinstance(claim, ClaimedPrivacyBackupItem) else "surface"
        )
        if error.code == "platform_privacy_execution_lease_lost":
            return PrivacyWorkerCycleResult(kind=kind, status="lease_lost", claimed=True)
        if error.code != "platform_privacy_execution_blocked":
            raise error
        if isinstance(claim, ClaimedPrivacyBackupItem):
            return self._fail_backup(
                identity,
                claim,
                error_code="privacy_resource_lock_pending",
                raw_error=error.code,
                fixed_now=fixed_now,
            )
        return self._fail_surface(
            identity,
            claim,
            error_code="privacy_resource_lock_pending",
            raw_error=error.code,
            fixed_now=fixed_now,
        )

    def _completion_error(
        self,
        error: PlatformSecurityError,
        *,
        identity: WorkloadIdentity,
        claim: ClaimedPrivacyWorkItem | ClaimedPrivacyBackupItem,
        fixed_now: datetime | None,
    ) -> PrivacyWorkerCycleResult | None:
        kind: PrivacyWorkKind = (
            "backup" if isinstance(claim, ClaimedPrivacyBackupItem) else "surface"
        )
        if error.code == "platform_privacy_execution_lease_lost":
            return PrivacyWorkerCycleResult(kind=kind, status="lease_lost", claimed=True)
        if error.code == "platform_privacy_execution_blocked":
            failure_code = "privacy_resource_lock_pending"
        elif error.code == "platform_privacy_backup_blocked" and kind == "backup":
            return PrivacyWorkerCycleResult(kind="backup", status="blocked", claimed=True)
        elif error.code == "platform_privacy_attestation_unavailable":
            failure_code = "privacy_temporary_dependency_failure"
        elif error.code in {
            "platform_privacy_attestation_invalid",
            "platform_privacy_backup_catalog_invalid",
            "platform_privacy_evidence_invalid",
        }:
            failure_code = "privacy_evidence_rejected"
        else:
            return None
        if isinstance(claim, ClaimedPrivacyBackupItem):
            return self._fail_backup(
                identity,
                claim,
                error_code=failure_code,
                raw_error=error.code,
                fixed_now=fixed_now,
            )
        return self._fail_surface(
            identity,
            claim,
            error_code=failure_code,
            raw_error=error.code,
            fixed_now=fixed_now,
        )

    def _fail_surface(
        self,
        identity: WorkloadIdentity,
        claim: ClaimedPrivacyWorkItem,
        *,
        error_code: str,
        raw_error: str,
        fixed_now: datetime | None,
    ) -> PrivacyWorkerCycleResult:
        failure = self._authority.fail_work_item(
            identity,
            claim,
            error_code=error_code,
            raw_error=raw_error,
            now=self._time(fixed_now),
        )
        if failure.status not in ("retry", "dead_letter"):
            raise RuntimeError("Privacy surface failure returned an invalid worker status")
        status = cast(Literal["retry", "dead_letter"], failure.status)
        return PrivacyWorkerCycleResult(kind="surface", status=status, claimed=True)

    def _fail_backup(
        self,
        identity: WorkloadIdentity,
        claim: ClaimedPrivacyBackupItem,
        *,
        error_code: str,
        raw_error: str,
        fixed_now: datetime | None,
    ) -> PrivacyWorkerCycleResult:
        failure = self._authority.fail_backup_item(
            identity,
            claim,
            error_code=error_code,
            raw_error=raw_error,
            now=self._time(fixed_now),
        )
        if failure.status not in ("retry", "dead_letter"):
            raise RuntimeError("Privacy Backup failure returned an invalid worker status")
        status = cast(Literal["retry", "dead_letter"], failure.status)
        return PrivacyWorkerCycleResult(kind="backup", status=status, claimed=True)

    @staticmethod
    def _dependency_failure(error: PrivacyDependencyError) -> tuple[str, str]:
        if error.error_code not in PRIVACY_EXECUTION_ERROR_CODES:
            return "privacy_adapter_contract_invalid", _INVALID_DEPENDENCY_CODE
        return error.error_code, error.raw_error

    def _time(self, fixed: datetime | None) -> datetime:
        value = fixed or self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Privacy worker clock must return a timezone-aware value")
        return value.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class PrivacyWorkerComponents:
    authority: PrivacyExecutionService
    identity_provider: PrivacyWorkloadIdentityProvider
    scope_provider: PrivacyExecutionScopeProvider
    adapter_registry: PrivacyAdapterRegistry
    evidence_signer: PrivacyEvidenceSigner


class PrivacyWorkerComponentFactory(Protocol):
    """Production integration point for real identity, adapters, verifier, and signer."""

    def build(
        self,
        *,
        dispatcher_engine: Engine,
        dispatcher_session_factory: sessionmaker[Session],
        verifier_engine: Engine,
        verifier_session_factory: sessionmaker[Session],
    ) -> PrivacyWorkerComponents: ...


PrivacyDatabaseAuthority = Literal["dispatcher", "verifier"]

_PRIVACY_ROLE_TABLE_PRIVILEGES: dict[PrivacyDatabaseAuthority, dict[str, frozenset[str]]] = {
    "dispatcher": {
        "SELECT": frozenset(
            {
                "saas_privacy_legal_holds",
                "saas_privacy_deletion_manifests",
                "saas_privacy_deletion_work_items",
                "saas_privacy_deletion_attempts",
                "saas_privacy_evidence_attestations",
                "saas_privacy_backup_retention_items",
            }
        ),
        "INSERT": frozenset(
            {
                "saas_privacy_deletion_attempts",
                "saas_privacy_backup_retention_items",
                "saas_control_plane_outbox",
            }
        ),
    },
    "verifier": {
        "SELECT": frozenset(
            {
                "saas_privacy_deletion_manifests",
                "saas_privacy_deletion_work_items",
                "saas_privacy_evidence_attestations",
                "saas_privacy_backup_retention_items",
                "saas_runtime_partitions",
            }
        ),
        "INSERT": frozenset({"saas_privacy_evidence_attestations"}),
    },
}

_PRIVACY_DISPATCHER_UPDATE_COLUMNS: dict[str, frozenset[str]] = {
    "saas_privacy_deletion_manifests": frozenset(
        {
            "status",
            "blockers",
            "surface_outcomes",
            "version",
            "retention_status",
            "retention_completed_at",
            "updated_at",
        }
    ),
    "saas_privacy_deletion_work_items": frozenset(
        {
            "status",
            "attempt_count",
            "available_at",
            "leased_at",
            "lease_expires_at",
            "lease_token_hash",
            "executor_identity_sha256",
            "lease_generation",
            "last_error_code",
            "last_error_sha256",
            "outcome_content_sha256",
            "evidence_attestation_id",
            "version",
            "updated_at",
        }
    ),
    "saas_privacy_backup_retention_items": frozenset(
        {
            "status",
            "attempt_count",
            "available_at",
            "leased_at",
            "lease_expires_at",
            "lease_token_hash",
            "executor_identity_sha256",
            "lease_generation",
            "last_error_code",
            "last_error_sha256",
            "purge_evidence_sha256",
            "evidence_attestation_id",
            "purged_at",
            "version",
            "updated_at",
        }
    ),
}

_PRIVACY_RLS_DEPENDENCY_SELECT_COLUMNS: dict[str, frozenset[str]] = {
    "saas_platform_role_assignments": frozenset({"principal_id", "role", "status", "expires_at"}),
    "saas_platform_support_sessions": frozenset(
        {"principal_id", "token_hash", "revoked_at", "expires_at"}
    ),
}


def verify_privacy_worker_database_role(
    engine: Engine,
    *,
    authority: PrivacyDatabaseAuthority = "dispatcher",
) -> None:
    """Fail startup unless a login has one exact Privacy authority boundary."""

    if engine.dialect.name != "postgresql":
        raise RuntimeError("the production Privacy worker requires PostgreSQL")
    with engine.connect() as connection:
        schema_facts = connection.execute(
            sa.text("SELECT current_schema(), current_schemas(false)")
        ).one()
        login_facts = connection.execute(
            sa.text(
                "SELECT current_user, session_user, role.rolcanlogin, role.rolsuper, "
                "role.rolbypassrls, role.rolinherit "
                "FROM pg_roles AS role WHERE role.rolname = current_user"
            )
        ).one()
        base_role = f"saas_privacy_{authority}"
        base_facts = connection.execute(
            sa.text(
                "SELECT rolcanlogin, rolsuper, rolbypassrls, rolinherit "
                "FROM pg_roles WHERE rolname = :base_role"
            ),
            {"base_role": base_role},
        ).one_or_none()
        login_memberships = (
            connection.execute(
                sa.text(
                    "SELECT granted.rolname FROM pg_auth_members AS membership "
                    "JOIN pg_roles AS member ON member.oid = membership.member "
                    "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
                    "WHERE member.rolname = current_user ORDER BY granted.rolname"
                )
            )
            .scalars()
            .all()
        )
        base_memberships = (
            connection.execute(
                sa.text(
                    "SELECT granted.rolname FROM pg_auth_members AS membership "
                    "JOIN pg_roles AS member ON member.oid = membership.member "
                    "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
                    "WHERE member.rolname = :base_role ORDER BY granted.rolname"
                ),
                {"base_role": base_role},
            )
            .scalars()
            .all()
        )
        owned_tables = connection.execute(
            sa.text(
                "SELECT count(*) FROM pg_class AS relation "
                "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                "JOIN pg_roles AS owner ON owner.oid = relation.relowner "
                "WHERE namespace.nspname = 'public' "
                "AND relation.relkind IN ('r', 'p') "
                "AND relation.relname LIKE 'saas_%' AND owner.rolname = current_user"
            )
        ).scalar_one()
        table_privileges = connection.execute(
            sa.text(
                "SELECT relation.relname, "
                "has_table_privilege(current_user, relation.oid, 'SELECT'), "
                "has_table_privilege(current_user, relation.oid, 'INSERT'), "
                "has_table_privilege(current_user, relation.oid, 'UPDATE'), "
                "has_table_privilege(current_user, relation.oid, 'DELETE'), "
                "has_table_privilege(current_user, relation.oid, 'TRUNCATE'), "
                "has_table_privilege(current_user, relation.oid, 'REFERENCES'), "
                "has_table_privilege(current_user, relation.oid, 'TRIGGER') "
                "FROM pg_class AS relation "
                "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                "WHERE namespace.nspname = 'public' "
                "AND relation.relkind IN ('r', 'p') "
                "AND relation.relname LIKE 'saas_%' ORDER BY relation.relname"
            )
        ).all()
        update_columns = connection.execute(
            sa.text(
                "SELECT relation.relname, attribute.attname FROM pg_class AS relation "
                "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                "JOIN pg_attribute AS attribute ON attribute.attrelid = relation.oid "
                "WHERE namespace.nspname = 'public' "
                "AND relation.relkind IN ('r', 'p') "
                "AND relation.relname LIKE 'saas_%' "
                "AND attribute.attnum > 0 AND NOT attribute.attisdropped "
                "AND has_column_privilege(current_user, relation.oid, attribute.attnum, "
                "'UPDATE') ORDER BY relation.relname, attribute.attname"
            )
        ).all()
        column_only_selects = connection.execute(
            sa.text(
                "SELECT relation.relname, attribute.attname FROM pg_class AS relation "
                "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                "JOIN pg_attribute AS attribute ON attribute.attrelid = relation.oid "
                "WHERE namespace.nspname = 'public' "
                "AND relation.relkind IN ('r', 'p') "
                "AND relation.relname LIKE 'saas_%' "
                "AND attribute.attnum > 0 AND NOT attribute.attisdropped "
                "AND NOT has_table_privilege(current_user, relation.oid, 'SELECT') "
                "AND has_column_privilege(current_user, relation.oid, attribute.attnum, "
                "'SELECT') ORDER BY relation.relname, attribute.attname"
            )
        ).all()

    current_schema, search_path = schema_facts
    if current_schema != "public" or list(search_path) != ["public"]:
        raise RuntimeError("Privacy database login must use only the public search_path")
    current_user, session_user, can_login, is_superuser, bypasses_rls, inherits_roles = login_facts
    if current_user != session_user:
        raise RuntimeError("Privacy connection must not start under an assumed database role")
    if not can_login or is_superuser or bypasses_rls or not inherits_roles:
        raise RuntimeError("Privacy database login violates the non-bypass RLS posture")
    if base_facts != (False, False, False, True):
        raise RuntimeError(f"{base_role} must remain a NOLOGIN non-bypass base role")
    if list(login_memberships) != [base_role] or base_memberships:
        raise RuntimeError(f"Privacy database login must inherit only {base_role}")

    actual_table_privileges = {
        privilege: frozenset(row[0] for row in table_privileges if row[index])
        for index, privilege in enumerate(
            ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"),
            start=1,
        )
    }
    expected_table_privileges = _PRIVACY_ROLE_TABLE_PRIVILEGES[authority]
    expected_updates = _PRIVACY_DISPATCHER_UPDATE_COLUMNS if authority == "dispatcher" else {}
    actual_updates: dict[str, set[str]] = {}
    for table_name, column_name in update_columns:
        actual_updates.setdefault(table_name, set()).add(column_name)
    actual_column_selects: dict[str, set[str]] = {}
    for table_name, column_name in column_only_selects:
        actual_column_selects.setdefault(table_name, set()).add(column_name)
    expected_column_selects = _PRIVACY_RLS_DEPENDENCY_SELECT_COLUMNS
    normalized_updates = {table: frozenset(columns) for table, columns in actual_updates.items()}
    normalized_column_selects = {
        table: frozenset(columns) for table, columns in actual_column_selects.items()
    }
    if (
        owned_tables
        or actual_table_privileges["SELECT"] != expected_table_privileges["SELECT"]
        or actual_table_privileges["INSERT"] != expected_table_privileges["INSERT"]
        or any(
            actual_table_privileges[name]
            for name in ("DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")
        )
        or normalized_updates != expected_updates
        or normalized_column_selects != expected_column_selects
    ):
        raise RuntimeError(
            "Privacy database login has an unsafe SaaS table privilege boundary: "
            f"authority={authority}; select={sorted(actual_table_privileges['SELECT'])}; "
            f"insert={sorted(actual_table_privileges['INSERT'])}; "
            f"update_columns={normalized_updates}; "
            f"select_columns={normalized_column_selects}"
        )


def _load_component_factory(reference: str) -> PrivacyWorkerComponentFactory:
    module_name, separator, attribute_name = reference.partition(":")
    if not separator or not module_name or not attribute_name:
        raise ValueError("Privacy component factory must use the 'module:attribute' form")
    candidate = getattr(importlib.import_module(module_name), attribute_name)
    factory = candidate() if isinstance(candidate, type) else candidate
    if not callable(getattr(factory, "build", None)):
        raise TypeError("Privacy component factory must provide build()")
    return cast(PrivacyWorkerComponentFactory, factory)


def _positive_number(name: str, default: str) -> float:
    raw = os.environ.get(name, default)
    try:
        value = float(raw)
    except ValueError as error:
        raise RuntimeError(f"{name} must be a number") from error
    if value <= 0:
        raise RuntimeError(f"{name} must be positive")
    return value


def main() -> int:
    """Load externally supplied production components and run one worker."""

    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    dispatcher_database_url = os.environ.get(
        "OMNIGENT_SAAS_CONTROL_PLANE_DATABASE_URL", ""
    ).strip()
    verifier_database_url = os.environ.get(
        "OMNIGENT_SAAS_PRIVACY_VERIFIER_DATABASE_URL", ""
    ).strip()
    factory_reference = os.environ.get("OMNIGENT_SAAS_PRIVACY_WORKER_FACTORY", "").strip()
    if not dispatcher_database_url:
        raise RuntimeError("OMNIGENT_SAAS_CONTROL_PLANE_DATABASE_URL is required")
    if not verifier_database_url:
        raise RuntimeError("OMNIGENT_SAAS_PRIVACY_VERIFIER_DATABASE_URL is required")
    if not factory_reference:
        raise RuntimeError("OMNIGENT_SAAS_PRIVACY_WORKER_FACTORY is required")

    dispatcher_engine = sa.create_engine(dispatcher_database_url, pool_pre_ping=True)
    verifier_engine = sa.create_engine(verifier_database_url, pool_pre_ping=True)
    try:
        verify_privacy_worker_database_role(dispatcher_engine, authority="dispatcher")
        verify_privacy_worker_database_role(verifier_engine, authority="verifier")
        dispatcher_sessions = sessionmaker(
            dispatcher_engine, expire_on_commit=False, class_=Session
        )
        verifier_sessions = sessionmaker(verifier_engine, expire_on_commit=False, class_=Session)
        components = _load_component_factory(factory_reference).build(
            dispatcher_engine=dispatcher_engine,
            dispatcher_session_factory=dispatcher_sessions,
            verifier_engine=verifier_engine,
            verifier_session_factory=verifier_sessions,
        )
        stop = threading.Event()

        def _stop(_signum: int, _frame: object) -> None:
            stop.set()

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)
        worker = PrivacyWorker(
            components.authority,
            identity_provider=components.identity_provider,
            scope_provider=components.scope_provider,
            adapter_registry=components.adapter_registry,
            evidence_signer=components.evidence_signer,
            idle_interval=_positive_number("OMNIGENT_SAAS_PRIVACY_IDLE_SECONDS", "0.5"),
            error_backoff=_positive_number("OMNIGENT_SAAS_PRIVACY_ERROR_BACKOFF_SECONDS", "1"),
            max_error_backoff=_positive_number("OMNIGENT_SAAS_PRIVACY_MAX_BACKOFF_SECONDS", "30"),
        )
        stats = worker.run(stop)
        _LOGGER.info("Privacy worker stopped: %s", stats)
        return 0
    finally:
        verifier_engine.dispose()
        dispatcher_engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
