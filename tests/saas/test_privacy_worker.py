from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa

from saas.control_plane.platform_security import PlatformSecurityError
from saas.control_plane.privacy_attestation import PrivacyDsseEnvelope
from saas.control_plane.privacy_execution import (
    ClaimedPrivacyBackupItem,
    ClaimedPrivacyWorkItem,
    PrivacyBackupCatalogEntry,
    PrivacyDestructiveAuthorization,
    PrivacyEvidenceOutcome,
    PrivacyExecutionCompletion,
    PrivacyExecutionFailure,
    PrivacyTargetType,
    WorkloadIdentity,
)
from saas.privacy_worker import (
    PrivacyBackupAdapter,
    PrivacyBackupAdapterResult,
    PrivacyDependencyError,
    PrivacyExecutionScope,
    PrivacySurfaceAdapter,
    PrivacySurfaceAdapterResult,
    PrivacyWorker,
    _load_component_factory,
    verify_privacy_worker_database_role,
)

NOW = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)
TARGET_ID = uuid4()
MANIFEST_ID = uuid4()
WORK_ID = uuid4()
BACKUP_ID = uuid4()
IDENTITY = WorkloadIdentity(
    issuer="https://workload.example.test",
    subject="spiffe://prod/privacy-worker",
    audience="omnigent:privacy-execution",
    authenticated_at=NOW - timedelta(minutes=1),
    expires_at=NOW + timedelta(hours=1),
)
WORK_CLAIM = ClaimedPrivacyWorkItem(
    item_id=WORK_ID,
    manifest_id=MANIFEST_ID,
    target_type="global_user",
    target_id=TARGET_ID,
    tenant_id=None,
    surface="object_and_artifact_store",
    disposition="erase",
    resource_scope_hmac="a" * 64,
    adapter_type="object-store-v1",
    attempt_id=uuid4(),
    attempt_number=1,
    lease_generation=1,
    replay_generation=0,
    lease_token="surface-lease-secret",
    lease_expires_at=NOW + timedelta(minutes=5),
)
BACKUP_CLAIM = ClaimedPrivacyBackupItem(
    item_id=BACKUP_ID,
    manifest_id=MANIFEST_ID,
    target_type="global_user",
    target_id=TARGET_ID,
    tenant_id=None,
    provider="backup-provider-v1",
    backup_data_class="database_snapshot",
    backup_locator_hmac="b" * 64,
    resource_handle_ref="backup://raw-provider-handle/secret",
    catalog_snapshot_sha256="c" * 64,
    tombstone_sha256="d" * 64,
    attempt_id=uuid4(),
    attempt_number=1,
    lease_generation=1,
    replay_generation=0,
    lease_token="backup-lease-secret",
    lease_expires_at=NOW + timedelta(minutes=5),
)
SURFACE_SCOPE = PrivacyExecutionScope(
    kind="surface",
    target_type="global_user",
    target_id=TARGET_ID,
    manifest_id=MANIFEST_ID,
)
BACKUP_SCOPE = PrivacyExecutionScope(
    kind="backup",
    target_type="global_user",
    target_id=TARGET_ID,
    manifest_id=MANIFEST_ID,
)
ENVELOPE = PrivacyDsseEnvelope(
    envelope={"payloadType": "test", "payload": "test", "signatures": []},
    artifact_uri="https://evidence.example.test/privacy/test.json",
    immutability_receipt_sha256="e" * 64,
    kms_audit_receipt_sha256="f" * 64,
)


class _IdentityProvider:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def identity(self, *, now: datetime) -> WorkloadIdentity:
        assert now == NOW
        self.events.append("identity")
        return IDENTITY


class _ScriptedScopeProvider:
    def __init__(
        self,
        outcomes: list[PrivacyExecutionScope | None | Exception],
        *,
        stop: threading.Event | None = None,
    ) -> None:
        self.outcomes = outcomes
        self.stop = stop

    def next_scope(self) -> PrivacyExecutionScope | None:
        outcome = self.outcomes.pop(0)
        if not self.outcomes and self.stop is not None:
            self.stop.set()
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class _Authority:
    def __init__(
        self,
        events: list[str],
        *,
        work_claim: ClaimedPrivacyWorkItem | None = WORK_CLAIM,
        backup_claim: ClaimedPrivacyBackupItem | None = BACKUP_CLAIM,
        complete_error: PlatformSecurityError | None = None,
        authorize_error: PlatformSecurityError | None = None,
    ) -> None:
        self.events = events
        self.work_claim = work_claim
        self.backup_claim = backup_claim
        self.complete_error = complete_error
        self.authorize_error = authorize_error
        self.claim_transaction_open = False
        self.failures: list[tuple[str, str, str]] = []

    def claim_work_item(
        self,
        identity: WorkloadIdentity,
        *,
        target_type: PrivacyTargetType,
        target_id: UUID,
        manifest_id: UUID,
        now: datetime | None = None,
    ) -> ClaimedPrivacyWorkItem | None:
        assert identity == IDENTITY
        assert (target_type, target_id, manifest_id, now) == (
            "global_user",
            TARGET_ID,
            MANIFEST_ID,
            NOW,
        )
        self.claim_transaction_open = True
        self.events.append("claim_surface:start")
        self.claim_transaction_open = False
        self.events.append("claim_surface:committed")
        return self.work_claim

    def claim_backup_item(
        self,
        identity: WorkloadIdentity,
        *,
        target_type: PrivacyTargetType,
        target_id: UUID,
        manifest_id: UUID,
        now: datetime | None = None,
    ) -> ClaimedPrivacyBackupItem | None:
        assert identity == IDENTITY
        assert (target_type, target_id, manifest_id, now) == (
            "global_user",
            TARGET_ID,
            MANIFEST_ID,
            NOW,
        )
        self.claim_transaction_open = True
        self.events.append("claim_backup:start")
        self.claim_transaction_open = False
        self.events.append("claim_backup:committed")
        return self.backup_claim

    def authorize_destructive_execution(
        self,
        identity: WorkloadIdentity,
        claim: ClaimedPrivacyWorkItem | ClaimedPrivacyBackupItem,
        *,
        now: datetime | None = None,
    ) -> PrivacyDestructiveAuthorization:
        assert identity == IDENTITY and now == NOW
        kind = "backup" if isinstance(claim, ClaimedPrivacyBackupItem) else "surface"
        self.claim_transaction_open = True
        self.events.append(f"authorize_{kind}:start")
        self.claim_transaction_open = False
        self.events.append(f"authorize_{kind}:committed")
        if self.authorize_error is not None:
            raise self.authorize_error
        return PrivacyDestructiveAuthorization(
            item_id=claim.item_id,
            attempt_id=claim.attempt_id,
            lease_generation=claim.lease_generation,
            replay_generation=claim.replay_generation,
            authorized_at=NOW,
            expires_at=claim.lease_expires_at,
            authorization_sha256="9" * 64,
        )

    def complete_work_item(
        self,
        identity: WorkloadIdentity,
        claim: ClaimedPrivacyWorkItem,
        *,
        outcome: PrivacyEvidenceOutcome,
        envelope: PrivacyDsseEnvelope,
        backup_catalog: tuple[PrivacyBackupCatalogEntry, ...] = (),
        now: datetime | None = None,
    ) -> PrivacyExecutionCompletion:
        assert identity == IDENTITY and claim == WORK_CLAIM
        assert outcome.evidence_sha256 == "1" * 64
        assert envelope == ENVELOPE and not backup_catalog and now == NOW
        self.events.append("complete_surface")
        if self.complete_error is not None:
            raise self.complete_error
        return PrivacyExecutionCompletion(
            item_id=claim.item_id,
            attempt_id=claim.attempt_id,
            attestation_id=uuid4(),
            status="succeeded",
        )

    def fail_work_item(
        self,
        identity: WorkloadIdentity,
        claim: ClaimedPrivacyWorkItem,
        *,
        error_code: str,
        raw_error: str,
        now: datetime | None = None,
    ) -> PrivacyExecutionFailure:
        assert identity == IDENTITY and claim == WORK_CLAIM and now == NOW
        self.events.append("fail_surface")
        self.failures.append(("surface", error_code, raw_error))
        status = (
            "retry"
            if error_code in {"privacy_provider_timeout", "privacy_resource_lock_pending"}
            else "dead_letter"
        )
        return PrivacyExecutionFailure(
            item_id=claim.item_id,
            attempt_id=claim.attempt_id,
            status=status,
            available_at=NOW + timedelta(seconds=5),
        )

    def complete_backup_item(
        self,
        identity: WorkloadIdentity,
        claim: ClaimedPrivacyBackupItem,
        *,
        evidence_sha256: str,
        envelope: PrivacyDsseEnvelope,
        now: datetime | None = None,
    ) -> PrivacyExecutionCompletion:
        assert identity == IDENTITY and claim == BACKUP_CLAIM
        assert evidence_sha256 == "2" * 64 and envelope == ENVELOPE and now == NOW
        self.events.append("complete_backup")
        if self.complete_error is not None:
            raise self.complete_error
        return PrivacyExecutionCompletion(
            item_id=claim.item_id,
            attempt_id=claim.attempt_id,
            attestation_id=uuid4(),
            status="purged",
        )

    def fail_backup_item(
        self,
        identity: WorkloadIdentity,
        claim: ClaimedPrivacyBackupItem,
        *,
        error_code: str,
        raw_error: str,
        now: datetime | None = None,
    ) -> PrivacyExecutionFailure:
        assert identity == IDENTITY and claim == BACKUP_CLAIM and now == NOW
        self.events.append("fail_backup")
        self.failures.append(("backup", error_code, raw_error))
        status = (
            "retry"
            if error_code in {"privacy_provider_timeout", "privacy_resource_lock_pending"}
            else "dead_letter"
        )
        return PrivacyExecutionFailure(
            item_id=claim.item_id,
            attempt_id=claim.attempt_id,
            status=status,
            available_at=NOW + timedelta(seconds=5),
        )


class _SurfaceAdapter:
    def __init__(
        self,
        authority: _Authority,
        events: list[str],
        *,
        error: Exception | None = None,
    ) -> None:
        self.authority = authority
        self.events = events
        self.error = error

    def execute(
        self,
        *,
        claim: ClaimedPrivacyWorkItem,
        identity: WorkloadIdentity,
        authorization: PrivacyDestructiveAuthorization,
    ) -> PrivacySurfaceAdapterResult:
        assert not self.authority.claim_transaction_open
        assert claim == WORK_CLAIM and identity == IDENTITY
        assert authorization.item_id == claim.item_id
        assert authorization.expires_at == claim.lease_expires_at
        self.events.append("adapter_surface")
        if self.error is not None:
            raise self.error
        return PrivacySurfaceAdapterResult(
            outcome=PrivacyEvidenceOutcome(evidence_sha256="1" * 64)
        )


class _BackupAdapter:
    def __init__(self, authority: _Authority, events: list[str]) -> None:
        self.authority = authority
        self.events = events

    def execute(
        self,
        *,
        claim: ClaimedPrivacyBackupItem,
        identity: WorkloadIdentity,
        authorization: PrivacyDestructiveAuthorization,
    ) -> PrivacyBackupAdapterResult:
        assert not self.authority.claim_transaction_open
        assert claim == BACKUP_CLAIM and identity == IDENTITY
        assert authorization.item_id == claim.item_id
        assert authorization.expires_at == claim.lease_expires_at
        self.events.append("adapter_backup")
        return PrivacyBackupAdapterResult(evidence_sha256="2" * 64)


class _Registry:
    def __init__(
        self,
        *,
        surface: PrivacySurfaceAdapter | None,
        backup: PrivacyBackupAdapter | None,
    ) -> None:
        self.surface = surface
        self.backup = backup

    def surface_adapter(self, adapter_type: str) -> PrivacySurfaceAdapter | None:
        assert adapter_type == WORK_CLAIM.adapter_type
        return self.surface

    def backup_adapter(self, provider: str) -> PrivacyBackupAdapter | None:
        assert provider == BACKUP_CLAIM.provider
        return self.backup


class _Signer:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def sign_surface(
        self,
        *,
        identity: WorkloadIdentity,
        claim: ClaimedPrivacyWorkItem,
        result: PrivacySurfaceAdapterResult,
        observed_at: datetime,
    ) -> PrivacyDsseEnvelope:
        assert identity == IDENTITY and claim == WORK_CLAIM
        assert result.outcome.evidence_sha256 == "1" * 64 and observed_at == NOW
        self.events.append("sign_surface")
        return ENVELOPE

    def sign_backup(
        self,
        *,
        identity: WorkloadIdentity,
        claim: ClaimedPrivacyBackupItem,
        result: PrivacyBackupAdapterResult,
        observed_at: datetime,
    ) -> PrivacyDsseEnvelope:
        assert identity == IDENTITY and claim == BACKUP_CLAIM
        assert result.evidence_sha256 == "2" * 64 and observed_at == NOW
        self.events.append("sign_backup")
        return ENVELOPE


def _worker(
    authority: _Authority,
    events: list[str],
    *,
    surface: PrivacySurfaceAdapter | None,
    backup: PrivacyBackupAdapter | None,
    scope_provider: _ScriptedScopeProvider | None = None,
    logger: logging.Logger | None = None,
) -> PrivacyWorker:
    return PrivacyWorker(
        authority,
        identity_provider=_IdentityProvider(events),
        scope_provider=scope_provider or _ScriptedScopeProvider([]),
        adapter_registry=_Registry(surface=surface, backup=backup),
        evidence_signer=_Signer(events),
        clock=lambda: NOW,
        idle_interval=0.001,
        error_backoff=0.001,
        max_error_backoff=0.002,
        logger=logger,
    )


def test_surface_cycle_commits_claim_before_adapter_and_completes_once() -> None:
    events: list[str] = []
    authority = _Authority(events)
    adapter = _SurfaceAdapter(authority, events)
    worker = _worker(authority, events, surface=adapter, backup=None)

    result = worker.run_once(SURFACE_SCOPE, now=NOW)

    assert result.status == "succeeded"
    assert result.claimed
    assert events == [
        "identity",
        "claim_surface:start",
        "claim_surface:committed",
        "authorize_surface:start",
        "authorize_surface:committed",
        "adapter_surface",
        "sign_surface",
        "complete_surface",
    ]


def test_due_backup_cycle_never_logs_raw_provider_handle(
    caplog: pytest.LogCaptureFixture,
) -> None:
    events: list[str] = []
    authority = _Authority(events)
    adapter = _BackupAdapter(authority, events)
    worker = _worker(authority, events, surface=None, backup=adapter)

    with caplog.at_level(logging.DEBUG):
        result = worker.run_once(BACKUP_SCOPE, now=NOW)

    assert result.status == "purged"
    assert events[-5:] == [
        "authorize_backup:start",
        "authorize_backup:committed",
        "adapter_backup",
        "sign_backup",
        "complete_backup",
    ]
    assert BACKUP_CLAIM.resource_handle_ref not in caplog.text
    assert BACKUP_CLAIM.lease_token not in caplog.text


def test_retryable_adapter_failure_is_hashed_by_authority_and_not_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    events: list[str] = []
    authority = _Authority(events)
    raw_error = "provider timeout at backup://raw-secret-handle"
    adapter = _SurfaceAdapter(
        authority,
        events,
        error=PrivacyDependencyError("privacy_provider_timeout", raw_error),
    )
    worker = _worker(authority, events, surface=adapter, backup=None)

    with caplog.at_level(logging.DEBUG):
        result = worker.run_once(SURFACE_SCOPE, now=NOW)

    assert result.status == "retry"
    assert authority.failures == [("surface", "privacy_provider_timeout", raw_error)]
    assert raw_error not in caplog.text
    assert "sign_surface" not in events


def test_unregistered_adapter_fails_closed_with_stable_terminal_error() -> None:
    events: list[str] = []
    authority = _Authority(events)
    worker = _worker(authority, events, surface=None, backup=None)

    result = worker.run_once(SURFACE_SCOPE, now=NOW)

    assert result.status == "dead_letter"
    assert authority.failures == [
        (
            "surface",
            "privacy_adapter_contract_invalid",
            "privacy surface adapter is not registered",
        )
    ]


def test_competing_lease_returns_no_work_without_calling_adapter() -> None:
    events: list[str] = []
    authority = _Authority(events, work_claim=None)
    adapter = _SurfaceAdapter(authority, events)
    worker = _worker(authority, events, surface=adapter, backup=None)

    result = worker.run_once(SURFACE_SCOPE, now=NOW)

    assert result.status == "no_work"
    assert not result.claimed
    assert events == ["identity", "claim_surface:start", "claim_surface:committed"]


@pytest.mark.parametrize("scope", [SURFACE_SCOPE, BACKUP_SCOPE])
def test_hold_fence_failure_prevents_adapter_side_effect_and_settles_lease(
    scope: PrivacyExecutionScope,
) -> None:
    events: list[str] = []
    authority = _Authority(
        events,
        authorize_error=PlatformSecurityError(
            "platform_privacy_execution_blocked",
            "Legal Hold won the destructive authorization fence",
        ),
    )
    worker = _worker(
        authority,
        events,
        surface=_SurfaceAdapter(authority, events),
        backup=_BackupAdapter(authority, events),
    )

    result = worker.run_once(scope, now=NOW)

    kind = "backup" if scope.kind == "backup" else "surface"
    assert result.status == "retry"
    assert f"adapter_{kind}" not in events
    assert authority.failures == [
        (kind, "privacy_resource_lock_pending", "platform_privacy_execution_blocked")
    ]


def test_completion_fence_loss_is_expected_and_does_not_mutate_stale_lease() -> None:
    events: list[str] = []
    authority = _Authority(
        events,
        complete_error=PlatformSecurityError(
            "platform_privacy_execution_lease_lost",
            "lease token was fenced",
        ),
    )
    worker = _worker(
        authority,
        events,
        surface=_SurfaceAdapter(authority, events),
        backup=None,
    )

    result = worker.run_once(SURFACE_SCOPE, now=NOW)

    assert result.status == "lease_lost"
    assert authority.failures == []


def test_loop_backs_off_without_logging_raw_infrastructure_error(
    caplog: pytest.LogCaptureFixture,
) -> None:
    stop = threading.Event()
    provider = _ScriptedScopeProvider(
        [RuntimeError("raw database endpoint and credential"), None],
        stop=stop,
    )
    events: list[str] = []
    authority = _Authority(events)
    logger = logging.getLogger("test-privacy-worker")
    worker = _worker(
        authority,
        events,
        surface=None,
        backup=None,
        scope_provider=provider,
        logger=logger,
    )

    with caplog.at_level(logging.ERROR, logger=logger.name):
        stats = worker.run(stop)

    assert stats.infrastructure_failures == 1
    assert stats.cycles == 1
    assert "RuntimeError" in caplog.text
    assert "raw database endpoint and credential" not in caplog.text


@pytest.mark.parametrize(
    ("idle_interval", "error_backoff", "max_error_backoff"),
    [
        (0.0, 1.0, 30.0),
        (0.5, 0.0, 30.0),
        (0.5, 2.0, 1.0),
    ],
)
def test_worker_rejects_unsafe_poll_intervals(
    idle_interval: float,
    error_backoff: float,
    max_error_backoff: float,
) -> None:
    events: list[str] = []
    authority = _Authority(events)
    with pytest.raises(ValueError):
        PrivacyWorker(
            authority,
            identity_provider=_IdentityProvider(events),
            scope_provider=_ScriptedScopeProvider([]),
            adapter_registry=_Registry(surface=None, backup=None),
            evidence_signer=_Signer(events),
            idle_interval=idle_interval,
            error_backoff=error_backoff,
            max_error_backoff=max_error_backoff,
        )


def test_component_factory_loader_requires_explicit_build_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = SimpleNamespace(build=lambda **_kwargs: None)
    monkeypatch.setattr(
        "saas.privacy_worker.importlib.import_module",
        lambda _module: SimpleNamespace(factory=factory),
    )

    assert _load_component_factory("privacy_components:factory") is factory
    with pytest.raises(ValueError):
        _load_component_factory("invalid-reference")


def test_role_verifier_rejects_non_postgresql_engine() -> None:
    engine = sa.create_engine("sqlite+pysqlite:///:memory:")
    try:
        with pytest.raises(RuntimeError, match="requires PostgreSQL"):
            verify_privacy_worker_database_role(engine)
    finally:
        engine.dispose()
