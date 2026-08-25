from __future__ import annotations

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from hashlib import sha256
from typing import cast
from uuid import UUID, uuid4

import pytest

from saas.control_plane.onboarding_workflow import (
    RuntimePartitionTarget,
    RuntimeProjectTarget,
    RuntimeProviderBindingSnapshot,
)
from saas.control_plane.runtime_provider import (
    ProductionRuntimePartitionAdapter,
    RuntimeProviderBinding,
    RuntimeProviderCredential,
    RuntimeProviderError,
    RuntimeProviderFailureDisposition,
    RuntimeProviderJournalEntry,
    RuntimeProviderOperation,
    RuntimeProviderOperationJournal,
    RuntimeProviderOperationKind,
    RuntimeProviderOutcome,
    RuntimeProviderReceipt,
    RuntimeProviderResponse,
    canonical_sha256,
)

_SIGNING_KEY = b"runtime-provider-contract-signing-key"
_SOURCE_REVISION = "14df304a8e958da36b8a606a2c825e3a6642247e"


@dataclass(slots=True)
class _CredentialAuthority:
    secret: str = field(default="provider-secret-value", repr=False)
    version: str = "provider-secret-version-7"
    production_capable: bool = True
    uses_ambient_credentials: bool = False

    @contextmanager
    def acquire(
        self,
        *,
        binding: RuntimeProviderBinding,
        operation: RuntimeProviderOperationKind,
    ) -> Iterator[RuntimeProviderCredential]:
        del operation
        yield RuntimeProviderCredential(
            credential_ref_hash=binding.credential_ref_hash,
            version=self.version,
            material=self.secret,
        )


@dataclass(slots=True)
class _UnavailableCredentialAuthority(_CredentialAuthority):
    acquisitions: int = 0

    @contextmanager
    def acquire(
        self,
        *,
        binding: RuntimeProviderBinding,
        operation: RuntimeProviderOperationKind,
    ) -> Iterator[RuntimeProviderCredential]:
        del binding, operation
        self.acquisitions += 1
        raise RuntimeError("credential backend unavailable")


@dataclass(slots=True)
class _EnterFailingCredentialAuthority(_CredentialAuthority):
    acquisitions: int = 0

    @contextmanager
    def acquire(
        self,
        *,
        binding: RuntimeProviderBinding,
        operation: RuntimeProviderOperationKind,
    ) -> Iterator[RuntimeProviderCredential]:
        del binding, operation
        self.acquisitions += 1
        if False:  # pragma: no cover - keeps this a context-manager generator
            yield RuntimeProviderCredential("0" * 64, "unreachable", object())
        raise RuntimeError("credential context unavailable")


@dataclass(slots=True)
class _ScopeMismatchedCredentialAuthority(_CredentialAuthority):
    acquisitions: int = 0

    @contextmanager
    def acquire(
        self,
        *,
        binding: RuntimeProviderBinding,
        operation: RuntimeProviderOperationKind,
    ) -> Iterator[RuntimeProviderCredential]:
        del binding, operation
        self.acquisitions += 1
        yield RuntimeProviderCredential(
            credential_ref_hash="f" * 64,
            version=self.version,
            material=self.secret,
        )


@dataclass(slots=True)
class _ExitFailingCredentialAuthority(_CredentialAuthority):
    exits: int = 0

    @contextmanager
    def acquire(
        self,
        *,
        binding: RuntimeProviderBinding,
        operation: RuntimeProviderOperationKind,
    ) -> Iterator[RuntimeProviderCredential]:
        del operation
        yield RuntimeProviderCredential(
            credential_ref_hash=binding.credential_ref_hash,
            version=self.version,
            material=self.secret,
        )
        self.exits += 1
        raise RuntimeError("credential cleanup unavailable")


@dataclass(slots=True)
class _SuppressingCredentialAuthority(_CredentialAuthority):
    suppressions: int = 0

    def acquire(
        self,
        *,
        binding: RuntimeProviderBinding,
        operation: RuntimeProviderOperationKind,
    ) -> AbstractContextManager[RuntimeProviderCredential]:
        del operation
        authority = self

        class _CredentialContext(AbstractContextManager[RuntimeProviderCredential]):
            def __enter__(self) -> RuntimeProviderCredential:
                return RuntimeProviderCredential(
                    credential_ref_hash=binding.credential_ref_hash,
                    version=authority.version,
                    material=authority.secret,
                )

            def __exit__(self, *_error: object) -> bool:
                authority.suppressions += 1
                return True

        return _CredentialContext()


@dataclass(slots=True)
class _ReceiptVerifier:
    production_capable: bool = True
    test_only: bool = False
    reject: bool = False
    verified: list[RuntimeProviderReceipt] = field(default_factory=list)

    def verify(
        self,
        *,
        binding: RuntimeProviderBinding,
        receipt: RuntimeProviderReceipt,
        payload: bytes,
    ) -> bool:
        assert binding.binding_hash == receipt.binding_hash
        self.verified.append(receipt)
        expected = sha256(_SIGNING_KEY + payload).hexdigest()
        return not self.reject and receipt.signature_hex == expected


@dataclass(slots=True)
class _ReceiptSink:
    production_capable: bool = True
    durable: bool = True
    conflict_safe: bool = True
    receipts: list[RuntimeProviderReceipt] = field(default_factory=list)
    entries: dict[
        tuple[str, RuntimeProviderOperationKind, str],
        tuple[str, RuntimeProviderResponse | None],
    ] = field(default_factory=dict)

    def lookup(self, operation: RuntimeProviderOperation) -> RuntimeProviderJournalEntry | None:
        key = (operation.provider_type, operation.kind, operation.idempotency_hash)
        existing = self.entries.get(key)
        if existing is None:
            return None
        request_hash, response = existing
        return RuntimeProviderJournalEntry(
            request_hash=request_hash,
            is_new=False,
            response=response,
        )

    def begin(self, operation: RuntimeProviderOperation) -> RuntimeProviderJournalEntry:
        key = (operation.provider_type, operation.kind, operation.idempotency_hash)
        existing = self.entries.get(key)
        if existing is None:
            self.entries[key] = (operation.request_hash, None)
            return RuntimeProviderJournalEntry(
                request_hash=operation.request_hash,
                is_new=True,
            )
        request_hash, response = existing
        if request_hash != operation.request_hash:
            raise RuntimeProviderError(
                "provider_idempotency_conflict",
                RuntimeProviderFailureDisposition.IDEMPOTENCY_CONFLICT,
            )
        return RuntimeProviderJournalEntry(
            request_hash=request_hash,
            is_new=False,
            response=response,
        )

    def record_verified(
        self,
        *,
        operation: RuntimeProviderOperation,
        response: RuntimeProviderResponse,
    ) -> None:
        key = (operation.provider_type, operation.kind, operation.idempotency_hash)
        request_hash, prior = self.entries[key]
        if request_hash != operation.request_hash:
            raise RuntimeError("journal request conflict")
        if prior is not None and prior.receipt.receipt_hash != response.receipt.receipt_hash:
            raise RuntimeError("journal receipt conflict")
        self.entries[key] = (request_hash, response)
        if prior is None:
            self.receipts.append(response.receipt)


@dataclass(slots=True)
class _ConformanceClient:
    provider_type: str = "contract-provider"
    production_capable: bool = True
    test_only: bool = False
    unknown_once: bool = False
    invalid_receipt: str | None = None
    compensation_absent: bool = False
    executions: list[RuntimeProviderOperation] = field(default_factory=list)
    reconciliations: list[RuntimeProviderOperation] = field(default_factory=list)
    requests: dict[
        tuple[RuntimeProviderOperationKind, str], tuple[str, RuntimeProviderResponse]
    ] = field(default_factory=dict)
    _unknown_raised: bool = False

    def execute(
        self,
        operation: RuntimeProviderOperation,
        credential: RuntimeProviderCredential,
    ) -> RuntimeProviderResponse:
        self.executions.append(operation)
        key = (operation.kind, operation.idempotency_hash)
        existing = self.requests.get(key)
        if existing is not None:
            request_hash, response = existing
            if request_hash != operation.request_hash:
                raise RuntimeProviderError(
                    "provider_idempotency_conflict",
                    RuntimeProviderFailureDisposition.IDEMPOTENCY_CONFLICT,
                    "unsafe provider payload must be redacted",
                )
            return self._response(
                operation,
                credential,
                outcome=RuntimeProviderOutcome.REPLAYED,
                provider_request_id=response.receipt.provider_request_id,
                provider_resource_id=response.receipt.provider_resource_id,
            )
        outcome = (
            RuntimeProviderOutcome.ALREADY_ABSENT
            if self.compensation_absent and _is_compensation(operation.kind)
            else RuntimeProviderOutcome.APPLIED
        )
        response = self._response(operation, credential, outcome=outcome)
        self.requests[key] = (operation.request_hash, response)
        if self.unknown_once and not self._unknown_raised:
            self._unknown_raised = True
            raise RuntimeProviderError(
                "provider_submit_timeout",
                RuntimeProviderFailureDisposition.UNKNOWN_EFFECT_RECONCILE,
                "provider-secret-value appeared in a low-level timeout",
            )
        return response

    def reconcile(
        self,
        operation: RuntimeProviderOperation,
        credential: RuntimeProviderCredential,
    ) -> RuntimeProviderResponse:
        self.reconciliations.append(operation)
        existing = self.requests[(operation.kind, operation.idempotency_hash)][1]
        return self._response(
            operation,
            credential,
            outcome=(
                RuntimeProviderOutcome.ALREADY_ABSENT
                if existing.receipt.outcome is RuntimeProviderOutcome.ALREADY_ABSENT
                else RuntimeProviderOutcome.REPLAYED
            ),
            provider_request_id=existing.receipt.provider_request_id,
            provider_resource_id=existing.receipt.provider_resource_id,
        )

    def _response(
        self,
        operation: RuntimeProviderOperation,
        credential: RuntimeProviderCredential,
        *,
        outcome: RuntimeProviderOutcome,
        provider_request_id: str | None = None,
        provider_resource_id: str | None = None,
    ) -> RuntimeProviderResponse:
        attributes: dict[str, object] = {}
        if operation.kind is RuntimeProviderOperationKind.ALLOCATE_PARTITION:
            attributes = {
                "runtime_version": "0.11.0.dev0",
                "physical_partition_key": "physical-partition-42",
                "placement_generation": 1,
                "source_revision": _SOURCE_REVISION,
                "adapter_contract_version": "0.2.0",
                "runtime_user_key": "runtime-user-42",
            }
        elif operation.kind is RuntimeProviderOperationKind.PROVISION_DEFAULT_PROJECT:
            attributes = {"runtime_resource_id": "runtime-project-42"}
        if provider_resource_id is None and outcome is not RuntimeProviderOutcome.ALREADY_ABSENT:
            provider_resource_id = {
                RuntimeProviderOperationKind.ALLOCATE_PARTITION: "physical-partition-42",
                RuntimeProviderOperationKind.PROVISION_DEFAULT_PROJECT: "runtime-project-42",
                RuntimeProviderOperationKind.COMPENSATE_DEFAULT_PROJECT: "runtime-project-42",
                RuntimeProviderOperationKind.COMPENSATE_PARTITION: "physical-partition-42",
            }[operation.kind]
        receipt = _signed_receipt(
            operation,
            credential,
            outcome=outcome,
            provider_request_id=provider_request_id or f"request-{operation.kind.value}",
            provider_resource_id=provider_resource_id,
            result_hash=canonical_sha256(attributes),
        )
        if self.invalid_receipt == "target":
            receipt = replace(receipt, target_hash="f" * 64)
        elif self.invalid_receipt == "signature":
            receipt = replace(receipt, signature_hex="f" * 64)
        elif self.invalid_receipt == "result":
            attributes["runtime_user_key"] = "tampered-runtime-user"
        return RuntimeProviderResponse(receipt=receipt, attributes=attributes)


def _signed_receipt(
    operation: RuntimeProviderOperation,
    credential: RuntimeProviderCredential,
    *,
    outcome: RuntimeProviderOutcome,
    provider_request_id: str,
    provider_resource_id: str | None,
    result_hash: str,
) -> RuntimeProviderReceipt:
    unsigned = RuntimeProviderReceipt(
        schema_version=1,
        provider_type=operation.provider_type,
        operation=operation.kind,
        outcome=outcome,
        placement_id=operation.placement_id,
        binding_revision=operation.binding_revision,
        binding_hash=operation.binding_hash,
        target_hash=operation.target_hash,
        idempotency_hash=operation.idempotency_hash,
        request_hash=operation.request_hash,
        credential_ref_hash=credential.credential_ref_hash,
        credential_version_hash=credential.version_hash,
        result_hash=result_hash,
        provider_request_id=provider_request_id,
        provider_resource_id=provider_resource_id,
        observed_at=datetime(2026, 8, 25, tzinfo=timezone.utc),
        receipt_hash="0" * 64,
        signature_key_id="kms-runtime-receipts-v1",
        signature_hex="0" * 64,
    )
    payload = unsigned.unsigned_payload()
    return replace(
        unsigned,
        receipt_hash=sha256(payload).hexdigest(),
        signature_hex=sha256(_SIGNING_KEY + payload).hexdigest(),
    )


def _resign_receipt(receipt: RuntimeProviderReceipt) -> RuntimeProviderReceipt:
    payload = receipt.unsigned_payload()
    return replace(
        receipt,
        receipt_hash=sha256(payload).hexdigest(),
        signature_hex=sha256(_SIGNING_KEY + payload).hexdigest(),
    )


def _binding(placement_id: UUID) -> RuntimeProviderBinding:
    return RuntimeProviderBinding(
        provider_type="contract-provider",
        placement_id=placement_id,
        binding_revision="provider-binding-2026-08-25-v1",
        endpoint_ref="service://runtime-provider-cn-east-1",
        credential_ref="vault://runtime-provider/production",
        account_ref_hash=sha256(b"provider-account-42").hexdigest(),
        region="cn-east-1",
    )


def _partition_target(
    placement_id: UUID,
    *,
    partition_id: UUID | None = None,
    binding: RuntimeProviderBinding | None = None,
) -> RuntimePartitionTarget:
    effective_binding = binding or _binding(placement_id)
    return RuntimePartitionTarget(
        onboarding_id=uuid4(),
        tenant_id=uuid4(),
        space_id=uuid4(),
        user_id=uuid4(),
        runtime_partition_id=partition_id or uuid4(),
        placement_id=placement_id,
        runtime_type="omnigent",
        data_region="cn-east-1",
        failure_domain="cn-east-1a",
        official_schema_revision="p0s000000002",
        capacity_class="starter",
        provider_binding=RuntimeProviderBindingSnapshot(
            provider_type=effective_binding.provider_type,
            binding_revision=effective_binding.binding_revision,
            binding_hash=effective_binding.binding_hash,
        ),
    )


def _adapter(
    *,
    binding: RuntimeProviderBinding,
    client: _ConformanceClient | None = None,
    credentials: _CredentialAuthority | None = None,
    verifier: _ReceiptVerifier | None = None,
    sink: _ReceiptSink | None = None,
    historical_bindings: tuple[RuntimeProviderBinding, ...] = (),
) -> tuple[
    ProductionRuntimePartitionAdapter,
    _ConformanceClient,
    _CredentialAuthority,
    _ReceiptVerifier,
    _ReceiptSink,
]:
    effective_client = client or _ConformanceClient()
    effective_credentials = credentials or _CredentialAuthority()
    effective_verifier = verifier or _ReceiptVerifier()
    effective_sink = sink or _ReceiptSink()
    return (
        ProductionRuntimePartitionAdapter(
            bindings={binding.placement_id: binding},
            client=effective_client,
            credentials=effective_credentials,
            receipt_verifier=effective_verifier,
            operation_journal=effective_sink,
            historical_bindings=historical_bindings,
        ),
        effective_client,
        effective_credentials,
        effective_verifier,
        effective_sink,
    )


def test_all_four_operations_require_verified_receipts_and_sink_compensation() -> None:
    placement_id = uuid4()
    binding = _binding(placement_id)
    adapter, _client, _credentials, verifier, sink = _adapter(binding=binding)
    partition = _partition_target(placement_id)
    project = RuntimeProjectTarget(
        partition=partition,
        project_id=uuid4(),
        project_name="Getting Started",
    )

    allocation = adapter.allocate_partition(
        target=partition,
        idempotency_key="onboarding:42:runtime",
    )
    project_allocation = adapter.provision_default_project(
        target=project,
        idempotency_key="onboarding:42:project",
    )
    assert (
        adapter.compensate_default_project(
            target=project,
            idempotency_key="onboarding:42:project:compensate",
        )
        is None
    )
    assert (
        adapter.compensate_partition(
            target=partition,
            idempotency_key="onboarding:42:runtime:compensate",
        )
        is None
    )

    assert allocation.physical_partition_key == "physical-partition-42"
    assert project_allocation.runtime_resource_id == "runtime-project-42"
    assert len(verifier.verified) == 4
    assert sink.receipts == verifier.verified
    assert adapter.last_receipt is sink.receipts[-1]
    for receipt in sink.receipts:
        assert receipt.binding_revision == binding.binding_revision
        assert receipt.binding_hash == binding.binding_hash
        assert len(receipt.target_hash) == 64
        assert len(receipt.idempotency_hash) == 64
        assert receipt.receipt_hash == sha256(receipt.unsigned_payload()).hexdigest()


def test_provider_replay_keeps_same_target_request_and_resource_identity() -> None:
    placement_id = uuid4()
    binding = _binding(placement_id)
    client = _ConformanceClient()
    target = _partition_target(placement_id)
    first, *_ = _adapter(binding=binding, client=client)
    second, *_ = _adapter(binding=binding, client=client)

    first_allocation = first.allocate_partition(target=target, idempotency_key="stable-key")
    second_allocation = second.allocate_partition(target=target, idempotency_key="stable-key")

    assert first_allocation.physical_partition_key == second_allocation.physical_partition_key
    assert len(client.executions) == 2
    assert client.executions[0].request_hash == client.executions[1].request_hash
    assert client.executions[0].target_hash == client.executions[1].target_hash
    assert second.last_receipt is not None
    assert second.last_receipt.outcome is RuntimeProviderOutcome.REPLAYED


def test_same_idempotency_key_with_another_target_fails_before_provider_call() -> None:
    placement_id = uuid4()
    adapter, client, *_ = _adapter(binding=_binding(placement_id))
    first = _partition_target(placement_id)
    adapter.allocate_partition(target=first, idempotency_key="conflict-key")
    changed = replace(first, runtime_partition_id=uuid4())

    with pytest.raises(RuntimeProviderError) as raised:
        adapter.allocate_partition(target=changed, idempotency_key="conflict-key")

    assert raised.value.disposition is RuntimeProviderFailureDisposition.IDEMPOTENCY_CONFLICT
    assert len(client.executions) == 1


def test_unknown_effect_reconciles_instead_of_submitting_again_and_redacts_error() -> None:
    placement_id = uuid4()
    binding = _binding(placement_id)
    client = _ConformanceClient(unknown_once=True)
    journal = _ReceiptSink()
    adapter, *_ = _adapter(
        binding=binding,
        client=client,
        sink=journal,
    )
    target = _partition_target(placement_id)

    with pytest.raises(RuntimeProviderError) as unknown:
        adapter.allocate_partition(target=target, idempotency_key="unknown-key")
    assert unknown.value.disposition is RuntimeProviderFailureDisposition.UNKNOWN_EFFECT_RECONCILE
    assert "provider-secret-value" not in str(unknown.value)

    restarted, *_ = _adapter(binding=binding, client=client, sink=journal)
    recovered = restarted.allocate_partition(target=target, idempotency_key="unknown-key")
    assert recovered.physical_partition_key == "physical-partition-42"
    assert len(client.executions) == 1
    assert len(client.reconciliations) == 1
    assert restarted.last_receipt is not None
    assert restarted.last_receipt.outcome is RuntimeProviderOutcome.REPLAYED


@pytest.mark.parametrize("tamper", ["signature", "outcome", "credential_ref"])
def test_journal_replay_fails_closed_for_tampered_response(tamper: str) -> None:
    placement_id = uuid4()
    binding = _binding(placement_id)
    client = _ConformanceClient()
    journal = _ReceiptSink()
    adapter, *_ = _adapter(binding=binding, client=client, sink=journal)
    target = _partition_target(placement_id)

    adapter.allocate_partition(target=target, idempotency_key="journal-tamper")
    operation = client.executions[-1]
    key = (operation.provider_type, operation.kind, operation.idempotency_hash)
    request_hash, stored = journal.entries[key]
    assert stored is not None
    receipt = stored.receipt
    if tamper == "signature":
        tampered_receipt = replace(receipt, signature_hex="f" * 64)
    elif tamper == "outcome":
        tampered_receipt = _resign_receipt(
            replace(receipt, outcome=RuntimeProviderOutcome.ALREADY_ABSENT)
        )
    else:
        tampered_receipt = _resign_receipt(
            replace(
                receipt,
                credential_ref_hash=sha256(b"another-provider-credential-ref").hexdigest(),
            )
        )
    journal.entries[key] = (
        request_hash,
        RuntimeProviderResponse(receipt=tampered_receipt, attributes=stored.attributes),
    )
    replay_verifier = _ReceiptVerifier()
    restarted, *_ = _adapter(
        binding=binding,
        client=client,
        verifier=replay_verifier,
        sink=journal,
    )

    with pytest.raises(RuntimeProviderError) as raised:
        restarted.allocate_partition(target=target, idempotency_key="journal-tamper")

    assert raised.value.disposition is RuntimeProviderFailureDisposition.RECEIPT_INVALID
    assert restarted.last_receipt is None
    assert len(client.executions) == 1
    assert client.reconciliations == []


def test_journal_replay_accepts_historical_receipt_after_credential_rotation() -> None:
    placement_id = uuid4()
    binding = _binding(placement_id)
    client = _ConformanceClient()
    journal = _ReceiptSink()
    adapter, *_ = _adapter(binding=binding, client=client, sink=journal)
    target = _partition_target(placement_id)

    first = adapter.allocate_partition(target=target, idempotency_key="journal-rotation")
    historical_receipt = journal.receipts[-1]
    replay_verifier = _ReceiptVerifier()
    restarted, *_ = _adapter(
        binding=binding,
        client=client,
        credentials=_CredentialAuthority(version="provider-secret-version-8"),
        verifier=replay_verifier,
        sink=journal,
    )

    replayed = restarted.allocate_partition(
        target=target,
        idempotency_key="journal-rotation",
    )

    assert replayed == first
    assert replay_verifier.verified == [historical_receipt]
    assert (
        historical_receipt.credential_version_hash
        != sha256(b"provider-secret-version-8").hexdigest()
    )
    assert len(client.executions) == 1
    assert client.reconciliations == []


def test_binding_rotation_replays_and_compensates_only_with_frozen_historical_binding() -> None:
    placement_id = uuid4()
    old_binding = _binding(placement_id)
    new_binding = replace(
        old_binding,
        binding_revision="provider-binding-2026-08-25-v2",
        endpoint_ref="service://runtime-provider-cn-east-1-v2",
        credential_ref="vault://runtime-provider/production-v2",
    )
    client = _ConformanceClient()
    journal = _ReceiptSink()
    frozen_target = _partition_target(placement_id, binding=old_binding)
    original, *_ = _adapter(binding=old_binding, client=client, sink=journal)
    first = original.allocate_partition(
        target=frozen_target,
        idempotency_key="binding-rotation-runtime",
    )

    rotated, *_ = _adapter(
        binding=new_binding,
        client=client,
        sink=journal,
        historical_bindings=(old_binding,),
    )
    active_snapshot = rotated.binding_snapshot(placement_id)
    replayed = rotated.allocate_partition(
        target=frozen_target,
        idempotency_key="binding-rotation-runtime",
    )
    rotated.compensate_partition(
        target=frozen_target,
        idempotency_key="binding-rotation-compensation",
    )

    assert active_snapshot.binding_hash == new_binding.binding_hash
    assert replayed == first
    assert len(client.executions) == 2
    assert client.executions[-1].binding_hash == old_binding.binding_hash
    assert all(
        operation.binding_hash != new_binding.binding_hash for operation in client.executions
    )


def test_binding_rotation_without_frozen_history_fails_before_new_account_effect() -> None:
    placement_id = uuid4()
    old_binding = _binding(placement_id)
    new_binding = replace(
        old_binding,
        binding_revision="provider-binding-2026-08-25-v2",
        account_ref_hash=sha256(b"provider-account-84").hexdigest(),
    )
    client = _ConformanceClient()
    journal = _ReceiptSink()
    frozen_target = _partition_target(placement_id, binding=old_binding)
    rotated, *_ = _adapter(binding=new_binding, client=client, sink=journal)

    with pytest.raises(RuntimeProviderError) as raised:
        rotated.allocate_partition(
            target=frozen_target,
            idempotency_key="binding-history-missing",
        )

    assert raised.value.code == "provider_binding_snapshot_unavailable"
    assert raised.value.disposition is RuntimeProviderFailureDisposition.UNKNOWN_EFFECT_RECONCILE
    assert client.executions == []
    assert client.reconciliations == []
    assert journal.entries == {}


def test_active_binding_region_mismatch_fails_before_journal_or_provider_effect() -> None:
    placement_id = uuid4()
    binding = replace(_binding(placement_id), region="us-west-2")
    client = _ConformanceClient()
    journal = _ReceiptSink()
    adapter, *_ = _adapter(binding=binding, client=client, sink=journal)

    with pytest.raises(RuntimeProviderError) as raised:
        adapter.allocate_partition(
            target=_partition_target(placement_id, binding=binding),
            idempotency_key="binding-region-mismatch-active",
        )

    assert raised.value.code == "provider_binding_region_mismatch"
    assert raised.value.disposition is RuntimeProviderFailureDisposition.PERMANENT_NO_EFFECT
    assert journal.entries == {}
    assert client.executions == []
    assert client.reconciliations == []


def test_historical_binding_region_mismatch_fails_before_replay_or_compensation() -> None:
    placement_id = uuid4()
    historical = replace(
        _binding(placement_id),
        binding_revision="runtime-binding-historical",
        region="eu-central-1",
    )
    active = replace(
        _binding(placement_id),
        binding_revision="runtime-binding-current",
    )
    client = _ConformanceClient()
    journal = _ReceiptSink()
    adapter, *_ = _adapter(
        binding=active,
        client=client,
        sink=journal,
        historical_bindings=(historical,),
    )
    target = _partition_target(placement_id, binding=historical)

    with pytest.raises(RuntimeProviderError) as raised:
        adapter.compensate_partition(
            target=target,
            idempotency_key="binding-region-mismatch-historical",
        )

    assert raised.value.code == "provider_binding_region_mismatch"
    assert raised.value.disposition is RuntimeProviderFailureDisposition.PERMANENT_NO_EFFECT
    assert journal.entries == {}
    assert client.executions == []
    assert client.reconciliations == []


def test_completed_journal_replay_does_not_require_current_provider_credentials() -> None:
    placement_id = uuid4()
    binding = _binding(placement_id)
    client = _ConformanceClient()
    journal = _ReceiptSink()
    adapter, *_ = _adapter(binding=binding, client=client, sink=journal)
    target = _partition_target(placement_id)

    first = adapter.allocate_partition(target=target, idempotency_key="journal-offline")
    unavailable = _UnavailableCredentialAuthority()
    replay_verifier = _ReceiptVerifier()
    restarted, *_ = _adapter(
        binding=binding,
        client=client,
        credentials=unavailable,
        verifier=replay_verifier,
        sink=journal,
    )

    replayed = restarted.allocate_partition(
        target=target,
        idempotency_key="journal-offline",
    )

    assert replayed == first
    assert unavailable.acquisitions == 0
    assert replay_verifier.verified == [journal.receipts[-1]]
    assert len(client.executions) == 1
    assert client.reconciliations == []


@pytest.mark.parametrize(
    "credentials",
    [
        _UnavailableCredentialAuthority(),
        _EnterFailingCredentialAuthority(),
        _ScopeMismatchedCredentialAuthority(),
    ],
    ids=["acquire", "enter", "scope"],
)
def test_pre_fence_credential_failure_is_unknown_and_does_not_create_journal_fence(
    credentials: _CredentialAuthority,
) -> None:
    placement_id = uuid4()
    binding = _binding(placement_id)
    client = _ConformanceClient()
    journal = _ReceiptSink()
    target = _partition_target(placement_id)
    failed, *_ = _adapter(
        binding=binding,
        client=client,
        credentials=credentials,
        sink=journal,
    )

    with pytest.raises(RuntimeProviderError) as raised:
        failed.allocate_partition(target=target, idempotency_key="credential-before-effect")

    assert raised.value.disposition is RuntimeProviderFailureDisposition.UNKNOWN_EFFECT_RECONCILE
    assert journal.entries == {}
    assert client.executions == []
    assert client.reconciliations == []

    retry, *_ = _adapter(binding=binding, client=client, sink=journal)
    recovered = retry.allocate_partition(
        target=target,
        idempotency_key="credential-before-effect",
    )

    assert recovered.physical_partition_key == "physical-partition-42"
    assert len(client.executions) == 1
    assert client.reconciliations == []


def test_concurrent_winner_prevents_loser_from_claiming_no_effect() -> None:
    from threading import Barrier, Event

    placement_id = uuid4()
    binding = _binding(placement_id)
    journal = _ReceiptSink()
    client = _ConformanceClient()
    target = _partition_target(placement_id)
    rendezvous = Barrier(2)
    winner_done = Event()

    @dataclass(slots=True)
    class _LoseAfterLookupCredentials(_CredentialAuthority):
        @contextmanager
        def acquire(
            self,
            *,
            binding: RuntimeProviderBinding,
            operation: RuntimeProviderOperationKind,
        ) -> Iterator[RuntimeProviderCredential]:
            del binding, operation
            rendezvous.wait(timeout=5)
            assert winner_done.wait(timeout=5)
            raise RuntimeError("credential backend unavailable after concurrent effect")
            yield  # pragma: no cover

    loser, *_ = _adapter(
        binding=binding,
        client=client,
        credentials=_LoseAfterLookupCredentials(),
        sink=journal,
    )
    winner, *_ = _adapter(binding=binding, client=client, sink=journal)

    def lose() -> RuntimeProviderError:
        with pytest.raises(RuntimeProviderError) as raised:
            loser.allocate_partition(target=target, idempotency_key="pre-fence-race")
        return raised.value

    with ThreadPoolExecutor(max_workers=1) as executor:
        losing = executor.submit(lose)
        rendezvous.wait(timeout=5)
        completed = winner.allocate_partition(target=target, idempotency_key="pre-fence-race")
        winner_done.set()
        error = losing.result(timeout=5)

    assert completed.physical_partition_key == "physical-partition-42"
    assert error.disposition is RuntimeProviderFailureDisposition.UNKNOWN_EFFECT_RECONCILE
    assert len(client.executions) == 1
    assert len(journal.receipts) == 1


@pytest.mark.parametrize(
    "credentials_type",
    [
        _UnavailableCredentialAuthority,
        _EnterFailingCredentialAuthority,
        _ScopeMismatchedCredentialAuthority,
    ],
    ids=["acquire", "enter", "scope"],
)
@pytest.mark.parametrize("compensation", [False, True], ids=["operation", "compensation"])
def test_pending_fence_credential_failure_remains_unknown_until_reconciled(
    credentials_type: type[_CredentialAuthority],
    compensation: bool,
) -> None:
    placement_id = uuid4()
    binding = _binding(placement_id)
    client = _ConformanceClient(unknown_once=True)
    journal = _ReceiptSink()
    target = _partition_target(placement_id)
    idempotency_key = "pending-credential-compensation" if compensation else "pending-credential"
    first, *_ = _adapter(binding=binding, client=client, sink=journal)

    with pytest.raises(RuntimeProviderError) as initial:
        if compensation:
            first.compensate_partition(target=target, idempotency_key=idempotency_key)
        else:
            first.allocate_partition(target=target, idempotency_key=idempotency_key)

    expected = (
        RuntimeProviderFailureDisposition.COMPENSATION_UNKNOWN
        if compensation
        else RuntimeProviderFailureDisposition.UNKNOWN_EFFECT_RECONCILE
    )
    assert initial.value.disposition is expected
    assert len(client.executions) == 1
    assert client.reconciliations == []

    blocked, *_ = _adapter(
        binding=binding,
        client=client,
        credentials=credentials_type(),
        sink=journal,
    )
    with pytest.raises(RuntimeProviderError) as credential_failure:
        if compensation:
            blocked.compensate_partition(target=target, idempotency_key=idempotency_key)
        else:
            blocked.allocate_partition(target=target, idempotency_key=idempotency_key)

    assert credential_failure.value.disposition is expected
    assert len(client.executions) == 1
    assert client.reconciliations == []

    recovered, *_ = _adapter(binding=binding, client=client, sink=journal)
    if compensation:
        assert (
            recovered.compensate_partition(target=target, idempotency_key=idempotency_key) is None
        )
    else:
        assert (
            recovered.allocate_partition(
                target=target, idempotency_key=idempotency_key
            ).physical_partition_key
            == "physical-partition-42"
        )
    assert len(client.executions) == 1
    assert len(client.reconciliations) == 1


def test_pending_fence_rejects_begin_regression_to_new_without_execution() -> None:
    class _RegressingJournal(_ReceiptSink):
        regress: bool = False

        def begin(self, operation: RuntimeProviderOperation) -> RuntimeProviderJournalEntry:
            entry = super().begin(operation)
            return replace(entry, is_new=True) if self.regress else entry

    placement_id = uuid4()
    binding = _binding(placement_id)
    client = _ConformanceClient(unknown_once=True)
    journal = _RegressingJournal()
    target = _partition_target(placement_id)
    first, *_ = _adapter(binding=binding, client=client, sink=journal)

    with pytest.raises(RuntimeProviderError):
        first.allocate_partition(target=target, idempotency_key="journal-regression")
    journal.regress = True
    restarted, *_ = _adapter(binding=binding, client=client, sink=journal)

    with pytest.raises(RuntimeProviderError) as raised:
        restarted.allocate_partition(target=target, idempotency_key="journal-regression")

    assert raised.value.code == "provider_journal_invalid"
    assert raised.value.disposition is RuntimeProviderFailureDisposition.UNKNOWN_EFFECT_RECONCILE
    assert len(client.executions) == 1
    assert client.reconciliations == []


@pytest.mark.parametrize("stage", ["lookup", "begin"])
@pytest.mark.parametrize("compensation", [False, True], ids=["operation", "compensation"])
def test_journal_availability_failure_is_never_reported_as_no_effect(
    stage: str,
    compensation: bool,
) -> None:
    class _UnavailableJournal(_ReceiptSink):
        def lookup(
            self, operation: RuntimeProviderOperation
        ) -> RuntimeProviderJournalEntry | None:
            if stage == "lookup":
                raise RuntimeError("journal-secret-lookup")
            return super().lookup(operation)

        def begin(self, operation: RuntimeProviderOperation) -> RuntimeProviderJournalEntry:
            if stage == "begin":
                raise RuntimeError("journal-secret-begin")
            return super().begin(operation)

    placement_id = uuid4()
    binding = _binding(placement_id)
    client = _ConformanceClient()
    journal = _UnavailableJournal()
    adapter, *_ = _adapter(binding=binding, client=client, sink=journal)
    target = _partition_target(placement_id)

    with pytest.raises(RuntimeProviderError) as raised:
        if compensation:
            adapter.compensate_partition(target=target, idempotency_key="journal-unavailable")
        else:
            adapter.allocate_partition(target=target, idempotency_key="journal-unavailable")

    expected = (
        RuntimeProviderFailureDisposition.COMPENSATION_UNKNOWN
        if compensation
        else RuntimeProviderFailureDisposition.UNKNOWN_EFFECT_RECONCILE
    )
    assert raised.value.disposition is expected
    assert raised.value.code == "provider_journal_unavailable"
    assert "journal-secret" not in str(raised.value)
    assert client.executions == []
    assert client.reconciliations == []


def test_credential_context_cannot_suppress_receipt_rejection() -> None:
    placement_id = uuid4()
    binding = _binding(placement_id)
    client = _ConformanceClient()
    credentials = _SuppressingCredentialAuthority()
    verifier = _ReceiptVerifier(reject=True)
    journal = _ReceiptSink()
    adapter, *_ = _adapter(
        binding=binding,
        client=client,
        credentials=credentials,
        verifier=verifier,
        sink=journal,
    )

    with pytest.raises(RuntimeProviderError) as raised:
        adapter.allocate_partition(
            target=_partition_target(placement_id),
            idempotency_key="suppressed-receipt-rejection",
        )

    assert raised.value.disposition is RuntimeProviderFailureDisposition.UNKNOWN_EFFECT_RECONCILE
    assert raised.value.code == "provider_credential_lifecycle_failed"
    assert credentials.suppressions == 1
    assert len(client.executions) == 1
    assert journal.receipts == []
    assert next(iter(journal.entries.values()))[1] is None


@pytest.mark.parametrize("compensation", [False, True], ids=["operation", "compensation"])
def test_terminal_begin_replay_exit_failure_is_unknown_and_remains_replayable(
    compensation: bool,
) -> None:
    class _LookupMissOnceJournal(_ReceiptSink):
        miss_once: bool = False

        def lookup(
            self, operation: RuntimeProviderOperation
        ) -> RuntimeProviderJournalEntry | None:
            if self.miss_once:
                self.miss_once = False
                return None
            return super().lookup(operation)

    placement_id = uuid4()
    binding = _binding(placement_id)
    client = _ConformanceClient()
    journal = _LookupMissOnceJournal()
    target = _partition_target(placement_id)
    idempotency_key = "terminal-exit-compensation" if compensation else "terminal-exit"
    initial, *_ = _adapter(binding=binding, client=client, sink=journal)
    if compensation:
        assert initial.compensate_partition(target=target, idempotency_key=idempotency_key) is None
    else:
        initial.allocate_partition(target=target, idempotency_key=idempotency_key)

    journal.miss_once = True
    failing_credentials = _ExitFailingCredentialAuthority()
    replay, *_ = _adapter(
        binding=binding,
        client=client,
        credentials=failing_credentials,
        sink=journal,
    )
    with pytest.raises(RuntimeProviderError) as raised:
        if compensation:
            replay.compensate_partition(target=target, idempotency_key=idempotency_key)
        else:
            replay.allocate_partition(target=target, idempotency_key=idempotency_key)

    expected = (
        RuntimeProviderFailureDisposition.COMPENSATION_UNKNOWN
        if compensation
        else RuntimeProviderFailureDisposition.UNKNOWN_EFFECT_RECONCILE
    )
    assert raised.value.disposition is expected
    assert failing_credentials.exits == 1

    unavailable = _UnavailableCredentialAuthority()
    replay_without_credentials, *_ = _adapter(
        binding=binding,
        client=client,
        credentials=unavailable,
        sink=journal,
    )
    if compensation:
        assert (
            replay_without_credentials.compensate_partition(
                target=target,
                idempotency_key=idempotency_key,
            )
            is None
        )
    else:
        replay_without_credentials.allocate_partition(
            target=target,
            idempotency_key=idempotency_key,
        )
    assert unavailable.acquisitions == 0


def test_journal_replay_snapshots_attributes_before_receipt_verification() -> None:
    placement_id = uuid4()
    binding = _binding(placement_id)
    client = _ConformanceClient()
    journal = _ReceiptSink()
    adapter, *_ = _adapter(binding=binding, client=client, sink=journal)
    target = _partition_target(placement_id)

    first = adapter.allocate_partition(target=target, idempotency_key="journal-snapshot")
    operation = client.executions[-1]
    key = (operation.provider_type, operation.kind, operation.idempotency_hash)
    request_hash, stored = journal.entries[key]
    assert stored is not None
    mutable_attributes = dict(stored.attributes)
    journal.entries[key] = (
        request_hash,
        RuntimeProviderResponse(
            receipt=stored.receipt,
            attributes=mutable_attributes,
        ),
    )

    class _MutatingVerifier(_ReceiptVerifier):
        def verify(
            self,
            *,
            binding: RuntimeProviderBinding,
            receipt: RuntimeProviderReceipt,
            payload: bytes,
        ) -> bool:
            mutable_attributes["runtime_user_key"] = "tampered-after-result-hash"
            return super().verify(binding=binding, receipt=receipt, payload=payload)

    restarted, *_ = _adapter(
        binding=binding,
        client=client,
        verifier=_MutatingVerifier(),
        sink=journal,
    )

    replayed = restarted.allocate_partition(
        target=target,
        idempotency_key="journal-snapshot",
    )

    assert replayed == first
    assert mutable_attributes["runtime_user_key"] == "tampered-after-result-hash"
    assert len(client.executions) == 1
    assert client.reconciliations == []


def test_compensation_accepts_signed_already_absent_receipt() -> None:
    placement_id = uuid4()
    adapter, _client, _credentials, verifier, sink = _adapter(
        binding=_binding(placement_id),
        client=_ConformanceClient(compensation_absent=True),
    )
    target = _partition_target(placement_id)

    assert (
        adapter.compensate_partition(
            target=target,
            idempotency_key="absent-compensation",
        )
        is None
    )
    assert verifier.verified[-1].outcome is RuntimeProviderOutcome.ALREADY_ABSENT
    assert sink.receipts[-1].provider_resource_id is None
    assert adapter.last_receipt is sink.receipts[-1]


@pytest.mark.parametrize("invalid_receipt", ["target", "signature", "result"])
def test_invalid_provider_receipt_fails_closed(invalid_receipt: str) -> None:
    placement_id = uuid4()
    adapter, *_ = _adapter(
        binding=_binding(placement_id),
        client=_ConformanceClient(invalid_receipt=invalid_receipt),
    )

    with pytest.raises(RuntimeProviderError) as raised:
        adapter.allocate_partition(
            target=_partition_target(placement_id),
            idempotency_key=f"invalid-{invalid_receipt}",
        )
    assert raised.value.disposition is RuntimeProviderFailureDisposition.RECEIPT_INVALID
    assert adapter.last_receipt is None


def test_compensation_unknown_effect_uses_compensation_reconcile_contract() -> None:
    placement_id = uuid4()
    adapter, client, *_ = _adapter(
        binding=_binding(placement_id),
        client=_ConformanceClient(unknown_once=True),
    )
    target = _partition_target(placement_id)

    with pytest.raises(RuntimeProviderError) as unknown:
        adapter.compensate_partition(
            target=target,
            idempotency_key="unknown-compensation",
        )
    assert unknown.value.disposition is RuntimeProviderFailureDisposition.COMPENSATION_UNKNOWN

    assert (
        adapter.compensate_partition(
            target=target,
            idempotency_key="unknown-compensation",
        )
        is None
    )
    assert len(client.executions) == 1
    assert len(client.reconciliations) == 1


def test_receipt_hashes_and_signatures_require_strict_lowercase_hex() -> None:
    placement_id = uuid4()
    adapter, _client, _credentials, _verifier, sink = _adapter(binding=_binding(placement_id))
    adapter.allocate_partition(
        target=_partition_target(placement_id),
        idempotency_key="strict-lower-hex",
    )
    receipt = sink.receipts[-1]

    with pytest.raises(ValueError, match="signature"):
        replace(receipt, signature_hex="A" * 64)
    with pytest.raises(ValueError, match="result hash"):
        replace(receipt, result_hash="A" * 64)


def test_secret_values_are_absent_from_repr_errors_operations_and_receipts() -> None:
    placement_id = uuid4()
    binding = _binding(placement_id)
    credentials = _CredentialAuthority(secret="super-secret-provider-token")
    adapter, client, *_rest, sink = _adapter(
        binding=binding,
        credentials=credentials,
        client=_ConformanceClient(unknown_once=True),
    )

    with pytest.raises(RuntimeProviderError) as raised:
        adapter.allocate_partition(
            target=_partition_target(placement_id),
            idempotency_key="secret-redaction-key",
        )

    rendered = "\n".join(
        (
            repr(binding),
            repr(client.executions[0]),
            str(raised.value),
            repr(credentials),
            repr(
                RuntimeProviderCredential(
                    credential_ref_hash=binding.credential_ref_hash,
                    version="provider-secret-version-7",
                    material="super-secret-provider-token",
                )
            ),
            repr(sink.receipts),
        )
    )
    assert "super-secret-provider-token" not in rendered
    assert "vault://runtime-provider/production" not in rendered
    assert "secret-redaction-key" not in rendered
    assert binding.account_ref_hash in repr(binding)


@pytest.mark.parametrize(
    "disposition",
    [
        RuntimeProviderFailureDisposition.RETRYABLE_NO_EFFECT,
        RuntimeProviderFailureDisposition.PERMANENT_NO_EFFECT,
        RuntimeProviderFailureDisposition.UNKNOWN_EFFECT_RECONCILE,
        RuntimeProviderFailureDisposition.IDEMPOTENCY_CONFLICT,
        RuntimeProviderFailureDisposition.RECEIPT_INVALID,
        RuntimeProviderFailureDisposition.COMPENSATION_RETRYABLE,
        RuntimeProviderFailureDisposition.COMPENSATION_UNKNOWN,
    ],
)
def test_failure_taxonomy_has_stable_secret_free_dispositions(
    disposition: RuntimeProviderFailureDisposition,
) -> None:
    error = RuntimeProviderError(disposition.value, disposition)
    assert error.disposition is disposition
    assert str(error)


def test_production_adapter_rejects_test_clients_ambient_credentials_and_test_verifiers() -> None:
    placement_id = uuid4()
    binding = _binding(placement_id)

    class _JournalWithoutLookup:
        production_capable = True
        durable = True
        conflict_safe = True

        def begin(self, operation: RuntimeProviderOperation) -> RuntimeProviderJournalEntry:
            raise AssertionError(operation)

        def record_verified(
            self,
            *,
            operation: RuntimeProviderOperation,
            response: RuntimeProviderResponse,
        ) -> None:
            raise AssertionError(operation, response)

    with pytest.raises(ValueError, match="test or mismatched"):
        _adapter(binding=binding, client=_ConformanceClient(test_only=True))
    with pytest.raises(ValueError, match="ambient"):
        _adapter(
            binding=binding,
            credentials=_CredentialAuthority(uses_ambient_credentials=True),
        )
    with pytest.raises(ValueError, match="verifier"):
        _adapter(binding=binding, verifier=_ReceiptVerifier(test_only=True))
    with pytest.raises(ValueError, match="journal"):
        _adapter(binding=binding, sink=_ReceiptSink(durable=False))
    with pytest.raises(TypeError, match="operation journal"):
        ProductionRuntimePartitionAdapter(
            bindings={binding.placement_id: binding},
            client=_ConformanceClient(),
            credentials=_CredentialAuthority(),
            receipt_verifier=_ReceiptVerifier(),
            operation_journal=cast(
                RuntimeProviderOperationJournal,
                _JournalWithoutLookup(),
            ),
        )
    with pytest.raises(ValueError, match="ambient or inline"):
        replace(binding, credential_ref="env://RUNTIME_PROVIDER_TOKEN")


def test_production_adapter_readiness_rejects_uninitialized_or_overridden_instances() -> None:
    uninitialized = object.__new__(ProductionRuntimePartitionAdapter)
    with pytest.raises(RuntimeError, match="construction-sealed"):
        uninitialized.assert_production_ready()

    with pytest.raises(TypeError, match="cannot be subclassed"):

        class _OverriddenRuntimeAdapter(ProductionRuntimePartitionAdapter):
            pass


def test_canonical_hash_rejects_unsupported_values_and_is_order_independent() -> None:
    first = canonical_sha256({"b": 2, "a": {"value": "same"}})
    second = canonical_sha256({"a": {"value": "same"}, "b": 2})
    assert first == second
    assert len(first) == 64 and first == first.lower()
    with pytest.raises(TypeError, match="unsupported"):
        canonical_sha256({"float": 1.5})


def _is_compensation(kind: RuntimeProviderOperationKind) -> bool:
    return kind in {
        RuntimeProviderOperationKind.COMPENSATE_DEFAULT_PROJECT,
        RuntimeProviderOperationKind.COMPENSATE_PARTITION,
    }
