"""Provider-neutral production contract for Runtime Partition provisioning.

This module deliberately contains no concrete Provider transport and no secret
lookup implementation.  It adapts a deployment-owned Provider client to the
existing :class:`RuntimePartitionProvisioner` seam while making request replay,
failure classification, and signed receipt verification mandatory.
"""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from hashlib import sha256
from types import MappingProxyType
from typing import Protocol, cast
from urllib.parse import urlsplit
from uuid import UUID

from saas.control_plane.onboarding_workflow import (
    RuntimePartitionAllocation,
    RuntimePartitionTarget,
    RuntimeProjectAllocation,
    RuntimeProjectTarget,
    RuntimeProviderBindingSnapshot,
)

_LOWER_HEX_64 = re.compile(r"[0-9a-f]{64}")
_LOWER_HEX_SIGNATURE = re.compile(r"(?:[0-9a-f]{2}){32,512}")
_SAFE_TOKEN = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
_PRODUCTION_CREDENTIAL_SCHEMES = frozenset({"kms", "secret", "vault", "workload-identity"})
_FORBIDDEN_PROVIDER_TYPES = frozenset(
    {"fake", "in-memory", "local", "memory", "mock", "stub", "test"}
)
_PRODUCTION_ADAPTER_SEAL = object()


class RuntimeProviderOperationKind(StrEnum):
    ALLOCATE_PARTITION = "allocate_partition"
    PROVISION_DEFAULT_PROJECT = "provision_default_project"
    COMPENSATE_DEFAULT_PROJECT = "compensate_default_project"
    COMPENSATE_PARTITION = "compensate_partition"


class RuntimeProviderOutcome(StrEnum):
    APPLIED = "applied"
    REPLAYED = "replayed"
    ALREADY_ABSENT = "already_absent"


class RuntimeProviderFailureDisposition(StrEnum):
    RETRYABLE_NO_EFFECT = "retryable_no_effect"
    PERMANENT_NO_EFFECT = "permanent_no_effect"
    UNKNOWN_EFFECT_RECONCILE = "unknown_effect_reconcile"
    IDEMPOTENCY_CONFLICT = "idempotency_conflict"
    RECEIPT_INVALID = "receipt_invalid"
    COMPENSATION_RETRYABLE = "compensation_retryable"
    COMPENSATION_UNKNOWN = "compensation_unknown"


_SAFE_FAILURE_MESSAGES: dict[RuntimeProviderFailureDisposition, str] = {
    RuntimeProviderFailureDisposition.RETRYABLE_NO_EFFECT: (
        "Runtime Provider operation can be retried safely"
    ),
    RuntimeProviderFailureDisposition.PERMANENT_NO_EFFECT: (
        "Runtime Provider rejected the operation before applying it"
    ),
    RuntimeProviderFailureDisposition.UNKNOWN_EFFECT_RECONCILE: (
        "Runtime Provider outcome requires reconciliation"
    ),
    RuntimeProviderFailureDisposition.IDEMPOTENCY_CONFLICT: (
        "Runtime Provider idempotency identity belongs to another request"
    ),
    RuntimeProviderFailureDisposition.RECEIPT_INVALID: ("Runtime Provider receipt is invalid"),
    RuntimeProviderFailureDisposition.COMPENSATION_RETRYABLE: (
        "Runtime Provider compensation can be retried safely"
    ),
    RuntimeProviderFailureDisposition.COMPENSATION_UNKNOWN: (
        "Runtime Provider compensation requires reconciliation"
    ),
}


class RuntimeProviderError(RuntimeError):
    """Secret-free, stable failure returned to the onboarding Saga."""

    def __init__(
        self,
        code: str,
        disposition: RuntimeProviderFailureDisposition,
        message: str | None = None,
        *,
        retry_after_seconds: int | None = None,
    ) -> None:
        if _SAFE_TOKEN.fullmatch(code) is None:
            raise ValueError("Runtime Provider error code is invalid")
        if retry_after_seconds is not None and not 1 <= retry_after_seconds <= 86400:
            raise ValueError("Runtime Provider retry delay is invalid")
        self.code = code
        self.disposition = disposition
        self.retry_after_seconds = retry_after_seconds
        super().__init__(message or _SAFE_FAILURE_MESSAGES[disposition])


@dataclass(frozen=True, slots=True)
class RuntimeProviderBinding:
    """Pinned deployment binding for one Placement; refs never contain values."""

    provider_type: str
    placement_id: UUID
    binding_revision: str
    endpoint_ref: str = field(repr=False)
    credential_ref: str = field(repr=False)
    account_ref_hash: str
    region: str

    def __post_init__(self) -> None:
        provider_type = self.provider_type.strip().lower()
        if (
            _SAFE_TOKEN.fullmatch(provider_type) is None
            or provider_type in _FORBIDDEN_PROVIDER_TYPES
        ):
            raise ValueError("Runtime Provider type is not production-safe")
        if _SAFE_TOKEN.fullmatch(self.binding_revision) is None:
            raise ValueError("Runtime Provider binding revision is invalid")
        region = self.region.strip().lower()
        if _SAFE_TOKEN.fullmatch(region) is None:
            raise ValueError("Runtime Provider region is invalid")
        _require_lower_hex(self.account_ref_hash, "Provider account reference hash")
        _require_opaque_ref(self.endpoint_ref, "Provider endpoint reference")
        _require_credential_ref(self.credential_ref)
        object.__setattr__(self, "provider_type", provider_type)
        object.__setattr__(self, "region", region)

    @property
    def endpoint_ref_hash(self) -> str:
        return _text_hash(self.endpoint_ref)

    @property
    def credential_ref_hash(self) -> str:
        return _text_hash(self.credential_ref)

    @property
    def binding_hash(self) -> str:
        return canonical_sha256(
            {
                "schema_version": 1,
                "provider_type": self.provider_type,
                "placement_id": str(self.placement_id),
                "binding_revision": self.binding_revision,
                "endpoint_ref_hash": self.endpoint_ref_hash,
                "credential_ref_hash": self.credential_ref_hash,
                "account_ref_hash": self.account_ref_hash,
                "region": self.region,
            }
        )


@dataclass(frozen=True, slots=True)
class RuntimeProviderCredential:
    """Short-lived credential handle whose material is never printable."""

    credential_ref_hash: str
    version: str
    material: object = field(repr=False)

    def __post_init__(self) -> None:
        _require_lower_hex(self.credential_ref_hash, "credential reference hash")
        if not self.version.strip() or len(self.version) > 256:
            raise ValueError("Runtime Provider credential version is invalid")

    @property
    def version_hash(self) -> str:
        return _text_hash(self.version)


class RuntimeProviderCredentialAuthority(Protocol):
    """Deployment authority for non-ambient, short-lived Provider credentials."""

    production_capable: bool
    uses_ambient_credentials: bool

    def acquire(
        self,
        *,
        binding: RuntimeProviderBinding,
        operation: RuntimeProviderOperationKind,
    ) -> AbstractContextManager[RuntimeProviderCredential]: ...


@dataclass(frozen=True, slots=True)
class RuntimeProviderOperation:
    """Canonical request whose hashes bind one key to one frozen target."""

    kind: RuntimeProviderOperationKind
    provider_type: str
    placement_id: UUID
    binding_revision: str
    binding_hash: str
    target_hash: str
    idempotency_hash: str
    request_hash: str
    target_json: str = field(repr=False)
    idempotency_key: str = field(repr=False)

    def __post_init__(self) -> None:
        for value, label in (
            (self.binding_hash, "binding hash"),
            (self.target_hash, "target hash"),
            (self.idempotency_hash, "idempotency hash"),
            (self.request_hash, "request hash"),
        ):
            _require_lower_hex(value, label)
        if not self.idempotency_key or len(self.idempotency_key) > 256:
            raise ValueError("Runtime Provider idempotency key is invalid")
        target = json.loads(self.target_json)
        if not isinstance(target, dict) or canonical_json(target) != self.target_json:
            raise ValueError("Runtime Provider target document is not canonical")
        if canonical_sha256(target) != self.target_hash:
            raise ValueError("Runtime Provider target hash is invalid")

    @property
    def target(self) -> Mapping[str, object]:
        return MappingProxyType(cast(dict[str, object], json.loads(self.target_json)))


@dataclass(frozen=True, slots=True)
class RuntimeProviderReceipt:
    """Signed, secret-free Provider observation bound to one operation request."""

    schema_version: int
    provider_type: str
    operation: RuntimeProviderOperationKind
    outcome: RuntimeProviderOutcome
    placement_id: UUID
    binding_revision: str
    binding_hash: str
    target_hash: str
    idempotency_hash: str
    request_hash: str
    credential_ref_hash: str
    credential_version_hash: str
    result_hash: str
    provider_request_id: str
    provider_resource_id: str | None
    observed_at: datetime
    receipt_hash: str
    signature_key_id: str
    signature_hex: str = field(repr=False)

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("Runtime Provider receipt schema is unsupported")
        for value, label in (
            (self.binding_hash, "binding hash"),
            (self.target_hash, "target hash"),
            (self.idempotency_hash, "idempotency hash"),
            (self.request_hash, "request hash"),
            (self.credential_ref_hash, "credential reference hash"),
            (self.credential_version_hash, "credential version hash"),
            (self.result_hash, "result hash"),
            (self.receipt_hash, "receipt hash"),
        ):
            _require_lower_hex(value, label)
        if _SAFE_TOKEN.fullmatch(self.signature_key_id) is None:
            raise ValueError("Runtime Provider receipt signing key is invalid")
        if _LOWER_HEX_SIGNATURE.fullmatch(self.signature_hex) is None:
            raise ValueError("Runtime Provider receipt signature is invalid")
        if not self.provider_request_id.strip() or len(self.provider_request_id) > 512:
            raise ValueError("Runtime Provider request identity is invalid")
        if self.provider_resource_id is not None and (
            not self.provider_resource_id.strip() or len(self.provider_resource_id) > 512
        ):
            raise ValueError("Runtime Provider resource identity is invalid")
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise ValueError("Runtime Provider receipt timestamp must be timezone-aware")

    def unsigned_document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "provider_type": self.provider_type,
            "operation": self.operation.value,
            "outcome": self.outcome.value,
            "placement_id": str(self.placement_id),
            "binding_revision": self.binding_revision,
            "binding_hash": self.binding_hash,
            "target_hash": self.target_hash,
            "idempotency_hash": self.idempotency_hash,
            "request_hash": self.request_hash,
            "credential_ref_hash": self.credential_ref_hash,
            "credential_version_hash": self.credential_version_hash,
            "result_hash": self.result_hash,
            "provider_request_id": self.provider_request_id,
            "provider_resource_id": self.provider_resource_id,
            "observed_at": self.observed_at.isoformat(),
            "signature_key_id": self.signature_key_id,
        }

    def unsigned_payload(self) -> bytes:
        return canonical_json(self.unsigned_document()).encode("utf-8")


class RuntimeProviderReceiptVerifier(Protocol):
    """Production verification hook, commonly backed by a KMS/HSM public key."""

    production_capable: bool
    test_only: bool

    def verify(
        self,
        *,
        binding: RuntimeProviderBinding,
        receipt: RuntimeProviderReceipt,
        payload: bytes,
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class RuntimeProviderResponse:
    receipt: RuntimeProviderReceipt
    attributes: Mapping[str, object] = field(repr=False)


class RuntimeProviderClient(Protocol):
    """Deployment-owned Provider transport; no implementation is supplied here."""

    provider_type: str
    production_capable: bool
    test_only: bool

    def execute(
        self,
        operation: RuntimeProviderOperation,
        credential: RuntimeProviderCredential,
    ) -> RuntimeProviderResponse: ...

    def reconcile(
        self,
        operation: RuntimeProviderOperation,
        credential: RuntimeProviderCredential,
    ) -> RuntimeProviderResponse: ...


@dataclass(frozen=True, slots=True)
class RuntimeProviderJournalEntry:
    """Durable invocation fence returned before any Provider side effect."""

    request_hash: str
    is_new: bool
    response: RuntimeProviderResponse | None = None

    def __post_init__(self) -> None:
        _require_lower_hex(self.request_hash, "journal request hash")
        if self.is_new and self.response is not None:
            raise ValueError("new Runtime Provider journal entry cannot have a response")


class RuntimeProviderOperationJournal(Protocol):
    """Durable, conflict-safe operation fence and verified receipt authority.

    ``lookup`` is read-only and must never create an operation fence.  It lets
    the adapter replay an already verified response without acquiring current
    Provider credentials.  ``begin`` remains the atomic effect fence and must
    run after credential validation but before the transport is invoked.

    ``begin`` must atomically bind the Provider idempotency identity to the
    request hash before the transport is invoked.  A later call observing an
    existing entry without a response must return ``is_new=False`` so the
    adapter reconciles after process death or acknowledgement loss.
    """

    production_capable: bool
    durable: bool
    conflict_safe: bool

    def lookup(
        self,
        operation: RuntimeProviderOperation,
    ) -> RuntimeProviderJournalEntry | None: ...

    def begin(self, operation: RuntimeProviderOperation) -> RuntimeProviderJournalEntry: ...

    def record_verified(
        self,
        *,
        operation: RuntimeProviderOperation,
        response: RuntimeProviderResponse,
    ) -> None: ...


class ProductionRuntimePartitionAdapter:
    """Verified production adapter for the existing four-operation Runtime SPI."""

    def __init_subclass__(cls, **kwargs: object) -> None:
        del kwargs
        raise TypeError("ProductionRuntimePartitionAdapter cannot be subclassed")

    def __init__(
        self,
        *,
        bindings: Mapping[UUID, RuntimeProviderBinding],
        client: RuntimeProviderClient,
        credentials: RuntimeProviderCredentialAuthority,
        receipt_verifier: RuntimeProviderReceiptVerifier,
        operation_journal: RuntimeProviderOperationJournal,
        historical_bindings: tuple[RuntimeProviderBinding, ...] = (),
    ) -> None:
        if not bindings:
            raise ValueError("at least one Runtime Provider binding is required")
        for name, dependency, methods in (
            ("client", client, ("execute", "reconcile")),
            ("credential authority", credentials, ("acquire",)),
            ("receipt verifier", receipt_verifier, ("verify",)),
            (
                "operation journal",
                operation_journal,
                ("lookup", "begin", "record_verified"),
            ),
        ):
            if any(not callable(getattr(dependency, method, None)) for method in methods):
                raise TypeError(f"Runtime Provider {name} is incomplete")
        frozen = dict(bindings)
        if any(key != binding.placement_id for key, binding in frozen.items()):
            raise ValueError("Runtime Provider binding key does not match its Placement")
        archived = tuple(historical_bindings)
        all_bindings = (*frozen.values(), *archived)
        binding_identities: dict[tuple[UUID, str], RuntimeProviderBinding] = {}
        binding_revisions: dict[tuple[UUID, str], str] = {}
        for binding in all_bindings:
            identity = (binding.placement_id, binding.binding_hash)
            if identity in binding_identities and binding_identities[identity] != binding:
                raise ValueError("Runtime Provider binding identity is ambiguous")
            revision = (binding.placement_id, binding.binding_revision)
            prior_hash = binding_revisions.setdefault(revision, binding.binding_hash)
            if prior_hash != binding.binding_hash:
                raise ValueError("Runtime Provider binding revision is ambiguous")
            binding_identities[identity] = binding
        provider_type = client.provider_type.strip().lower()
        if (
            not client.production_capable
            or client.test_only
            or provider_type in _FORBIDDEN_PROVIDER_TYPES
            or any(binding.provider_type != provider_type for binding in all_bindings)
        ):
            raise ValueError("test or mismatched Runtime Provider client is forbidden")
        if not credentials.production_capable or credentials.uses_ambient_credentials:
            raise ValueError("ambient or non-production Provider credentials are forbidden")
        if not receipt_verifier.production_capable or receipt_verifier.test_only:
            raise ValueError("test or non-production receipt verifier is forbidden")
        if not (
            operation_journal.production_capable
            and operation_journal.durable
            and operation_journal.conflict_safe
        ):
            raise ValueError(
                "Runtime Provider operation journal must be durable and conflict-safe"
            )
        self._bindings = MappingProxyType(frozen)
        self._bindings_by_identity = MappingProxyType(binding_identities)
        self._client = client
        self._credentials = credentials
        self._verifier = receipt_verifier
        self._journal = operation_journal
        self._lock = threading.RLock()
        self._last_receipt: RuntimeProviderReceipt | None = None
        self.__production_adapter_seal = _PRODUCTION_ADAPTER_SEAL
        self.assert_production_ready()

    def assert_production_ready(self) -> None:
        """Fail closed for uninitialized, substituted, or degraded adapters."""

        if (
            type(self) is not ProductionRuntimePartitionAdapter
            or getattr(self, "_ProductionRuntimePartitionAdapter__production_adapter_seal", None)
            is not _PRODUCTION_ADAPTER_SEAL
        ):
            raise RuntimeError("Runtime Provider adapter is not construction-sealed")
        try:
            ready = (
                bool(self._bindings)
                and bool(self._bindings_by_identity)
                and self._client.production_capable
                and not self._client.test_only
                and self._credentials.production_capable
                and not self._credentials.uses_ambient_credentials
                and self._verifier.production_capable
                and not self._verifier.test_only
                and self._journal.production_capable
                and self._journal.durable
                and self._journal.conflict_safe
                and all(
                    callable(method)
                    for method in (
                        self._client.execute,
                        self._client.reconcile,
                        self._credentials.acquire,
                        self._verifier.verify,
                        self._journal.lookup,
                        self._journal.begin,
                        self._journal.record_verified,
                    )
                )
            )
        except (AttributeError, TypeError):
            ready = False
        if not ready:
            raise RuntimeError("Runtime Provider adapter is not production-ready")

    @property
    def last_receipt(self) -> RuntimeProviderReceipt | None:
        with self._lock:
            return self._last_receipt

    def binding_snapshot(self, placement_id: UUID) -> RuntimeProviderBindingSnapshot:
        """Return the active non-secret identity that the Saga must persist."""

        binding = self._bindings.get(placement_id)
        if binding is None:
            raise _failure(
                RuntimeProviderFailureDisposition.PERMANENT_NO_EFFECT,
                code="provider_binding_missing",
            )
        return RuntimeProviderBindingSnapshot(
            provider_type=binding.provider_type,
            binding_revision=binding.binding_revision,
            binding_hash=binding.binding_hash,
        )

    def allocate_partition(
        self, *, target: RuntimePartitionTarget, idempotency_key: str
    ) -> RuntimePartitionAllocation:
        response = self._invoke(
            kind=RuntimeProviderOperationKind.ALLOCATE_PARTITION,
            placement_id=target.placement_id,
            binding_snapshot=target.provider_binding,
            target_region=target.data_region,
            target_document=_partition_target_document(target),
            idempotency_key=idempotency_key,
        )
        if response.receipt.outcome is RuntimeProviderOutcome.ALREADY_ABSENT:
            raise _failure(RuntimeProviderFailureDisposition.RECEIPT_INVALID)
        allocation = RuntimePartitionAllocation(
            runtime_version=_attribute_text(response, "runtime_version", 64),
            physical_partition_key=_attribute_text(response, "physical_partition_key", 128),
            placement_generation=_attribute_positive_int(response, "placement_generation"),
            source_revision=_attribute_text(response, "source_revision", 64),
            adapter_contract_version=_attribute_text(response, "adapter_contract_version", 32),
            runtime_user_key=_attribute_text(response, "runtime_user_key", 128),
            receipt_hash=response.receipt.receipt_hash,
        )
        if response.receipt.provider_resource_id != allocation.physical_partition_key:
            raise _failure(RuntimeProviderFailureDisposition.RECEIPT_INVALID)
        return allocation

    def provision_default_project(
        self, *, target: RuntimeProjectTarget, idempotency_key: str
    ) -> RuntimeProjectAllocation:
        response = self._invoke(
            kind=RuntimeProviderOperationKind.PROVISION_DEFAULT_PROJECT,
            placement_id=target.partition.placement_id,
            binding_snapshot=target.partition.provider_binding,
            target_region=target.partition.data_region,
            target_document=_project_target_document(target),
            idempotency_key=idempotency_key,
        )
        if response.receipt.outcome is RuntimeProviderOutcome.ALREADY_ABSENT:
            raise _failure(RuntimeProviderFailureDisposition.RECEIPT_INVALID)
        resource_id = _attribute_text(response, "runtime_resource_id", 256)
        if response.receipt.provider_resource_id != resource_id:
            raise _failure(RuntimeProviderFailureDisposition.RECEIPT_INVALID)
        return RuntimeProjectAllocation(
            runtime_resource_id=resource_id,
            receipt_hash=response.receipt.receipt_hash,
        )

    def compensate_default_project(
        self, *, target: RuntimeProjectTarget, idempotency_key: str
    ) -> None:
        self._invoke(
            kind=RuntimeProviderOperationKind.COMPENSATE_DEFAULT_PROJECT,
            placement_id=target.partition.placement_id,
            binding_snapshot=target.partition.provider_binding,
            target_region=target.partition.data_region,
            target_document=_project_target_document(target),
            idempotency_key=idempotency_key,
        )

    def compensate_partition(
        self, *, target: RuntimePartitionTarget, idempotency_key: str
    ) -> None:
        self._invoke(
            kind=RuntimeProviderOperationKind.COMPENSATE_PARTITION,
            placement_id=target.placement_id,
            binding_snapshot=target.provider_binding,
            target_region=target.data_region,
            target_document=_partition_target_document(target),
            idempotency_key=idempotency_key,
        )

    def _invoke(
        self,
        *,
        kind: RuntimeProviderOperationKind,
        placement_id: UUID,
        binding_snapshot: RuntimeProviderBindingSnapshot,
        target_region: str,
        target_document: dict[str, object],
        idempotency_key: str,
    ) -> RuntimeProviderResponse:
        binding = self._bindings_by_identity.get((placement_id, binding_snapshot.binding_hash))
        if binding is None or (
            binding.provider_type != binding_snapshot.provider_type
            or binding.binding_revision != binding_snapshot.binding_revision
        ):
            raise _uncertain_for_operation(
                kind,
                code="provider_binding_snapshot_unavailable",
            )
        if binding.region != target_region:
            raise _failure(
                RuntimeProviderFailureDisposition.PERMANENT_NO_EFFECT,
                code="provider_binding_region_mismatch",
            )
        operation = _operation(
            kind=kind,
            binding=binding,
            target_document=target_document,
            idempotency_key=idempotency_key,
        )
        try:
            observed_entry = self._journal.lookup(operation)
        except RuntimeProviderError as error:
            raise _sanitized_for_operation(error, operation.kind) from None
        except Exception:  # noqa: BLE001 - sanitize journal availability failures
            raise _uncertain_for_operation(
                operation.kind,
                code="provider_journal_unavailable",
            ) from None
        if observed_entry is not None and observed_entry.is_new:
            raise _uncertain_for_operation(
                operation.kind,
                code="provider_journal_invalid",
            )
        if observed_entry is not None and observed_entry.request_hash != operation.request_hash:
            raise _failure(RuntimeProviderFailureDisposition.IDEMPOTENCY_CONFLICT)
        if observed_entry is not None and observed_entry.response is not None:
            response = self._validate_journal_response(
                binding,
                operation,
                observed_entry.response,
            )
            with self._lock:
                self._last_receipt = response.receipt
            return response
        historical_effect_pending = observed_entry is not None
        journal_fence_acquired = historical_effect_pending

        try:
            credential_context = self._credentials.acquire(
                binding=binding,
                operation=operation.kind,
            )
        except RuntimeProviderError as error:
            raise _uncertain_for_operation(
                operation.kind,
                code=error.code,
                retry_after_seconds=error.retry_after_seconds,
            ) from None
        except Exception:  # noqa: BLE001 - sanitize deployment credential failures
            raise _uncertain_for_operation(
                operation.kind,
                code="provider_credential_unavailable",
            ) from None

        provider_invoked = False
        journal_replay = False
        credential_body_completed = False
        try:
            with credential_context as credential:
                self._validate_credential(binding, credential)
                try:
                    journal_entry = self._journal.begin(operation)
                except RuntimeProviderError as error:
                    raise _sanitized_for_operation(error, operation.kind) from None
                except Exception:  # noqa: BLE001 - sanitize journal availability failures
                    raise _uncertain_for_operation(
                        operation.kind,
                        code="provider_journal_unavailable",
                    ) from None
                if journal_entry.request_hash != operation.request_hash:
                    raise _failure(RuntimeProviderFailureDisposition.IDEMPOTENCY_CONFLICT)
                if historical_effect_pending and journal_entry.is_new:
                    raise _uncertain_for_operation(
                        operation.kind,
                        code="provider_journal_invalid",
                    )
                journal_fence_acquired = True
                if journal_entry.response is not None:
                    response = self._validate_journal_response(
                        binding,
                        operation,
                        journal_entry.response,
                    )
                    journal_replay = True
                else:
                    reconcile = not journal_entry.is_new
                    try:
                        provider_invoked = True
                        response = (
                            self._client.reconcile(operation, credential)
                            if reconcile
                            else self._client.execute(operation, credential)
                        )
                    except RuntimeProviderError as error:
                        raise _sanitized_for_operation(error, operation.kind) from None
                    except Exception:  # noqa: BLE001 - unknown transport outcome must reconcile
                        disposition = (
                            RuntimeProviderFailureDisposition.COMPENSATION_UNKNOWN
                            if _is_compensation(operation.kind)
                            else RuntimeProviderFailureDisposition.UNKNOWN_EFFECT_RECONCILE
                        )
                        raise _failure(disposition) from None
                    response = RuntimeProviderResponse(
                        receipt=response.receipt,
                        attributes=MappingProxyType(dict(response.attributes)),
                    )
                    self._verify_receipt(binding, operation, credential, response)
                    _validate_response_shape(operation.kind, response)
                credential_body_completed = True
            # Context managers are allowed by Python to suppress a body
            # exception.  Credential authorities are not allowed to turn a
            # failed receipt/journal check into a successful Provider result.
            if not credential_body_completed:
                raise _uncertain_for_operation(
                    operation.kind,
                    code="provider_credential_lifecycle_failed",
                )
        except RuntimeProviderError as error:
            if (
                historical_effect_pending or not journal_fence_acquired
            ) and error.disposition not in {
                RuntimeProviderFailureDisposition.IDEMPOTENCY_CONFLICT,
                RuntimeProviderFailureDisposition.RECEIPT_INVALID,
            }:
                raise _uncertain_for_operation(
                    operation.kind,
                    code=error.code,
                    retry_after_seconds=error.retry_after_seconds,
                ) from None
            if credential_body_completed:
                raise _uncertain_for_operation(
                    operation.kind,
                    code="provider_credential_lifecycle_failed",
                ) from None
            sanitized = _sanitized_for_operation(error, operation.kind)
            raise sanitized from None
        except Exception:  # noqa: BLE001 - sanitize credential lifecycle failures
            if (
                historical_effect_pending
                or not journal_fence_acquired
                or provider_invoked
                or credential_body_completed
            ):
                raise _uncertain_for_operation(
                    operation.kind,
                    code="provider_credential_lifecycle_failed",
                ) from None
            raise _failure(
                RuntimeProviderFailureDisposition.PERMANENT_NO_EFFECT,
                code="provider_credential_lifecycle_failed",
            ) from None

        if journal_replay:
            with self._lock:
                self._last_receipt = response.receipt
            return response

        try:
            self._journal.record_verified(operation=operation, response=response)
        except Exception:  # noqa: BLE001 - durable receipt commit is an effect boundary
            disposition = (
                RuntimeProviderFailureDisposition.COMPENSATION_UNKNOWN
                if _is_compensation(operation.kind)
                else RuntimeProviderFailureDisposition.UNKNOWN_EFFECT_RECONCILE
            )
            raise _failure(
                disposition,
                code="provider_journal_commit_failed",
            ) from None
        with self._lock:
            self._last_receipt = response.receipt
        return response

    def _validate_journal_response(
        self,
        binding: RuntimeProviderBinding,
        operation: RuntimeProviderOperation,
        response: RuntimeProviderResponse,
    ) -> RuntimeProviderResponse:
        try:
            response = RuntimeProviderResponse(
                receipt=response.receipt,
                attributes=MappingProxyType(dict(response.attributes)),
            )
        except Exception:  # noqa: BLE001 - journal response is an untrusted durability boundary
            raise _failure(RuntimeProviderFailureDisposition.RECEIPT_INVALID) from None
        receipt = response.receipt
        try:
            result_hash = canonical_sha256(response.attributes)
        except (TypeError, ValueError):
            raise _failure(RuntimeProviderFailureDisposition.RECEIPT_INVALID) from None
        if not (
            receipt.provider_type == operation.provider_type
            and receipt.operation is operation.kind
            and receipt.placement_id == operation.placement_id
            and receipt.binding_revision == operation.binding_revision
            and receipt.binding_hash == operation.binding_hash
            and receipt.target_hash == operation.target_hash
            and receipt.idempotency_hash == operation.idempotency_hash
            and receipt.request_hash == operation.request_hash
            and receipt.credential_ref_hash == binding.credential_ref_hash
            and receipt.result_hash == result_hash
            and receipt.receipt_hash == sha256(receipt.unsigned_payload()).hexdigest()
        ):
            raise _failure(RuntimeProviderFailureDisposition.RECEIPT_INVALID)
        if _is_compensation(operation.kind):
            allowed = {
                RuntimeProviderOutcome.APPLIED,
                RuntimeProviderOutcome.REPLAYED,
                RuntimeProviderOutcome.ALREADY_ABSENT,
            }
        else:
            allowed = {RuntimeProviderOutcome.APPLIED, RuntimeProviderOutcome.REPLAYED}
        if receipt.outcome not in allowed:
            raise _failure(RuntimeProviderFailureDisposition.RECEIPT_INVALID)
        try:
            verified = self._verifier.verify(
                binding=binding,
                receipt=receipt,
                payload=receipt.unsigned_payload(),
            )
        except Exception:  # noqa: BLE001 - verifier internals must not escape or leak
            raise _failure(RuntimeProviderFailureDisposition.RECEIPT_INVALID) from None
        if not verified:
            raise _failure(RuntimeProviderFailureDisposition.RECEIPT_INVALID)
        _validate_response_shape(operation.kind, response)
        return response

    @staticmethod
    def _validate_credential(
        binding: RuntimeProviderBinding,
        credential: RuntimeProviderCredential,
    ) -> None:
        if credential.credential_ref_hash != binding.credential_ref_hash:
            raise _failure(
                RuntimeProviderFailureDisposition.PERMANENT_NO_EFFECT,
                code="provider_credential_scope_mismatch",
            )

    def _verify_receipt(
        self,
        binding: RuntimeProviderBinding,
        operation: RuntimeProviderOperation,
        credential: RuntimeProviderCredential,
        response: RuntimeProviderResponse,
    ) -> None:
        receipt = response.receipt
        try:
            result_hash = canonical_sha256(response.attributes)
        except (TypeError, ValueError):
            raise _failure(RuntimeProviderFailureDisposition.RECEIPT_INVALID) from None
        expected = (
            receipt.provider_type == operation.provider_type
            and receipt.operation is operation.kind
            and receipt.placement_id == operation.placement_id
            and receipt.binding_revision == operation.binding_revision
            and receipt.binding_hash == operation.binding_hash
            and receipt.target_hash == operation.target_hash
            and receipt.idempotency_hash == operation.idempotency_hash
            and receipt.request_hash == operation.request_hash
            and receipt.credential_ref_hash == binding.credential_ref_hash
            and receipt.credential_version_hash == credential.version_hash
            and receipt.result_hash == result_hash
            and receipt.receipt_hash == sha256(receipt.unsigned_payload()).hexdigest()
        )
        if not expected:
            raise _failure(RuntimeProviderFailureDisposition.RECEIPT_INVALID)
        if _is_compensation(operation.kind):
            allowed = {
                RuntimeProviderOutcome.APPLIED,
                RuntimeProviderOutcome.REPLAYED,
                RuntimeProviderOutcome.ALREADY_ABSENT,
            }
        else:
            allowed = {RuntimeProviderOutcome.APPLIED, RuntimeProviderOutcome.REPLAYED}
        if receipt.outcome not in allowed:
            raise _failure(RuntimeProviderFailureDisposition.RECEIPT_INVALID)
        try:
            verified = self._verifier.verify(
                binding=binding,
                receipt=receipt,
                payload=receipt.unsigned_payload(),
            )
        except Exception:  # noqa: BLE001 - verifier internals must not escape or leak
            raise _failure(RuntimeProviderFailureDisposition.RECEIPT_INVALID) from None
        if not verified:
            raise _failure(RuntimeProviderFailureDisposition.RECEIPT_INVALID)


def canonical_json(document: Mapping[str, object]) -> str:
    """Return deterministic UTF-8 JSON and reject non-canonical value types."""

    normalized = _normalize(document)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def canonical_sha256(document: Mapping[str, object]) -> str:
    return sha256(canonical_json(document).encode("utf-8")).hexdigest()


def _normalize(value: object) -> object:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("canonical timestamps must be timezone-aware")
        return value.isoformat()
    if isinstance(value, Mapping):
        normalized: dict[str, object] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise TypeError("canonical document keys must be strings")
            normalized[key] = _normalize(child)
        return normalized
    if isinstance(value, (list, tuple)):
        return [_normalize(child) for child in value]
    raise TypeError("canonical document contains an unsupported value")


def _operation(
    *,
    kind: RuntimeProviderOperationKind,
    binding: RuntimeProviderBinding,
    target_document: dict[str, object],
    idempotency_key: str,
) -> RuntimeProviderOperation:
    target_json = canonical_json(target_document)
    target_hash = sha256(target_json.encode("utf-8")).hexdigest()
    idempotency_hash = _text_hash(idempotency_key)
    request_document: dict[str, object] = {
        "schema_version": 1,
        "operation": kind.value,
        "provider_type": binding.provider_type,
        "placement_id": str(binding.placement_id),
        "binding_revision": binding.binding_revision,
        "binding_hash": binding.binding_hash,
        "target_hash": target_hash,
        "idempotency_hash": idempotency_hash,
    }
    return RuntimeProviderOperation(
        kind=kind,
        provider_type=binding.provider_type,
        placement_id=binding.placement_id,
        binding_revision=binding.binding_revision,
        binding_hash=binding.binding_hash,
        target_hash=target_hash,
        idempotency_hash=idempotency_hash,
        request_hash=canonical_sha256(request_document),
        target_json=target_json,
        idempotency_key=idempotency_key,
    )


def _partition_target_document(target: RuntimePartitionTarget) -> dict[str, object]:
    return {
        "schema_version": 1,
        "onboarding_id": str(target.onboarding_id),
        "tenant_id": str(target.tenant_id),
        "space_id": str(target.space_id),
        "user_id": str(target.user_id),
        "runtime_partition_id": str(target.runtime_partition_id),
        "placement_id": str(target.placement_id),
        "runtime_type": target.runtime_type,
        "data_region": target.data_region,
        "failure_domain": target.failure_domain,
        "official_schema_revision": target.official_schema_revision,
        "capacity_class": target.capacity_class,
        "provider_binding": {
            "provider_type": target.provider_binding.provider_type,
            "binding_revision": target.provider_binding.binding_revision,
            "binding_hash": target.provider_binding.binding_hash,
        },
    }


def _project_target_document(target: RuntimeProjectTarget) -> dict[str, object]:
    return {
        "schema_version": 1,
        "partition": _partition_target_document(target.partition),
        "project_id": str(target.project_id),
        "project_name": target.project_name,
    }


def _validate_response_shape(
    kind: RuntimeProviderOperationKind,
    response: RuntimeProviderResponse,
) -> None:
    if kind is RuntimeProviderOperationKind.ALLOCATE_PARTITION:
        expected = {
            "runtime_version",
            "physical_partition_key",
            "placement_generation",
            "source_revision",
            "adapter_contract_version",
            "runtime_user_key",
        }
        if set(response.attributes) != expected:
            raise _failure(RuntimeProviderFailureDisposition.RECEIPT_INVALID)
        physical_partition_key = _attribute_text(
            response,
            "physical_partition_key",
            128,
        )
        _attribute_text(response, "runtime_version", 64)
        _attribute_positive_int(response, "placement_generation")
        _attribute_text(response, "source_revision", 64)
        _attribute_text(response, "adapter_contract_version", 32)
        _attribute_text(response, "runtime_user_key", 128)
        if response.receipt.provider_resource_id != physical_partition_key:
            raise _failure(RuntimeProviderFailureDisposition.RECEIPT_INVALID)
        return
    if kind is RuntimeProviderOperationKind.PROVISION_DEFAULT_PROJECT:
        if set(response.attributes) != {"runtime_resource_id"}:
            raise _failure(RuntimeProviderFailureDisposition.RECEIPT_INVALID)
        runtime_resource_id = _attribute_text(response, "runtime_resource_id", 256)
        if response.receipt.provider_resource_id != runtime_resource_id:
            raise _failure(RuntimeProviderFailureDisposition.RECEIPT_INVALID)
        return
    if response.attributes:
        raise _failure(RuntimeProviderFailureDisposition.RECEIPT_INVALID)
    if (
        response.receipt.outcome is not RuntimeProviderOutcome.ALREADY_ABSENT
        and response.receipt.provider_resource_id is None
    ):
        raise _failure(RuntimeProviderFailureDisposition.RECEIPT_INVALID)


def _attribute_text(
    response: RuntimeProviderResponse,
    name: str,
    maximum: int,
) -> str:
    value = response.attributes.get(name)
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise _failure(RuntimeProviderFailureDisposition.RECEIPT_INVALID)
    return value


def _attribute_positive_int(response: RuntimeProviderResponse, name: str) -> int:
    value = response.attributes.get(name)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise _failure(RuntimeProviderFailureDisposition.RECEIPT_INVALID)
    return value


def _require_lower_hex(value: str, label: str) -> None:
    if _LOWER_HEX_64.fullmatch(value) is None:
        raise ValueError(f"Runtime {label} must be 64 lowercase hexadecimal characters")


def _require_opaque_ref(value: str, label: str) -> None:
    if not value.strip() or len(value) > 512 or any(character.isspace() for character in value):
        raise ValueError(f"{label} is invalid")
    parsed = urlsplit(value)
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"{label} must not contain credentials")


def _require_credential_ref(value: str) -> None:
    _require_opaque_ref(value, "Provider credential reference")
    scheme = urlsplit(value).scheme.lower()
    if scheme not in _PRODUCTION_CREDENTIAL_SCHEMES:
        raise ValueError("ambient or inline Provider credentials are forbidden")


def _text_hash(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _is_compensation(kind: RuntimeProviderOperationKind) -> bool:
    return kind in {
        RuntimeProviderOperationKind.COMPENSATE_DEFAULT_PROJECT,
        RuntimeProviderOperationKind.COMPENSATE_PARTITION,
    }


def _failure(
    disposition: RuntimeProviderFailureDisposition,
    *,
    code: str | None = None,
) -> RuntimeProviderError:
    return RuntimeProviderError(
        code or disposition.value,
        disposition,
        _SAFE_FAILURE_MESSAGES[disposition],
    )


def _uncertain_for_operation(
    kind: RuntimeProviderOperationKind,
    *,
    code: str,
    retry_after_seconds: int | None = None,
) -> RuntimeProviderError:
    disposition = (
        RuntimeProviderFailureDisposition.COMPENSATION_UNKNOWN
        if _is_compensation(kind)
        else RuntimeProviderFailureDisposition.UNKNOWN_EFFECT_RECONCILE
    )
    return RuntimeProviderError(
        code,
        disposition,
        _SAFE_FAILURE_MESSAGES[disposition],
        retry_after_seconds=retry_after_seconds,
    )


def _sanitized_for_operation(
    error: RuntimeProviderError,
    kind: RuntimeProviderOperationKind,
) -> RuntimeProviderError:
    disposition = error.disposition
    if _is_compensation(kind):
        if disposition is RuntimeProviderFailureDisposition.RETRYABLE_NO_EFFECT:
            disposition = RuntimeProviderFailureDisposition.COMPENSATION_RETRYABLE
        elif disposition is RuntimeProviderFailureDisposition.UNKNOWN_EFFECT_RECONCILE:
            disposition = RuntimeProviderFailureDisposition.COMPENSATION_UNKNOWN
    elif disposition is RuntimeProviderFailureDisposition.COMPENSATION_RETRYABLE:
        disposition = RuntimeProviderFailureDisposition.RETRYABLE_NO_EFFECT
    elif disposition is RuntimeProviderFailureDisposition.COMPENSATION_UNKNOWN:
        disposition = RuntimeProviderFailureDisposition.UNKNOWN_EFFECT_RECONCILE
    return RuntimeProviderError(
        error.code,
        disposition,
        _SAFE_FAILURE_MESSAGES[disposition],
        retry_after_seconds=error.retry_after_seconds,
    )


__all__ = [
    "ProductionRuntimePartitionAdapter",
    "RuntimeProviderBinding",
    "RuntimeProviderClient",
    "RuntimeProviderCredential",
    "RuntimeProviderCredentialAuthority",
    "RuntimeProviderError",
    "RuntimeProviderFailureDisposition",
    "RuntimeProviderJournalEntry",
    "RuntimeProviderOperation",
    "RuntimeProviderOperationJournal",
    "RuntimeProviderOperationKind",
    "RuntimeProviderOutcome",
    "RuntimeProviderReceipt",
    "RuntimeProviderReceiptVerifier",
    "RuntimeProviderResponse",
    "canonical_json",
    "canonical_sha256",
]
