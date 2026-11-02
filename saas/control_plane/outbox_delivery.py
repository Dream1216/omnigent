"""Exact typed business consumers; unknown envelopes remain unsupported."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from decimal import Decimal
from types import SimpleNamespace
from typing import Literal, Protocol, cast, overload
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.billing_models import PricingSnapshotRecord, UsageEventRecord
from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.outbox import OutboxClaimRoute, OutboxPublishError
from saas.control_plane.outbox_delivery_models import UsageReconciliationIngressRecord
from saas.control_plane.rls import RlsContext, apply_rls_context
from saas.observability import SloMetrics


class NativeUsageFacts(Protocol):
    """Read-only fields shared by the verified getter and immutable ORM fact."""

    @property
    def id(self) -> UUID: ...

    @property
    def tenant_id(self) -> UUID: ...

    @property
    def space_id(self) -> UUID | None: ...

    @property
    def project_id(self) -> UUID | None: ...

    @property
    def run_id(self) -> UUID | None: ...

    @property
    def meter(self) -> str: ...

    @property
    def quantity(self) -> Decimal: ...

    @property
    def unit(self) -> str: ...

    @property
    def provider(self) -> str: ...

    @property
    def provider_request_id(self) -> str: ...

    @property
    def pricing_snapshot_id(self) -> UUID: ...

    @property
    def currency(self) -> str: ...

    @property
    def customer_charge_minor(self) -> int: ...

    @property
    def attributes(self) -> dict[str, object]: ...

    @property
    def occurred_at(self) -> datetime: ...


class NativePricingFacts(Protocol):
    """Read-only fields shared by the verified getter and immutable ORM fact."""

    @property
    def id(self) -> UUID: ...

    @property
    def tenant_id(self) -> UUID: ...

    @property
    def plan_key(self) -> str: ...

    @property
    def currency(self) -> str: ...

    @property
    def rates(self) -> dict[str, dict[str, object]]: ...

    @property
    def version(self) -> int: ...

    @property
    def effective_from(self) -> datetime: ...

    @property
    def effective_until(self) -> datetime | None: ...


@overload
def native_delivery_row(
    db: Session, name: Literal["usage_facts"], event_id: UUID
) -> NativeUsageFacts | None: ...


@overload
def native_delivery_row(
    db: Session, name: Literal["pricing_facts"], event_id: UUID
) -> NativePricingFacts | None: ...


@overload
def native_delivery_row(
    db: Session,
    name: Literal["usage_source", "audit_source", "revocation_source", "revocation_authority"],
    event_id: UUID,
) -> SimpleNamespace | None: ...


def native_delivery_row(
    db: Session, name: str, event_id: UUID
) -> NativeUsageFacts | NativePricingFacts | SimpleNamespace | None:
    names = {
        "usage_source": "saas_delivery_usage_outbox_source_v1",
        "audit_source": "saas_delivery_audit_outbox_source_v1",
        "revocation_source": "saas_delivery_revocation_outbox_source_v1",
        "usage_facts": "saas_delivery_usage_facts_v1",
        "pricing_facts": "saas_delivery_pricing_facts_v1",
        "revocation_authority": "saas_delivery_revocation_authority_v1",
    }
    # Only fixed packaged getter names; caller data is always a bind parameter.
    function = names[name]
    row = (
        db.execute(sa.text(f"SELECT * FROM public.{function}(:event_id)"), {"event_id": event_id})
        .mappings()
        .one_or_none()
    )
    return None if row is None else SimpleNamespace(**cast(Mapping[str, object], row))


def delivery_source(db: Session, kind: Literal["usage", "audit", "revocation"], event_id: UUID):
    if db.get_bind().dialect.name == "postgresql":
        return native_delivery_row(
            db,
            cast(Literal["usage_source", "audit_source", "revocation_source"], kind + "_source"),
            event_id,
        )
    return db.get(ControlPlaneOutboxEvent, event_id)


def utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def usage_facts(
    usage: NativeUsageFacts | UsageEventRecord,
    pricing: NativePricingFacts | PricingSnapshotRecord,
) -> dict[str, object]:
    """Materialize the original immutable business facts, without a financial posting."""
    return {
        "usage": {
            "id": str(usage.id),
            "tenant_id": str(usage.tenant_id),
            "space_id": None if usage.space_id is None else str(usage.space_id),
            "project_id": None if usage.project_id is None else str(usage.project_id),
            "run_id": None if usage.run_id is None else str(usage.run_id),
            "meter": usage.meter,
            "quantity": str(usage.quantity),
            "unit": usage.unit,
            "provider": usage.provider,
            "provider_request_id": usage.provider_request_id,
            "pricing_snapshot_id": str(usage.pricing_snapshot_id),
            "currency": usage.currency,
            "customer_charge_minor": usage.customer_charge_minor,
            "attributes": usage.attributes,
            "occurred_at": utc(usage.occurred_at).isoformat(),
        },
        "pricing": {
            "id": str(pricing.id),
            "tenant_id": str(pricing.tenant_id),
            "plan_key": pricing.plan_key,
            "currency": pricing.currency,
            "rates": pricing.rates,
            "version": pricing.version,
            "effective_from": utc(pricing.effective_from).isoformat(),
            "effective_until": None
            if pricing.effective_until is None
            else utc(pricing.effective_until).isoformat(),
        },
    }


def verify_usage_ingress(
    db: Session,
    usage: NativeUsageFacts | UsageEventRecord,
    pricing: NativePricingFacts | PricingSnapshotRecord,
) -> UsageReconciliationIngressRecord:
    row = db.scalar(
        sa.select(UsageReconciliationIngressRecord).where(
            UsageReconciliationIngressRecord.tenant_id == usage.tenant_id,
            UsageReconciliationIngressRecord.usage_event_id == usage.id,
        )
    )
    if row is None:
        raise OutboxPublishError("usage_ingress_pending", retryable=True, pre_side_effect=True)
    if (
        row.facts_sha256 != digest(usage_facts(usage, pricing))
        or digest(row.facts) != row.facts_sha256
    ):
        raise OutboxPublishError("usage_ingress_conflict", retryable=False, pre_side_effect=True)
    return row


class UsageReconciliationConsumer:
    """Usage Outbox -> independently committed immutable reconciliation ingress.

    The consumer cannot settle reservations, post customer/provider ledgers, credit
    balances, fabricate ProviderCost, or approve any billing period. A successful
    publish requires a separate database readback of the actual receiver fact.
    """

    claim_routes = (OutboxClaimRoute("billing", "billing.usage.recorded"),)

    def __init__(
        self,
        factory: sessionmaker[Session],
        *,
        product_revision: str,
        metrics: SloMetrics | None = None,
    ) -> None:
        if re.fullmatch(r"[0-9a-f]{40}", product_revision) is None:
            raise ValueError("consumer requires the exact current Product revision")
        self._factory = factory
        self.product_revision = product_revision
        self.metrics = metrics

    @staticmethod
    def _source(db: Session, event_id: UUID, event: Mapping[str, object]):
        source = delivery_source(db, "usage", event_id)
        if source is None:
            raise OutboxPublishError("usage_source_missing", retryable=True, pre_side_effect=True)
        if (
            source.aggregate_type != "billing"
            or source.event_type != "billing.usage.recorded"
            or source.tenant_id is None
            or any(
                getattr(source, key) != event[key]
                for key in ("aggregate_type", "event_type", "aggregate_key", "payload")
            )
        ):
            raise OutboxPublishError(
                "usage_source_mismatch", retryable=False, pre_side_effect=True
            )
        apply_rls_context(db, RlsContext(tenant_id=source.tenant_id))
        try:
            usage_id = UUID(str(source.payload["usage_event_id"]))
        except (KeyError, ValueError, TypeError):
            raise OutboxPublishError(
                "usage_reference_invalid", retryable=False, pre_side_effect=True
            ) from None
        usage = (
            native_delivery_row(db, "usage_facts", event_id)
            if db.get_bind().dialect.name == "postgresql"
            else db.get(UsageEventRecord, usage_id)
        )
        if (
            usage is None
            or usage.tenant_id != source.tenant_id
            or source.aggregate_key != str(usage_id)
        ):
            raise OutboxPublishError("usage_scope_mismatch", retryable=False, pre_side_effect=True)
        pricing = (
            native_delivery_row(db, "pricing_facts", event_id)
            if db.get_bind().dialect.name == "postgresql"
            else db.get(PricingSnapshotRecord, usage.pricing_snapshot_id)
        )
        if (
            pricing is None
            or pricing.tenant_id != usage.tenant_id
            or pricing.currency != usage.currency
        ):
            raise OutboxPublishError(
                "usage_pricing_mismatch", retryable=False, pre_side_effect=True
            )
        exact = {
            "usage_event_id": str(usage.id),
            "tenant_id": str(usage.tenant_id),
            "pricing_snapshot_id": str(pricing.id),
            "currency": usage.currency,
            "customer_charge_minor": usage.customer_charge_minor,
            "meter": usage.meter,
            "unit": usage.unit,
            "provider": usage.provider,
            "provider_request_id": usage.provider_request_id,
        }
        if any(
            source.payload[key] != value for key, value in exact.items() if key in source.payload
        ):
            raise OutboxPublishError(
                "usage_payload_mismatch", retryable=False, pre_side_effect=True
            )
        if (
            "quantity" in source.payload
            and Decimal(str(source.payload["quantity"])) != usage.quantity
        ):
            raise OutboxPublishError(
                "usage_quantity_mismatch", retryable=False, pre_side_effect=True
            )
        return source, usage, pricing

    def publish(
        self,
        *,
        event_id: UUID,
        event_type: str,
        aggregate_type: str,
        aggregate_key: str,
        payload: dict[str, object],
    ) -> None:
        event = {
            "event_type": event_type,
            "aggregate_type": aggregate_type,
            "aggregate_key": aggregate_key,
            "payload": payload,
        }
        replayed = False
        with self._factory.begin() as db:
            source, usage, pricing = self._source(db, event_id, event)
            facts = usage_facts(usage, pricing)
            existing = db.get(UsageReconciliationIngressRecord, event_id)
            if existing is None:
                try:
                    with db.begin_nested():
                        db.add(
                            UsageReconciliationIngressRecord(
                                outbox_event_id=event_id,
                                tenant_id=source.tenant_id,
                                usage_event_id=usage.id,
                                pricing_snapshot_id=pricing.id,
                                source_request_hash=source.request_hash,
                                facts_sha256=digest(facts),
                                facts=facts,
                                product_revision=self.product_revision,
                                source_created_at=source.created_at,
                            )
                        )
                        db.flush()
                except IntegrityError:
                    # Another actual consumer may have committed the same immutable
                    # receiver fact. Read it; never UPDATE an inbox to make it fit.
                    replayed = True
            else:
                replayed = True
            received = verify_usage_ingress(db, usage, pricing)
            if (
                received.outbox_event_id != event_id
                or received.source_request_hash != source.request_hash
            ):
                raise OutboxPublishError(
                    "usage_delivery_conflict", retryable=False, pre_side_effect=False
                )
        # The receive transaction has committed. A new Session must observe it.
        with self._factory() as db, db.begin():
            source, usage, pricing = self._source(db, event_id, event)
            verify_usage_ingress(db, usage, pricing)
            source_created_at = utc(source.created_at)
        if self.metrics is not None:
            elapsed = (datetime.now(UTC) - source_created_at).total_seconds()
            if elapsed < 0:
                self.metrics.count("coverage_gap", "blocked")
                raise OutboxPublishError(
                    "usage_observer_clock_invalid", retryable=True, pre_side_effect=False
                )
            self.metrics.duration(
                "outbox_usage_delivery",
                "replayed" if replayed else "success",
                elapsed,
            )


class PlatformAuditJournalConsumer:
    """Deliver the original audit chain to a retained encrypted/signed journal.

    This is not the customer-approved AuditExport API: it grants no support,
    export or download authority. Only a version-pinned destination readback and
    an independent immutable receiver commit permit the original Outbox ACK.
    Production composition must supply independent audit-purpose KMS identities.
    """

    claim_routes = (OutboxClaimRoute("platform_audit", "platform.audit.persisted"),)
    purpose = "platform-audit-journal"

    def __init__(self, factory, store, cipher, signer, *, product_revision, metrics=None):
        if re.fullmatch(r"[0-9a-f]{40}", product_revision) is None:
            raise ValueError("audit consumer requires an exact Product SHA")
        self.factory, self.store, self.cipher, self.signer = factory, store, cipher, signer
        self.product_revision, self.metrics = product_revision, metrics

    @staticmethod
    def _facts(event):
        facts = {
            "sequence_no": event.sequence_no,
            "tenant_id": None if event.tenant_id is None else str(event.tenant_id),
            "actor_type": event.actor_type,
            "actor_id": str(event.actor_id),
            "event_type": event.event_type,
            "target_type": event.target_type,
            "target_id": str(event.target_id),
            "operation_id": None if event.operation_id is None else str(event.operation_id),
            "payload_hash": event.payload_hash,
            "previous_hash": event.previous_hash,
            "occurred_at": utc(event.occurred_at).isoformat(),
        }
        if digest(event.payload) != event.payload_hash or digest(facts) != event.event_hash:
            raise OutboxPublishError(
                "audit_source_hash_invalid", retryable=False, pre_side_effect=True
            )
        return {
            "id": str(event.id),
            **facts,
            "event_hash": event.event_hash,
            "payload": event.payload,
        }

    @staticmethod
    def _key(facts):
        return f"platform/{facts['sequence_no']:020d}-{facts['id']}.json"

    @classmethod
    def _context(cls, facts):
        return {
            "purpose": cls.purpose,
            "chain": "platform",
            "audit_event_id": facts["id"],
            "sequence": str(facts["sequence_no"]),
        }

    def _read_source(self, event_id, event):
        from saas.control_plane.platform_governed_models import PlatformAuditEventRecord

        with self.factory() as db, db.begin():
            source = delivery_source(db, "audit", event_id)
            if source is None or any(
                getattr(source, key) != event[key]
                for key in ("aggregate_type", "event_type", "aggregate_key", "payload")
            ):
                raise OutboxPublishError(
                    "audit_source_mismatch", retryable=False, pre_side_effect=True
                )
            try:
                audit_id = UUID(source.aggregate_key)
            except (TypeError, ValueError):
                raise OutboxPublishError(
                    "audit_source_reference_invalid", retryable=False, pre_side_effect=True
                ) from None
            if db.get_bind().dialect.name == "postgresql":
                chain = [
                    SimpleNamespace(**row)
                    for row in db.execute(
                        sa.text("SELECT * FROM public.saas_delivery_audit_chain_v1(:event_id)"),
                        {"event_id": event_id},
                    ).mappings()
                ]
                audit = next((row for row in chain if row.id == audit_id), None)
            else:
                chain = None
                audit = db.get(PlatformAuditEventRecord, audit_id)
            if audit is None:
                raise OutboxPublishError(
                    "audit_event_missing", retryable=True, pre_side_effect=True
                )
            facts = self._facts(audit)
            if (
                source.aggregate_type != "platform_audit"
                or source.event_type != "platform.audit.persisted"
                or source.tenant_id != audit.tenant_id
                or source.payload
                != {
                    "audit_event_id": str(audit.id),
                    "sequence_no": audit.sequence_no,
                    "event_hash": audit.event_hash,
                }
                or source.request_hash != audit.event_hash
            ):
                raise OutboxPublishError(
                    "audit_source_envelope_invalid", retryable=False, pre_side_effect=True
                )
            previous = (
                next((row for row in chain if row.sequence_no == audit.sequence_no - 1), None)
                if chain is not None
                else db.scalar(
                    sa.select(PlatformAuditEventRecord).where(
                        PlatformAuditEventRecord.sequence_no == audit.sequence_no - 1
                    )
                )
            )
            if audit.sequence_no == 1:
                if audit.previous_hash != "0" * 64:
                    raise OutboxPublishError(
                        "audit_chain_origin_invalid", retryable=False, pre_side_effect=True
                    )
                before = None
            elif previous is None or previous.event_hash != audit.previous_hash:
                raise OutboxPublishError(
                    "audit_chain_link_invalid", retryable=False, pre_side_effect=True
                )
            else:
                before = self._facts(previous)
            return facts, before, source.created_at, source.tenant_id

    def _open(self, stored, facts):
        try:
            value = json.loads(stored.body)
            fields = {
                "schema_version",
                "purpose",
                "product_revision",
                "signing_key_id",
                "algorithm",
                "ciphertext",
                "content_hash",
                "signature",
            }
            if (
                not isinstance(value, dict)
                or set(value) != fields
                or canonical(value) != stored.body
                or value["schema_version"] != 1
                or value["purpose"] != self.purpose
                or not isinstance(value["product_revision"], str)
                or re.fullmatch(r"[0-9a-f]{40}", value["product_revision"]) is None
                or value["signing_key_id"] != self.signer.key_id
                or value["algorithm"] != self.signer.algorithm
            ):
                raise ValueError("journal identity is invalid")
            signed = {k: v for k, v in value.items() if k not in {"signature", "content_hash"}}
            if digest(signed) != value["content_hash"] or not self.signer.verify(
                value["content_hash"], value["signature"]
            ):
                raise ValueError("journal signature is invalid")
            plaintext = self.cipher.decrypt(value["ciphertext"], context=self._context(facts))
            if plaintext is None or plaintext.encode() != canonical(facts):
                raise ValueError("journal source binding is invalid")
            if not stored.version or not stored.etag:
                raise ValueError("journal version is missing")
            return value
        except (TypeError, ValueError, KeyError):
            raise OutboxPublishError(
                "audit_destination_invalid", retryable=False, pre_side_effect=False
            ) from None

    def _check_previous(self, before):
        from saas.control_plane.outbox_delivery_models import PlatformAuditJournalDeliveryRecord

        if before is None:
            return
        with self.factory() as db, db.begin():
            receipt = db.scalar(
                sa.select(PlatformAuditJournalDeliveryRecord).where(
                    PlatformAuditJournalDeliveryRecord.audit_event_id == UUID(before["id"])
                )
            )
            if receipt is None:
                raise OutboxPublishError(
                    "audit_predecessor_pending", retryable=True, pre_side_effect=True
                )
            expected_version, expected_sha = receipt.storage_version, receipt.journal_sha256
        previous = self.store.read(self._key(before))
        if (
            previous is None
            or previous.version != expected_version
            or hashlib.sha256(previous.body).hexdigest() != expected_sha
        ):
            raise OutboxPublishError(
                "audit_predecessor_readback_failed", retryable=True, pre_side_effect=True
            )
        self._open(previous, before)

    def publish(self, *, event_id, event_type, aggregate_type, aggregate_key, payload):
        from saas.control_plane.outbox_delivery_models import PlatformAuditJournalDeliveryRecord

        event = {
            "event_type": event_type,
            "aggregate_type": aggregate_type,
            "aggregate_key": aggregate_key,
            "payload": payload,
        }
        facts, before, origin, tenant_id = self._read_source(event_id, event)
        self._check_previous(before)
        key = self._key(facts)
        existing = self.store.read(key)
        replayed = existing is not None
        if existing is None:
            sealed = {
                "schema_version": 1,
                "purpose": self.purpose,
                "product_revision": self.product_revision,
                "signing_key_id": self.signer.key_id,
                "algorithm": self.signer.algorithm,
                "ciphertext": self.cipher.encrypt(
                    canonical(facts).decode(), context=self._context(facts)
                ),
            }
            sealed["content_hash"] = digest(sealed)
            sealed["signature"] = self.signer.sign(sealed["content_hash"])
            try:
                existing = self.store.conditional_put(key, canonical(sealed), expected_etag=None)
            except Exception:  # noqa: BLE001 -- never leak private KMS/S3 request data
                # Do not repeat an uncertain destination write. A concurrent exact
                # source journal can be read and verified without another write.
                existing = self.store.read(key)
                if existing is None:
                    raise OutboxPublishError(
                        "audit_destination_uncertain", retryable=True, pre_side_effect=False
                    ) from None
        self._open(existing, facts)
        independent = self.store.read(key)
        if (
            independent is None
            or independent.version != existing.version
            or independent.body != existing.body
        ):
            raise OutboxPublishError(
                "audit_destination_readback_failed", retryable=True, pre_side_effect=False
            )
        self._open(independent, facts)
        journal_sha = hashlib.sha256(independent.body).hexdigest()
        with self.factory.begin() as db:
            row = db.get(PlatformAuditJournalDeliveryRecord, event_id)
            if row is None:
                with db.begin_nested():
                    try:
                        row = PlatformAuditJournalDeliveryRecord(
                            outbox_event_id=event_id,
                            audit_event_id=UUID(facts["id"]),
                            audit_sequence=facts["sequence_no"],
                            tenant_id=tenant_id,
                            event_hash=facts["event_hash"],
                            journal_sha256=journal_sha,
                            storage_key=key,
                            storage_version=independent.version,
                            signing_key_id=self.signer.key_id,
                            product_revision=self.product_revision,
                            source_created_at=origin,
                        )
                        db.add(row)
                        db.flush()
                    except IntegrityError:
                        # Roll back only the insert race; never rewrite a receipt.
                        raise OutboxPublishError(
                            "audit_receipt_insert_race", retryable=True, pre_side_effect=False
                        ) from None
            if (
                row.audit_event_id != UUID(facts["id"])
                or row.event_hash != facts["event_hash"]
                or row.journal_sha256 != journal_sha
                or row.storage_key != key
                or row.storage_version != independent.version
                or row.signing_key_id != self.signer.key_id
            ):
                raise OutboxPublishError(
                    "audit_receipt_conflict", retryable=False, pre_side_effect=False
                )
        with self.factory() as db, db.begin():
            row = db.get(PlatformAuditJournalDeliveryRecord, event_id)
            if (
                row is None
                or row.journal_sha256 != journal_sha
                or row.storage_version != independent.version
            ):
                raise OutboxPublishError(
                    "audit_receipt_readback_failed", retryable=True, pre_side_effect=False
                )
        if self.metrics is not None:
            elapsed = (datetime.now(UTC) - utc(origin)).total_seconds()
            if elapsed < 0:
                self.metrics.count("coverage_gap", "blocked")
                raise OutboxPublishError(
                    "audit_observer_clock_invalid", retryable=True, pre_side_effect=False
                )
            self.metrics.duration(
                "outbox_audit_delivery", "replayed" if replayed else "success", elapsed
            )
