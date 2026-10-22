"""Persistent Runner mTLS certificate rotation and revocation authority."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Collection
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

import sqlalchemy as sa
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.certificate_models import (
    RUNNER_CERTIFICATE_PURPOSES,
    RunnerCertificateRecord,
)
from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.scheduling_models import RunnerRegistrationRecord


class CertificateLifecycleError(RuntimeError):
    """Stable fail-closed error for certificate lifecycle operations."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class ActivatedRunnerCertificate:
    """Non-secret receipt for one activated Runner leaf certificate."""

    certificate_id: UUID
    runner_id: UUID
    runner_connection_generation: int
    purpose: str
    fingerprint_sha256: str
    rotation_generation: int
    certificate_not_after: datetime
    trust_bundle_version: str


@dataclass(frozen=True, slots=True)
class _InspectedCertificate:
    runner_id: UUID
    fingerprint_sha256: str
    spki_sha256: str
    serial_hex: str
    spiffe_id: str
    not_before: datetime
    not_after: datetime


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    return (
        value.replace(tzinfo=timezone.utc)
        if value.tzinfo is None
        else value.astimezone(timezone.utc)
    )


def _validate_time(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return value.astimezone(timezone.utc)


def _text(value: str, *, field: str, maximum: int) -> str:
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > maximum or "\x00" in normalized:
        raise CertificateLifecycleError(
            f"{field}_invalid", f"Runner certificate {field.replace('_', ' ')} is invalid"
        )
    return normalized


def _inspect_certificate(certificate_der: bytes) -> _InspectedCertificate:
    if not certificate_der or len(certificate_der) > 32_768:
        raise CertificateLifecycleError(
            "runner_certificate_invalid", "Runner certificate is invalid"
        )
    try:
        certificate = x509.load_der_x509_certificate(certificate_der)
        basic_constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        extended_usage = certificate.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
        subject_alt_name = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        san_values = list(subject_alt_name)
        signature_hash = certificate.signature_hash_algorithm
    except (UnsupportedAlgorithm, ValueError, x509.ExtensionNotFound, TypeError) as exc:
        raise CertificateLifecycleError(
            "runner_certificate_invalid", "Runner certificate is invalid"
        ) from exc
    if (
        basic_constraints.ca
        or not key_usage.digital_signature
        or key_usage.key_cert_sign
        or key_usage.crl_sign
        or set(extended_usage) != {ExtendedKeyUsageOID.CLIENT_AUTH}
        or len(san_values) != 1
        or not isinstance(san_values[0], x509.UniformResourceIdentifier)
        or signature_hash is None
        or signature_hash.name.lower() not in {"sha256", "sha384", "sha512"}
    ):
        raise CertificateLifecycleError(
            "runner_certificate_profile_invalid", "Runner certificate profile is invalid"
        )
    spiffe_id = san_values[0].value
    prefix = "spiffe://omnigent/runner/"
    if not spiffe_id.startswith(prefix):
        raise CertificateLifecycleError(
            "runner_certificate_identity_invalid", "Runner certificate identity is invalid"
        )
    runner_value = spiffe_id[len(prefix) :]
    try:
        runner_id = UUID(runner_value)
    except ValueError as exc:
        raise CertificateLifecycleError(
            "runner_certificate_identity_invalid", "Runner certificate identity is invalid"
        ) from exc
    if str(runner_id) != runner_value:
        raise CertificateLifecycleError(
            "runner_certificate_identity_invalid", "Runner certificate identity is invalid"
        )
    public_key = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return _InspectedCertificate(
        runner_id=runner_id,
        fingerprint_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
        spki_sha256=hashlib.sha256(public_key).hexdigest(),
        serial_hex=format(certificate.serial_number, "x"),
        spiffe_id=spiffe_id,
        not_before=_as_utc(certificate.not_valid_before_utc),
        not_after=_as_utc(certificate.not_valid_after_utc),
    )


def _event(
    *,
    event_type: str,
    fingerprint: str,
    payload: dict[str, object],
) -> ControlPlaneOutboxEvent:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    suffix = event_type.rsplit(".", 1)[-1]
    return ControlPlaneOutboxEvent(
        tenant_id=None,
        aggregate_type="runner_certificate",
        aggregate_key=fingerprint,
        event_type=event_type,
        payload=payload,
        idempotency_key=f"runner-cert:{fingerprint}:{suffix}",
        request_hash=hashlib.sha256(encoded).hexdigest(),
    )


class RunnerCertificateAuthority:
    """Rotate and authorize public Runner certificates using PostgreSQL authority."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        accepted_trust_bundle_versions: Collection[str],
        maximum_certificate_lifetime: timedelta = timedelta(hours=24),
        maximum_rotation_overlap: timedelta = timedelta(minutes=15),
        allowed_clock_skew: timedelta = timedelta(minutes=2),
    ) -> None:
        versions = frozenset(
            _text(value, field="trust_bundle_version", maximum=64)
            for value in accepted_trust_bundle_versions
        )
        if (
            not versions
            or maximum_certificate_lifetime <= timedelta(0)
            or maximum_rotation_overlap < timedelta(0)
            or allowed_clock_skew < timedelta(0)
        ):
            raise ValueError("Runner certificate authority policy is invalid")
        self._session_factory = session_factory
        self._accepted_trust_bundle_versions = versions
        self._maximum_certificate_lifetime = maximum_certificate_lifetime
        self._maximum_rotation_overlap = maximum_rotation_overlap
        self._allowed_clock_skew = allowed_clock_skew

    def activate_certificate(
        self,
        *,
        runner_id: UUID,
        runner_connection_generation: int,
        purpose: str,
        certificate_der: bytes,
        trust_bundle_version: str,
        rotation_overlap: timedelta = timedelta(minutes=5),
        now: datetime | None = None,
    ) -> ActivatedRunnerCertificate:
        """Bind a CA-issued leaf to the current Runner and overlap the previous leaf."""

        activated_at = _validate_time(now or _utcnow(), field="activation time")
        normalized_purpose = _text(purpose, field="purpose", maximum=32)
        normalized_bundle = _text(trust_bundle_version, field="trust_bundle_version", maximum=64)
        if normalized_purpose not in RUNNER_CERTIFICATE_PURPOSES:
            raise CertificateLifecycleError(
                "runner_certificate_purpose_invalid", "Runner certificate purpose is invalid"
            )
        if normalized_bundle not in self._accepted_trust_bundle_versions:
            raise CertificateLifecycleError(
                "runner_certificate_trust_bundle_unapproved",
                "Runner certificate trust bundle is not approved",
            )
        if (
            runner_connection_generation <= 0
            or rotation_overlap < timedelta(0)
            or rotation_overlap > self._maximum_rotation_overlap
        ):
            raise CertificateLifecycleError(
                "runner_certificate_rotation_invalid", "Runner certificate rotation is invalid"
            )
        inspected = _inspect_certificate(certificate_der)
        if inspected.runner_id != runner_id:
            raise CertificateLifecycleError(
                "runner_certificate_identity_mismatch",
                "Runner certificate does not match the selected Runner",
            )
        if (
            inspected.not_before > activated_at + self._allowed_clock_skew
            or inspected.not_after <= activated_at
            or inspected.not_after - inspected.not_before > self._maximum_certificate_lifetime
        ):
            raise CertificateLifecycleError(
                "runner_certificate_validity_invalid", "Runner certificate validity is invalid"
            )

        with self._session_factory.begin() as db:
            existing = db.scalar(
                sa.select(RunnerCertificateRecord)
                .where(RunnerCertificateRecord.fingerprint_sha256 == inspected.fingerprint_sha256)
                .with_for_update()
            )
            if existing is not None:
                if (
                    existing.status == "active"
                    and existing.runner_id == runner_id
                    and existing.runner_connection_generation == runner_connection_generation
                    and existing.purpose == normalized_purpose
                    and existing.trust_bundle_version == normalized_bundle
                ):
                    return self._receipt(existing)
                raise CertificateLifecycleError(
                    "runner_certificate_reuse_invalid",
                    "Runner certificate cannot be reused for another lifecycle",
                )

            runner = db.scalar(
                sa.select(RunnerRegistrationRecord)
                .where(RunnerRegistrationRecord.id == runner_id)
                .with_for_update()
            )
            if (
                runner is None
                or runner.status not in {"online", "draining"}
                or runner.connection_generation != runner_connection_generation
            ):
                raise CertificateLifecycleError(
                    "runner_certificate_runner_stale",
                    "Runner certificate target is not the current Runner incarnation",
                )

            # The Runner row is the serialization point for rotations. Re-read the
            # fingerprint after taking that lock so concurrent retries return the
            # first receipt instead of racing the unique constraint.
            existing = db.scalar(
                sa.select(RunnerCertificateRecord).where(
                    RunnerCertificateRecord.fingerprint_sha256 == inspected.fingerprint_sha256
                )
            )
            if existing is not None:
                if (
                    existing.status == "active"
                    and existing.runner_id == runner_id
                    and existing.runner_connection_generation == runner_connection_generation
                    and existing.purpose == normalized_purpose
                    and existing.trust_bundle_version == normalized_bundle
                ):
                    return self._receipt(existing)
                raise CertificateLifecycleError(
                    "runner_certificate_reuse_invalid",
                    "Runner certificate cannot be reused for another lifecycle",
                )

            previous = list(
                db.scalars(
                    sa.select(RunnerCertificateRecord)
                    .where(
                        RunnerCertificateRecord.runner_id == runner_id,
                        RunnerCertificateRecord.purpose == normalized_purpose,
                        RunnerCertificateRecord.status.in_(("active", "retiring")),
                    )
                    .with_for_update()
                )
            )
            retire_at = activated_at + rotation_overlap
            for record in previous:
                if _as_utc(record.activated_at) > activated_at:
                    raise CertificateLifecycleError(
                        "runner_certificate_rotation_invalid",
                        "Runner certificate rotation cannot move backwards in time",
                    )
                record.status = "retiring"
                deadline = min(_as_utc(record.certificate_not_after), retire_at)
                if record.retire_at is not None:
                    deadline = min(_as_utc(record.retire_at), deadline)
                record.retire_at = deadline

            generation = (
                int(
                    db.scalar(
                        sa.select(
                            sa.func.coalesce(
                                sa.func.max(RunnerCertificateRecord.rotation_generation), 0
                            )
                        ).where(
                            RunnerCertificateRecord.runner_id == runner_id,
                            RunnerCertificateRecord.purpose == normalized_purpose,
                        )
                    )
                    or 0
                )
                + 1
            )
            record = RunnerCertificateRecord(
                runner_id=runner_id,
                runner_connection_generation=runner_connection_generation,
                purpose=normalized_purpose,
                fingerprint_sha256=inspected.fingerprint_sha256,
                spki_sha256=inspected.spki_sha256,
                serial_hex=inspected.serial_hex,
                spiffe_id=inspected.spiffe_id,
                trust_bundle_version=normalized_bundle,
                rotation_generation=generation,
                certificate_not_before=inspected.not_before,
                certificate_not_after=inspected.not_after,
                status="active",
                activated_at=activated_at,
            )
            db.add(record)
            db.flush()
            payload: dict[str, object] = {
                "certificate_id": str(record.id),
                "fingerprint_sha256": record.fingerprint_sha256,
                "purpose": record.purpose,
                "rotation_generation": record.rotation_generation,
                "runner_connection_generation": record.runner_connection_generation,
                "runner_id": str(record.runner_id),
                "trust_bundle_version": record.trust_bundle_version,
            }
            db.add(
                _event(
                    event_type="runner.certificate.activated",
                    fingerprint=record.fingerprint_sha256,
                    payload=payload,
                )
            )
            return self._receipt(record)

    def revoke_certificate(
        self,
        *,
        fingerprint_sha256: str,
        reason: str,
        now: datetime | None = None,
    ) -> bool:
        """Revoke one leaf immediately; repeated revocation is idempotent."""

        revoked_at = _validate_time(now or _utcnow(), field="revocation time")
        fingerprint = fingerprint_sha256.lower()
        if len(fingerprint) != 64 or any(
            character not in "0123456789abcdef" for character in fingerprint
        ):
            raise CertificateLifecycleError(
                "runner_certificate_fingerprint_invalid",
                "Runner certificate fingerprint is invalid",
            )
        normalized_reason = _text(reason, field="revocation_reason", maximum=256)
        with self._session_factory.begin() as db:
            record = db.scalar(
                sa.select(RunnerCertificateRecord)
                .where(RunnerCertificateRecord.fingerprint_sha256 == fingerprint)
                .with_for_update()
            )
            if record is None:
                return False
            if record.status == "revoked":
                return True
            if revoked_at < _as_utc(record.activated_at):
                raise CertificateLifecycleError(
                    "runner_certificate_revocation_time_invalid",
                    "Runner certificate revocation cannot precede activation",
                )
            record.status = "revoked"
            record.revoked_at = revoked_at
            record.revocation_reason = normalized_reason
            record.retire_at = record.retire_at or revoked_at
            payload: dict[str, object] = {
                "certificate_id": str(record.id),
                "fingerprint_sha256": record.fingerprint_sha256,
                "purpose": record.purpose,
                "reason": normalized_reason,
                "runner_id": str(record.runner_id),
            }
            db.add(
                _event(
                    event_type="runner.certificate.revoked",
                    fingerprint=record.fingerprint_sha256,
                    payload=payload,
                )
            )
            return True

    def is_runner_certificate_authorized(
        self,
        *,
        runner_id: UUID,
        certificate_der: bytes,
        purpose: str,
        now: datetime | None = None,
    ) -> bool:
        """Authorize an exact presented leaf against current durable Runner state."""

        checked_at = _validate_time(now or _utcnow(), field="authorization time")
        try:
            normalized_purpose = _text(purpose, field="purpose", maximum=32)
            inspected = _inspect_certificate(certificate_der)
        except CertificateLifecycleError:
            return False
        if (
            normalized_purpose not in RUNNER_CERTIFICATE_PURPOSES
            or inspected.runner_id != runner_id
        ):
            return False
        with self._session_factory.begin() as db:
            if db.get_bind().dialect.name == "postgresql":
                db.execute(
                    sa.text(
                        "SELECT set_config('app.presented_certificate_fingerprint', "
                        ":fingerprint, true), "
                        "set_config('app.presented_certificate_purpose', :purpose, true)"
                    ),
                    {
                        "fingerprint": inspected.fingerprint_sha256,
                        "purpose": normalized_purpose,
                    },
                )
            row = db.execute(
                sa.select(RunnerCertificateRecord, RunnerRegistrationRecord)
                .join(
                    RunnerRegistrationRecord,
                    RunnerRegistrationRecord.id == RunnerCertificateRecord.runner_id,
                )
                .where(
                    RunnerCertificateRecord.fingerprint_sha256 == inspected.fingerprint_sha256,
                    RunnerCertificateRecord.purpose == normalized_purpose,
                )
            ).first()
            if row is None:
                return False
            record, runner = row
            accepted_lifecycle = record.status == "active" or (
                record.status == "retiring"
                and record.retire_at is not None
                and checked_at < _as_utc(record.retire_at)
            )
            return bool(
                accepted_lifecycle
                and record.trust_bundle_version in self._accepted_trust_bundle_versions
                and _as_utc(record.certificate_not_before)
                <= checked_at
                < _as_utc(record.certificate_not_after)
                and record.runner_id == runner_id
                and record.runner_connection_generation == runner.connection_generation
                and runner.status in {"online", "draining"}
                and record.spiffe_id == inspected.spiffe_id
                and record.spki_sha256 == inspected.spki_sha256
                and record.serial_hex == inspected.serial_hex
                and _as_utc(record.certificate_not_before) == inspected.not_before
                and _as_utc(record.certificate_not_after) == inspected.not_after
            )

    @staticmethod
    def _receipt(record: RunnerCertificateRecord) -> ActivatedRunnerCertificate:
        return ActivatedRunnerCertificate(
            certificate_id=record.id,
            runner_id=record.runner_id,
            runner_connection_generation=record.runner_connection_generation,
            purpose=record.purpose,
            fingerprint_sha256=record.fingerprint_sha256,
            rotation_generation=record.rotation_generation,
            certificate_not_after=_as_utc(record.certificate_not_after),
            trust_bundle_version=record.trust_bundle_version,
        )


__all__ = [
    "ActivatedRunnerCertificate",
    "CertificateLifecycleError",
    "RunnerCertificateAuthority",
]
