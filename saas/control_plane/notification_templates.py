"""Versioned built-in notification catalog and idempotent metadata bootstrap."""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime
from hashlib import sha256
from importlib.resources import files
from typing import Literal, cast
from uuid import UUID

from saas.control_plane.notification_delivery import (
    NotificationActor,
    NotificationDeliveryError,
    NotificationDeliveryService,
    NotificationTemplate,
    NotificationTemplateView,
)

_REQUIRED_DEFAULTS = frozenset(
    {
        ("approval.requested", "in_app"),
        ("approval.requested", "email"),
        ("approval.reminder", "in_app"),
        ("approval.reminder", "email"),
        ("approval.escalated", "in_app"),
        ("approval.escalated", "email"),
        ("approval.expired", "in_app"),
        ("approval.expired", "email"),
        ("approval.decision_failed", "in_app"),
        ("approval.decision_failed", "email"),
        ("approval.decided", "in_app"),
        ("approval.decided", "email"),
        ("operation_batch.completed", "in_app"),
        ("operation_batch.completed", "email"),
        ("notification.delivery_dead_letter", "in_app"),
    }
)


@dataclass(frozen=True, slots=True)
class NotificationTemplateManifestEntry:
    template_key: str
    channel: Literal["in_app", "email"]
    locale: str
    version: int
    content_artifact_handle: str
    content_sha256: str
    variables_schema_sha256: str


@dataclass(frozen=True, slots=True)
class NotificationTemplateManifest:
    schema_version: int
    manifest_version: str
    templates: tuple[NotificationTemplateManifestEntry, ...]


@dataclass(frozen=True, slots=True)
class _CatalogArtifact:
    handle: str
    template_key: str
    channel: Literal["in_app", "email"]
    locale: str
    version: int
    subject: str = field(repr=False)
    body: str = field(repr=False)
    allowed_variables: frozenset[str]
    required_variables: frozenset[str]
    content_sha256: str
    variables_schema_sha256: str


class PackagedNotificationTemplateCatalog:
    """Read-only package catalog verified against the deployment manifest."""

    def __init__(self) -> None:
        self.manifest = load_notification_template_manifest()
        artifacts = _load_catalog_artifacts()
        by_handle = {value.handle: value for value in artifacts}
        if len(by_handle) != len(artifacts):
            raise NotificationDeliveryError("notification_template_catalog_invalid")
        for entry in self.manifest.templates:
            artifact = by_handle.get(entry.content_artifact_handle)
            if artifact is None or (
                artifact.template_key != entry.template_key
                or artifact.channel != entry.channel
                or artifact.locale != entry.locale
                or artifact.version != entry.version
                or not hmac.compare_digest(artifact.content_sha256, entry.content_sha256)
                or not hmac.compare_digest(
                    artifact.variables_schema_sha256,
                    entry.variables_schema_sha256,
                )
            ):
                raise NotificationDeliveryError("notification_template_catalog_invalid")
        self._by_handle = by_handle

    def get(
        self,
        *,
        key: str,
        locale: str,
        version: int | None = None,
        artifact_handle: str | None = None,
        expected_content_sha256: str | None = None,
        expected_variables_schema_sha256: str | None = None,
    ) -> NotificationTemplate | None:
        if artifact_handle is not None:
            artifact = self._by_handle.get(artifact_handle)
            candidates = () if artifact is None else (artifact,)
        else:
            candidates = tuple(
                value
                for value in self._by_handle.values()
                if value.template_key == key and value.locale == locale
            )
        candidates = tuple(
            value
            for value in candidates
            if value.template_key == key
            and value.locale == locale
            and (version is None or value.version == version)
        )
        if not candidates:
            return None
        artifact = max(candidates, key=lambda value: value.version)
        if (
            expected_content_sha256 is not None
            and not hmac.compare_digest(artifact.content_sha256, expected_content_sha256)
        ) or (
            expected_variables_schema_sha256 is not None
            and not hmac.compare_digest(
                artifact.variables_schema_sha256,
                expected_variables_schema_sha256,
            )
        ):
            raise NotificationDeliveryError("notification_template_artifact_mismatch")
        return NotificationTemplate(
            key=artifact.template_key,
            locale=artifact.locale,
            version=artifact.version,
            subject=artifact.subject,
            body=artifact.body,
            allowed_variables=artifact.allowed_variables,
            required_variables=artifact.required_variables,
        )


class NotificationTemplateBootstrap:
    """Idempotently publish the immutable default metadata into PostgreSQL."""

    def __init__(
        self,
        deliveries: NotificationDeliveryService,
        *,
        manifest: NotificationTemplateManifest | None = None,
    ) -> None:
        self._deliveries = deliveries
        self._manifest = manifest or load_notification_template_manifest()

    def seed(
        self,
        actor: NotificationActor,
        *,
        tenant_id: UUID | None = None,
        now: datetime | None = None,
    ) -> tuple[NotificationTemplateView, ...]:
        values = []
        for entry in self._manifest.templates:
            values.append(
                self._deliveries.create_template(
                    actor,
                    tenant_id=tenant_id,
                    template_key=entry.template_key,
                    channel=entry.channel,
                    locale=entry.locale,
                    version=entry.version,
                    content_artifact_handle=entry.content_artifact_handle,
                    content_sha256=entry.content_sha256,
                    variables_schema_sha256=entry.variables_schema_sha256,
                    idempotency_key=(
                        f"builtin:{self._manifest.manifest_version}:"
                        f"{entry.content_artifact_handle}"
                    ),
                    now=now,
                )
            )
        return tuple(values)


def load_notification_template_manifest() -> NotificationTemplateManifest:
    try:
        raw = json.loads(
            files("saas.production")
            .joinpath("notification-template-manifest.json")
            .read_text(encoding="utf-8")
        )
        entries = tuple(
            NotificationTemplateManifestEntry(
                template_key=str(value["template_key"]),
                channel=cast(Literal["in_app", "email"], value["channel"]),
                locale=str(value["locale"]),
                version=int(value["version"]),
                content_artifact_handle=str(value["content_artifact_handle"]),
                content_sha256=str(value["content_sha256"]),
                variables_schema_sha256=str(value["variables_schema_sha256"]),
            )
            for value in raw["templates"]
        )
        manifest = NotificationTemplateManifest(
            schema_version=int(raw["schema_version"]),
            manifest_version=str(raw["manifest_version"]),
            templates=entries,
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise NotificationDeliveryError("notification_template_manifest_invalid") from error
    identities = {
        (value.template_key, value.channel, value.locale, value.version) for value in entries
    }
    handles = {value.content_artifact_handle for value in entries}
    coverage = {(value.template_key, value.channel) for value in entries}
    if (
        manifest.schema_version != 1
        or not manifest.manifest_version.strip()
        or len(identities) != len(entries)
        or len(handles) != len(entries)
        or not coverage >= _REQUIRED_DEFAULTS
        or any(
            value.channel not in {"in_app", "email"}
            or value.version < 1
            or len(value.content_sha256) != 64
            or len(value.variables_schema_sha256) != 64
            for value in entries
        )
    ):
        raise NotificationDeliveryError("notification_template_manifest_invalid")
    return manifest


def _load_catalog_artifacts() -> tuple[_CatalogArtifact, ...]:
    try:
        raw = json.loads(
            files("saas.production")
            .joinpath("notification-template-catalog.json")
            .read_text(encoding="utf-8")
        )
        if int(raw["schema_version"]) != 1:
            raise ValueError("unsupported notification catalog schema")
        values = []
        for value in raw["artifacts"]:
            subject, body = str(value["subject"]), str(value["body"])
            allowed = frozenset(str(item) for item in value["allowed_variables"])
            required = frozenset(str(item) for item in value["required_variables"])
            content_hash = sha256(
                json.dumps(
                    {"body": body, "subject": subject},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            schema_hash = sha256(
                json.dumps(
                    {
                        "allowed_variables": sorted(allowed),
                        "required_variables": sorted(required),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            if not required <= allowed:
                raise ValueError("required variables are not allowlisted")
            values.append(
                _CatalogArtifact(
                    handle=str(value["handle"]),
                    template_key=str(value["template_key"]),
                    channel=cast(Literal["in_app", "email"], value["channel"]),
                    locale=str(value["locale"]),
                    version=int(value["version"]),
                    subject=subject,
                    body=body,
                    allowed_variables=allowed,
                    required_variables=required,
                    content_sha256=content_hash,
                    variables_schema_sha256=schema_hash,
                )
            )
        return tuple(values)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise NotificationDeliveryError("notification_template_catalog_invalid") from error


__all__ = [
    "NotificationTemplateBootstrap",
    "NotificationTemplateManifest",
    "NotificationTemplateManifestEntry",
    "PackagedNotificationTemplateCatalog",
    "load_notification_template_manifest",
]
