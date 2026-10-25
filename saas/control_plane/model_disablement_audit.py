"""Reference-only model cutoff delivery to the existing shared audit chain."""

from __future__ import annotations

import json
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import DBAPIError

from omnigent.db.query_context import query_name_scope
from saas.control_plane.model_disablement import DISABLEMENT_EVENT
from saas.control_plane.model_gateway_audit import verify_source_audit_function
from saas.control_plane.outbox import OutboxPublisher, OutboxPublishError

DISABLEMENT_AUDIT_SIGNATURE = "public.saas_audit_model_disablement_v1(uuid,jsonb)"
DISABLEMENT_AUDIT_SOURCE_SHA256 = (
    "93f14f7147bfc13013208462d701f29886f94876331afe9d792207e10a3cab61"
)


def verify_disablement_audit_function(connection: Connection) -> int | None:
    return verify_source_audit_function(
        connection,
        signature=DISABLEMENT_AUDIT_SIGNATURE,
        expected_source_hash=DISABLEMENT_AUDIT_SOURCE_SHA256,
        source_table="public.saas_model_publication_disablements",
    )


class ModelDisablementAuditPublisher:
    _event_type = DISABLEMENT_EVENT
    _reference_key = "disablement_id"
    _function_name = "public.saas_audit_model_disablement_v1"
    _failure_prefix = "model_disablement_audit"
    _query_name = "saas.model_disablement_audit.retain_evidence"

    def __init__(self, engine: Engine, fallback: OutboxPublisher) -> None:
        self._engine, self._fallback = engine, fallback

    def validate_outbox_configuration(self) -> None:
        if self._engine.dialect.name != "postgresql":
            raise RuntimeError(f"{self._failure_prefix}_requires_postgresql")
        with self._engine.connect() as db:
            if self._verify_function(db) is None:
                raise RuntimeError(f"{self._failure_prefix}_function_unavailable")

    def _verify_function(self, connection: Connection) -> int | None:
        return verify_disablement_audit_function(connection)

    def publish(
        self,
        *,
        event_id: UUID,
        event_type: str,
        aggregate_type: str,
        aggregate_key: str,
        payload: dict[str, object],
    ) -> None:
        if event_type != self._event_type and payload.get("event_type") != self._event_type:
            self._fallback.publish(
                event_id=event_id,
                event_type=event_type,
                aggregate_type=aggregate_type,
                aggregate_key=aggregate_key,
                payload=payload,
            )
            return
        try:
            if (
                not isinstance(event_id, UUID)
                or not event_id.int
                or event_type != self._event_type
                or aggregate_type != "platform_model"
                or set(payload) != {"event_type", "schema_version", self._reference_key}
                or payload["event_type"] != event_type
                or type(payload["schema_version"]) is not int
                or payload["schema_version"] != 1
                or payload[self._reference_key] != aggregate_key
                or not isinstance(aggregate_key, str)
                or not UUID(aggregate_key).int
                or str(UUID(aggregate_key)) != aggregate_key
            ):
                raise ValueError
        except (ValueError, TypeError, KeyError):
            raise OutboxPublishError(
                f"{self._failure_prefix}_envelope_rejected",
                retryable=False,
                pre_side_effect=True,
            ) from None
        try:
            with (
                query_name_scope(self._query_name),
                self._engine.begin() as db,
            ):
                result = db.scalar(
                    sa.text(f"SELECT {self._function_name}(:event_id,CAST(:payload AS jsonb))"),
                    {"event_id": event_id, "payload": json.dumps(payload)},
                )
                if type(result) is not bool:
                    raise RuntimeError(f"{self._failure_prefix}_result_invalid")
        except DBAPIError as error:
            invalid = getattr(error.orig, "sqlstate", None) == "22023"
            raise OutboxPublishError(
                f"{self._failure_prefix}_evidence_rejected"
                if invalid
                else f"{self._failure_prefix}_unavailable",
                retryable=not invalid,
                pre_side_effect=invalid,
            ) from None

    def close(self) -> None:
        close = getattr(self._fallback, "close", None)
        if callable(close):
            close()
