"""Reference-only gateway audit delivery through the existing dispatcher login."""

from __future__ import annotations

import json
import re
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import DBAPIError

from omnigent.db.query_context import query_name_scope
from saas.control_plane.model_gateway_evidence import (
    GATEWAY_EVIDENCE_AGGREGATE,
    GATEWAY_EVIDENCE_EVENT,
)
from saas.control_plane.outbox import OutboxPublisher, OutboxPublishError

GATEWAY_AUDIT_SIGNATURE = "public.saas_audit_model_gateway_evidence_v1(uuid,jsonb)"
GATEWAY_AUDIT_SOURCE_SHA256 = "29e4dcdc4732fb13cada9977c9813657df950f84edeb08ad7aaecdd9c3d40ff3"
_KEYS = {"event_type", "tenant_id", "reservation_id", "evidence_id", "evidence_sha256"}


def verify_gateway_audit_function(connection: Connection) -> int | None:
    """Allow only this source-pinned definer; older schemas have no such authority."""

    row = connection.execute(
        sa.text(
            "SELECT routine.oid,routine.prosecdef,routine.prokind,language.lanname,"
            "routine.proconfig,pg_get_function_result(routine.oid),"
            "encode(sha256(convert_to(routine.prosrc,'UTF8')),'hex'),"
            "pg_get_userbyid(routine.proowner),(SELECT count(*)=4 "
            "AND bool_and(relowner=routine.proowner) FROM pg_class WHERE oid IN ("
            "to_regclass('public.saas_model_gateway_evidence'),"
            "to_regclass('public.saas_control_plane_outbox'),"
            "to_regclass('public.saas_platform_audit_events'),"
            "to_regclass('public.saas_platform_audit_chain_heads'))),"
            "routine.provolatile,routine.proparallel,routine.proleakproof,routine.proisstrict "
            "FROM pg_proc routine JOIN pg_language language ON language.oid=routine.prolang "
            "WHERE routine.oid=to_regprocedure(:signature)"
        ),
        {"signature": GATEWAY_AUDIT_SIGNATURE},
    ).one_or_none()
    if row is None:
        return None
    oid, definer, kind, language, config, result, source_hash, owner, same_owner, *flags = row
    acls = connection.execute(
        sa.text(
            "SELECT pg_get_userbyid(acl.grantee),pg_get_userbyid(acl.grantor),"
            "acl.privilege_type,acl.is_grantable FROM pg_proc routine "
            "CROSS JOIN LATERAL aclexplode(COALESCE(routine.proacl,"
            "acldefault('f',routine.proowner))) acl WHERE routine.oid=:oid"
        ),
        {"oid": oid},
    ).all()
    if (
        not definer
        or kind != "f"
        or language != "plpgsql"
        or config != ["search_path=pg_catalog, pg_temp"]
        or result != "boolean"
        or source_hash != GATEWAY_AUDIT_SOURCE_SHA256
        or not same_owner
        or flags != ["v", "u", False, False]
        or set(map(tuple, acls))
        != {(owner, owner, "EXECUTE", False), ("saas_dispatcher", owner, "EXECUTE", False)}
        or len(acls) != 2
    ):
        raise RuntimeError("model_gateway_audit_function_contract_rejected")
    return int(oid)


class ModelGatewayAuditPublisher:
    """Append to the shared audit chain; never mutate budgets or customer charges."""

    def __init__(self, engine: Engine, fallback: OutboxPublisher) -> None:
        self._engine = engine
        self._fallback = fallback

    def validate_outbox_configuration(self) -> None:
        if self._engine.dialect.name != "postgresql":
            raise RuntimeError("model_gateway_audit_requires_postgresql")
        with self._engine.connect() as connection:
            if verify_gateway_audit_function(connection) is None:
                raise RuntimeError("model_gateway_audit_function_unavailable")

    def publish(
        self,
        *,
        event_id: UUID,
        event_type: str,
        aggregate_type: str,
        aggregate_key: str,
        payload: dict[str, object],
    ) -> None:
        if not (
            event_type == GATEWAY_EVIDENCE_EVENT
            or aggregate_type == GATEWAY_EVIDENCE_AGGREGATE
            or payload.get("event_type") == GATEWAY_EVIDENCE_EVENT
        ):
            self._fallback.publish(
                event_id=event_id,
                event_type=event_type,
                aggregate_type=aggregate_type,
                aggregate_key=aggregate_key,
                payload=payload,
            )
            return
        try:
            witness = payload.get("evidence_sha256")
            if (
                not isinstance(event_id, UUID)
                or event_id.int == 0
                or event_type != GATEWAY_EVIDENCE_EVENT
                or aggregate_type != GATEWAY_EVIDENCE_AGGREGATE
                or set(payload) != _KEYS
                or payload.get("event_type") != event_type
                or payload.get("reservation_id") != aggregate_key
                or not isinstance(witness, str)
                or re.fullmatch(r"[0-9a-f]{64}", witness) is None
            ):
                raise ValueError
            for name in ("tenant_id", "reservation_id", "evidence_id"):
                value = payload[name]
                if not isinstance(value, str) or str(UUID(value)) != value or UUID(value).int == 0:
                    raise ValueError
        except (ValueError, TypeError, KeyError):
            raise OutboxPublishError(
                "model_gateway_audit_envelope_rejected", retryable=False, pre_side_effect=True
            ) from None
        try:
            with (
                query_name_scope("saas.model_gateway_audit.retain_evidence"),
                self._engine.begin() as db,
            ):
                result = db.scalar(
                    sa.text(
                        "SELECT public.saas_audit_model_gateway_evidence_v1("
                        ":event_id,CAST(:payload AS jsonb))"
                    ),
                    {"event_id": event_id, "payload": json.dumps(payload)},
                )
                if type(result) is not bool:
                    raise RuntimeError("model_gateway_audit_result_invalid")
        except DBAPIError as error:
            if getattr(error.orig, "sqlstate", None) == "22023":
                raise OutboxPublishError(
                    "model_gateway_audit_evidence_rejected", retryable=False, pre_side_effect=True
                ) from None
            raise OutboxPublishError(
                "model_gateway_audit_unavailable", retryable=True, pre_side_effect=False
            ) from None

    def close(self) -> None:
        close = getattr(self._fallback, "close", None)
        if callable(close):
            close()
