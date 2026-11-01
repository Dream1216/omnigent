"""Keep retained R/S audit delivery available to a rollback application."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import DBAPIError

from omnigent.db.query_context import query_name_scope
from saas.control_plane.outbox import OutboxClaimRoute, OutboxPublisher, OutboxPublishError


@dataclass(frozen=True)
class _Contract:
    event: str
    aggregate: str
    reference: str
    function: str
    source_table: str
    source_hash: str


_CONTRACTS = (
    _Contract(
        "model_gateway.evidence_retained",
        "model_gateway_budget",
        "reservation_id",
        "public.saas_audit_model_gateway_evidence_v1",
        "public.saas_model_gateway_evidence",
        "320f3ba6c139b43d55e43585b2f5aef999e315662641716bf80d881232f789bd",
    ),
    _Contract(
        "platform.model_publication.disabled",
        "platform_model",
        "disablement_id",
        "public.saas_audit_model_disablement_v1",
        "public.saas_model_publication_disablements",
        "93f14f7147bfc13013208462d701f29886f94876331afe9d792207e10a3cab61",
    ),
    _Contract(
        "platform.model_publication.revocation_requested",
        "platform_model",
        "revocation_id",
        "public.saas_audit_model_revocation_v1",
        "public.saas_model_publication_revocations",
        "33d263ca882740db9c144df91421e218a4249dad107453b0bbd9200679140dfc",
    ),
)


def verify_retained_model_audit_functions(connection: Connection) -> tuple[int, ...]:
    """Admit only the three source-pinned, dispatcher-only retained audit RPCs."""

    found = []
    for contract in _CONTRACTS:
        row = connection.execute(
            sa.text(
                "SELECT routine.oid,routine.prosecdef,routine.prokind,language.lanname,"
                "routine.proconfig,pg_get_function_result(routine.oid),"
                "encode(sha256(convert_to(routine.prosrc,'UTF8')),'hex'),"
                "pg_get_userbyid(routine.proowner),(SELECT count(*)=4 "
                "AND bool_and(relowner=routine.proowner) FROM pg_class WHERE oid IN ("
                "to_regclass(:source_table),to_regclass('public.saas_control_plane_outbox'),"
                "to_regclass('public.saas_platform_audit_events'),"
                "to_regclass('public.saas_platform_audit_chain_heads'))),"
                "routine.provolatile,routine.proparallel,routine.proleakproof,routine.proisstrict "
                "FROM pg_proc routine JOIN pg_language language ON language.oid=routine.prolang "
                "WHERE routine.oid=to_regprocedure(:signature)"
            ),
            {
                "signature": contract.function + "(uuid,jsonb)",
                "source_table": contract.source_table,
            },
        ).one_or_none()
        if row is None:
            continue
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
            or source_hash != contract.source_hash
            or not same_owner
            or flags != ["v", "u", False, False]
            or set(map(tuple, acls))
            != {(owner, owner, "EXECUTE", False), ("saas_dispatcher", owner, "EXECUTE", False)}
            or len(acls) != 2
        ):
            raise RuntimeError("retained_model_audit_function_contract_rejected")
        found.append(int(oid))
    model_tables = tuple(
        connection.execute(
            sa.text(
                "SELECT to_regclass('public.saas_model_connections') IS NOT NULL,"
                "to_regclass('public.saas_model_gateway_evidence') IS NOT NULL,"
                "to_regclass('public.saas_model_publication_disablements') IS NOT NULL,"
                "to_regclass('public.saas_model_publication_revocations') IS NOT NULL"
            )
        ).one()
    )
    if model_tables not in {(False, False, False, False), (True, True, True, True)}:
        raise RuntimeError("retained_model_audit_schema_contract_rejected")
    expected_count = len(_CONTRACTS) if all(model_tables) else 0
    if len(found) != expected_count:
        raise RuntimeError("retained_model_audit_function_set_incomplete")
    return tuple(found)


def _uuid_reference(value: object) -> bool:
    try:
        return isinstance(value, str) and bool(UUID(value).int) and str(UUID(value)) == value
    except ValueError:
        return False


class RetainedModelAuditPublisher:
    """Deliver retained reference events, never ordinary provider or pricing work."""

    def __init__(self, engine: Engine, fallback: OutboxPublisher) -> None:
        self._engine, self._fallback = engine, fallback
        self._claim_routes: tuple[OutboxClaimRoute, ...] | None = None
        self._routes_validated = False

    @property
    def claim_routes(self) -> tuple[OutboxClaimRoute, ...] | None:
        if not self._routes_validated:
            raise RuntimeError("retained_model_audit_routes_not_validated")
        return self._claim_routes

    def validate_outbox_configuration(self) -> None:
        self._routes_validated = False
        if self._engine.dialect.name != "postgresql":
            raise RuntimeError("retained_model_audit_requires_postgresql")
        with self._engine.connect() as connection:
            retained = verify_retained_model_audit_functions(connection)
        fallback_routes = getattr(self._fallback, "claim_routes", None)
        if fallback_routes is None:
            # A legacy unrestricted fallback keeps its existing envelope contract.
            self._claim_routes = None
        else:
            routes = tuple(fallback_routes)
            if not routes or any(not isinstance(route, OutboxClaimRoute) for route in routes):
                raise RuntimeError("retained_model_audit_fallback_routes_rejected")
            if retained:
                routes += tuple(
                    OutboxClaimRoute(contract.aggregate, contract.event, contract.event)
                    for contract in _CONTRACTS
                )
            for index, route in enumerate(routes):
                if any(
                    route.aggregate_type == other.aggregate_type
                    and route.event_type == other.event_type
                    and (
                        route.payload_event_type is None
                        or other.payload_event_type is None
                        or route.payload_event_type == other.payload_event_type
                    )
                    for other in routes[:index]
                ):
                    raise RuntimeError("retained_model_audit_claim_routes_overlap")
            self._claim_routes = routes
        self._routes_validated = True

    def publish(
        self,
        *,
        event_id: UUID,
        event_type: str,
        aggregate_type: str,
        aggregate_key: str,
        payload: dict[str, object],
    ) -> None:
        matches = [
            contract
            for contract in _CONTRACTS
            if (
                event_type == contract.event
                or payload.get("event_type") == contract.event
                or (
                    contract.reference == "reservation_id" and aggregate_type == contract.aggregate
                )
            )
        ]
        if not matches:
            self._fallback.publish(
                event_id=event_id,
                event_type=event_type,
                aggregate_type=aggregate_type,
                aggregate_key=aggregate_key,
                payload=payload,
            )
            return
        valid = len(matches) == 1
        contract = matches[0]
        gateway = contract.reference == "reservation_id"
        keys = (
            {"event_type", "tenant_id", "reservation_id", "evidence_id", "evidence_sha256"}
            if gateway
            else {"event_type", "schema_version", contract.reference}
        )
        valid = (
            valid
            and isinstance(event_id, UUID)
            and bool(event_id.int)
            and event_type == contract.event
            and aggregate_type == contract.aggregate
            and set(payload) == keys
            and payload.get("event_type") == contract.event
            and _uuid_reference(aggregate_key)
            and payload.get(contract.reference) == aggregate_key
        )
        if gateway:
            witness = payload.get("evidence_sha256")
            valid = (
                valid
                and all(_uuid_reference(payload.get(key)) for key in ("tenant_id", "evidence_id"))
                and (
                    isinstance(witness, str) and re.fullmatch("[0-9a-f]{64}", witness) is not None
                )
            )
        else:
            valid = (
                valid
                and type(payload.get("schema_version")) is int
                and payload.get("schema_version") == 1
            )
        if not valid:
            raise OutboxPublishError(
                "retained_model_audit_envelope_rejected", retryable=False, pre_side_effect=True
            )
        try:
            with (
                query_name_scope("saas.retained_model_audit.retain_evidence"),
                self._engine.begin() as db,
            ):
                result = db.scalar(
                    sa.text(f"SELECT {contract.function}(:event_id,CAST(:payload AS jsonb))"),
                    {"event_id": event_id, "payload": json.dumps(payload)},
                )
                if type(result) is not bool:
                    raise RuntimeError("retained_model_audit_result_invalid")
        except DBAPIError as error:
            invalid = getattr(error.orig, "sqlstate", None) == "22023"
            raise OutboxPublishError(
                "retained_model_audit_evidence_rejected"
                if invalid
                else "retained_model_audit_unavailable",
                retryable=not invalid,
                pre_side_effect=invalid,
            ) from None

    def close(self) -> None:
        close = getattr(self._fallback, "close", None)
        if callable(close):
            close()
