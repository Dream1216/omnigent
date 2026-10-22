"""Owner-only maintenance of a complete, fenced Runtime placement.

The recovery coordinator supplies real backup/fence and installed-provider checks.
No HTTP service, role grant, environment authority or default proof adapter exists.
Private checkpoints retain the complete CAS; public results contain hashes only.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from uuid import UUID, uuid4

from psycopg import sql
from psycopg.types.json import Jsonb

from saas.production import postgresql_migration as migration
from saas.production import postgresql_preserving_adapter as db
from saas.production.postgresql_preserving_recovery import RecoveryOperation

HEAD = "p0s000000018"
TABLES = (
    "saas_runtime_placements",
    "saas_runtime_partitions",
    "saas_runtime_resource_bindings",
    "saas_runtime_identity_aliases",
)


@dataclass(frozen=True)
class RuntimeMaintenanceOperation:
    recovery: RecoveryOperation
    realm: str
    namespace: str
    namespace_uid: str
    cluster_uid: str
    placement_id: str
    runtime_version: str
    upstream_revision: str
    official_schema_revision: str
    adapter_contract_version: str
    runtime_observation_ref: str
    runtime_observation_sha256: str

    def validate(self) -> None:
        self.recovery.validate()
        db.need(self.realm in {"isolation", "production"}, "invalid_maintenance_realm")
        for value in (self.namespace_uid, self.cluster_uid, self.placement_id):
            db.need(str(UUID(value)) == value, "invalid_maintenance_scope_uuid")
        for value in (
            self.namespace,
            self.runtime_version,
            self.official_schema_revision,
            self.adapter_contract_version,
            self.runtime_observation_ref,
        ):
            db.need(
                isinstance(value, str) and 0 < len(value) <= 1024 and value.strip() == value,
                "runtime_target_or_observation_missing",
            )
        db.need(
            bool(re.fullmatch(r"[0-9a-f]{40}", self.upstream_revision)), "upstream_pin_invalid"
        )
        db.need(
            bool(re.fullmatch(r"[0-9a-f]{64}", self.runtime_observation_sha256)),
            "runtime_observation_pin_invalid",
        )


def upgraded_scope(before: dict, operation: RuntimeMaintenanceOperation) -> dict:
    """Project only lineage/generation changes; never rewrite scope or physical IDs."""
    result = copy.deepcopy(before)
    db.need(len(result["placements"]) == 1, "exact_placement_required")
    placement = result["placements"][0]
    db.need(placement["id"] == operation.placement_id, "placement_scope_mismatch")
    db.need(placement["status"] == "active", "placement_not_active")
    placement["official_schema_revision"] = operation.official_schema_revision
    partitions = {row["id"]: row for row in result["partitions"]}
    db.need(bool(partitions), "complete_nonempty_partition_scope_required")
    for partition in partitions.values():
        db.need(partition["placement_id"] == placement["id"], "partition_scope_mismatch")
        db.need(partition["status"] == "active", "nonactive_partition_requires_separate_review")
        generation = partition["placement_generation"]
        db.need(type(generation) is int and 0 < generation < 2**63 - 1, "generation_exhausted")
        partition.update(
            runtime_version=operation.runtime_version,
            source_revision=operation.upstream_revision,
            adapter_contract_version=operation.adapter_contract_version,
            placement_generation=generation + 1,
        )
    for binding in result["bindings"]:
        partition = partitions.get(binding["runtime_partition_id"])
        if partition is None:
            raise db.Refused("binding_partition_missing")
        db.need(
            (binding["tenant_id"], binding["space_id"])
            == (partition["tenant_id"], partition["space_id"]),
            "binding_scope_mismatch",
        )
        if binding["status"] != "active":
            continue
        db.need(
            binding["partition_generation"] == partition["placement_generation"] - 1,
            "active_binding_generation_stale",
        )
        generation = binding["binding_generation"]
        db.need(type(generation) is int and 0 < generation < 2**63 - 1, "generation_exhausted")
        binding.update(
            partition_generation=partition["placement_generation"],
            binding_generation=generation + 1,
        )
    for alias in result["aliases"]:
        db.need(alias["runtime_partition_id"] in partitions, "alias_scope_mismatch")
    return result


class RuntimePlacementMaintenance:
    """prepare/apply/reconcile over a dedicated direct owner and existing coordinator.

    verify_runtime must read the actual installed digest/product, provider workspace
    inventory, migration receipt and namespace/cluster/database identity for EVERY
    supplied partition/binding. before_mutation rechecks the retained backup and
    live write fence. Both callbacks must return None after successful checks.
    References/hashes in the operation alone never authorize SQL.
    """

    def __init__(
        self,
        *,
        plan,
        engines: Mapping,
        owner,
        maintenance,
        operation: RuntimeMaintenanceOperation,
        source_gold: dict,
        verify_runtime: Callable[[RuntimeMaintenanceOperation, dict], None],
        before_mutation: Callable[[RecoveryOperation, str], None],
        checkpoint: Callable[[str, dict], None],
        max_rows: int,
    ) -> None:
        operation.validate()
        migration._validate_plan(plan)
        db.need(
            plan.product_revision == operation.recovery.candidate_product_revision,
            "candidate_product_mismatch",
        )
        db.need(
            db.sha(db.canonical(source_gold)) == operation.recovery.source_gold_sha256,
            "source_gold_bytes_mismatch",
        )
        db.need(
            all(callable(item) for item in (verify_runtime, before_mutation, checkpoint)),
            "real_coordinator_adapters_required",
        )
        db.need(type(max_rows) is int and 0 < max_rows <= 100000, "bounded_scope_required")
        self.plan, self.engines, self.owner, self.maintenance = plan, engines, owner, maintenance
        self.operation, self.gold = operation, source_gold
        self.verify_runtime, self.before_mutation, self.checkpoint = (
            verify_runtime,
            before_mutation,
            checkpoint,
        )
        self.maximum = max_rows
        self._identity()

    def _identity(self):
        for connection in (self.owner, self.maintenance):
            db.require_idle(connection)
            db.need(
                db.database_identity(connection, self.maintenance)
                == self.operation.recovery.database_identity,
                "actual_database_identity_mismatch",
            )
            db.require_idle(connection)
        principal = db.one(
            self.owner,
            "SELECT current_user AS login, session_user AS session_login, "
            "rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,rolreplication "
            "FROM pg_catalog.pg_roles WHERE rolname=current_user",
        )
        db.need(
            principal["login"] == principal["session_login"] == self.plan.saas_owner.login
            and not any(principal[k] for k in principal if k not in {"login", "session_login"}),
            "direct_nonprivileged_owner_required",
        )
        db.require_idle(self.owner)

    def _settings(self, *, read_only: bool):
        self.owner.execute(
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
            if read_only
            else "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"
        )
        self.owner.execute("SET LOCAL row_security=on")
        self.owner.execute("SET LOCAL search_path=pg_catalog,pg_temp")
        self.owner.execute("SET LOCAL lock_timeout='5s'")
        self.owner.execute("SET LOCAL statement_timeout='60s'")
        db.need(
            self.owner.execute("SELECT version_num FROM public.saas_alembic_version").fetchall()
            == [(HEAD,)],
            "current_runtime_maintenance_head_required",
        )

    def _scope(self):
        placement_id = self.operation.placement_id
        statements = {
            "placements": (
                "SELECT to_jsonb(r) FROM public.saas_runtime_placements r WHERE id=%s ORDER BY id",
            ),
            "partitions": (
                "SELECT to_jsonb(r) FROM public.saas_runtime_partitions r "
                "WHERE placement_id=%s ORDER BY id",
            ),
            "bindings": (
                "SELECT to_jsonb(r) FROM public.saas_runtime_resource_bindings r "
                "JOIN public.saas_runtime_partitions p ON p.id=r.runtime_partition_id "
                "WHERE p.placement_id=%s ORDER BY r.id",
            ),
            "aliases": (
                "SELECT to_jsonb(r) FROM public.saas_runtime_identity_aliases r "
                "JOIN public.saas_runtime_partitions p ON p.id=r.runtime_partition_id "
                "WHERE p.placement_id=%s ORDER BY r.runtime_partition_id,r.user_id",
            ),
        }
        result = {}
        for name, (statement,) in statements.items():
            rows = self.owner.execute(
                statement + " LIMIT %s", (placement_id, self.maximum + 1)
            ).fetchall()
            db.need(len(rows) <= self.maximum, "complete_scope_exceeds_bound")
            result[name] = [row[0] for row in rows]
        # Preserve real timestamps in the CAS, but do not change them: explicit
        # lineage updates have no ORM onupdate, keeping history byte-for-byte.
        upgraded_scope(result, self.operation)
        return result

    def _quiescent(self):
        active = self.owner.execute(
            "SELECT EXISTS(SELECT 1 FROM public.saas_runs r WHERE r.project_id IN "
            "(SELECT b.project_id FROM public.saas_runtime_resource_bindings b "
            "JOIN public.saas_runtime_partitions p ON p.id=b.runtime_partition_id "
            "WHERE p.placement_id=%s AND b.project_id IS NOT NULL) AND "
            "(r.terminal_at IS NULL OR r.lease_expires_at>clock_timestamp())) OR "
            "EXISTS(SELECT 1 FROM public.saas_worktree_instances w JOIN public.saas_runs r "
            "ON r.id=w.run_id JOIN public.saas_runtime_resource_bindings b "
            "ON b.project_id=r.project_id "
            "JOIN public.saas_runtime_partitions p ON p.id=b.runtime_partition_id "
            "WHERE p.placement_id=%s AND (w.lease_expires_at>clock_timestamp() "
            "OR w.status IN ('reserved','materializing','ready','checkpointing'))) OR "
            "EXISTS(SELECT 1 FROM public.saas_capability_tokens c "
            "JOIN public.saas_runtime_resource_bindings b ON b.project_id=c.project_id "
            "JOIN public.saas_runtime_partitions p ON p.id=b.runtime_partition_id "
            "WHERE p.placement_id=%s AND c.revoked_at IS NULL "
            "AND c.expires_at>clock_timestamp()) OR "
            "EXISTS(SELECT 1 FROM public.saas_runner_registrations "
            "WHERE placement_id=%s AND active_leases>0)",
            (self.operation.placement_id,) * 4,
        ).fetchone()[0]
        db.need(active is False, "placement_not_drained")

    def _validate_state(self, state):
        db.need(
            state.get("phase") == "prepared" and state.get("operation") == asdict(self.operation),
            "prepared_operation_required",
        )
        db.need(
            state.get("before_sha256") == db.sha(db.canonical(state["before"]))
            and state.get("after") == upgraded_scope(state["before"], self.operation),
            "prepared_scope_or_projection_corrupt",
        )

    def prepare(self) -> dict:
        self._identity()
        verified = migration._verify_state(self.plan, dict(self.engines))
        db.need(
            verified.saas_head == HEAD
            and verified.official_head == self.operation.official_schema_revision,
            "installed_source_and_runtime_heads_required",
        )
        # The installed source verifier chooses independent source-owned gold;
        # the supplied retained gold is additionally pinned by the operation.
        with self.owner.transaction():
            self._settings(read_only=True)
            before = self._scope()
            self._quiescent()
        db.need(
            self.verify_runtime(self.operation, copy.deepcopy(before)) is None,
            "runtime_proof_must_not_return_flag",
        )
        state = {
            "phase": "prepared",
            "operation": asdict(self.operation),
            "before": before,
            "before_sha256": db.sha(db.canonical(before)),
            "after": upgraded_scope(before, self.operation),
        }
        self.checkpoint("runtime_metadata_prepared", copy.deepcopy(state))
        return state

    def _receipt(self):
        return self.owner.execute(
            "SELECT request_hash,payload FROM public.saas_control_plane_outbox "
            "WHERE idempotency_key=%s AND aggregate_type='runtime_placement' "
            "AND aggregate_key=%s AND event_type='runtime.placement.upgraded'",
            (
                "runtime-maintenance:" + self.operation.recovery.operation_id,
                self.operation.placement_id,
            ),
        ).fetchall()

    def _result(self, state, current, receipt):
        db.need(len(receipt) == 1, "runtime_upgrade_receipt_missing_or_conflicting")
        request_hash = db.sha(
            db.canonical(
                {"operation": state["operation"], "before_sha256": state["before_sha256"]}
            )
        )
        payload = self._payload(state)
        db.need(receipt[0] == (request_hash, payload), "runtime_upgrade_receipt_conflict")
        db.need(current == state["after"], "committed_runtime_scope_drift")
        return {
            "operation_id": self.operation.recovery.operation_id,
            "before_sha256": state["before_sha256"],
            "after_sha256": db.sha(db.canonical(current)),
            "phase": "runtime_metadata_committed",
            "production_admitted": False,
        }

    def _payload(self, state):
        return {
            "operation_id": self.operation.recovery.operation_id,
            "placement_id": self.operation.placement_id,
            "before_sha256": state["before_sha256"],
            "after_sha256": db.sha(db.canonical(state["after"])),
            "product_revision": self.operation.recovery.candidate_product_revision,
            "upstream_revision": self.operation.upstream_revision,
            "official_schema_revision": self.operation.official_schema_revision,
            "partitions": len(state["after"]["partitions"]),
            "bindings": len(state["after"]["bindings"]),
        }

    def reconcile(self, state: dict) -> dict:
        """Read-only outcome lookup after an unknown COMMIT; no automatic retries."""
        self._validate_state(state)
        self._identity()
        with self.owner.transaction():
            self._settings(read_only=True)
            return self._result(state, self._scope(), self._receipt())

    def apply(self, state: dict) -> dict:
        self._validate_state(state)
        self._identity()
        db.need(
            self.before_mutation(self.operation.recovery, "upgrade_runtime_metadata") is None,
            "coordinator_must_revalidate_not_return_authorized_flag",
        )
        db.need(
            self.verify_runtime(self.operation, copy.deepcopy(state["before"])) is None,
            "runtime_proof_must_not_return_flag",
        )
        self.checkpoint("runtime_metadata_before_sql", copy.deepcopy(state))
        # SERIALIZABLE plus table locks protects the complete membership set,
        # including phantom partitions/bindings; the live external fence is still mandatory.
        with self.owner.transaction():
            self._settings(read_only=False)
            for table in TABLES:
                self.owner.execute(
                    sql.SQL("LOCK TABLE public.{} IN SHARE ROW EXCLUSIVE MODE").format(
                        sql.Identifier(table)
                    )
                )
            current, receipt = self._scope(), self._receipt()
            if receipt:
                result = self._result(state, current, receipt)
            else:
                db.need(current == state["before"], "complete_placement_CAS_failed")
                self._quiescent()
                for key, table, fields in (
                    ("placements", TABLES[0], ("official_schema_revision",)),
                    (
                        "partitions",
                        TABLES[1],
                        (
                            "runtime_version",
                            "source_revision",
                            "adapter_contract_version",
                            "placement_generation",
                        ),
                    ),
                    ("bindings", TABLES[2], ("partition_generation", "binding_generation")),
                ):
                    for old, new in zip(state["before"][key], state["after"][key], strict=True):
                        if old == new:
                            continue
                        changed = self.owner.execute(
                            sql.SQL(
                                "UPDATE public.{} AS r SET {} WHERE id=%s AND to_jsonb(r)=%s"
                            ).format(
                                sql.Identifier(table),
                                sql.SQL(",").join(
                                    sql.SQL("{}=%s").format(sql.Identifier(field))
                                    for field in fields
                                ),
                            ),
                            (*[new[field] for field in fields], old["id"], Jsonb(old)),
                        )
                        db.need(changed.rowcount == 1, "runtime_row_CAS_failed")
                payload = self._payload(state)
                request_hash = db.sha(
                    db.canonical(
                        {"operation": state["operation"], "before_sha256": state["before_sha256"]}
                    )
                )
                self.owner.execute(
                    "INSERT INTO public.saas_control_plane_outbox "
                    "(id,aggregate_type,aggregate_key,event_type,payload,idempotency_key,"
                    "request_hash,attempt_count) "
                    "VALUES (%s,'runtime_placement',%s,'runtime.placement.upgraded',%s,%s,%s,0)",
                    (
                        uuid4(),
                        self.operation.placement_id,
                        Jsonb(payload),
                        "runtime-maintenance:" + self.operation.recovery.operation_id,
                        request_hash,
                    ),
                )
                result = self._result(state, self._scope(), self._receipt())
            # Re-read actual backup/fence and installed/provider facts after SQL,
            # before COMMIT. The provider adapter validates physical resources
            # against the original scope; it must not wait for another connection
            # to observe this transaction's uncommitted metadata.
            db.need(
                self.verify_runtime(self.operation, copy.deepcopy(state["before"])) is None,
                "runtime_proof_must_not_return_flag",
            )
            self._quiescent()
            # The real fence check is last, after provider I/O. Its existing
            # lease contract must cover the bounded COMMIT, not just this read.
            db.need(
                self.before_mutation(
                    self.operation.recovery, "upgrade_runtime_metadata_before_commit"
                )
                is None,
                "coordinator_must_revalidate_not_return_authorized_flag",
            )
        # Failure here leaves a real committed operation and a closed outer fence.
        # The caller uses reconcile; it must not invent a failed/rolled-back result.
        self.checkpoint("runtime_metadata_committed", copy.deepcopy(result))
        return result
