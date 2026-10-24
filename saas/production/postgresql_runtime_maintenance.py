"""Owner-only maintenance of a complete, fenced Runtime placement.

The recovery coordinator supplies real backup/fence and installed-provider checks.
No HTTP service, role grant, environment authority or default proof adapter exists.
Private checkpoints retain the complete CAS; public results contain hashes only.
"""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, replace
from importlib.resources import files
from uuid import UUID, uuid4, uuid5

from psycopg import sql
from psycopg.types.json import Jsonb

from saas.production import postgresql_migration as migration
from saas.production import postgresql_preserving_adapter as db
from saas.production.postgresql_preserving_recovery import (
    ExplicitTRecoveryOperation,
    RecoveryOperation,
)

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


@dataclass(frozen=True, kw_only=True)
class FencedTRuntimeOperation(RuntimeMaintenanceOperation):
    """Only the explicit T recovery may project an old target before nf inverse.

    The actual database remains nf/P18 while owner policies exist. A real proof
    adapter must distinguish that current source from the staged original T
    target; no old provider is claimed ready until after the real inverse.
    """

    direction: str
    source_official_schema_revision: str

    def validate(self) -> None:
        super().validate()
        recovery = self.recovery
        if type(recovery) is not ExplicitTRecoveryOperation:
            raise db.Refused("typed_t_recovery_required")
        db.need(
            self.direction in {"to_t", "to_candidate"}
            and self.source_official_schema_revision == "nf12ab34cd56"
            and self.official_schema_revision
            == ("mm1a2b3c4d5e" if self.direction == "to_t" else "nf12ab34cd56"),
            "fenced_t_runtime_transition_invalid",
        )
        if self.direction == "to_t":
            db.need(
                self.runtime_version == "0.18.0.dev20261006"
                and self.upstream_revision == recovery.rollback_upstream_revision
                and self.adapter_contract_version == recovery.rollback_adapter_contract_version,
                "fenced_t_runtime_target_mismatch",
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
            and verified.official_head
            == (
                self.operation.source_official_schema_revision
                if type(self.operation) is FencedTRuntimeOperation
                else self.operation.official_schema_revision
            ),
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


class FencedTRuntimeRecovery:
    """Existing owner primitives composed around T inverse, never under T RLS.

    Runtime rows are projected while nf/P18 owner policies still exist, before
    preserving.prepare captures its exact facts. After the real T inverse the
    original signed pair must pass the same Project/Host/Session probes. Reentry
    first restores nf/P18 and the same receipt OIDs, then freshly projects every
    current partition/binding, including legitimate rollback-period projects.

    verify_transition(parent, typed_operation, complete_scope) must perform real
    current-provider/fence plus staged-original-target checks, explicitly
    distinguishing actual nf/P18 from the pending mm/T target. verify_pair must
    run the actual original paired images against the SAME retained projects.
    Neither callback has a default or accepts a caller ready/authorized flag.
    """

    def __init__(
        self, *, preserving, runtime_operations, verify_transition, verify_pair, max_rows
    ):
        from omnigent.version import VERSION
        from saas.production import postgresql_preserving_recovery as recovery
        from saas.production import postgresql_runtime_maintenance_native as native

        upstream = json.loads(files("saas").joinpath("upstream-baseline.json").read_text())[
            "upstream_revision"
        ]

        db.need(
            type(preserving) is recovery.PreservingPostgreSqlRecovery,
            "native_t_preserving_required",
        )
        operation = preserving.operation
        db.need(
            type(operation) is recovery.ExplicitTRecoveryOperation, "typed_t_recovery_required"
        )
        operation.validate()
        # The exact Product/Server/Host pins belong to the versioned operation
        # and independently derived target Gold, not a known-broken old pair.
        # Neither this contract nor Gold is approval: real proof adapters below
        # must independently verify the approved immutable signed target.
        target = operation.target_contract()
        db.need(
            db.sha(db.canonical(preserving.gold)) == operation.source_gold_sha256
            and preserving.gold.get("rollback_target") == target,
            "explicit_t_source_gold_binding_changed",
        )
        db.need(
            target["saas_head"] == recovery.T_HEAD
            and target["official_head"] == "mm1a2b3c4d5e"
            and target["upstream_revision"] == "825f8500d7cc8e997e5562fa55694cd146165f3c"
            and target["adapter_contract_version"] == "0.2.0",
            "original_t_runtime_contract_required",
        )
        db.need(
            callable(verify_transition) and callable(verify_pair),
            "actual_t_transition_and_pair_adapters_required",
        )
        db.need(type(max_rows) is int and 0 < max_rows <= 100000, "bounded_scope_required")
        operations = tuple(runtime_operations)
        db.need(
            bool(operations)
            and all(type(item) is RuntimeMaintenanceOperation for item in operations),
            "fixed_runtime_scope_operations_required",
        )
        db.need(
            len({item.placement_id for item in operations}) == len(operations),
            "duplicate_runtime_placement",
        )
        for item in operations:
            item.validate()
            db.need(
                asdict(item.recovery) == asdict(operation)
                and item.runtime_version == VERSION
                and item.upstream_revision == upstream
                and item.official_schema_revision == "nf12ab34cd56"
                and item.adapter_contract_version == "0.2.0",
                "candidate_runtime_template_mismatch",
            )
        self.preserving, self.native = preserving, native
        self.operations = tuple(sorted(operations, key=lambda item: item.placement_id))
        self.verify_transition, self.verify_pair, self.maximum = (
            verify_transition,
            verify_pair,
            max_rows,
        )

    def _save(self, phase, state):
        self.preserving.checkpoint(phase, copy.deepcopy(state))

    def _validate(self, state, phase):
        from saas.production.postgresql_preserving_recovery import require_checkpoint_operation

        require_checkpoint_operation(state, self.preserving.operation)
        db.need(
            state.get("phase") == phase
            and state.get("runtime_templates") == [asdict(item) for item in self.operations],
            "t_runtime_phase_or_scope_changed",
        )

    def _rows(self):
        p = self.preserving
        return self.native.runtime_rows_snapshot(
            p.maintenance,
            expected_identity=p.operation.database_identity,
            owner=p.owner,
            maximum=self.maximum,
        )

    def _facts(self):
        from saas.production.postgresql_preserving_recovery import _source_projection

        p = self.preserving
        projection = p._capture(p.maintenance, "public")  # Complete receipt coverage first.
        db.need(len(projection["tables"]) == 3, "complete_receipts_required")
        projection = _source_projection(p.plan, p.engines)
        db.need(
            projection["inventory_sha256"] == p.gold["candidate_inventory_sha256"]
            and projection["security_sha256"] == p.gold["candidate_security_sha256"],
            "independent_clean_source_gold_mismatch",
        )
        db.need(
            not any(
                row[0] == "relation" and row[1].startswith("p:") for row in projection["inventory"]
            ),
            "t_partitioned_layout_not_qualified",
        )
        tables = sorted(
            row[1][2:]
            for row in projection["inventory"]
            if row[0] == "relation"
            and row[1].startswith("r:")
            and row[1][2:] not in {"alembic_version", "saas_alembic_version"}
        )
        return p._t_facts(tuple(tables), head="p0s000000018")

    def _operation(self, template, direction):
        parent = self.preserving.operation
        child = replace(
            parent,
            operation_id=str(
                uuid5(
                    UUID(parent.operation_id),
                    "t-runtime:" + direction + ":" + template.placement_id,
                )
            ),
        )
        values = dict(asdict(template))
        values["recovery"] = child
        if direction == "to_t":
            values.update(
                runtime_version="0.18.0.dev20261006",
                upstream_revision=parent.rollback_upstream_revision,
                official_schema_revision="mm1a2b3c4d5e",
                adapter_contract_version=parent.rollback_adapter_contract_version,
            )
        return FencedTRuntimeOperation(
            **values, direction=direction, source_official_schema_revision="nf12ab34cd56"
        )

    def _control(self, index, direction, outer):
        p = self.preserving
        operation = self._operation(self.operations[index], direction)

        def proof(actual, before):
            db.need(actual == operation, "runtime_child_operation_changed")
            db.need(
                self.verify_transition(p.operation, actual, copy.deepcopy(before)) is None,
                "transition_proof_must_not_return_flag",
            )

        def fence(actual, phase):
            db.need(actual == operation.recovery, "runtime_child_fence_changed")
            db.need(
                p.before_mutation(p.operation, "t_runtime:" + direction + ":" + phase) is None,
                "coordinator_must_revalidate_not_return_authorized_flag",
            )

        def checkpoint(phase, child_state):
            prior = outer.get("runtime_child", {})
            prepared = (
                child_state if child_state.get("phase") == "prepared" else prior.get("state")
            )
            db.need(prepared is not None, "runtime_prepared_checkpoint_required")
            outer["runtime_child"] = {
                **{
                    key: copy.deepcopy(prior[key])
                    for key in ("before_facts", "before_rows", "expected_rows")
                    if key in prior
                },
                "index": index,
                "direction": direction,
                "state": copy.deepcopy(prepared),
                "phase": phase,
                "native_checkpoint": copy.deepcopy(child_state),
            }
            self._save("t_runtime:" + direction + ":" + phase, outer)

        return RuntimePlacementMaintenance(
            plan=p.plan,
            engines=p.engines,
            owner=p.owner,
            maintenance=p.maintenance,
            operation=operation,
            source_gold=p.gold,
            verify_runtime=proof,
            before_mutation=fence,
            checkpoint=checkpoint,
            max_rows=self.maximum,
        )

    def prepare(self):
        p = self.preserving
        p._begin("prepare_fenced_t_runtime_rebinding")
        validated = p.prepare()
        before = validated["t_before"]
        rows = self._rows()
        self._require_placements(rows)
        state = {
            "phase": "runtime_rebinding_prepared",
            "operation": asdict(p.operation),
            "runtime_templates": [asdict(item) for item in self.operations],
            "before_runtime_rows": rows,
            "before_runtime_facts": before,
            "initial_preserving_state": validated,
            "completed_transitions": [],
        }
        self._save(state["phase"], state)
        return state

    def _require_placements(self, rows):
        affected = {
            item["id"]
            for item in rows["placements"]
            if item["runtime_type"] == "omnigent" and item["status"] == "active"
        }
        db.need(
            affected == {item.placement_id for item in self.operations},
            "complete_runtime_placement_set_required",
        )

    def _apply_runtime(self, state, direction):
        result = copy.deepcopy(state)
        for index in range(len(self.operations)):
            p = self.preserving
            p._begin("t_runtime:" + direction + ":before_prepare")
            before_facts, before_rows = self._facts(), self._rows()
            self._require_placements(before_rows)
            control = self._control(index, direction, result)
            prepared = control.prepare()
            expected = copy.deepcopy(before_rows)
            for name in expected:
                key = (
                    (lambda row: (row["runtime_partition_id"], row["user_id"]))
                    if name == "aliases"
                    else (lambda row: row["id"])
                )
                replacement = {key(row): row for row in prepared["after"][name]}
                expected[name] = [replacement.get(key(row), row) for row in expected[name]]
            result["runtime_child"] = {
                "index": index,
                "direction": direction,
                "state": prepared,
                "phase": "prepared",
                "before_facts": before_facts,
                "before_rows": before_rows,
                "expected_rows": expected,
            }
            self._save("t_runtime:" + direction + ":prepared_before_sql", result)
            control.apply(prepared)  # Unknown COMMIT propagates; never retry here.
            control.reconcile(prepared)  # Actual stable receipt + complete scope.
            after_facts, after_rows = self._facts(), self._rows()
            request_hash = db.sha(
                db.canonical(
                    {
                        "operation": prepared["operation"],
                        "before_sha256": prepared["before_sha256"],
                    }
                )
            )
            delta = self.native.assert_runtime_transition_facts(
                before_facts,
                after_facts,
                expected_rows=expected,
                actual_rows=after_rows,
                maintenance=p.maintenance,
                expected_request_hash=request_hash,
                expected_payload=control._payload(prepared),
                idempotency_key="runtime-maintenance:" + control.operation.recovery.operation_id,
                maximum=p.maximum,
            )
            result["completed_transitions"].append(
                {"direction": direction, "index": index, "delta": delta}
            )
            self._save("t_runtime:" + direction + ":exact_delta_verified", result)
        return result

    def inverse(self, state):
        self._validate(state, "runtime_rebinding_prepared")
        db.need(
            self._rows() == state["before_runtime_rows"]
            and self._facts() == state["before_runtime_facts"],
            "t_runtime_prepared_CAS_failed",
        )
        result = self._apply_runtime(state, "to_t")
        result["preserving"] = self.preserving.prepare()
        self._save("t_runtime:old_projection_before_inverse", result)
        result["preserving"] = self.preserving.inverse(result["preserving"])
        result["phase"] = "t_inverse_original_pair_verification_required"
        self._save(result["phase"], result)
        return result

    def verify_original_pair(self, state):
        self._validate(state, "t_inverse_original_pair_verification_required")
        db.need(
            self.verify_pair(self.preserving.operation, copy.deepcopy(state)) is None,
            "actual_original_pair_and_same_projects_required",
        )
        self._verify_events_unchanged(state)
        result = {**state, "phase": "t_original_pair_same_projects_verified"}
        self._save(result["phase"], result)
        return result

    def reattach(self, state):
        self._validate(state, "t_original_pair_same_projects_verified")
        db.need(
            self.verify_pair(self.preserving.operation, copy.deepcopy(state)) is None,
            "actual_original_pair_and_same_projects_required",
        )
        self._verify_events_unchanged(state)
        self._require_placements(self._rows())
        result = copy.deepcopy(state)
        result["preserving"] = self.preserving.reattach(result["preserving"])
        result = self._apply_runtime(result, "to_candidate")
        result["phase"] = "candidate_runtime_rebound_actual_epochs_and_business_required"
        self._save(result["phase"], result)
        return result

    def _verify_events_unchanged(self, state):
        p = self.preserving
        db.require_idle(p.maintenance)
        with p.maintenance.transaction():
            p.maintenance.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            p.maintenance.execute("SET LOCAL row_security=on")
            p.maintenance.execute("SET LOCAL statement_timeout='60s'")
            db.need(
                p.maintenance.execute(
                    "SELECT pg_catalog.row_security_active("
                    "'public.saas_control_plane_outbox'::regclass)"
                ).fetchone()[0]
                is False,
                "runtime_outbox_full_reader_required",
            )
            for transition in state["completed_transitions"]:
                delta = transition["delta"]
                rows = p.maintenance.execute(
                    "SELECT to_jsonb(e) FROM public.saas_control_plane_outbox e "
                    "WHERE idempotency_key=%s",
                    (delta["idempotency_key"],),
                ).fetchall()
                if len(rows) == 1:
                    document = rows[0][0]
                    db.need(
                        document["attempt_count"] == 0
                        and all(
                            document[name] is None
                            for name in (
                                "available_at",
                                "claimed_at",
                                "claim_token",
                                "last_error",
                                "last_error_code",
                                "last_error_digest",
                                "published_at",
                                "quarantined_at",
                            )
                        ),
                        "legacy_outbox_worker_touched_runtime_event",
                    )
                db.need(
                    len(rows) == 1 and db.sha(db.canonical(rows[0][0])) == delta["event_sha256"],
                    "legacy_outbox_worker_touched_runtime_event",
                )

    def reconcile_runtime_unknown_commit(self, state):
        """Read-only lookup only; no continuation/inverse/reattach by this method."""
        from saas.production.postgresql_preserving_recovery import require_checkpoint_operation

        require_checkpoint_operation(state, self.preserving.operation)
        child = state["runtime_child"]
        db.need(
            child["direction"] in {"to_t", "to_candidate"}
            and type(child["index"]) is int
            and 0 <= child["index"] < len(self.operations),
            "runtime_child_scope_invalid",
        )
        db.need(
            all(
                type(child.get(key)) is dict
                for key in ("before_facts", "before_rows", "expected_rows")
            ),
            "runtime_unknown_commit_full_baseline_required",
        )
        control = self._control(child["index"], child["direction"], copy.deepcopy(state))
        self.preserving._begin("readonly_unknown_runtime_commit_reconciliation")
        db.need(
            control.verify_runtime(control.operation, copy.deepcopy(child["state"]["before"]))
            is None,
            "runtime_proof_must_not_return_flag",
        )
        result = control.reconcile(child["state"])
        delta = self.native.assert_runtime_transition_facts(
            child["before_facts"],
            self._facts(),
            expected_rows=child["expected_rows"],
            actual_rows=self._rows(),
            maintenance=self.preserving.maintenance,
            expected_request_hash=db.sha(
                db.canonical(
                    {
                        "operation": child["state"]["operation"],
                        "before_sha256": child["state"]["before_sha256"],
                    }
                )
            ),
            expected_payload=control._payload(child["state"]),
            idempotency_key="runtime-maintenance:" + control.operation.recovery.operation_id,
            maximum=self.preserving.maximum,
        )
        return {**result, "complete_facts_delta": delta, "automatic_continuation": False}
