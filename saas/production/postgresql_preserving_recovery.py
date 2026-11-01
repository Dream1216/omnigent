"""Explicit maintenance composition for preserving P18/P17 -> P15 and reattachment.

No environment read, connection creation, import I/O, signing identity or automatic
migration downgrade. The existing recovery coordinator supplies the real direct
maintenance/identity-reader and owner connections, validates its existing retained
encrypted backup and live write fence before every mutation, and durably records
checkpoints. Ordinary Alembic P17 downgrade and unknown-archive rejection remain.

This module never declares an old image, App, RPO, 900s drill or admission healthy.
After inverse, the coordinator must boot and test the original signed old digest.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, fields, replace
from importlib.resources import files
from typing import TypeGuard
from uuid import UUID

from alembic import command

from saas.control_plane.migrations.typed_business_delivery import SOURCE_NATIVE_SQL
from saas.production import postgresql_migration as migration
from saas.production import postgresql_preserving_adapter as adapter
from saas.production import postgresql_preserving_native as native
from saas.production import postgresql_runtime_maintenance_native as runtime_native


@dataclass(frozen=True)
class RecoveryOperation:
    """Pins to existing backup/fence evidence, not a caller authorization boolean.

    The before_mutation adapter must re-read the real existing backup VersionID,
    retained ciphertext/manifest/KMS version and live fence generation/scope. Its
    implementation is supplied by the existing recovery coordinator; no no-op or
    default production verifier is provided here. A digest-shaped string alone
    is never documented as proof that remote bytes/fence were actually checked.
    """

    operation_id: str
    candidate_product_revision: str
    candidate_server_digest: str
    rollback_product_revision: str
    rollback_server_digest: str
    database_identity: dict
    backup_object_uri: str
    backup_object_version: str
    backup_ciphertext_sha256: str
    backup_manifest_sha256: str
    backup_kms_key_version: str
    fence_generation: int
    fence_scope_sha256: str
    fence_record_sha256: str
    source_gold_sha256: str

    def validate(self) -> None:
        adapter.need(str(UUID(self.operation_id)) == self.operation_id, "operation_uuid_invalid")
        for value in (self.candidate_product_revision, self.rollback_product_revision):
            adapter.need(bool(re.fullmatch(r"[0-9a-f]{40}", value)), "product_pin_invalid")
        for value in (self.candidate_server_digest, self.rollback_server_digest):
            adapter.need(bool(re.fullmatch(r"sha256:[0-9a-f]{64}", value)), "image_pin_invalid")
        for value in (
            self.backup_ciphertext_sha256,
            self.backup_manifest_sha256,
            self.fence_scope_sha256,
            self.fence_record_sha256,
            self.source_gold_sha256,
        ):
            adapter.need(bool(re.fullmatch(r"[0-9a-f]{64}", value)), "evidence_pin_invalid")
        adapter.need(
            type(self.fence_generation) is int and self.fence_generation > 0,
            "fence_generation_invalid",
        )
        for value in (
            self.backup_object_uri,
            self.backup_object_version,
            self.backup_kms_key_version,
        ):
            adapter.need(
                isinstance(value, str) and bool(value.strip()) and value == value.strip(),
                "retained_backup_reference_missing",
            )
        adapter.need(
            self.database_identity.get("server_major") in (16, 18), "database_major_invalid"
        )


T_PROTOCOL = "omnigent.postgresql-preserving-explicit-t/v1"
T_HEAD = "lm2t00000001"


@dataclass(frozen=True, kw_only=True)
class ExplicitTRecoveryOperation(RecoveryOperation):
    contract_version: str
    rollback_saas_target: str
    rollback_host_digest: str
    rollback_upstream_revision: str
    rollback_adapter_contract_version: str

    def validate(self) -> None:
        super().validate()
        adapter.need(
            type(self.contract_version) is str
            and self.contract_version == T_PROTOCOL
            and type(self.rollback_saas_target) is str
            and self.rollback_saas_target == T_HEAD,
            "explicit_t_protocol_or_target_invalid",
        )
        adapter.need(
            type(self.rollback_host_digest) is str
            and bool(re.fullmatch(r"sha256:[0-9a-f]{64}", self.rollback_host_digest))
            and type(self.rollback_upstream_revision) is str
            and bool(re.fullmatch(r"[0-9a-f]{40}", self.rollback_upstream_revision))
            and type(self.rollback_adapter_contract_version) is str
            and self.rollback_adapter_contract_version == "0.2.0",
            "explicit_t_pair_and_contract_required",
        )

    def target_contract(self) -> dict:
        return {
            "contract_version": self.contract_version,
            "saas_head": T_HEAD,
            "official_head": "mm1a2b3c4d5e",
            "product_revision": self.rollback_product_revision,
            "server_digest": self.rollback_server_digest,
            "host_digest": self.rollback_host_digest,
            "upstream_revision": self.rollback_upstream_revision,
            "adapter_contract_version": self.rollback_adapter_contract_version,
        }


def load_operation_document(document: object) -> RecoveryOperation:
    """Strict decoding; no field fill/rebase/hash recompute or authority effect."""
    if not isinstance(document, dict) or type(document) is not dict:
        raise adapter.Refused("operation_document_must_be_object")
    old_keys = {f.name for f in fields(RecoveryOperation)}
    t_keys = {f.name for f in fields(ExplicitTRecoveryOperation)}
    if set(document) == old_keys:
        operation = RecoveryOperation(**document)
    else:
        adapter.need(
            set(document) == t_keys and document.get("contract_version") == T_PROTOCOL,
            "operation_document_version_or_shape_unknown",
        )
        operation = ExplicitTRecoveryOperation(**document)
    adapter.need(
        all(
            type(value) is str
            for name, value in document.items()
            if name not in {"database_identity", "fence_generation"}
        )
        and type(document["database_identity"]) is dict
        and type(document["fence_generation"]) is int,
        "operation_document_field_types_invalid",
    )
    try:
        operation.validate()
    except (TypeError, ValueError, AttributeError):
        raise adapter.Refused("operation_document_invalid") from None
    return operation


def require_checkpoint_operation(state: dict, expected_operation: RecoveryOperation) -> None:
    """Pure binding check; phase/catalog/actual authority are still mandatory."""
    adapter.need(
        type(expected_operation) in {RecoveryOperation, ExplicitTRecoveryOperation},
        "operation_type_unknown",
    )
    expected_operation.validate()
    adapter.need(type(state) is dict, "checkpoint_document_must_be_object")
    operation = load_operation_document(state.get("operation"))
    adapter.need(
        type(operation) is type(expected_operation)
        and asdict(operation) == asdict(expected_operation),
        "checkpoint_operation_mismatch",
    )


def _is_explicit_t(operation: RecoveryOperation) -> TypeGuard[ExplicitTRecoveryOperation]:
    adapter.need(
        type(operation) in {RecoveryOperation, ExplicitTRecoveryOperation},
        "operation_type_unknown",
    )
    return type(operation) is ExplicitTRecoveryOperation


def _rollback_revision(operation: RecoveryOperation) -> str:
    return T_HEAD if _is_explicit_t(operation) else "p0s000000015"


def _manifest():
    """Load exact source-owned DDL/inverse, never SQL from an operator argument."""
    raw = files("saas.production").joinpath("preserving-p17-source-manifest.json").read_bytes()
    adapter.need(hashlib.sha256(raw).hexdigest() == native.MANIFEST_SHA, "manifest_pin_mismatch")
    value = json.loads(raw)
    adapter.need(
        value["revision"] == "p0s000000017" and len(value["functions"]) == 14,
        "manifest_contract_mismatch",
    )
    adapter.need(
        hashlib.sha256(SOURCE_NATIVE_SQL.encode()).hexdigest()
        == value["reattach_source_only_sql_sha256"],
        "source_reattach_sql_mismatch",
    )
    return value


def _migrate(engine, kind, revision, *, down=False):
    with engine.connect() as connection:
        config = migration._migration_config(kind)
        config.attributes["connection"] = connection
        (command.downgrade if down else command.upgrade)(config, revision)


def _source_projection(plan, engines):
    with engines["official_owner"].connect() as o, engines["saas_owner"].connect() as s:
        major = int(o.exec_driver_sql("SHOW server_version_num").scalar_one()) // 10000
        bootstrap = o.exec_driver_sql("SELECT rolname FROM pg_roles WHERE oid=10").scalar_one()
        catalog = migration._canonical_runner_management_catalog(
            {
                "official_head": o.exec_driver_sql(
                    "SELECT version_num FROM alembic_version"
                ).scalar_one(),
                "saas_head": s.exec_driver_sql(
                    "SELECT version_num FROM saas_alembic_version"
                ).scalar_one(),
                "ownership": migration._object_ownership_projection(
                    o,
                    s,
                    official_owner=plan.official_owner.login,
                    saas_owner=plan.saas_owner.login,
                ),
                "runtime_acls": migration._verify_runtime_acl(o),
                "runtime_rls_tables": [
                    x.table_name for x in migration.load_runtime_rls_contract()
                ],
                "official_security": migration._official_security_catalog(
                    o, official_owner=plan.official_owner.login
                ),
                "control_plane_security": migration._control_plane_security_catalog(
                    s, saas_owner=plan.saas_owner.login
                ),
            },
            principal_operator=plan.principal_operator.login,
            bootstrap_name=bootstrap,
        )
        aliases = migration._source_catalog_role_aliases(
            principal_operator=plan.principal_operator.login,
            database_owner=plan.database_owner.login,
            official_owner=plan.official_owner.login,
            saas_owner=plan.saas_owner.login,
            bootstrap_name=bootstrap,
            bindings=plan.service_role_graph,
        )
        normalized = migration._sort_normalized_source_catalog_rows(
            migration._normalize_source_catalog(catalog, role_aliases=aliases)
        )
        inventory = migration._public_schema_inventory(
            o,
            official_owner=plan.official_owner.login,
            saas_owner=plan.saas_owner.login,
        )
        return {
            "major": major,
            "inventory": inventory,
            "catalog": normalized,
            "inventory_sha256": adapter.sha(adapter.canonical(inventory)),
            "security_sha256": adapter.sha(adapter.canonical(normalized)),
        }


def _original_t_security_projection(catalog, role_edges):
    """Match the original T capability enumeration after proving retired roles inert.

    The retained receipt ACLs still reference these three P17 roles. Their full
    archive metadata and shared dependencies are checked before this projection;
    this accepts no membership or authority in the original T business catalog.
    """
    adapter.need(
        catalog.get("saas_head") == T_HEAD and catalog.get("official_head") == "mm1a2b3c4d5e",
        "explicit_t_original_source_heads_required",
    )
    retired = {"saas_usage_consumer", "saas_audit_delivery", "saas_revocation_consumer"}
    security = catalog["control_plane_security"]
    rows = security["roles"]
    selected = [row for row in rows if row[0] in retired]
    expected = [
        [role, False, False, False, False, False, False, True, -1, "null"]
        for role in sorted(retired)
    ]
    adapter.need(
        adapter.canonical(sorted(selected)) == adapter.canonical(expected),
        "explicit_t_retained_delivery_role_flags_changed",
    )
    adapter.need(
        not any(set(row[:3]) & retired for row in role_edges),
        "explicit_t_retained_delivery_role_membership",
    )
    projected = {
        **catalog,
        "control_plane_security": {
            **security,
            "roles": [row for row in rows if row[0] not in retired],
        },
    }
    pattern = re.compile(
        r"(?<![A-Za-z0-9_])(?:saas_usage_consumer|saas_audit_delivery|"
        r"saas_revocation_consumer)(?![A-Za-z0-9_])"
    )

    def references_retired_role(value):
        if isinstance(value, str):
            return pattern.search(value) is not None
        if isinstance(value, dict):
            return any(
                references_retired_role(k) or references_retired_role(v) for k, v in value.items()
            )
        if isinstance(value, (list, tuple)):
            return any(references_retired_role(item) for item in value)
        return False

    adapter.need(
        not references_retired_role(projected),
        "explicit_t_retained_delivery_role_has_business_authority",
    )
    return projected


class PreservingPostgreSqlRecovery:
    """Small phase API over the already qualified native SQL/move primitives.

    before_mutation(operation, phase) must return None after actual existing
    recovery checks; a boolean authorized/ready flag is rejected. checkpoint
    persists each private state record durably before the next operation. Any
    SQL, fence, backup or checkpoint failure must keep the outer fence closed;
    no method blindly reruns an unknown committed phase or stamps a missing DDL.
    """

    def __init__(
        self,
        *,
        plan,
        engines: Mapping,
        owner,
        database_owner,
        maintenance,
        operation: RecoveryOperation,
        source_gold: dict,
        before_mutation: Callable[[RecoveryOperation, str], None],
        checkpoint: Callable[[str, dict], None],
        max_copy_bytes: int,
    ) -> None:
        _is_explicit_t(operation)
        operation.validate()
        adapter.need(
            callable(before_mutation) and callable(checkpoint), "coordinator_callbacks_required"
        )
        adapter.need(type(max_copy_bytes) is int and max_copy_bytes > 0, "copy_bound_required")
        adapter.need(
            adapter.sha(adapter.canonical(source_gold)) == operation.source_gold_sha256,
            "source_gold_bytes_mismatch",
        )
        adapter.need(
            plan.product_revision == operation.candidate_product_revision,
            "candidate_product_mismatch",
        )
        migration._validate_plan(plan)  # Real installed candidate SHA, no monkeypatch.
        self.plan, self.engines = plan, engines
        self.owner, self.database_owner, self.maintenance = owner, database_owner, maintenance
        self.operation, self.gold = operation, source_gold
        if _is_explicit_t(operation):
            adapter.need(
                source_gold.get("rollback_target") == operation.target_contract(),
                "explicit_t_target_gold_mismatch",
            )
        self.before_mutation, self.checkpoint = before_mutation, checkpoint
        self.maximum = max_copy_bytes
        self.manifest = _manifest()
        self.columns = {
            t["name"]: tuple(c["name"] for c in t["columns"]) for t in self.manifest["tables"]
        }
        adapter.need(owner.info.user == plan.saas_owner.login, "direct_table_owner_required")
        adapter.need(
            database_owner.info.user == plan.database_owner.login, "direct_database_owner_required"
        )
        self._identity()

    def _identity(self):
        for connection in (self.owner, self.database_owner, self.maintenance):
            adapter.need(
                adapter.database_identity(connection, self.maintenance)
                == self.operation.database_identity,
                "database_identity_changed",
            )
            adapter.require_idle(connection)

    def _capture(self, connection, schema):
        return adapter.capture(
            connection,
            expected_identity=self.operation.database_identity,
            expected_principal=connection.info.user,
            schema=schema,
            columns=self.columns,
            max_copy_bytes=self.maximum,
            identity_connection=self.maintenance,
        )

    def _begin(self, phase):
        self._identity()
        adapter.need(
            self.before_mutation(self.operation, phase) is None,
            "coordinator_must_revalidate_not_return_authorized_flag",
        )

    def _save(self, phase, state):
        self.checkpoint(phase, state)

    def _t_source_gold(self) -> None:
        operation = self.operation
        if not _is_explicit_t(operation):
            raise adapter.Refused("explicit_t_operation_required")
        adapter.need(
            adapter.sha(adapter.canonical(self.gold)) == operation.source_gold_sha256
            and self.gold.get("rollback_target") == operation.target_contract(),
            "explicit_t_source_gold_binding_changed",
        )
        old_plan = replace(self.plan, business_delivery_service_role_bindings=None)
        key = (self.operation.database_identity["server_major"], "mm1a2b3c4d5e", "lm2t00000001")
        inventory = migration._PUBLIC_SCHEMA_INVENTORY_SHA256.get(key)
        security = migration._source_security_catalog_baselines(old_plan.service_role_graph).get(
            key
        )
        adapter.need(
            inventory is not None
            and security is not None
            and self.gold.get("old_inventory_sha256") == inventory
            and self.gold.get("old_security_sha256") == security,
            "explicit_t_old_source_gold_required",
        )

    def _t_facts(self, tables, *, head, receipt_schema="public"):
        return runtime_native.capture_t_preserved_facts(
            self.owner,
            maintenance=self.maintenance,
            expected_identity=self.operation.database_identity,
            expected_tables=tuple(tables),
            max_copy_bytes=self.maximum,
            expected_head=head,
            receipt_schema=receipt_schema,
        )

    def _t_old_catalog(self, state) -> None:
        archive = adapter.archive_name(self.operation.operation_id)
        adapter.need(state["archive"] == archive, "explicit_t_archive_scope_changed")
        adapter.require_archive_acl(
            self.database_owner,
            archive,
            self.plan.database_owner.login,
            self.plan.saas_owner.login,
        )
        retained = self._capture(self.owner, archive)
        adapter.need(
            retained["tables"] == state["archived"]["tables"]
            and retained["archive_catalog"] == state["archive_inventory"],
            "explicit_t_retained_archive_metadata_or_facts_changed",
        )
        native.require_retained_delivery_role_dependencies(
            self.maintenance, retained["tables"], self.operation.database_identity["database_oid"]
        )
        old_plan = replace(self.plan, business_delivery_service_role_bindings=None)
        observed = _source_projection(old_plan, self.engines)
        edges = native.role_edges(self.maintenance)
        source_catalog = _original_t_security_projection(observed["catalog"], edges)
        adapter.need(
            observed["inventory_sha256"] == self.gold["old_inventory_sha256"]
            and adapter.sha(adapter.canonical(source_catalog)) == self.gold["old_security_sha256"]
            and edges == self.gold["old_role_edges"]
            and native.object_access(self.database_owner) == self.gold["old_access"],
            "explicit_t_old_catalog_mismatch",
        )

    def prepare(self) -> dict:
        """Read only; source verifier and complete owner/maintenance COPY coverage."""
        if _is_explicit_t(self.operation):
            self._t_source_gold()
        self._identity()
        if _is_explicit_t(self.operation):
            self._begin("prepare_explicit_t_target_and_drain")
        verified = migration._verify_state(self.plan, dict(self.engines))
        adapter.need(
            verified.official_head == "nf12ab34cd56" and verified.saas_head == "p0s000000018",
            "candidate_heads_required",
        )
        adapter.need(
            native.role_edges(self.maintenance) == self.gold["candidate_role_edges"],
            "candidate_role_graph_drift",
        )
        adapter.need(
            native.object_access(self.database_owner) == self.gold["candidate_access"],
            "candidate_database_public_acl_drift",
        )
        # Independent clean-source gold contains no live OIDs. The original
        # source-owned verifier above and normalized projection below validate
        # definitions/ownership/ACLs before actual OIDs are captured for this
        # operation's CAS. An observed deployed catalog is never learned as gold.
        projection = _source_projection(self.plan, self.engines)
        adapter.need(
            projection["inventory_sha256"] == self.gold["candidate_inventory_sha256"]
            and projection["security_sha256"] == self.gold["candidate_security_sha256"],
            "independent_clean_source_gold_mismatch",
        )
        source = native.source_snapshot(self.owner, self.manifest)
        before = self._capture(self.owner, "public")
        complete = self._capture(self.maintenance, "public")
        adapter.need(before["tables"] == complete["tables"], "owner_not_full_receipt_coverage")
        state = {
            "phase": "prepared",
            "operation": asdict(self.operation),
            "manifest_sha256": native.MANIFEST_SHA,
            "before": before,
            "p17_source_snapshot": source,
            "p18_policy_snapshot": runtime_native.policy_snapshot(self.owner),
            "archive": adapter.archive_name(self.operation.operation_id),
        }
        if _is_explicit_t(self.operation):
            adapter.need(
                not any(
                    row[0] == "relation" and row[1].startswith("p:")
                    for row in projection["inventory"]
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
            state["t_before"] = self._t_facts(tables, head="p0s000000018")
            adapter.need(
                self.gold.get("old_builtin_pg_notify")
                == {
                    k: v
                    for k, v in state["t_before"]["builtin_pg_notify"].items()
                    if k not in {"oid", "raw_acl"}
                }
                | {"acl_is_null": state["t_before"]["builtin_pg_notify"]["raw_acl"] is None},
                "explicit_t_builtin_acl_target_mismatch",
            )
        self._save("prepared", state)
        return state

    def _remove_project_identity_guard(self) -> dict:
        """Remove only the exact current guard after complete candidate gold/CAS."""

        def snapshot():
            routine = self.owner.execute(
                "SELECT p.oid::bigint,pg_get_functiondef(p.oid),"
                "pg_get_userbyid(p.proowner),p.proacl::text FROM pg_proc p "
                "WHERE p.oid=to_regprocedure('public.saas_guard_project_identity_immutable()')"
            ).fetchone()
            trigger = self.owner.execute(
                "SELECT t.oid::bigint,t.tgrelid::bigint,t.tgfoid::bigint,t.tgenabled,"
                "pg_get_triggerdef(t.oid,true) FROM pg_trigger t "
                "WHERE t.tgrelid='public.saas_projects'::regclass "
                "AND t.tgname='trg_saas_projects_identity_immutable'"
            ).fetchone()
            columns = self.owner.execute(
                "SELECT pg_get_userbyid(a.grantee),pg_get_userbyid(a.grantor),"
                "a.privilege_type,a.is_grantable FROM pg_attribute c "
                "CROSS JOIN LATERAL aclexplode(c.attacl) a "
                "WHERE c.attrelid='public.saas_projects'::regclass AND c.attname='id' "
                "ORDER BY 1,2,3,4"
            ).fetchall()
            return routine, trigger, columns

        before = snapshot()
        projection = _source_projection(self.plan, self.engines)
        adapter.need(
            projection["inventory_sha256"] == self.gold["candidate_inventory_sha256"]
            and projection["security_sha256"] == self.gold["candidate_security_sha256"]
            and migration._project_identity_guard_inventory_predecessor(projection["inventory"])
            is not None
            and migration._source_catalog_project_lock_predecessor(projection["catalog"])
            is not None,
            "candidate_project_identity_guard_or_gold_changed",
        )
        lock_acl = ("saas_app", self.plan.saas_owner.login, "UPDATE", False)
        adapter.need(
            before[0] is not None and before[1] is not None and before[2].count(lock_acl) == 1,
            "candidate_project_identity_guard_scope_changed",
        )
        with self.owner.transaction():
            self.owner.execute("SET LOCAL lock_timeout='2s'")
            self.owner.execute("SET LOCAL statement_timeout='60s'")
            self.owner.execute("LOCK TABLE public.saas_projects IN ACCESS EXCLUSIVE MODE")
            adapter.need(snapshot() == before, "candidate_project_identity_guard_CAS_failed")
            self.owner.execute("REVOKE UPDATE (id) ON public.saas_projects FROM saas_app")
            self.owner.execute(
                "DROP TRIGGER trg_saas_projects_identity_immutable ON public.saas_projects"
            )
            self.owner.execute(
                "DROP FUNCTION public.saas_guard_project_identity_immutable() RESTRICT"
            )
            after = snapshot()
            adapter.need(
                after[0] is None
                and after[1] is None
                and after[2] == [row for row in before[2] if row != lock_acl],
                "candidate_project_identity_guard_inverse_mismatch",
            )
        return {"routine": before[0], "trigger": before[1], "column_acls": before[2]}

    def inverse(self, state: dict) -> dict:
        """Detach original objects, fixed P17 inverse, original P16/nf downgrade."""
        adapter.need(
            state["phase"] == "prepared" and state["operation"] == asdict(self.operation),
            "prepared_operation_required",
        )
        require_checkpoint_operation(state, self.operation)
        # This current P16 lineage includes T. Do not detach receipts or remove
        # policies before discovering any original retained-data refusal.
        if _is_explicit_t(self.operation):
            self._t_source_gold()
        self._begin("preflight_source_inverse")
        if _is_explicit_t(self.operation):
            preflight = self._t_facts(state["t_before"]["tables"], head="p0s000000018")
            adapter.need(preflight == state["t_before"], "t_prepared_facts_CAS_failed")
        else:
            preflight = runtime_native.require_source_inverse_possible(
                self.owner,
                maintenance=self.maintenance,
                expected_identity=self.operation.database_identity,
            )
        state = {**state, "source_inverse_preflight": preflight}
        self._save("source_inverse_preflight_passed", state)
        self._begin("remove_p18_owner_policies")
        if _is_explicit_t(self.operation):
            state = {
                **state,
                "project_identity_guard_removed": self._remove_project_identity_guard(),
            }
        runtime_native.remove_p18_policies(self.owner, state["p18_policy_snapshot"])
        self._save("p18_policies_removed", state)
        self._begin("prepare_archive")
        inventory = adapter.prepare_archive(
            self.database_owner,
            operation_id=self.operation.operation_id,
            expected_identity=self.operation.database_identity,
            expected_table_owner=self.plan.saas_owner.login,
            identity_connection=self.maintenance,
        )
        state = {**state, "prepared_archive_inventory": inventory}
        self._save("archive_prepared", state)
        self._begin("detach_receipts")
        scope = adapter.MoveScope(
            self.operation.operation_id,
            "detach",
            self.operation.database_identity,
            self.plan.saas_owner.login,
            state["before"]["tables"],
            self.columns,
            self.maximum,
            inventory,
        )
        detached = adapter.move_receipts(self.owner, scope, identity_connection=self.maintenance)
        archived = self._capture(self.owner, state["archive"])
        state = {
            **state,
            "detached": detached,
            "archived": archived,
            "archive_inventory": adapter.archive_catalog(self.maintenance),
        }
        self._save("receipts_detached", state)
        self._begin("remove_p17_source_objects")
        native.remove_sources(
            self.owner, self.manifest, state["p17_source_snapshot"], state["archive"]
        )
        self._save("source_objects_removed", state)
        self._begin("restore_old_role_graph_and_acls")
        native.reverse_additive_role_edges(
            self.maintenance, self.gold["old_role_edges"], self.gold["candidate_role_edges"]
        )
        native.change_additive_access(
            self.database_owner, self.gold["old_access"], self.gold["candidate_access"]
        )
        self._save("old_role_graph_and_acls_restored", state)
        self._begin("original_p16_downgrade")
        _migrate(
            self.engines["saas_owner"],
            "saas",
            _rollback_revision(self.operation),
            down=True,
        )
        self._save("p16_downgraded", state)
        self._begin("original_nf_downgrade")
        _migrate(self.engines["official_owner"], "official", "mm1a2b3c4d5e", down=True)
        adapter.need(
            native.head(self.owner) == _rollback_revision(self.operation),
            "old_saas_head_missing",
        )
        if _is_explicit_t(self.operation):
            self._t_old_catalog(state)
            adapter.need(
                self._t_facts(
                    state["t_before"]["tables"],
                    head="lm2t00000001",
                    receipt_schema=state["archive"],
                )
                == state["t_before"],
                "t_retained_facts_or_builtin_acl_changed",
            )
        adapter.need(
            self._capture(self.owner, state["archive"])["tables"] == archived["tables"],
            "archived_receipt_drift",
        )
        state = {**state, "phase": "inverse_complete_old_signed_image_verification_required"}
        self._save(state["phase"], state)
        return state

    def reattach(self, state: dict) -> dict:
        """Return exact archived objects; never ordinary P17 CREATE or new receipts."""
        adapter.need(
            state["phase"] == "inverse_complete_old_signed_image_verification_required"
            and state["operation"] == asdict(self.operation),
            "known_inverse_state_required",
        )
        require_checkpoint_operation(state, self.operation)
        if _is_explicit_t(self.operation):
            self._t_source_gold()
            self._begin("prepare_explicit_t_reentry_backup_and_drain")
            self._t_old_catalog(state)
            current = self._t_facts(
                state["t_before"]["tables"], head="lm2t00000001", receipt_schema=state["archive"]
            )
            adapter.need(
                current["builtin_pg_notify"] == state["t_before"]["builtin_pg_notify"]
                and {k: current["tables"][k] for k in adapter.TABLES}
                == {k: state["t_before"]["tables"][k] for k in adapter.TABLES},
                "t_archived_receipts_or_builtin_acl_changed",
            )
            state = {**state, "t_reentry_before": current}
            self._save("t_reentry_fenced_facts_captured", state)
        self._begin("original_nf_p16_reupgrade")
        _migrate(self.engines["official_owner"], "official", "nf12ab34cd56")
        _migrate(self.engines["saas_owner"], "saas", "p0s000000016")
        native.restore_additive_role_edges(
            self.maintenance, self.gold["old_role_edges"], self.gold["candidate_role_edges"]
        )
        native.change_additive_access(
            self.database_owner, self.gold["old_access"], self.gold["candidate_access"], True
        )
        self._save("p16_and_candidate_role_graph_restored", state)
        self._begin("reattach_original_receipts")
        scope = adapter.MoveScope(
            self.operation.operation_id,
            "reattach",
            self.operation.database_identity,
            self.plan.saas_owner.login,
            state["archived"]["tables"],
            self.columns,
            self.maximum,
            state["archive_inventory"],
        )
        restored = adapter.move_receipts(self.owner, scope, identity_connection=self.maintenance)
        self._save("original_receipts_reattached", {**state, "restored": restored})
        self._begin("rebuild_exact_source_only_objects")
        with self.owner.transaction():
            adapter.need(native.head(self.owner) == "p0s000000016", "p16_head_required")
            self.owner.execute(SOURCE_NATIVE_SQL)
            adapter.need(
                native.semantic_sources(native.source_snapshot(self.owner, self.manifest))
                == native.semantic_sources(state["p17_source_snapshot"]),
                "source_semantics_changed",
            )
            changed = self.owner.execute(
                "UPDATE public.saas_alembic_version SET version_num='p0s000000017' "
                "WHERE version_num='p0s000000016' RETURNING version_num"
            ).fetchall()
            adapter.need(changed == [("p0s000000017",)], "source_head_cas_failed")
        adapter.need(
            self._capture(self.owner, "public")["tables"] == state["before"]["tables"],
            "original_receipts_not_exact",
        )
        self._save("p17_source_objects_rebuilt", state)
        self._begin("drop_exact_empty_archive")
        native.exact_empty_archive_drop(
            self.database_owner,
            adapter,
            state["archive"],
            self.operation.database_identity,
            self.plan.saas_owner.login,
            self.maintenance,
        )
        self._save("p17_exact_objects_reattached", state)
        self._begin("restore_p18_owner_policies")
        _migrate(self.engines["saas_owner"], "saas", "p0s000000018")
        if _is_explicit_t(self.operation):
            migration._apply_control_plane_authority(self.engines["saas_owner"])
        # P18 policies are recreated by their real migration. P17 receipt table
        # OIDs/rows/FKs remain the exact archived originals.
        migration._verify_state(self.plan, dict(self.engines))
        if _is_explicit_t(self.operation):
            adapter.need(
                self._t_facts(state["t_before"]["tables"], head="p0s000000018")
                == state["t_reentry_before"],
                "t_reentry_facts_or_builtin_acl_changed",
            )
        state = {
            **state,
            "phase": "reattached_candidate_runtime_and_real_65s_epoch_required",
            "restored": restored,
            "old_or_candidate_App_admitted": False,
        }
        self._save(state["phase"], state)
        return state
