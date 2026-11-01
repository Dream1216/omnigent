# Fenced retained Runtime placement maintenance

## Scope and authority

The internal `RuntimePlacementMaintenance` API is used by the existing owner
migration/recovery coordinator. It opens no connections, reads no ambient
configuration, creates no role, exposes no HTTP endpoint, and has no default
proof adapter. Never invoke it from a tenant/project management handler.

Use the same reviewed four-authority `ProductionPostgreSqlPlan`, the existing
NOSUPERUSER/NOBYPASSRLS direct table-owner connection, and the existing independent
maintenance/identity reader. The runtime/provider identity adapter must verify:

- the exact installed product SHA and immutable image, upstream commit, official
  schema, runtime/adapter versions and native migration receipt;
- actual namespace/cluster/database UID/system identity and the operation's
  isolation or production realm;
- the complete affected Placement set and every real physical workspace/project
  read back through its existing provider authority, without replacing old
  projects or copying an old allocation receipt as an upgrade proof.

The `RecoveryOperation` binds the original encrypted retained backup object URI,
VersionID, ciphertext/manifest hashes, KMS version and live write-fence generation.
The coordinator's `before_mutation` must re-read these actual facts on each phase.
An `approved` boolean or a caller JSON digest is never an authority. No additional
maintenance signer class is required or created. Existing production signing,
independent admission and release gates still apply for their original purposes.

## Prepare, review, apply

1. Freeze a new exact source with P18 and independently derived PG16/18 gold for
   all supported service profiles. Missing gold fails before migration. Keep
   all P17 source migration/helper/manifest bytes and old anchors unchanged.
2. Stop new writers, drain all affected Runs, worktree leases and capabilities,
   retain the real backup/WAL/object evidence, and establish the original live
   write fence. Cover the complete global Placement, including other tenants.
3. Construct `RuntimeMaintenanceOperation(recovery=..., realm=...,
   namespace=..., namespace_uid=..., cluster_uid=..., placement_id=...,
   runtime_version=..., upstream_revision=..., official_schema_revision=...,
   adapter_contract_version=..., runtime_observation_ref=...,
   runtime_observation_sha256=...)` from actual readback. References alone do not
   replace the required adapter verification.
4. Construct `RuntimePlacementMaintenance` with that operation, exact plan,
   engines, owner and maintenance connections, retained source gold, bounded
   `max_rows`, real `verify_runtime`, `before_mutation`, and durable `checkpoint`
   callbacks. Call `prepare()`. Retain its complete private state; public reports
   should disclose hashes/counts only. No row is changed by prepare.
5. Review the exact complete before/after state. Apply with `apply(state)`.
   The transaction locks the four metadata relations in fixed order, verifies
   the full membership set and every row, checks drain state again, advances
   each partition and active binding generation, and inserts one original
   Outbox initial-state receipt. It re-reads backup/fence and installed/provider facts after SQL and
   immediately before COMMIT; a failure rolls back both metadata and Outbox. The
   provider callback verifies the original physical scope and must not wait for
   another connection to observe this transaction's uncommitted metadata.
   Physical keys, Project/Space/Tenant IDs,
   aliases, timestamps and retired binding history remain unchanged. Nonactive
   partitions require a separately reviewed recovery; they are never omitted.
6. On an unknown COMMIT acknowledgement or a failed post-commit checkpoint, keep
   the fence. `reconcile(state)` is read-only and verifies the stable receipt
   request hash and exact resulting metadata. Do not blindly repeat mutation or
   fabricate a failed/healthy result. A conflicting scope/receipt refuses.
7. Read back the actual migrated provider and resolver, run the original old
   project/history and new Run tests, then continue the existing release gates.
   The returned `production_admitted: false` is not a deployment or admission.

## Failure and rollback

Missing/expired proof adapters, changed source/identity/realm, nonempty active
execution, additional or missing metadata rows, stale generations, overflow,
checkpoint failures and source-policy drift stop the operation. SQL errors roll
back metadata and Outbox together. An outer fence remains closed until verified
outcome and recovery are established.

No inverse rewrites old facts or decrements a generation while new runtime writes
can exist. The reviewed P18 policy inverse and the original same-OID P17 receipt
reattachment are in `postgresql_preserving_recovery`. Its source-inverse path
refuses all retained lm1/lm2 model, budget, execution and protected audit facts
before any policy change, archive creation or detach. Its independent existing
maintenance reader must have verified unfiltered visibility; an RLS-filtered zero
is rejected. Use the original database
backup recovery path and preserve/replay post-backup business/typed receipt facts
for that case. See `backup-restore.md`. Only an actual signed old-stack drill can
prove the required full rollback time; component tests do not do so.
