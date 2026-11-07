# Backup and restore runbook

## Preconditions

Backups are encrypted, deletion-protected, and stored in a different failure
domain under an identity that production application roles cannot assume. Each
backup record binds database or object version, source SHA, schema head, adapter
contract, KMS key version, start and completion time, and integrity hash.

Never restore production data into a shared development environment. Tenant
restore uses an isolated account, network, keys, object prefix, search index,
and Runner pool until validation is complete.

## Restore sequence

1. Select a recovery point within the approved data-class RPO and preserve the
   original backup and WAL chain.
2. Restore PostgreSQL and object versions into isolation. Keep all application
   traffic disabled and use `NOSUPERUSER NOBYPASSRLS` probe roles.
3. Apply the exact official migrations followed by SaaS migrations. Stop on
   schema signature, policy, extension, source, or adapter drift.
4. Replay deletion tombstones, session and grant revocations, membership and
   policy versions, Partition and Binding generations, and Outbox or Run Event
   cursors newer than the base backup.
5. Verify row counts and content hashes by Tenant, every control-plane table
   enumerated by the current forced-RLS acceptance test, all 18 runtime
   workspace policies, active-binding uniqueness, key decryptability, ledger
   conservation, and missing object references.
6. Rebuild T2 Worktrees and temporary environments from Base Revision,
   ChangeSet artifacts, and Environment Snapshot. Never restore an old writable
   lease or fence token.
7. Promote a canary scope only after authorization, logout, deletion,
   revocation, Run replay, audit, and billing probes pass. Expand gradually.

## Full user checkout before Runner launch

Retain the original native checkpoint state in the existing encrypted backup.
Its existing `environment_snapshot_ref` identifies the full user tree; the Git
`recovery_artifact_ref` alone contains only HEAD relative to Base Revision.
An ordinary allocation without an Environment Snapshot does not prove full
user-file recovery.

The backup owner decrypts the existing independent backup into quarantine,
verifies the complete original file/private-Git manifest, and delivers only the
quiesced user checkout to the new owned work volume. Use the product's
`PreparedWorktreeRestores(work_root / "restore-snapshots")` and
`prepare_checkpoint(original_quarantine_native_state, verified_quarantine_checkout)`.
This reads the Source-written checkpoint binding without requiring a released
lease or copying old state into the active Runner. If the actual original grant
was retained before release, `prepare(actual_checkpoint_grant, verified_quarantine_checkout)`
is also supported, or deliver to
`delivery_path(actual_checkpoint_grant.environment_snapshot_ref)` with metadata
preserved and call `seal(actual_checkpoint_grant)`. Retain the original native
checkpoint state or sealed delivery receipt with the encrypted backup; do not reconstruct
grant fields from a model reply or restore old Runner state, locks or leases.
These local owner operations create no execution grant or independent backup.

The production factory connects this consumer to the existing materializer.
After the new fenced allocation and private Git checkout, it validates the
original ChangeSet/repository/base/head/artifact binding and copies every entry,
including ignored files and the entire private `.git`, preserving hardlinks,
ownership, modes, timestamps and extended attributes. It compares the complete
source and restored tree, validates containment/quota/private Git, and checks
the current native grant before acknowledging ready. Only then can the original
isolation grant and fixed Agent/Preview launch proceed. Missing/changed delivery,
lost authority or cancellation prevents readiness and launch. Keep the verified
delivery until the existing backup-retention policy permits removal; failed
temporary copies never authorize removal of the original user data.

## Drill evidence

### Original Sessions on the Aliyun provider

The browser/ordinary CLI Session is the original Conversation, not a native
ExecutionSession/Run. Keep its actual Project binding, owner, Host and workspace.
The existing Aliyun Session/storage authorizer revalidates those original
permissions; recovery adds no public selectors, database schema or signing service.

For a selected original Session, quiesce its writer before capture. Record the
actual tenant/space/Project, physical workspace, Conversation and Host IDs,
source Sandbox, actual cwd and both admitted OSS volume identities. Capture the
whole `/home/user/workspace`, including `.git`, ignored/untracked files, private
branches, hardlinks, modes, timestamps and extended attributes. Exclude only
`workspace/inputs` and `workspace/artifacts`: these are separate existing OSS
mounts and require their own complete versioned backup/restore evidence.
Preserve the existing encrypted, independent backup and verify the source tree
again after capture. A Git clone or attachment replay is not this backup.

Use the existing PAX capture/decryption transport. The archive must contain one
explicit `workspace` directory and its complete local descendants. Stage the
independently verified plaintext PAX under a selected existing Session mount;
`inputs` is read-only inside the VM, while `artifacts` permits the existing
authorized writer/capture operation. Neither needs a new volume or IAM scope.
Both sources are pinned by complete archive SHA before and after extraction;
the restored tree is independently checked against the original complete tree
digest. Keep traffic/writers fenced during capture and restore.

The importer copies the selected archive to an unlinked owner-private local
file before parsing; validation and extraction consume that same private copy.
Capture uncompressed PAX: compressed inputs are refused. Limits are 9 GiB of
archive bytes, 8 GiB of logical file data, 1 MiB per metadata read and 64 MiB of
cumulative header/metadata reads. Reserve space for the private archive plus the
restored tree and fresh baseline; a failed import blocks Host startup and retains
the original backup and existing mounts.
The existing final Host image build also records its real `tar --version` and
executes those extraction options as `user`; component proofs do not substitute
for this final-image tool check or real Session recovery.

An owner-only descriptor contains `schema_version:1`, the actual `tenant_id`,
`space_id`, `project_id`, `workspace_id`, `session_id`, `host_id`,
`source_sandbox_id`, `archive_relative_path`, `archive_sha256`, `tree_sha256`,
and optionally `archive_mount` (`inputs` by default, or `artifacts`). UUIDs are
validated/normalized from the actual stored identities. The tree digest is
the existing complete metadata/private-Git digest with only those two mount
roots excluded; it is not a HEAD hash. The approved backup owner may obtain it
using `saas.production.aliyun_workspace_recovery._digest` on the quiesced original
root. Never derive it from the new clone, a model response or test data.

Pin that descriptor in the existing canonical/hash-pinned v3 Aliyun profile:

```json
"storage": {
  "workspace_recovery": {
    "descriptor_file": "/absolute/owner-only/original-session-recovery.json",
    "descriptor_sha256": "actual-complete-descriptor-sha256"
  }
}
```

This fragment supplements the existing storage credentials/tenant configuration.
The normal Session retry or `omnigent resume` entry still performs its original
authorization. `provision` reuses the admitted Session OSS mounts; `start_host`
then imports before clone, Host credentials or Host execution. The packaged
consumer validates PAX paths/types/links/quota, extracts to a fresh same-filesystem
quarantine, compares the complete tree and private repository directories, and
promotes it before Runner initialization/any Agent read. Successful import skips
clone entirely; an incomplete/mismatched source stops bootstrap without a
Git-only fallback. A receipt bound to the actual target VM prevents later user
edits from being rolled back when the same restored VM reconnects. An unrelated
existing VM cannot be overwritten by a fresh-import request.

The source archive/delivery is retained. This is a bounded operator restore of
the selected original Session, not an automatic backup service for all Sessions.
Actual source/target volumes, OSS versions, identity revalidation, complete-file
comparison before first read, real reply and measured RPO/RTO remain mandatory
drill evidence. Local/parser tests do not establish that production recovery.

Run at least one randomly selected Tenant restore and one regional or cluster
restore every 90 days. Record requested and achieved recovery points, actual
RPO/RTO, lost or corrected facts, manual steps, revision tuple, hash report,
negative RLS output, tombstone and revocation replay, sign-off roles, and dated
remediation. A backup without successful isolated restore evidence is not a
production capability.

Write the signed immutable drill record against
`saas/production/recovery-policy.json`, then validate the exact release candidate:

```bash
uv run python -m saas.scripts.check_recovery_readiness \
  --product-revision "$(git rev-parse HEAD)" \
  --require-ready
```

The protected promotion workflow must persist the JSON report beside the source
backup manifest and DSSE envelope. Structural validation without `--require-ready`
is suitable for pull requests and is expected to report `blocked` while either the
Tenant or cluster production drill is absent. CI fixtures, local databases, and a
successful backup job are never copied into the production evidence directory.

For a disposable CI-only logical restore compatibility check, run:

```bash
OMNIGENT_SAAS_TEST_POSTGRES_URL='postgresql+psycopg://...' \
  uv run python -m saas.scripts.run_postgresql_restore_contract \
  --allow-disposable-databases \
  --output artifacts/postgresql-restore-contract.json
```

This command creates and force-drops two uniquely named databases on the supplied
test cluster. It must never target a shared or production administrative endpoint.
Its output is intentionally labelled `ci_contract_not_production_drill` and cannot be
placed in the production recovery-evidence directory.

## P18 policy inverse and retained facts

Ordinary P18 downgrade refuses before any SQL. The explicit preserving recovery
composition revalidates source-owned catalog gold and the original backup/fence,
compares all four policy OIDs/definitions/owners under locks, and removes only
those policies with the exact 18-to-17 head CAS in one transaction. It does not
rewrite P17's table, source-function or archive manifest. Reattachment restores
the same P17 receipt table OIDs, rows, foreign keys and ACLs, then runs the real
P18 migration and the full current-source verifier.

The current P16 lineage includes all retained lm1/lm2 contracts. Before any
policy removal, archive creation or receipt detach, source-inverse preflight
requires the existing independent maintenance connection to prove complete SELECT
visibility with `row_security=on` and `row_security_active=false` for every
affected relation. A filtered empty owner/app view cannot authorize an inverse.
It conservatively refuses any Run, execution Session, model routing/publication/
verification fact, budget reservation, or retained gateway/disablement/revocation
audit event. In particular a budget row need not reference an existing Run.
No grant, role switch or RLS relaxation is performed. Recover the encrypted database/WAL
point and retained objects through the existing database recovery path, retaining
all post-backup Usage/Audit/Outbox and typed receipt facts for verified replay.
Do not disable the lm2s guard, delete execution facts, stamp a missing migration,
or substitute a locally rebuilt old image.

Neither a policy inverse nor a disposable database test proves the 900-second
full rollback. That measurement includes the actual fence, retained encrypted
backup/object readback, original signed immutable Server/Host stack, database
recovery, history/auth/revocation/billing/audit checks and independent admission.
Re-upgrade requires the real new 65-second LISTEN-epoch readiness barrier; old
per-process ACKs cannot be replayed as a restarted process's success.


### Explicit T preserving target

The preserving coordinator defaults to P15. `ExplicitTRecoveryOperation` is a separate,
explicit typed maintenance proposal; it does not approve or select a new N−1 release.
The original P15 operation retains its exact 15 fields and checkpoint bytes. T
requires version `omnigent.postgresql-preserving-explicit-t/v1` and five explicit
fields; JSON decoding refuses missing/extra fields or an unknown version/target,
without filling defaults, recomputing pins or rebasing an old checkpoint.
Its operation must bind the original Server/Host pair, product, upstream,
adapter and `mm1a2b3c4d5e`/`lm2t00000001` tuple. Independent target source gold
must match the source-owned T inventory/security profile, role edges, database
and public/default ACLs. The current `pg_notify` raw ACL, including NULL versus
an array, owner, grantor/grantee and grant options, is preserved exactly. An
incompatible target ACL is refused; this primitive never edits system catalogs.

The existing coordinator must validate the actual retained encrypted backup,
KMS version, current write fence, exact original signed pair and drained typed
consumers/current-replica ACK set before every T phase. No production verifier
or no-op callback is supplied. Whole-table bounded COPY requires an independent
existing full reader and refuses prepared/in-flight writes, active execution,
unsupported tables or missing proof. All three P17 receipt objects retain OIDs,
rows, guards, indexes, FKs and ACLs through the original archive move.

The fixed inverse ends at 18→17→16→T and nf→mm; it never crosses T's retained
data guard. Ordinary P18/P17 Alembic downgrade remains refused. Reentry captures
newly committed, freshly fenced T facts before T→16 and exact receipt reattach,
then restores the original SOURCE-only objects and real P18 migration. New
rollback-period Usage/Audit/Outbox facts must be delivered with their original
IDs and hashes; old process ACKs are never replayed as a new process success.
The real 65-second epoch barrier, original signed pair startup/business tests,
RPO≤300 seconds, full ≤900-second drill and independent target approval remain
required. Unit phase routing or COPY hashes alone do not establish them.


### Fenced T runtime binding composition

`FencedTRuntimeRecovery` is a maintenance composition around the existing explicit
T recovery. It adds no HTTP endpoint, role grant or default proof adapter. The
original P15 operation/checkpoint protocol, source guard, migration SQL and gold
remain unchanged. A supplied operation must pin the existing original 3264
Server/Host pair; the target still requires separate release approval and fresh
image/security verification.

A database-only inverse preserves new runtime metadata, so it cannot by itself
make the original 0.18 App accept the same projects. Under a real write fence,
the composition first verifies the full current source and independent T gold.
While P18's owner policies still exist, the existing owner maintenance primitive
projects only the fixed placement schema, partition version/upstream/adapter and
monotonic partition/binding generations to the original 0.18/825/mm tuple. Every
active Omnigent placement must appear exactly once. Identity, tenant/space/project,
aliases, workspace/resource IDs and every other column remain unchanged. A
complete-table COPY comparison permits only those exact projections and the one
native source Outbox event per placement; no original Outbox fact is omitted.

The original preserving coordinator then prepares again, capturing the staged
metadata and its actual committed event, before the fixed 18→17→16→T/nf→mm
inverse. This is staged metadata under a fence, not proof an old provider is ready
against the still-current database. `verify_transition` must read the actual
installed candidate, namespace/cluster/database identity, provider workspace
inventory and retained original pair, without waiting for another connection to
see this transaction's uncommitted metadata. The existing live backup/fence
callback is called again immediately before commit. It must cover the bounded
commit and retain the fence on every failure.

After inverse, `verify_pair` must boot the actual original immutable Server AND
Host, verify their original receipts and run the original strict same-project
history/auth/Session/billing/audit checks. A JSON digest, boolean flag, current
binding validator or database fixture cannot replace that adapter. Old Runner
pools are a separate unresolved compatibility prerequisite: the original managed
projector selects upstream825/mm, while the same original fleet/readiness binds
its one admitted pool to Product3264. Those literal SHAs differ. The actual
transition adapter must refuse an unsatisfied approved execution scope before
staged metadata writes; a direct Host-only probe cannot silently substitute for
required managed Run recovery. The composition does not rewrite pool or Run
history or relabel upstream as Product. The old generic unscoped Outbox worker must remain
fenced from new runtime-maintenance events; an attempted claim, retry, terminal
change or missing event is refused rather than fabricated as published.

Reentry requires the original pair to be fenced and verified again. Existing
preserving reattachment first restores the same P17 receipt objects and the real
P18 policies, preserving all original and legitimate rollback-period facts. The
same owner primitive then projects the fresh complete scope back to the candidate
with a second generation increment. New global placements require separate
review and are refused; new projects in an existing placement remain in its fresh
complete scope. Actual new 65-second LISTEN epochs, delivery catch-up and business
checks remain required before removing the fence. A final state explicitly says
those checks are still outstanding and never grants production admission.

Checkpoints use the existing private durable recovery writer. Failure or unknown
COMMIT stops the composition. `reconcile_runtime_unknown_commit` is read-only and
checks the stable native source receipt and exact scope; it does not retry SQL,
run the inverse or resume reattachment. Retain the actual backup, file spool,
provider fence, source gold and private checkpoints for controlled reconciliation.
The full ≤900-second/RPO≤300-second drill must time the real signed stack and
actual adapters. Database fixture callbacks in the native test are explicitly
not operational backup/provider/image qualifications.

The fenced T composition binds Product, Server and Host through the unchanged
20-key `ExplicitTRecoveryOperation` and its independently derived target Gold.
Its target remains original upstream 825/mm/T, adapter 0.2 and runtime 0.18.
Changing the exact immutable pair requires the actual transition/pair adapters
to verify that separately approved signed target; valid-shaped pins and source
Gold never constitute approval. The known 3264 managed-pool conflict remains a
negative regression target, not a default recovery target.
