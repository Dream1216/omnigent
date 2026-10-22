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

## Drill evidence

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
