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
