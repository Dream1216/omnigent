# SaaS incident response runbook

## Severity and authority

Treat cross-tenant access, lost acknowledged Run Events, forged billing facts,
secret exposure, sandbox escape, unsigned production code, or recovery beyond
approved T0 limits as critical. The incident commander coordinates containment;
service Owners operate only their documented controls. Content access still
requires an explicit, scoped, expiring support grant. Break-glass cannot bypass
RLS and must produce immutable audit records.

## First 30 minutes

1. Freeze the evidence tuple: product, upstream, schema, adapter, image digest,
   feature-flag snapshot, Placement generation, and UTC time window.
2. Stop the smallest unsafe admission or mutation class. Do not delete queues,
   worktrees, logs, or artifacts and do not rewrite ledger facts.
3. Revoke affected sessions, capabilities, API keys, webhook secrets, Runner
   certificates, or image promotion rights. Increment the relevant security or
   generation version before restarting traffic.
4. Preserve database WAL, Outbox and Run cursors, object versions, audit
   segments, Runner lease and fencing records, and proxy decision logs under
   incident retention.
5. Identify affected Tenants from authorization and data evidence rather than
   broad service membership or staff assumption.

## Service-specific containment

- Queue or Worker: stop admission, keep persisted events, allow only fenced
  terminalization, release quota through correction facts, and quarantine
  poison messages without editing them.
- Runner or Sandbox: drain and quarantine the pool, revoke capabilities, block
  egress, preserve ChangeSet recovery material, and reject stale fence tokens.
- Billing: freeze new settlement, continue immutable ingestion when safe, and
  reconcile through reversing or correcting entries.
- Audit: switch to protected buffering only if ordering and hashes remain
  verifiable; never discard tenant or operator events to restore throughput.
- Admin: disable L2 and L3 mutations, expire privileged sessions, and retain
  already committed Operation state.

## Recovery and closure

Recover in isolation, replay revocations, tombstones, bindings, Run Events, and
Outbox facts, then run tenant isolation and ledger invariants before traffic.
Use canary Tenants and explicit rollback criteria. Closure requires an immutable
timeline, affected-Tenant list, notification decision, actual SLO or RPO/RTO,
root cause, tests that would have caught it, named action Owners and deadlines.
Security, recovery, and ledger exceptions keep release status NO-GO.
