# ADR-004: Runner isolation and responsibility modes

- Decision status: Accepted architecture
- Production approval: Governed by `../baseline.json` and bound by `../adr-approval-candidate.json`
- Technical owner: `execution-platform`

## Context

Runs execute untrusted repositories and tools. Shared, dedicated, and
customer-managed capacity have different placement and operational boundaries,
but must not have different authorization semantics or bypass central leases,
fencing, audit, and metering.

## Decision

Support Managed Shared, Managed Dedicated, and Customer-managed Runner modes
behind one registration, capability, scheduling, lease, fencing, event, and
metering contract. Mode changes placement and responsibility only. Every Runner
has a rotatable certificate identity, capability declaration, pool assignment,
incarnation, health state, and quarantine path. Admission is tenant-fair and
reserves capacity before dispatch.

Managed modes disable the upstream copy-on-write Runner zygote. Ambient cloud,
provider, database, and tenant credentials are stripped. Re-enabling any forked
process model requires a separate review proving post-fork reset of credentials,
file descriptors, native state, telemetry, caches, and tenant context.

The p0s10 direct Runner database projection is admitted only for an isolated
Beta with synthetic tenants, empty data, non-production secrets, and no
production traffic. It removes Runner table DML and exposes only the exact
reviewed Worktree, isolation, secret, and Preview RPC projection. A direct
Runner can still hold an open transaction on its own Worktree and ChangeSet,
the same-project quota row, and, during writer release, the same ChangeSetGroup;
PostgreSQL 18 bounds notification-queue amplification but does not turn an
untrusted direct database client into a production-safe boundary. These lock
and direct-connect residuals are accepted only for the isolated synthetic Beta.
Enterprise Production Admission requires an enforcing database proxy or removal
of direct Runner database credentials, plus central ownership of shared quota,
group-derivation, and garbage-collection transitions.

## Consequences and rollback

Dedicated and customer-managed modes require explicit shared-responsibility
terms and compatible upgrade windows. Rollback drains new leases, fences the
new incarnation, and re-admits work only on a compatible pool; a stale Runner
cannot resume merely because its process is alive.

## Acceptance evidence

- Two failure domains prove lease expiry, fencing, reconnect, and quarantine.
- Tenant pool isolation and weighted fairness hold under overload and retries.
- Certificate issue, rotation, revocation, and stolen-token cases fail closed.
- Negative tests prove no ambient credential or cross-sandbox state inheritance.
- A compromised Runner cannot forge an isolation grant, redeem a secret from a
  different execution profile, cross a capability action boundary, or continue
  claiming after RLS/catalog authority drift.
- Production evidence includes adversarial transaction-lock and direct-connect
  tests proving that shared quota, ChangeSetGroup, garbage collection, Preview,
  and Outbox authority cannot be held or mutated by an untrusted Runner.

## Owner confirmation

Governance downgrade: repository Owner `Dream1216` assumes this technical-owner
decision under `sole-owner-risk-waiver`; no independent execution-platform
Review is claimed. Production verification gates remain mandatory.

The technical owner confirms all three responsibility modes, canonical managed
process policy, capacity ownership, quarantine, and rollback behavior.
