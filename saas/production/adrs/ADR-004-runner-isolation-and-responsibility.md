# ADR-004: Runner isolation and responsibility modes

- Status: Proposed
- Technical owner: `execution-platform`
- Candidate: `omnigent-saas-p0-2026-08-09`

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

## Owner confirmation

The technical owner confirms all three responsibility modes, canonical managed
process policy, capacity ownership, quarantine, and rollback behavior.
