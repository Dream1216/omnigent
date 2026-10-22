# Control-plane degradation runbook

## Trigger and safety boundary

Open an incident when Auth, Authorizer, Placement Resolver, PostgreSQL, the
invalidation channel, or the shared Context Snapshot key service breaches its
SLO or produces inconsistent generations. Do not enable a broad read bypass.
The only degraded authorization path is the code-owned exact `GET/HEAD`
allowlist and an unexpired, session-bound snapshot with a maximum age of 60
seconds.

New login, scope selection, all mutations, WebSocket upgrades, new Runs,
Secrets, source export, member and billing operations, support access, and
unlisted reads remain unavailable. A 503 in those paths is the intended safe
result.

## Triage

1. Record product SHA, upstream SHA, schema head, adapter contract, region,
   Placement, first failure time, and affected anonymous Tenant counts.
2. Compare Auth failure rate, resolve p99, PostgreSQL pool saturation, oldest
   Outbox event, invalidation consumer lag, snapshot verification failures, and
   key IDs across at least two API replicas.
3. Run the current health and authorization probes. Confirm that a revoked
   membership is denied on every healthy replica and that a sensitive endpoint
   returns 503 when the control plane is intentionally unavailable.
4. If replicas disagree on keys, versions, or bindings, remove the stale
   replicas from service. Do not extend snapshot TTL.

## Containment and recovery

1. Stop scope selection and mutation traffic before shedding low-risk reads.
2. Reserve database connections for Auth, revocation, Outbox, and incident
   probes; reject bulk admin and export work at admission.
3. Recover PostgreSQL or the invalidation consumer, then require each replica
   to reload the active key ring and verify the current policy revision.
4. Keep degraded mode until two consecutive probe windows show matching
   membership, placement, partition, and binding generations on every replica.
5. Disable degraded mode, wait longer than the maximum snapshot TTL, and repeat
   the revocation and sensitive-operation probes.

## Closure evidence

Attach the immutable metrics window, exact probe output, affected scope, key
IDs, oldest accepted snapshot, Outbox recovery point, source revisions, and a
timeline. Any fail-open result is a security incident and blocks release until
the negative E2E is added or repaired.
