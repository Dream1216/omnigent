# ADR-003: Authorization snapshot and degradation

- Status: Accepted under sole-owner risk waiver
- Technical owner: `control-plane`
- Candidate: `omnigent-saas-p0-2026-08-09`

## Context

Multi-replica request handling needs a compact authorization context, but a
long-lived or caller-authored context makes revocation ineffective. Dependency
failure must not silently turn cached membership or permissions into authority
for destructive or privileged operations.

## Decision

After authenticating a human or machine principal, the control plane issues an
opaque, session-bound Context Snapshot containing only server-derived identity,
Tenant, Space, Project, authorization version, and expiry facts. Snapshots use
shared rotatable keys, have a maximum lifetime of 60 seconds, and are never
accepted from unsigned headers or client-selected scope.

On the healthy path, sensitive authorization is revalidated against live
membership, grant, credential, and resource versions. Transactional Outbox
events invalidate replica caches. During a declared dependency degradation,
only an exact, versioned allowlist of low-risk GET or HEAD operations may use an
unexpired snapshot; mutations, secrets, billing, support, identity, export, and
privileged reads fail closed.

## Consequences and rollback

The platform trades some availability for bounded authorization risk. Key
rotation retains only the overlap needed for in-flight snapshots. Rollback may
restore the previous verifier only if its key and version window remain valid;
it cannot extend snapshot lifetime.

## Acceptance evidence

- Two replicas prove immediate healthy-path membership and API-key revocation.
- Cache loss, PostgreSQL loss, Outbox delay, and key rotation obey the allowlist.
- Cross-tenant, stale version, expired, forged, and mixed-auth contexts fail.
- Degradation entry, exit, and every allowed request are auditable.

## Owner confirmation

Governance downgrade: repository Owner `Dream1216` assumes this technical-owner
decision under `sole-owner-risk-waiver`; no independent control-plane Review is
claimed. Production verification gates remain mandatory.

The technical owner confirms live revalidation coverage, the exact degraded
allowlist, key rotation, invalidation, and incident ownership.
