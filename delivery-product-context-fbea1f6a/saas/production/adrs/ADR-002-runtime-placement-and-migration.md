# ADR-002: Runtime Placement and migration protocol

- Decision status: Accepted architecture
- Production approval: Governed by `../baseline.json` and bound by `../adr-approval-candidate.json`
- Technical owner: `runtime-compatibility`

## Context

Official Omnigent uses workspace-scoped runtime resources, while the SaaS model
adds Tenant, Space, Project, region, plan, and capacity constraints. A numeric
workspace identifier is not globally unique and cannot be an authorization or
routing input supplied by a client.

## Decision

The control plane persists Runtime Placement, Runtime Partition, Runtime
Identity Alias, Runtime Resource Binding, and Generation. A server-side Resolver
selects Placement from residency, product plan, capacity, runtime lineage, and
Project affinity. An active binding never reroutes because of a request header,
cookie, query parameter, or stale cache entry.

Migration is a durable state machine: reserve target capacity, snapshot source,
restore target, catch up mutations, verify resource inventory, fence the old
generation, atomically cut over the authoritative binding, observe, and later
retire rollback material. Every adapter call binds the resolved physical
workspace and generation; stale generations fail closed.

## Consequences and rollback

Migration is asynchronous and may pause for operator review. Rollback switches
back only when the retained source is complete and no post-cutover invariant
would be violated. Otherwise the system completes forward recovery. Placement
identifiers remain internal and are never exposed as tenant authority.

## Acceptance evidence

- The same physical workspace number in two Placements remains isolated.
- Crash tests cover snapshot, catch-up, fencing, cutover, and cleanup.
- Stale resolver replicas and Runner leases cannot write after cutover.
- N-1 adapter rollback preserves live bindings and fails on unsupported schema.

## Owner confirmation

Governance downgrade: repository Owner `Dream1216` assumes this technical-owner
decision under `sole-owner-risk-waiver`; no independent runtime compatibility
Review is claimed. Production verification gates remain mandatory.

The technical owner confirms the Resolver inputs, migration state machine,
fencing rules, compatibility window, and rollback retention for the candidate.
