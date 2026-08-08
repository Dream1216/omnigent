# ADR-001: PostgreSQL topology and transaction boundary

- Status: Accepted under sole-owner risk waiver
- Technical owner: `platform-architecture`
- Candidate: `omnigent-saas-p0-2026-08-09`

## Context

Omnigent official tables and the SaaS control plane have different ownership,
migration, and isolation responsibilities. Runtime resources may also move
between Placements. Treating those databases as one implicit transaction would
couple upstream upgrades to downstream schema and create failure modes that
cannot be recovered safely.

## Decision

Each data region uses one managed multi-AZ PostgreSQL cluster with distinct
databases or schemas, owners, LOGIN roles, and least-privilege service roles for
official Omnigent and SaaS data. Official migrations run and pass compatibility
checks before SaaS migrations. Every request establishes server-derived Tenant,
Space, Project, actor, and Runtime Partition context; tenant-owned tables use
`ENABLE` and `FORCE ROW LEVEL SECURITY`.

A transaction may be atomic only inside one database and one Runtime Placement.
Operations spanning Placements use a durable Saga, Transactional Outbox,
idempotent consumers, explicit compensation, monotonic generation fencing, and
operator-review terminal states. Distributed 2PC, best-effort dual writes, and
client-selected physical workspace identifiers are prohibited.

## Consequences and rollback

Services must tolerate asynchronous completion and expose durable operation
state. Migration rollback restores the last compatible schema and adapter only
while retained N-1 bindings and snapshots remain valid; it never rewinds a
partially committed cross-Placement operation without compensation.

## Acceptance evidence

- Real PostgreSQL proves FORCE RLS denial for missing and cross-tenant context.
- Migration drift, two-head, wrong-order, and N-1 schema tests fail closed.
- Fault injection at every Saga/Outbox boundary converges or enters explicit
  operator review without orphaning authority.
- Backup and restore preserve bindings, generations, audit, usage, and Outbox.

## Owner confirmation

Governance downgrade: repository Owner `Dream1216` assumes this technical-owner
decision under `sole-owner-risk-waiver`; no independent architecture Review is
claimed. Production verification gates remain mandatory.

The technical owner confirms role separation, migration order, failure
semantics, operational ownership, and rollback material for this exact decision
bundle.
