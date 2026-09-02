# ADR-001: PostgreSQL topology and transaction boundary

- Decision status: Accepted architecture
- Production approval: Governed by `../baseline.json` and bound by `../adr-approval-candidate.json`
- Technical owner: `platform-architecture`

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

Database reachability is part of the authority boundary, not a DSN convention.
Before a Runner incarnation can receive work, a cluster owner or audited
superuser revokes `CONNECT`, `CREATE`, and `TEMPORARY` from `PUBLIC` on every
database in the cluster and grants only the reviewed per-database principals.
Each Runner LOGIN and its `saas_runner_agent` base role may have effective
`CONNECT` only to the receipt-bound application database and no effective
`CREATE` or `TEMPORARY` privilege on any database. The Runner verifies that
cluster-wide projection and its per-incarnation LOGIN `CONNECTION LIMIT 8`
before every claim and fails closed on drift; the Runner engine is bounded to
the same four pooled plus four overflow connections. The SaaS schema migration
must not pretend it can mutate databases owned by another authority.

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
- PostgreSQL 18 proves that each direct Runner can connect only to the
  receipt-bound database and is rejected when another database remains
  reachable through `PUBLIC` or a direct grant. PostgreSQL 16 remains the N-1
  migration and role-compatibility lane and must reject direct Runner runtime
  admission.
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
