# Omnigent SaaS downstream boundary

This directory owns the commercial SaaS control plane and the permanent
compatibility layer around the official Omnigent runtime. The official runtime
must not import this package; dependencies only flow from `saas` to `omnigent`.

P0 establishes three executable controls:

1. `upstream-baseline.json` pins the verified official source, schema, runner
   protocol, adapter contract, and source-intrusion budgets.
2. `compatibility/runtime_partition.py` derives a fail-closed RuntimeContext
   from trusted Placement, Partition, Identity Alias, and Resource Binding
   records, then projects only the physical workspace into Omnigent.
3. `scripts/check_upstream_delta.py` produces `upstream-delta-report.json` and
   blocks forbidden Native Bridge/Harness changes, reverse dependencies, stale
   lineage, or an exceeded patch/LOC/file budget.

The first P1 slice adds an independent control-plane schema and migration for
Global User, Tenant, Space, versioned Membership, Runtime Placement, Runtime
Partition, Identity Alias, and Resource Binding records. Its server-side
resolver:

- re-reads active Tenant and Space memberships before entering the runtime;
- rejects membership-version changes after a RequestContext is issued;
- resolves Placement, physical partition, identity alias, and revision metadata
  only from trusted database records;
- rejects unapproved source/schema/adapter revisions and `workspace_id = 0`;
- keeps project-scoped bindings closed until the P2 Project Authorizer exists.

This is foundation code, not production multi-tenancy proof. Authentication,
Project authorization, real PostgreSQL RLS, distributed Run/Runner control,
billing, and administration remain behind later gated phases.

Run the focused checks:

```bash
uv run pytest tests/saas
uv run pyrefly check saas
uv run python saas/scripts/check_upstream_delta.py \
  --output artifacts/upstream-delta-report.json
```

Exercise the independent migration against a disposable database:

```bash
export OMNIGENT_SAAS_DB_URL=sqlite:////tmp/omnigent-saas-control-plane.db
uv run alembic -c saas/control_plane/alembic.ini upgrade head
uv run alembic -c saas/control_plane/alembic.ini check
```
