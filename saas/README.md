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

This is foundation code, not production multi-tenancy proof. PostgreSQL control
plane repositories, RLS, authorization, distributed Run/Runner control, billing,
and administration are delivered in later gated phases.

Run the focused checks:

```bash
uv run pytest tests/saas
uv run pyrefly check saas
uv run python saas/scripts/check_upstream_delta.py \
  --output artifacts/upstream-delta-report.json
```
