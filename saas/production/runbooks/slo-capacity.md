# Production SLO and capacity evidence runbook

This runbook governs the evidence required before promoting an Omnigent SaaS release.
A green CI run, synthetic benchmark, healthy endpoint, or replica count is not a
production SLO observation. Promotion requires active dashboards plus one current,
exact-revision record accepted by
`python -m saas.scripts.check_slo_capacity_readiness`.

## Activate the six SLOs

1. Implement the six baseline measurement queries without raw Tenant identity or
   customer payloads. Keep valid client and authorization denials out of availability
   denominators, and publish exclusion counts beside eligible counts.
2. Publish secret-free HTTPS dashboards and immutable hashes for each dashboard,
   measurement query, and alert policy. Change each baseline `dashboard_state` from
   `planned` to `active` only after the production query and alert are independently
   reviewed.
3. Observe the exact release candidate for at least the longest baseline window in a
   real production region spanning two failure domains. Record rolling error-budget
   use and the maximum 1-hour and 6-hour burn rates.
4. Treat any SLO miss, exhausted budget, or excessive burn rate as a promotion block.
   Do not edit observations to remove incidents; fix the release or wait for a new
   complete window.

The required objectives are authentication availability, authorization/Placement
resolution latency, durable Run admission latency, immediate healthy and bounded
degraded revocation, Outbox delivery latency, and zero acknowledged durable Run Event
loss. The policy file is the machine-readable authority for exact values.

## Execute the capacity matrix

Use an isolated production-like environment with production traffic disabled. Replay
an approved, hashed cardinality and data profile for every service in the production
catalog: control plane, compatibility adapter, queue worker, Runner sandbox,
billing/metering, audit, and admin. Each service must execute all five scenarios:
steady state, hot Tenant, degraded dependency, backlog recovery, and reserved failure
capacity.

Account for every offered work unit as completed or deliberately rejected. Unexpected
errors, zero completed work, saturation above 80%, headroom below 20%, or Tenant
fairness below 0.90 block promotion. Capture evidence for API replicas, PostgreSQL
connections, queues, worker concurrency, Runner compute/disk/inodes, egress,
object/audit storage, fairness, and retry/DLQ budgets. A single aggregate CPU graph is
not enough.

## Drill alerts and publish evidence

Drill error-budget exhaustion, queue age, PostgreSQL pool saturation, Runner capacity,
storage growth, and dependency degradation. Each alert must fire, route to the real
on-call path, and be acknowledged within 300 seconds.

Publish the canonical record and its DSSE envelope in an approved immutable store and
record the object-version/lock receipt SHA-256.
The site-reliability, product-owner, and service-owner attestors independently bind the
same product revision after the observation window completes. Evidence records contain
only hashes and bounded aggregate metrics, never raw Tenant IDs, repository paths,
emails, secrets, traces, or customer content.

Run the protected promotion check with the immutable release revision:

```bash
uv run python -m saas.scripts.check_slo_capacity_readiness \
  --product-revision "$EXACT_PRODUCT_REVISION" \
  --require-ready \
  --output artifacts/slo-capacity-readiness-report.json
```

CI and local validation omit `--require-ready`. Until dashboards are active and a
qualifying production record exists, structural validation must pass while production
readiness remains blocked.
