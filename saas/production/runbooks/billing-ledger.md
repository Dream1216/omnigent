# Tenant billing, metering, and ledger operations

This runbook covers the first P6 billing-authority slice: Tenant subscription state,
immutable pricing snapshots and Usage facts, fixed-point entitlements, reservation
conservation, separate customer/provider ledgers, and reconciliation. It is a
code-contract runbook, not evidence of a live payment processor, invoice system, tax
engine, or production commercial acceptance.

## Production composition

1. Migrate through `p6a000000008`, then reapply
   `saas/control_plane/postgresql_roles.sql`. Verify all 67 control-plane and all 17
   Runtime tables retain `ENABLE ROW LEVEL SECURITY` plus `FORCE ROW LEVEL SECURITY`.
2. Construct `BillingControlPlane` with a session factory whose login inherits only
   `saas_billing`. Do not reuse `saas_app`, `saas_governance`, `saas_authenticator`, or
   the platform role for routine billing traffic.
3. Pass the billing service to `create_saas_http_integration`. The Cookie Admin router
   exposes content-blind subscription, pricing, entitlement, ledger, and reconciliation
   administration only. It intentionally has no HTTP endpoint for Credit, Usage,
   Reserve, Settlement, Refund, or Provider Cost ingestion.
4. Keep financial ingestion behind a separate authenticated internal transport. Until
   a workload identity is bound to an independently authorized metering principal, do
   not connect the service methods to an Internet-facing route or let a human Cookie
   session impersonate a worker.
5. Keep the Outbox dispatcher healthy. Each billing mutation and its secret-free event
   commit in the same transaction; downstream consumers deduplicate by immutable Event
   ID and never rebuild financial truth from delivery order.

## Monetary and metering invariants

- Money is an integer in the currency's configured minor unit. Quantities and unit
  sizes use `Decimal(38, 12)`. Floats are rejected at the service boundary.
- `UsageEvent` is append-only and records the exact Pricing Snapshot used at occurrence
  time. It is not itself a customer settlement or Provider cost.
- Pricing Snapshots and Usage facts are never updated or deleted. Corrections require a
  new snapshot or an explicit reversing/correcting ledger fact.
- One Tenant billing account has one currency in this slice. A currency change requires
  a future migration and explicit ledger-close workflow; it must not overwrite an
  active balance.
- Customer balance projection must equal the sum of all ledger deltas:
  `available`, `reserved`, and `consumed`. Reserve moves available to reserved; settle
  moves the charged portion to consumed and releases unused hold; release returns the
  full hold; refund reverses a completed settlement.
- A Reservation has one terminal outcome. Idempotency keys, Provider Request IDs,
  operation keys, row locks, and PostgreSQL advisory transaction locks make concurrent
  retries single-winner without granting UPDATE on Tenant metadata.
- Provider cost entries are independent append-only facts. A Provider refund is a new
  cost fact, never an update to the original receipt.
- Usage attributes use the fixed allowlist in `billing.py` and must not contain Prompt,
  code, Secret, Token, Credential, Authorization, or arbitrary high-cardinality data.

## Operator procedure

1. Configure the Subscription and seal a Pricing Snapshot before enabling admission.
   Verify the plan, currency, effective interval, meter, unit, unit size, and minor-unit
   rate. Never edit a sealed snapshot by SQL.
2. Configure each Tenant/Space/Project/User/Model entitlement with an explicit period,
   quantity limit, concurrency limit, and hard/soft-limit policy. Admission must use the
   authoritative Entitlement and Subscription status, not a browser value.
3. Grant or import customer Credit only through the protected financial-ingestion
   workflow with a unique idempotency key and external evidence reference. The Admin UI
   is deliberately unable to mint Credit.
4. Reserve before Provider I/O. If admission is denied, do not call the Provider. If a
   call is canceled before Provider acceptance, release the hold. If Provider outcome
   is unknown, retain the hold and reconcile; do not retry under a new operation key.
5. Record exactly one Usage fact per Provider Request and Meter. Settle the matching
   Reservation from that fact. Retries reuse the same Provider Request ID and
   idempotency key.
6. Record Provider estimates/final receipts/refunds independently. Run reconciliation
   over half-open UTC periods, inspect every mismatch, attach non-sensitive resolution
   evidence, and resolve rather than deleting exceptions.
7. Confirm billing Outbox lag, open mismatch count, balance/ledger projection, active
   Reservation age, and hard-limit rejection rate remain within the approved SLO.

## Failure, reconciliation, and rollback

- On an unavailable Provider before acceptance, release the Reservation. After possible
  acceptance with a lost response, preserve it as reserved and recover by the stable
  Provider Request ID; a blind retry can double-charge.
- If the balance projection differs from ledger sums, stop new financial mutations,
  preserve the database and Outbox evidence, and invoke the service-only audited
  projection rebuild with current Version, reason, and idempotency key. It recomputes
  only from ledger deltas and records before/after Outbox evidence. Never patch ledger
  rows or expose this repair through the ordinary Cookie console.
- If pricing overlap, currency drift, duplicate Provider facts, or unexplained negative
  projection is detected, fail admission closed and open a billing incident.
- Application rollback may hide the Billing view while retaining
  `p6a000000008`. Drain billing writers and Outbox delivery before a schema downgrade.
  A destructive downgrade deletes financial tables and requires an approved immutable
  backup, ledger export/hash, open-reservation disposition, and restore rehearsal.
- Restoring an old backup must replay post-backup Subscription suspension and mismatch
  resolutions and then re-run RLS, row-count/hash, balance, Reservation, Usage, and both
  ledger reconciliations before traffic resumes.

## Acceptance boundary

The slice is accepted only with SQLite migration compatibility, real PostgreSQL forced
RLS and least-privilege roles, cross-Tenant and missing-context denial, append-only
trigger rejection, concurrent Reservation single-winner behavior, Cookie/CSRF/Origin
and role denial, real Chromium UI coverage, non-empty logical backup/restore, Outbox
idempotency, wheel contents, patch replay, and intrusion-budget checks.

Those checks still do not prove the aggregate P6 gate. Production acceptance additionally
requires a non-human metering identity and internal transport, entitlement rollover,
real Provider webhook signature/
dedupe/out-of-order/replay handling, at least one real Provider invoice comparison,
payment/invoice/tax boundaries, production SLO/capacity, and customer sign-off. Keep P6
and release status `NO-GO` until that evidence is bound to the exact deployed revision.
