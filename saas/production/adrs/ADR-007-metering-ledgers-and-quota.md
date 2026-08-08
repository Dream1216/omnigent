# ADR-007: Metering, ledgers, reconciliation, and quota

- Status: Accepted under sole-owner risk waiver
- Technical owner: `billing-platform`
- Candidate: `omnigent-saas-p0-2026-08-09`

## Context

Provider usage, customer charges, entitlements, and quota are related but not
the same fact. Mutable counters or one best-effort webhook cannot support late
events, retries, refunds, plan changes, provider disputes, invoices, or audited
period close.

## Decision

Persist immutable Usage Receipts, versioned Pricing Snapshots, append-only
Customer and Provider ledger entries, Entitlement grants, Quota reservations,
and reconciliation exceptions as separate authorities. Monetary and usage
amounts use fixed-point units. Corrections append reversing or compensating
entries; finalized history is never overwritten.

Quota is reserved before provider work, committed from authoritative receipts,
and released or expired deterministically. Provider-native receipts are
preferred; locally derived receipts record provenance and confidence. Daily
reconciliation compares provider, usage, customer ledger, subscription,
payment, refund, and invoice facts. Period close freezes a versioned boundary
and requires explicit exception handling.

## Consequences and rollback

Billing is eventually reconciled rather than transactionally coupled to a
provider. Rollback may stop admission or pricing activation, but cannot delete
or rewrite ledger history. Pricing and entitlement changes are effective only
from a recorded version and time boundary.

## Acceptance evidence

- Duplicate, late, reordered, unknown-result, refund, and correction cases converge.
- Plan changes and quota races preserve reservations and ledger invariants.
- Provider invoice totals reconcile or enter a bounded owned exception queue.
- Webhook replay and period-close recovery are idempotent and fully audited.

## Owner confirmation

Governance downgrade: repository Owner `Dream1216` assumes this technical-owner
decision under `sole-owner-risk-waiver`; no independent billing-platform Review
is claimed. Production verification gates remain mandatory.

Billing confirms authoritative sources, fixed-point units, correction policy,
quota behavior, reconciliation ownership, close, invoice, payment, and tax gaps.
