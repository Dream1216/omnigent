# Tenant deletion and proof runbook

This runbook governs irreversible Tenant deletion. A database `DELETE`, a successful
background job, or a UI status is not sufficient evidence. Production completion
requires the exact policy inventory, signed manifest, reconciliation checks, retention
deadlines, and independent attestations validated by
`python -m saas.scripts.check_deletion_readiness`.

## Safety boundary

1. Resolve the Tenant through the authorized control-plane identity. Evidence stores
   only its SHA-256 identifier; never copy raw IDs, emails, object keys, repository
   paths, secrets, or customer content into the evidence repository.
2. Record the customer-export decision, authorization decision, idempotency key, legal
   hold result, and deletion reason. An unresolved legal hold blocks completion.
3. Before irreversible work, set the Tenant to `pending_deletion`, disable new
   admission, terminalize or quarantine active Runs, revoke Sessions/Tokens/Grants,
   remove Membership access, and persist the deletion request through Outbox.
4. Re-read every precondition from its authoritative store. Do not accept cached UI
   state or caller-supplied resource lists.

Deletion can be cancelled only before destructive surface work starts. After any
surface enters erasure, recovery is a forward-only incident procedure: restore only
into isolation, immediately replay the Tenant tombstone and all revocations, and never
re-enable traffic merely to reconstruct deleted content.

## Complete surface inventory

The approved workflow must reconcile all fifteen policy surfaces:

- control-plane and official Runtime PostgreSQL;
- object/artifact stores and vector/search indexes;
- caches and queues/DLQs;
- Provider/Connector state and Webhook state;
- enterprise identity provisioning state plus immutable identity Event Receipts;
- Runner Worktrees, checkpoints, bundles, recovery material, and writable layers;
- Secret references, KMS grants, and data keys;
- logs/traces, immutable audit/ledger facts, and backups/snapshots.

Primary, derived, external, and Runner surfaces must reach zero or cryptographic
erasure. SCIM Directory credentials and subject mappings must be erased; identity Event
Receipts, logs, and immutable audit/ledger facts may remain only after direct identifiers
are removed without making replay resurrect deleted identity, and a bounded retention
basis/deadline is recorded. Immutable backups may
remain only while runtime-inaccessible, bound to a deletion tombstone, and scheduled
for purge within the policy maximum. A missed deadline blocks readiness.

## Reconciliation and evidence

Run every policy check against authoritative APIs and stores, including both forced-RLS
layers, cross-Tenant canaries, zero object/index enumeration, cache invalidation,
queue/DLQ payload clearing, external revocation, SCIM token/mapping erasure and receipt
anonymization, Runner material destruction, KMS revocation, restore-with-tombstone,
and audit/ledger anonymization. Record one SHA-256
evidence digest per surface; do not embed raw records.

Publish the canonical manifest and DSSE envelope in an approved immutable store. The
privacy, security, and data-owner attestors must independently bind the exact product
revision after completion. Then run:

```bash
uv run python -m saas.scripts.check_deletion_readiness \
  --product-revision "$EXACT_PRODUCT_REVISION" \
  --require-ready \
  --output artifacts/deletion-readiness-report.json
```

CI and local validation omit `--require-ready`; an empty evidence directory must report
structural `pass` and production `blocked`. Never copy CI fixtures, synthetic manifests,
screenshots, or deletion-job output into the production evidence directory.
