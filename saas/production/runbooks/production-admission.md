# Production evidence admission

This is the final release boundary for the ten aggregate P0/P4/P5/P6 production
gates. A domain evidence JSON document is necessary but is not authoritative until
an approved production workflow admits its exact bytes with a trusted Ed25519 key.

## Revisions and trust boundary

Use two immutable revisions to avoid a self-referential commit:

1. `product_revision` is the exact source SHA that built the digest-pinned candidate.
2. `evidence_revision` is that candidate or a descendant containing only canonical
   evidence JSON, admission receipts, and the acceptance ledger.

The verifier requires `product_revision` to exist and be an ancestor of
`evidence_revision`. Any source, policy, workflow, migration, dependency, or verifier
change after the candidate blocks admission. The checkout must also be clean, so an
uncommitted receipt cannot authorize release.

## Key custody and receipt issuance

Create an Ed25519 signing key in the production KMS or HSM. Keep its private key
non-exportable and grant signing only to the protected production-evidence workflow.
Before cutting the candidate, register only its public PEM, exact workflow identity,
validity interval, purpose, and revocation state in
`saas/production/evidence-admission-keys.json`. The registry is part of the candidate
trust root and cannot change in the later evidence-only revision.

For every declared evidence document, the protected workflow creates one receipt in
`saas/production/evidence-admission-receipts`. The signature is DSSE PAE over canonical
JSON and binds the evidence kind, repository-relative path, byte SHA-256, exact product
revision, workflow identity, validity window, and signer key ID. Never copy a receipt
between paths, kinds, products, or revisions. Commit the evidence and receipts as an
evidence-only change through normal protected review.

Key revocation, expiry, malformed Base64, byte drift, revision mismatch, duplicate
receipt IDs or claims, unsafe paths, missing evidence, and untrusted workflow identity
all fail closed. Rotate with a short overlap, issue new receipts, then mark the old key
revoked; never delete historical key metadata.

## Final admission

Run the final command only from a protected production-evidence job with restricted
deployers, required reviewers, a clean checkout, and the full evidence Git history.
The aggregate command runs all eight domain verifiers, cryptographic admission,
candidate-lineage checks, and the ten-gate verifier. The current compatibility workflow
tests this implementation but intentionally does not claim final production admission.

The protected job executes:

```bash
PRODUCT_REVISION="$(git rev-parse <candidate-ref>)"
uv run python -m saas.scripts.check_evidence_admission \
  --product-revision "$PRODUCT_REVISION" \
  --require-ready
uv run python -m saas.scripts.check_production_readiness \
  --product-revision "$PRODUCT_REVISION" \
  --require-ready
```

Archive the workflow run URL, artifact ID and digest, evidence revision, product
revision, image digests, and aggregate report digest. A green compatibility workflow,
candidate image build, unsigned JSON file, local rehearsal, or manually edited ledger
is not production admission.
