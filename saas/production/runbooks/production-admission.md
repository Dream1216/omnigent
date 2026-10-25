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
non-exportable and grant signing only to an approved production signing broker. The
generic two-phase flow uses the protected workflow as issuer/finalizer and an external
broker as signer; a cloud-specific integration may instead authorize the workflow's
OIDC identity directly. Before cutting the candidate, register only its public PEM,
exact issuer workflow identity, validity interval, purpose, and revocation state in
`saas/production/evidence-admission-keys.json`. The registry is part of the candidate
trust root and cannot change in the later evidence-only revision.

For the GitHub-hosted issuer, the registered workflow identity must exactly equal the
protected runtime value of `github.workflow_ref`:

```text
Dream1216/omnigent/.github/workflows/saas-production-admission.yml@refs/heads/main
```

For a direct workload-identity integration, authorize the same immutable identity in
the KMS/HSM policy. For the generic external broker, require an independent production
approval and bind its audit record to `signature_payload_sha256`, key version, signer
principal, and request ID. Do not use a branch wildcard, actor name, repository secret
containing an exportable private key, or caller-supplied identity as the trust decision.

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

### Two-phase protected issuance

`.github/workflows/saas-production-admission.yml` also provides the two-phase receipt
entry point. It is deliberately not a signer and never accepts a private key. It runs
in the protected `production-evidence` Environment and has read-only repository
permissions. Use it in two separate, auditable runs:

1. Commit the canonical evidence JSON to protected `main`. Dispatch the workflow with
   the exact Product Revision, current `main` SHA as Evidence Revision, and a canonical
   `receipt_request_json` object using `action=prepare`. It names one of the eight
   evidence kinds, its declared path, active signer key ID, globally unique receipt ID,
   UTC issuance/expiry timestamps, and a null signature. The expiry must not exceed
   either the policy maximum age or signer-key expiry.
2. Download `artifacts/receipt-preparation.json`. Confirm the receipt fields, evidence
   SHA-256, Product Revision, workflow identity, validity window, and
   `signature_payload_sha256` in the change record.
3. Base64-decode `signature_payload_base64` and ask the non-exportable Ed25519 KMS/HSM
   key to sign those exact raw DSSE PAE bytes. Store the KMS request ID, key version,
   signer principal, response digest, and approval reference outside the repository.
4. Dispatch the same workflow against the same Evidence Revision with
   `action=finalize`; keep every other request field byte-for-byte identical and replace
   only `signature_base64` with the public signature. The workflow regenerates the
   payload from the protected checkout, rejects drift, verifies the signature against
   the registered public key, and uploads `artifacts/evidence-receipt/receipt.json`.
5. Add only the verified receipt JSON under
   `saas/production/evidence-admission-receipts/` in an evidence-only PR. Merging the
   receipt changes the Evidence Revision but not the signed Product Revision or
   evidence bytes. Run final production admission at that new protected `main` SHA.

The protected workflow request has this exact schema:

```json
{
  "action": "prepare",
  "evidence_kind": "baseline",
  "evidence_path": "saas/production/baseline.json",
  "signer_key_id": "production-admission-2026-01",
  "receipt_id": "baseline-2026-08-09-001",
  "issued_at": "2026-08-09T12:00:00Z",
  "expires_at": "2026-08-10T12:00:00Z",
  "signature_base64": null
}
```

Omit `receipt_request_json` entirely to run final ten-gate admission. The command-line
equivalents for a local issuance rehearsal are:

```bash
uv run python -m saas.scripts.prepare_evidence_receipt \
  --evidence-kind baseline \
  --evidence-path saas/production/baseline.json \
  --product-revision "$PRODUCT_REVISION" \
  --signer-key-id production-admission-2026-01 \
  --receipt-id baseline-2026-08-09-001 \
  --issued-at 2026-08-09T12:00:00Z \
  --expires-at 2026-08-10T12:00:00Z \
  --workflow-identity \
    Dream1216/omnigent/.github/workflows/saas-production-admission.yml@refs/heads/main \
  --output artifacts/receipt-preparation.json

printf '%s' "$PUBLIC_SIGNATURE_BASE64" | \
  uv run python -m saas.scripts.finalize_evidence_receipt \
    --preparation artifacts/receipt-preparation.json \
    --signature-stdin \
    --output artifacts/receipt.json
```

Every protected prepare or finalize attempt writes
`artifacts/evidence-receipt/receipt-issuance-report.json`, including failed-closed
attempts. The diagnostic binds the exact request bytes by SHA-256, records only public
request metadata and violations, and records whether a signature was present without
copying that signature into the report. The issuer still exits nonzero on failure, and
the workflow's `always()` artifact step must archive the report; an absent diagnostic
artifact is itself an acceptance failure.

Local command success is only a rehearsal: production-authoritative receipts must be
issued through the protected workflow, backed by the KMS/HSM audit record, reviewed as
an evidence-only change, and consumed by final admission. Workflow artifacts are not
committed automatically and cannot mutate the acceptance ledger.

## Final admission

Run the final command only from `.github/workflows/saas-production-admission.yml` on
the protected default `main` ref. GitHub Environment
`production-evidence` supplies the reviewer boundary. The workflow accepts only full
Git SHAs, requires the evidence input to equal the protected dispatch ref's exact SHA,
checks out that SHA without persisted credentials, and retains full Git history. It
runs all eight domain verifiers, cryptographic admission, candidate-lineage checks,
and the ten-gate verifier. Compatibility CI tests the implementation but cannot claim
production admission.

GitHub accepts `workflow_dispatch` only when the workflow file exists on the default
branch. Merging this contract to a staging or integration branch does not activate a
production entry point. Promote the complete SaaS candidate, including this workflow,
to protected `main` first; do not change the repository default branch or dispatch from
the staging branch to bypass that boundary. The image-candidate workflow watches this
file so a trust-root change always receives a new Product Revision and image candidate.

The protected job executes the equivalent of:

```bash
PRODUCT_REVISION="$(git rev-parse <candidate-ref>)"
uv run python -m saas.scripts.check_evidence_admission \
  --product-revision "$PRODUCT_REVISION" \
  --require-ready
uv run python -m saas.scripts.check_production_readiness \
  --product-revision "$PRODUCT_REVISION" \
  --require-ready
```

The workflow uses `saas.scripts.run_production_admission` to execute both checks,
archive their exact bytes, bind their SHA-256 values into one final bundle, and fail
unless all 8 evidence kinds, all 10 aggregate gates, the ledger, phases, and release
decision are simultaneously ready. A failed run still uploads diagnostics and never
changes the acceptance ledger.

Archive the workflow run URL, artifact ID and digest, evidence revision, product
revision, image digests, and aggregate report digest. A green compatibility workflow,
candidate image build, unsigned JSON file, local rehearsal, or manually edited ledger
is not production admission.


## Release-specific single-owner review exception

The normal independent role requirements remain the default. For release
`omnigent-saas-v0.19.0.dev20261020-3db749d7` only, the explicit owner directive
authorizes `Dream1216` (GitHub user ID `39821512`) to perform the human reviews.
This is a **degraded, sole-owner-risk-waiver**: separation of duties is absent.
`review-exception-policy.json` records the accepted governance risk, exact upstream
`3db749d784ff044304473939acaae3a65c0fec61`, adapter `0.2.0`, schema
`p0s000000017`, and expiry before `2026-12-20T00:00:00Z`. It waives no technical
gate, customer acceptance, signature, recovery, negative test, or metric. In
particular, the exact candidate still needs the full 30-day production SLO window;
a 3600-second canary does not satisfy final full production admission.

Complete the following after the source and trust root are frozen on protected main:

1. Dispatch this workflow with the exact Product/Evidence Revisions, empty
   `receipt_request_json`, and `review_exception_request_json` containing exactly
   `attestor_commitment` (the one real owner's SHA-256 commitment) and `expires_at`
   (UTC, within the policy interval). `Dream1216` must actually approve the
   `production-evidence` Environment in GitHub. The agent cannot approve for them.
2. The workflow writes a standalone canonical
   `review-exception-authorization.json` artifact. This is an authorization request
   bound to the Product/Evidence inputs, real actor commitment, expiry, workflow
   identity, and approved directive. It does not require a domain receipt or an
   exception record, avoiding a circular dependency. Require success on **run
   attempt 1**. A rerun is rejected; use a fresh dispatch and fresh human approval.
3. Run `uv run python -m saas.scripts.prepare_review_exception` with
   `--product-revision`, `--evidence-revision`, `--workflow-run`,
   `--attestor-commitment`, and `--expires-at`. The verifier fetches live repository,
   run, Environment approval and native artifact facts. It checks the archive's
   native digest, size, contents and exact manifest bindings. Repository/actions
   read permissions are sufficient; it has no write or approval authority.
4. Review and commit the generated canonical JSON under
   `saas/production/review-exception-evidence/`. Only that exact governed JSON
   format is allowed in the later evidence-only lineage; policies, arbitrary files,
   symlinks, amendments and changed source remain forbidden.
5. Use one actual domain attestation with role `sole-owner-risk-waiver`, its one
   real actor commitment, normal time/product/subject fields, and
   `review_exception: {"path": "<generated path>", "sha256": "<exact byte hash>"}`.
   Deletion retains its existing `actor_id_hmac` and subject binding. Other domains
   retain `actor_id_hash`. Do not fabricate separate people or duplicate roles.
6. Complete the original domain measurements and two-phase KMS/HSM receipts. Each
   signed domain byte hash binds the included exception reference. Every consuming
   check revalidates the live native authorization; facts are cached only inside
   that check and fail closed on API failure, expiry or retention loss.

The exception cannot authorize another product, upstream, schema, actor commitment,
expiry, workflow run or policy. Final admission still requires all eight signed
evidence domains, all ten aggregate gates, the ledger and all phase decisions.
