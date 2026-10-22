# Production evidence admission receipts

Production evidence is not authoritative merely because its JSON fields name a DSSE
URI or a trusted workflow. Each evidence document must have a detached Ed25519 receipt
in this directory. The receipt signs DSSE PAE bytes over the canonical receipt payload
and binds the exact repository-relative path, byte SHA-256, product revision, workflow
identity, validity window, and trusted key ID.

Public keys are registered in `saas/production/evidence-admission-keys.json`. Private
keys must remain in the production KMS/HSM-backed workflow and must never enter the
repository, CI artifacts, logs, or evidence bundle. An empty key registry is a safe
bootstrap state: all production gates remain blocked.

The product revision is the immutable code candidate. Receipts may be committed in a
later evidence-only descendant; the aggregate verifier requires that ancestry, rejects
non-evidence changes after the candidate, and requires a clean checkout. The trusted
public-key registry must already be part of the candidate and cannot be introduced or
changed by the later evidence commit. See
`saas/production/runbooks/production-admission.md` for the issuance and final workflow.

Changing evidence bytes, reusing a receipt for another evidence kind or path, using an
expired/revoked key, changing the workflow identity, or forging the signature fails
closed. Domain-specific evidence validation remains mandatory in addition to this
admission layer.
