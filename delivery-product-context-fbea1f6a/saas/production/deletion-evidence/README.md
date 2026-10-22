# Production tenant-deletion evidence

This directory intentionally contains no qualifying evidence yet. Only immutable,
exact-revision `production_tenant_deletion` manifests produced by the approved
workflow belong here. CI fixtures, local databases, screenshots, deletion-job success,
or database row counts alone are not production deletion proof.

Each record must cover every policy surface, prove revocation and cross-tenant
invariance, bind retention deadlines and backup tombstones, authenticate its canonical
content, and carry independent privacy, security, and `data_owner` attestations.
Every surface and the aggregate record must bind its payload to an Ed25519 DSSE
envelope, immutable-store receipt, KMS verification receipt, an allowlisted signing-key
identity and purpose, trusted workflow identity, and verification timestamp. URI-only artifacts or
control-plane completion states are not qualifying proof. Attestors must have distinct
HMAC-pseudonymized actor IDs and bind the same record subject and product revision.
Raw Tenant IDs, emails, repository paths, object keys, secrets, or customer content
must not be stored in this directory.
