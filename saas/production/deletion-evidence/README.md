# Production tenant-deletion evidence

This directory intentionally contains no qualifying evidence yet. Only immutable,
exact-revision `production_tenant_deletion` manifests produced by the approved
workflow belong here. CI fixtures, local databases, screenshots, deletion-job success,
or database row counts alone are not production deletion proof.

Each record must cover every policy surface, prove revocation and cross-tenant
invariance, bind retention deadlines and backup tombstones, authenticate its canonical
content, and carry independent privacy, security, and data-owner attestations. Raw
Tenant IDs, emails, repository paths, object keys, secrets, or customer content must
not be stored in this directory.
