# Casdoor identity release evidence

This directory holds the **current release's** identity acceptance wrappers.
It is intentionally empty of production JSON until the observations and
independent approvals exist. Local component proofs, synthetic test fixtures,
stage renders and Kubernetes dry-runs do not qualify production acceptance.

The `identity` evidence admission kind uses the existing Ed25519/DSSE production
workflow and reviewed key registry. The signature covers the exact wrapper
bytes, including the acceptance record and observation reference. Aggregate
readiness requires both `identity` domain readiness and `identity_admission`
for the production foundation and enterprise identity gates. A manually passed
ledger entry, a self-computed digest or an unsigned record cannot override either.
The final admission bundle now requires nine signed evidence kinds; the ten
aggregate gate IDs remain unchanged.

## Wrapper and observations

Each canonical JSON wrapper has exactly three fields:

```json
{
  "schema_version": 1,
  "acceptance": {},
  "observations": {
    "path": "saas/production/identity-evidence/observations/RECORD.json",
    "sha256": "SHA256_OF_EXACT_OBSERVATION_BYTES"
  }
}
```

`acceptance` uses the existing business-acceptance schema with
`evidence_kind=production_casdoor_identity_acceptance`. The fixed
`identity-policy.json` lists required integrations, checks, failure scenarios,
zero/positive metrics and independent identity-owner/security/SRE/customer-admin
approvals. Its `artifact.sha256` must equal the observation digest. Retain the
immutable observation artifact and its approved provenance envelope, and use
the corresponding approved URI/workflow in that acceptance record. The record's
`record_sha256` is the existing canonical business-record digest; it is separate
from, and does not replace, the production admission signature.

The observation document has exactly these fields:

- `schema_version`, `environment=production`, `product_revision` and `image_digest`.
- `provider_source_lock_sha256`, equal to the packaged provider source lock.
- `pins`, containing nonzero SHA-256 values for `image_evidence_sha256`,
  `identity_manifest_sha256`, `public_config_sha256`, `migration_receipt_sha256`,
  `service_role_graph_sha256` and `provider_configuration_sha256`.
- `provenance`, containing exact booleans: `live_provider=true`,
  `installed_metadata_override=false`, `private_ingress_direct_tls=true`,
  `provider_ca_and_hostname_verified=true`, and `signed_oidc_sessions=true`.
- `load`, containing positive integers `admitted_identity_population`,
  `baseline_verified_identity_count`, `worker_replica_count` and `load_seconds`.
- `enabled_channels`, exactly matching the reviewed release policy.
- `samples`, containing the measured convergence cases below.

The image evidence pin must match the actual bytes of
`saas/acceptance/p0-production-image-evidence.json`, and its product revision and
server manifest digest must match the identity processes. That image evidence
must independently pass the existing image and signed-admission gates. The
other pins identify the captured deployment/configuration/authority inputs;
their effective live contents still require the policy's deployment and
startup checks and approved collector artifact. A hash alone does not prove
the source data is correct.

The admitted population must have a complete initial baseline, at least two
independent worker replicas and at least 900 seconds of measured load. Load
duration cannot exceed the acceptance measurement window. Resource/HA claims
must include actual rollout and failure-domain observations, not merely replica
counts from a template.

## Convergence samples

Cover `password_reset`, `provider_disable`, `provider_delete`,
`verified_contact_change`, `missed_password_reset`, `missed_provider_disable`,
`missed_provider_delete` and `worker_restart`. Each case requires at least two
distinct hashed subjects and independent real signed-OIDC local sessions.
Keep raw tokens, passwords, provider responses and user contact fields out of
these files. Each sample contains exactly:

- `case`, `subject_sha256`, `global_user_before_sha256`,
  `global_user_after_sha256`, `session_sha256` and `oidc_verification_sha256`.
- `provider_event_sha256`, `triggered_at`, `inbox_committed_at`,
  `readback_completed_at`, `session_denied_at` and `transport`.
- `security_version_before`, `security_version_after`,
  `session_valid_before`, `session_valid_after`, `credential_owner_before`,
  `credential_owner_after` and `tenant_grant_delta`.

Times are UTC ISO timestamps ending in `Z` and must lie within the acceptance
window. The measured interval begins at the actual provider mutation and ends
when the previously valid local session is denied. It must be positive and at
most 300,000 milliseconds. Direct cases require
`transport=direct_authenticated_https`, the stable provider event digest and
an ordered durable Inbox commit before readback. Missed-event cases require
`transport=periodic_without_notification`, null event/Inbox fields, and an
actual omitted notification; captured-request replay is not direct delivery.

Global User must remain identical, credential authority must stay `casdoor`,
the previously valid signed-OIDC session must become invalid, security_version
must increase, and tenant grants must not change. Subject hashes must appear in
the acceptance inventory. Bind each sample's OIDC verification and event digest
to the collector's retained, secret-free proof; the validator checks shape and
consistency, while the trusted production workflow admits the observed facts.

Acceptance metrics must exactly reflect `load`, `convergence_sample_count`, and
`maximum_<case>_milliseconds` derived from the actual samples. A summary below
five minutes cannot hide a slower observation. Other policy metrics must also
pass, including zero old-password bypass, wrong binding, privilege escalation,
restored revoked-session acceptance, old callback acceptance and resurrection.

Only email/password is initially enabled in the reviewed identity policy.
Additional social or enterprise channels require an explicit policy change,
a `channel_<name>` integration with real callback/binding/tenant-authority
evidence, matching observed provider configuration and a new release candidate.
Absent channel credentials keep that channel disabled; they do not waive the
email path or automatically enable an unqualified identity source. Existing
enterprise/SCIM production gates remain independently required.

## Reproduce admission

From the repository root:

```sh
python -m saas.scripts.check_identity_readiness \
  --product-revision FULL_PRODUCT_GIT_SHA --require-ready
python -m saas.scripts.check_production_readiness \
  --product-revision FULL_PRODUCT_GIT_SHA --require-ready
```

Without current accepted observations these commands must fail readiness.
Inspect the report blockers and the foundation/identity gate requirements;
never create a passing JSON record to clear them. After independent approval,
use the existing protected production-admission receipt workflow for kind
`identity`, then rerun final admission on the committed evidence-only revision.
Policies, key registries, code and channel-enablement changes are not allowed
in an evidence-only delta.
