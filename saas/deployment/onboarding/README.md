# Production self-service onboarding composition

This directory is a fail-closed deployment contract, not a ready-to-apply
release. Render every `replace.*`, all-zero image digest, PostgreSQL CIDR and
Runtime Provider binding before a server-side dry-run.

## Process authority split

- Server: `saas_registration` and `saas_onboarding_status` only. It calls
  `build_production_onboarding_http_services()` and passes all three values in
  `integration_kwargs` to `create_saas_http_integration()`.
- Outbox Worker: restricted `saas_dispatcher` for claims, plus distinct
  `saas_registration`, `saas_onboarding` and existing `saas_executor` logins
  inside the configured publisher. The dispatcher login is never reused for a
  domain write.
- Migration Job: owner authorities only. It creates/grants the roles and emits
  a new receipt whose `service_role_bindings_sha256` covers the expanded
  canonical manifest.

The shared service-role manifest must add these exact entries to the existing
production profile:

```json
{"base_role":"saas_onboarding","login":"replace_onboarding_login","service":"onboarding"}
{"base_role":"saas_onboarding_status","login":"replace_onboarding_status_login","service":"onboarding_status"}
{"base_role":"saas_registration","login":"replace_registration_login","service":"registration"}
```

Keep the existing `executor -> saas_executor` entry. All login names must be
unique. The downstream production profile must therefore contain exactly 13
services: its 10 current services plus these three. Server, migration, and
onboarding now consume that same exact canonical authority; a reduced or
superset manifest is a deployment hard failure and must not be used to mint a
migration receipt. The policy file and full manifest must be canonical compact
JSON with one trailing newline; the init containers stage them as uid-owned
mode `0400` files before either process starts.

`service-role-bindings.example.json` is the exact 13-service canonical shape.
Only its `replace_*_login` values may be rendered; service and base-role names
are part of the migration/admission contract.

## Secret boundary

`omnigent-saas-onboarding-keys` contains `envelope.json` and `rate-limit.json`.
The same immutable key-ring revisions are mounted by Server and Worker during a
rotation overlap. Only the Worker mounts the Runtime Provider Secret. The
delivery mode is explicit:

- `OMNIGENT_SAAS_EMAIL_DELIVERY_MODE=resend` preserves the original contract.
  Only this mode mounts `omnigent-saas-email-provider`; the provider token is
  never an environment value.
- `OMNIGENT_SAAS_EMAIL_DELIVERY_MODE=platform_smtp` reads the enabled SMTP
  version from `saas_email_provider_configurations` for every Outbox delivery.
  Do not mount the Resend Secret or set `OMNIGENT_SAAS_EMAIL_FROM` in this mode.
  Configure exactly one existing non-exporting credential backend with
  `OMNIGENT_CREDENTIAL_CIPHER=kms|vault` and its key identifier. The SMTP
  password is decrypted only at the delivery boundary and is never returned by
  the Platform API.

Before switching to `platform_smtp`, migrate to `p0s000000012`, inject
`EmailProviderConfigurationService` into `create_platform_admin_app`, save and
test an enabled configuration in `/saas/admin`, and drain the old Resend
generation. A disabled or unreadable SMTP configuration fails closed onto the
bounded Outbox retry path; it never falls back to Resend.

Each PostgreSQL DSN is a complete `postgresql+psycopg` URL containing
`sslmode=verify-full&sslrootcert=/runtime/postgresql-ca.crt`; its username must
match the canonical service-role manifest. Owner, migration and `SET ROLE`
credentials are rejected at startup.

## Server integration dependency

`kubernetes.server-onboarding.patch.yaml` assumes the downstream production
Server Deployment and its `/runtime` memory volume already exist. The server
composition still must perform this explicit code-level injection:

```python
onboarding_http = build_production_onboarding_http_services()
integration = create_saas_http_integration(
    # existing required dependencies,
    **onboarding_http.integration_kwargs,
)
```

The built server must call `onboarding_http.close()` on shutdown. This repository
slice does not copy or modify the uncommitted downstream production Server WIP.

## Network and rollout boundary

The Worker has no ingress. Its base egress is limited to DNS and the rendered
PostgreSQL CIDR. Provider egress is intentionally absent: Resend mode adds only
the CNI-native `api.resend.com:443` FQDN rule; Platform SMTP adds only the
pre-approved relay hostname/IP and the configured TLS port. The UI cannot widen
NetworkPolicy, so changing the SMTP host or port requires a separately reviewed
egress change. Arbitrary public `443`, `465` or `587` egress is forbidden because
this Pod holds database, envelope, rate-limit, email and Runtime Provider
authorities. The Server retains its existing ingress policy and needs no email
provider egress.

Roll forward in this order: expand canonical role manifest, run migration and
approve its new receipt, create immutable Secrets, deploy one Worker canary,
deploy one Server canary, then run a real registration-email-verification-login
journey. Rollback stops new registrations, restores the prior Server/Worker
images and drains or quarantines events according to their immutable event IDs.
Do not roll back the additive tables/roles during an application rollback; old
images must ignore them. Key or email-contract rotations require the old Outbox
generation to drain before removing the previous key/provider contract.
