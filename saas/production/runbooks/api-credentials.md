# Service Account and API Key operations

This runbook covers the downstream `/api/v1` machine-identity contract. It does not
turn official Omnigent auth or database models into public API and does not authorize
Service Accounts on upstream Runtime routes.

## Production prerequisites

1. Inject an independent API-credential HMAC pepper of at least 32 random bytes from
   KMS/HSM-backed secret delivery when constructing `ApiCredentialService`. Never log,
   persist, bake into an image, or reuse the browser Cookie/signing secret as this
   pepper.
2. Run migrations through `p6a000000007`, then reapply
   `saas/control_plane/postgresql_roles.sql`. Confirm all 57 control-plane and all 17
   Runtime tables retain `ENABLE ROW LEVEL SECURITY` plus `FORCE ROW LEVEL SECURITY`.
3. Use separate database logins inheriting exactly `saas_governance` for management
   and `saas_authenticator` for token validation. Both must remain `NOSUPERUSER
   NOBYPASSRLS`.
4. Register both router tuples from `SaasHttpIntegration.extra_routers`: internal
   compatibility routes at `/saas` and the explicit public contract at `/api/v1`.

## Lifecycle rules

- A Service Account is non-interactive, project-bound, and has an explicitly selected
  active Steward. `created_by` is audit metadata and grants no authority.
- A manager must hold `grant.manage` and every permission assigned to a Key. This
  prevents a content-blind Tenant or Space administrator from minting content access.
- A Key is shown once. PostgreSQL stores only its HMAC-SHA256 digest, display prefix,
  exact permission set, network CIDRs, expiry, and account security version.
- CIDRs are canonical and evaluated against the transport peer IP. Do not pass an
  untrusted `X-Forwarded-For` value as `source_ip`; terminate trusted proxy identity
  before calling the authenticator if a proxy deployment needs original-client policy.
- Rotation revokes the old Key and creates the replacement in one transaction.
  Idempotent replay returns metadata with `token: null` and can never reveal the Key.
- Revocation is checked against PostgreSQL on every request. Last-used metadata is
  coalesced to one write per five minutes and is not an authorization cache.
- Steward transfer and Service Account suspension increment `security_version` and
  revoke all active Keys atomically. Their Outbox payloads never contain token or hash
  material.
- Cookie and Bearer credentials must not appear together. The middleware rejects the
  request as `ambiguous_authentication`; machine Bearer credentials are accepted only
  under `/api/v1` and are rejected on `/saas`, interactive login, and Runtime routes.

## Member removal

Wire `ServiceAccountRemovalImpactProvider` into the deployment's
`CompositeRemovalImpactProvider` as a required domain. A removal preflight lists each
active or suspended Service Account explicitly stewarded by the member and its
secret-free Key metadata. Any such account blocks removal. Transfer stewardship first,
issue replacement Keys if needed, confirm old Keys fail immediately, then rerun the
preflight so its hash reflects the new authoritative state.

## Incident response

For one compromised Key, revoke it and verify the corresponding
`api_credential.revoked` Outbox event is dispatched. For suspected account-wide or
pepper compromise, suspend every affected Service Account, rotate the pepper through a
dual-control incident procedure, and issue new Keys only after all old digests fail.
Do not treat `last_used_at` as proof that a Key was unused: updates are deliberately
coalesced and may be absent after a failed request.

## Acceptance evidence

Release evidence must include negative tests for malformed tokens, wrong secret, expiry,
network mismatch, cross-Tenant/Space/Project selectors, privilege escalation, interactive
login, Cookie/Bearer ambiguity, immediate revoke/rotate/Steward-transfer invalidation,
idempotent one-time disclosure, Outbox secret absence, member-removal blocking, exact
PostgreSQL credential-ID RLS, connection reuse, migration downgrade, backup/restore, and
tenant deletion. Passing CI is a code-contract subgate only; it does not supply
production Key rotation, KMS, deletion, DR, multi-AZ, SLO, or commercial evidence.
