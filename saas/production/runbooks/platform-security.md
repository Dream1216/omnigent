# Platform Security Foundation operations

This runbook operates the PC1 Staff Realm and content-blind Platform Control Plane.
It does not authorize customer-content access, support impersonation, break-glass,
Tenant lifecycle mutations, or production release. Those remain separate governed
capabilities and acceptance gates.

## Trust boundary and deployment

1. Deploy the Platform HTTP application on a dedicated HTTPS Origin. Configure a
   dedicated Audience, the `__Host-omnigent_platform_session` cookie, a separate CSRF
   secret and a Staff-only enterprise IdP. Never mount this application under the
   Tenant Origin or copy Tenant cookies into its ingress.
2. Require Passkey/WebAuthn or an equivalent phishing-resistant IdP assertion. Password
   authentication, bearer tokens, a Tenant session, mixed Staff/Tenant cookies, an
   incorrect Origin, and an incorrect Audience fail closed.
3. Migrate through `pc1a00000001`, then apply
   `saas/control_plane/postgresql_roles.sql` as the schema owner. Verify 73 control-plane
   tables and 17 Runtime tables retain both enabled and forced RLS.
4. Give each process login exactly one NOLOGIN role:

   - Staff assertion and session service: `saas_platform_authenticator`;
   - Platform browser API: `saas_platform_app`;
   - approved Staff and Assignment administration: `saas_platform_governance`;
   - content-blind projection writer: `saas_platform_projector`.

   None may inherit `saas_platform`, `saas_app`, `saas_governance`, or another platform
   process role. The emergency `saas_platform` credential is not application
   configuration and must remain in the separate recovery Realm.
5. Enable `PlatformHttpConfig.enabled` only after the Origin, Audience, cookie, IdP,
   database-role and negative-matrix checks below pass for the exact release revision.

## Staff bootstrap and role governance

- Synchronize the verified Staff Issuer and Subject into
  `saas_platform_staff_principals`. Provisioning creates an active but role-less
  principal and is idempotent only for the same identity connection reference.
- Bootstrap the first assignments through an externally approved, audited database
  procedure using `saas_platform_governance`. Preserve the approval reference, reason,
  assigning principal and expiry. Never turn a Tenant Owner or database login into a
  product Platform role.
- Thereafter use `PlatformAuthorizationService`: fresh authentication, an external
  approval reference, two-person separation, active-target validation and optimistic
  assignment versions are mandatory. Self-grant and self-revoke are denied.
- Session validation reloads current Staff security version and current active
  assignments. Suspension, security-version change, assignment revocation and expiry
  therefore take effect without waiting for the browser session to expire.
- The five built-in roles are `platform_operator`, `platform_security_auditor`,
  `support_agent`, `billing_operator` and `compliance_operator`. The machine-readable
  catalog is authoritative; wildcard and `allow_all` permissions are prohibited.

## Projection safety

- The projector accepts explicit Tenant/User metadata inputs only. It stores no code,
  Prompt, message, Artifact, Secret, request body or unmasked customer email.
- Projection updates are monotonic by `source_version`. Lists use UUID cursors, stable
  ordering, bounded page sizes and per-field permission filtering.
- The browser role can read projections only while its exact Staff principal has an
  active assignment. Tenant GUCs do not grant platform visibility. Customer and service
  roles have no table privilege on platform facts.
- Add a new projection field only with a migration, a catalog field permission, a safe
  projector input, output filtering, PostgreSQL denial coverage and recovery hashing.

## Verification

Run the unit, HTTP, real Chromium and real PostgreSQL matrices:

```bash
uv run pytest -q \
  tests/saas/test_platform_security.py \
  tests/saas/test_platform_http.py \
  tests/saas/test_platform_security_browser.py

export OMNIGENT_SAAS_TEST_POSTGRES_URL=\
postgresql+psycopg://postgres:postgres@127.0.0.1:5432/postgres
uv run pytest -q tests/saas/test_platform_security_postgresql.py
```

The PostgreSQL check must prove exact Staff identity and session lookup, role-less
denial, active-role access, transaction-local context cleanup, Tenant-role denial,
customer-content denial and inability to `SET ROLE saas_platform`. The Chromium check
must use HTTPS and prove Staff success plus mixed-cookie, wrong-Origin, bearer and
role-less denial.

Then run migration drift, isolated logical restore, wheel-content, Pyrefly and the full
compatibility matrix. The restore must retain non-empty Staff, Assignment, Session and
both projection tables, exact `pc1a00000001`, and the 73/17 forced-RLS inventories.

## Revocation, incident response and rollback

- For a suspected Staff session compromise, suspend the Staff principal or increment
  its security version, revoke its sessions, revoke or expire affected assignments and
  inspect IdP plus Platform request identifiers. Do not grant customer Membership to
  work around the outage.
- For an Origin, Audience, cookie or RLS composition error, disable the Platform feature
  flag and remove its ingress before changing data. Tenant administration remains on its
  independent Realm.
- A code rollback may leave the PC1 tables and forced policies in place. Do not downgrade
  the schema while a Platform process or session is active. Before a destructive
  downgrade, disable ingress, revoke all Staff sessions, stop authenticator/app/
  governance/projector processes, preserve approved Assignment evidence, take an
  immutable backup and rehearse restoration.
- Emergency recovery uses the separate incident and break-glass process. Never add
  `saas_platform` inheritance to make an application outage disappear.

## Acceptance boundary

Passing this runbook establishes the PC1 security foundation: independent Staff Realm,
versioned permissions and built-in roles, governed Assignments, content-blind
projections, least-privilege database roles and negative tests. It does not establish a
complete Platform Console, JIT Support, immutable audit, Global User/Tenant mutations,
enterprise identity, production evidence, or release GO.
