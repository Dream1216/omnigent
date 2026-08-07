# Platform Security Foundation operations

This runbook operates the PC1 Staff Realm, PC2 content-blind lifecycle authority, and
PC3 governed JIT Support/Admin Operation/audit-evidence boundary. It never grants
ambient customer-content access or makes the emergency database role an application
role. Destructive User/Tenant deletion and production release remain separate gates.

## Trust boundary and deployment

1. Deploy the Platform HTTP application on a dedicated HTTPS Origin. Configure a
   dedicated Audience, the `__Host-omnigent_platform_session` cookie, a separate CSRF
   secret and a Staff-only enterprise IdP. Never mount this application under the
   Tenant Origin or copy Tenant cookies into its ingress.
2. Require Passkey/WebAuthn or an equivalent phishing-resistant IdP assertion. Password
   authentication, bearer tokens, a Tenant session, mixed Staff/Tenant cookies, an
   incorrect Origin, and an incorrect Audience fail closed.
3. Migrate through `pc3a00000001`, then apply
   `saas/control_plane/postgresql_roles.sql` as the schema owner. Verify 81 control-plane
   tables and 17 Runtime tables retain both enabled and forced RLS.
4. Give each process login exactly one NOLOGIN role:

   - Staff assertion and session service: `saas_platform_authenticator`;
   - Platform browser API: `saas_platform_app`;
   - approved Staff and Assignment administration: `saas_platform_governance`;
   - content-blind projection writer: `saas_platform_projector`;
   - exact opaque JIT-session validation: `saas_platform_support`.

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

## PC2 lifecycle commands

- High-risk User suspend/restore and Tenant suspend/restore require a current
  `platform_operator` assignment, fresh phishing-resistant Staff authentication,
  approval reference, reason, expected version and idempotency key. The governance
  transaction rechecks current authority rather than trusting browser session claims.
- User suspension increments `security_version`, revokes all human Sessions, fails
  pending OIDC login transactions, suspends stewarded Service Accounts and revokes
  their active API Credentials. Restore never resurrects old Sessions or Credentials.
- Tenant suspension increments active members' security versions, revokes their
  Sessions, suspends Tenant Service Accounts and revokes active API Credentials.
  Restore only reopens the Tenant status; it does not reactivate revoked credentials.
- Owner Recovery is not ordinary ownership transfer. Preview must prove the existing
  Owner is inactive and the target is an active member; execution binds the preview
  hash plus Tenant/source/target versions and atomically demotes/promotes one Owner.
- Every accepted mutation appends a `saas_platform_lifecycle_operations` receipt and a
  secret-free Outbox event in the same transaction. Never treat an HTTP response alone
  as lifecycle evidence.

## PC2 Identity Conflict Case review

- The Staff queue exposes only case ID, Provider class, optional candidate User ID,
  lifecycle/review states, versions and timestamps. Raw email, Issuer, Subject, login
  assertion, Prompt, message and customer content remain unavailable to Staff roles.
- Only a current `platform_operator` with fresh authentication may assign one active
  Global User candidate or block a pending case. Every decision requires an external
  approval reference, reason, expected case version and idempotency key; PostgreSQL
  binds UPDATE to the one requested case.
- Assignment is not account linking. The candidate must reauthenticate in the customer
  Realm and use the existing Identity Conflict self-service challenge to approve or
  reject. Staff code must never insert `saas_identity_connections` for this workflow.
- A blocked case rejects later login resolution. Preserve the lifecycle receipt and
  Outbox event as security evidence. Downgrade from `pc2b00000001` is deliberately
  refused while any reviewed case or Identity Conflict operation exists; use an
  explicitly approved forward archival migration rather than deleting audit facts.

## PC3 governed Support and audit evidence

- Standard Support access is Tenant-bound, expires within one hour, and requires an
  active Tenant Owner/Admin/Security Auditor decision followed by a different Staff
  approver. The requester cannot self-approve. Customer identity status and
  `security_version` are rechecked in the same transaction.
- Break-glass access requires an incident reference, expires within 15 minutes, skips
  only customer pre-approval, and still requires a distinct Staff approver. It never
  inherits `saas_platform`, bypasses RLS, or broadens its requested scopes.
- Content scope is bound to exact Project IDs. A one-time disclosed Support token
  resolves only its active Grant, Tenant, Staff principal, scope and Project set. Store
  only its digest; revoke or expiry invalidates access immediately.
- Tenant administrators can list metadata, approve/reject, and immediately revoke an
  exact Grant from the Tenant Cookie/Origin/CSRF Realm. Customer revocation terminates
  all active Grant sessions in the same transaction and emits a redacted Outbox fact.
- Admin Operations, Grant transitions and export approvals are versioned and
  idempotent. The audit chain has a permanent locked head, monotonic sequence, payload
  hash, previous hash and event hash. Audit Event and Export rows reject update/delete.
- Audit exports require an authorized auditor request plus a different Staff approver.
  Production must inject an `AuditSigner` backed by an independently permissioned
  KMS/HSM HMAC key. `AuditSigningKey` is only for local tests; a plaintext production
  key is a release blocker.
- Run application traffic through `saas_platform_governance` only for governed
  mutations and through `saas_platform_support` only for exact token validation. Never
  grant either role membership in the emergency `saas_platform` role.

## Verification

Run the unit, HTTP, real Chromium and real PostgreSQL matrices:

```bash
uv run pytest -q \
  tests/saas/test_platform_security.py \
  tests/saas/test_platform_http.py \
  tests/saas/test_platform_security_browser.py \
  tests/saas/test_platform_lifecycle.py \
  tests/saas/test_platform_lifecycle_http.py \
  tests/saas/test_platform_governed_access.py \
  tests/saas/test_http_cookie_auth.py

export OMNIGENT_SAAS_TEST_POSTGRES_URL=\
postgresql+psycopg://postgres:postgres@127.0.0.1:5432/postgres
uv run pytest -q \
  tests/saas/test_platform_security_postgresql.py \
  tests/saas/test_platform_lifecycle_postgresql.py \
  tests/saas/test_platform_governed_access_postgresql.py
```

The PostgreSQL check must prove exact Staff identity and session lookup, role-less
denial, active-role access, transaction-local context cleanup, Tenant-role denial,
customer-content denial and inability to `SET ROLE saas_platform`. The Chromium check
must use HTTPS and prove Staff success plus mixed-cookie, wrong-Origin, bearer and
role-less denial.

Then run migration drift, isolated logical restore, wheel-content, Pyrefly and the full
compatibility matrix. The restore must retain non-empty Staff, Assignment, Session and
both projection tables, lifecycle receipts, exact `pc3a00000001`, and the 81/17
forced-RLS inventories.

## Revocation, incident response and rollback

- For a suspected Staff session compromise, suspend the Staff principal or increment
  its security version, revoke its sessions, revoke or expire affected assignments and
  inspect IdP plus Platform request identifiers. Do not grant customer Membership to
  work around the outage.
- For an Origin, Audience, cookie or RLS composition error, disable the Platform feature
  flag and remove its ingress before changing data. Tenant administration remains on its
  independent Realm.
- For suspected Support-token exposure, revoke the exact Grant first, confirm every
  linked Session has `revoked_at`, disable the Support data-plane login if containment
  is uncertain, and verify the audit chain before resuming. Do not widen a Grant during
  an incident; request a new versioned Grant instead.
- A code rollback may leave the PC1 tables and forced policies in place. Do not downgrade
  the schema while a Platform process or session is active. Before a destructive
  downgrade, disable ingress, revoke all Staff sessions, stop authenticator/app/
  governance/projector processes, preserve approved Assignment evidence, take an
  immutable backup and rehearse restoration.
- Downgrade from `pc3a00000001` is refused while any Grant, Session, Admin Operation,
  Audit Event or Export fact exists. Archive and verify evidence through an approved
  forward migration; never delete PC3 facts to make an older binary start.
- Emergency recovery uses the separate incident and break-glass process. Never add
  `saas_platform` inheritance to make an application outage disappear.

## Acceptance boundary

Passing this runbook establishes the code contracts for the PC1 security foundation,
PC2 lifecycle, and PC3 governed-access slice: independent Staff Realm, governed
Assignments, content-blind projections, least-privilege target-bound database roles,
User/Tenant suspend/restore, Session revocation and Owner Recovery. It does not
establish User/Tenant deletion, a complete Platform Console UI, production KMS signing,
deployed Staff IdP/Origins, multi-AZ/PITR evidence, or release GO.
