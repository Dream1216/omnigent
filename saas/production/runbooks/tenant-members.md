# Tenant Members administration

This runbook covers the Tenant-scoped member directory in the shared SaaS control
plane. It does not convert official server-wide account settings into Tenant
administration, expose credential secrets, or claim production SSO/SCIM readiness.

## Production composition

1. Migrate through `p6a000000007`, then reapply
   `saas/control_plane/postgresql_roles.psql`. Confirm the database logins remain
   `NOSUPERUSER NOBYPASSRLS` and inherit exactly one application role.
2. Construct the authentication `MembershipLifecycleService` with a session factory
   inheriting `saas_authenticator`. It performs login and invitation acceptance. Under
   forced RLS it can discover only the invitation whose SHA-256 Token hash was derived
   by the server for the current request.
3. Construct `TenantMemberAdministrationService` and the separate
   `member_lifecycle` service with a session factory inheriting `saas_governance`.
   Pass both to `create_saas_http_integration`; never use the authenticator connection
   for role, status, invitation-management, ownership, or removal mutations.
4. Serve the existing `/saas/admin/projects` application and register the returned
   internal router at `/saas`. Tenant Members is one view of that application, not a
   second deployment or authentication realm.
5. Keep the Outbox dispatcher healthy. Mutations and their secret-free Outbox records
   commit atomically; consumers deduplicate by event ID.

## Authorization and privacy

- `membership.read` controls the member and invitation directories. Tenant Owner,
  Admin, and Security Auditor have read access; ordinary members do not.
- Every query is bound to the authenticated actor and selected Tenant. Member rows,
  Space access, invitations, and mutation targets remain under forced PostgreSQL RLS.
- The directory returns display name, normalized primary email, Tenant role/status,
  Space role/status, and non-secret login-method summaries. It never returns password
  hashes, OAuth/OIDC subjects, issuers, access or refresh tokens, invitation hashes,
  session tokens, or credential material.
- Role/status mutations use the server-read current record plus an expected version.
  Elevation to Tenant Admin or Space Admin requires a reason, a freshly authenticated
  session, and the higher authority defined by the permission policy. Invitation cannot
  bypass the same elevation boundary.
- Sensitive reads and one-time-token responses use `Cache-Control: private, no-store`.
  Browser rendering uses text nodes for directory and audit content.

## Operator procedure

1. Sign in, connect the intended Tenant/Space context, open **Tenant Members**, and
   confirm the Tenant identifier before searching or changing a member.
2. For an invitation, choose the least-privileged Tenant and optional Space role,
   provide a non-sensitive reason when the role is privileged, and set an expiry no
   longer than 30 days. Copy the Token from the one-time disclosure and deliver it over
   the approved channel. It is not stored in browser state or Outbox.
3. If delivery is compromised, reissue with the current invitation version. The old
   Token fails immediately. Revoke a pending invitation when access is no longer
   required; neither operation can recover a Token later.
4. Role and suspend/resume changes require the displayed current version, reason, CSRF
   token, trusted Origin, and a unique idempotency key. On a version conflict, reread
   the member and decide again rather than retrying stale intent.
5. Use the impact preflight before member removal. Resolve every blocking ownership,
   Project grant, Service Account stewardship, Runtime, or other registered domain,
   then execute the still-current preflight. Never delete membership rows directly.
6. Transfer Tenant ownership only through the Owner-transfer action with a freshly
   authenticated session and explicit acceptance by the successor. Verify old sessions
   and authorization snapshots are invalidated as specified by the lifecycle result.
7. Confirm the corresponding membership/invitation/ownership/removal Outbox event was
   dispatched and contains no Token or Token hash.

## Rollback and incident handling

Application rollback may hide Tenant Members while retaining schema
`p6a000000007`. Before downgrading to `p6a000000006`, disable invitation acceptance;
that downgrade removes the exact-Token authenticator RLS path. Downgrading from
`p6a000000006` to `p6a000000005` removes the bounded directory indexes and requires a
verified backup and approved maintenance window.

For a leaked invitation, reissue or revoke it and verify the old Token fails. For an
unexpected privilege change, suspend the affected account, revoke sessions, inspect the
immutable Outbox/audit facts and authorization decisions, then restore access through a
new authorized mutation. Do not edit membership, invitation, or ownership rows by SQL.

## Acceptance evidence

Release evidence must include Cookie/Origin/CSRF denial, ordinary-member and
cross-Tenant denial, privacy-field absence, bounded pagination and stale-read rejection,
role/status optimistic concurrency, fresh-auth elevation, invitation create/reissue/
revoke/accept, old-Token denial, one-time disclosure, Outbox secret absence, Owner
transfer, removal impact preflight, real Chromium operation, distinct governance and
authenticator database roles, exact-Token forced RLS, migration round trip, logical
restore, wheel contents, upstream patch replay, and intrusion-budget checks. Passing
these code contracts does not supply production SSO/SCIM, regional DR, billing,
high-cardinality performance, or aggregate release evidence.
