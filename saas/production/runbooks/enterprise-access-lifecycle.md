# Enterprise group and custom-role lifecycle

This runbook covers Tenant group archival, Project custom-role retirement, and
bounded group-membership batches on the Cookie-only `/saas` Admin API. It does not
cover directory synchronization or prove SSO/SCIM production readiness.

## Production prerequisites

1. Run migrations through `p6a000000004` as the owner of the affected tables before
   serving the new routes. `p6a000000003` keeps RLS enabled, temporarily
   removes `FORCE` only for that table owner while holding the migration lock, restores
   `FORCE`, and then commits. Do not run application traffic with a partially applied
   migration. The migration preserves any pre-existing `archived` or `retired` row
   by copying its prior
   `updated_at` and `created_by` into lifecycle metadata and marking the reason as
   `legacy-state-backfill:p6a000000003`; treat that marker as unknown historical
   attribution rather than proof of the original operator.
   `p6a000000004` adds the hash-bound approval record and enables and forces RLS before
   commit.
2. Reapply `saas/control_plane/postgresql_roles.sql` and confirm all 57 control-plane
   and 17 Runtime tables still use both `ENABLE ROW LEVEL SECURITY` and `FORCE ROW
   LEVEL SECURITY`. Governance logins must remain `NOSUPERUSER NOBYPASSRLS`.
3. Register the enterprise router only through `SaasHttpIntegration`. The routes
   require an authenticated HttpOnly Cookie, trusted Origin, CSRF token, current
   session security version, server-resolved Tenant/Space context, and action-level
   `group.manage` or `custom_role.manage` authorization.
4. Make the Outbox dispatcher healthy before enabling mutations. Every lifecycle
   change is persisted with a secret-free Outbox event in the same transaction;
   downstream consumers must deduplicate by immutable event ID.

## Lifecycle rules

- First call `POST /tenants/{tenant}/groups/{group}/archive-preflights` or the
  corresponding Project custom-role `retire-preflights` route. The requester must have
  authenticated within five minutes. The server persists the exact target version,
  affected memberships, assignments, users, sessions, Projects and authorization
  versions as a 15-minute SHA-256-bound impact snapshot; only the summary is returned
  or emitted to Outbox.
- A different, currently authorized principal must call the scoped
  `.../retire-preflights/{preflight}/decisions` or
  `.../archive-preflights/{preflight}/decisions` route with `approve` or `reject` and a
  reason. Self-approval fails. An approval is invalidated if the target, impact, Project
  version, approver permission or TTL changes before execution.
- `POST /tenants/{tenant}/groups/{group}/archive` requires the approved preflight ID,
  matching current group version and reason, fresh authentication, and a Tenant-scoped
  idempotency key. It archives the group,
  removes every active group membership, revokes every active Project assignment,
  increments each affected Project authorization version once, increments each
  affected user's security version, and revokes that user's active sessions in one
  transaction.
- `POST /tenants/{tenant}/spaces/{space}/projects/{project}/custom-roles/{role}/retire`
  likewise requires its approved preflight ID, matching role version/reason, fresh
  authentication and idempotency key. It retires the role,
  revokes its active assignments, and increments the Project authorization version in
  one transaction.
- `POST /tenants/{tenant}/groups/{group}/membership-batches` accepts 1 through 100
  unique users. Every target, version, action, expiry, and active Tenant membership is
  validated before any mutation. One invalid item rolls back the entire batch.
  Removed users receive immediate session/security-version invalidation; additions and
  removals increment affected Project authorization versions once per batch.
- Archived groups and retired roles remain as immutable lifecycle facts for audit,
  restore, and deletion processing. Names are not silently reused. Restore a business
  capability by creating a new group or role and explicitly assigning it.
- An idempotent replay returns the persisted result and never repeats revocation or
  version increments. Reusing a key with a different actor, scope, payload, action, or
  expected version fails as an idempotency conflict.

## Operator procedure

1. Read the current group or role, create the scoped preflight, and compare its impact
   summary with the intended replacement. Do not derive the impact only in the browser.
2. A distinct Owner/Admin or authorized Project manager reviews the replacement and
   approves or rejects with a non-sensitive reason. The requester cannot reuse another
   operation's preflight or change its target version/reason at execution.
3. The original requester submits exactly one approved mutation with a new idempotency
   key while freshly authenticated. On an unknown transport
   result, retry the identical request with the same key. On a version conflict,
   reread impact and require a new operator decision and key.
4. Verify the response counts and affected Project IDs, then confirm the matching
   `group.archived`, `custom_role.retired`, or `group.membership.batch.changed` Outbox
   event was dispatched. Confirm removed users' old Cookies fail and authorization
   decisions observe the new Project version.
5. If a downstream consumer is unavailable, do not modify database rows manually.
   Repair the dispatcher/consumer and replay the durable event by event ID.

## Recovery, deletion, and rollback

The five enterprise tables, including `saas_enterprise_access_preflights`, remain part
of the `control_plane_database` deletion surface. Logical restore must preserve two
rows per table in the contract fixture and must replay post-backup approval execution
and lifecycle changes before access is considered revoked. The
CI restore contract is not production PITR or cross-failure-domain evidence.

Application rollback may stop serving the new routes only while Schema
`p6a000000004` remains forward-compatible. Downgrading to `p6a000000003` drops all
pending, rejected, approved and executed impact/approval history; downgrading further
to `p6a000000002` removes lifecycle audit columns. Either is destructive; do it only from a
verified pre-migration backup during an approved rollback window. Never reactivate an
archived group or retired role by direct SQL.

## Acceptance evidence

An implementation release must cover Cookie/Origin/CSRF denial, action authorization,
stale session snapshots, version conflicts, idempotent replay/conflict, batch
all-or-nothing behavior, concurrent single-winner archive/retire, session revocation,
Project version invalidation, Outbox secret absence, cross-Tenant PostgreSQL RLS,
fresh-auth expiry, self-approval denial, concurrent approval single-winner, stale impact
hash, approver-permission invalidation, rejection, legacy-state migration backfill,
upgrade/check/downgrade, logical restore approval replay, wheel
contents, upstream patch replay, and source-intrusion budgets. These are code-contract
gates only; directory federation, production audit export, production restore,
multi-AZ behavior, SLOs, signed images, and commercial acceptance remain separate
`NO-GO` gates.
