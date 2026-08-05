# Enterprise group and custom-role lifecycle

This runbook covers Tenant group archival, Project custom-role retirement, and
bounded group-membership batches on the Cookie-only `/saas` Admin API. It does not
cover directory synchronization or prove SSO/SCIM production readiness.

## Production prerequisites

1. Run migration `p6a000000003` as the owner of the affected tables before serving
   the new routes. In one PostgreSQL DDL transaction it keeps RLS enabled, temporarily
   removes `FORCE` only for that table owner while holding the migration lock, restores
   `FORCE`, and then commits. Do not run application traffic with a partially applied
   migration. The migration preserves any pre-existing `archived` or `retired` row
   by copying its prior
   `updated_at` and `created_by` into lifecycle metadata and marking the reason as
   `legacy-state-backfill:p6a000000003`; treat that marker as unknown historical
   attribution rather than proof of the original operator.
2. Reapply `saas/control_plane/postgresql_roles.sql` and confirm all 56 control-plane
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

- `POST /tenants/{tenant}/groups/{group}/archive` requires the current group version, a
  non-empty reason, and a Tenant-scoped idempotency key. It archives the group,
  removes every active group membership, revokes every active Project assignment,
  increments each affected Project authorization version once, increments each
  affected user's security version, and revokes that user's active sessions in one
  transaction.
- `POST /tenants/{tenant}/spaces/{space}/projects/{project}/custom-roles/{role}/retire`
  requires the current role version, reason, and idempotency key. It retires the role,
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

1. Read the current group or role and record its version. For a group, enumerate its
   active members and Project assignments; for a role, enumerate active assignments.
2. Confirm the replacement owner, group, or role is active and authorized before
   destructive execution. Record a reason that contains no credential, token, source
   content, or personal data.
3. Submit exactly one mutation with a new idempotency key. On an unknown transport
   result, retry the identical request with the same key. On a version conflict,
   reread impact and require a new operator decision and key.
4. Verify the response counts and affected Project IDs, then confirm the matching
   `group.archived`, `custom_role.retired`, or `group.membership.batch.changed` Outbox
   event was dispatched. Confirm removed users' old Cookies fail and authorization
   decisions observe the new Project version.
5. If a downstream consumer is unavailable, do not modify database rows manually.
   Repair the dispatcher/consumer and replay the durable event by event ID.

## Recovery, deletion, and rollback

The four enterprise tables remain part of the `control_plane_database` deletion
surface. Logical restore must preserve two rows per table in the contract fixture and
must replay post-backup lifecycle changes before access is considered revoked. The
CI restore contract is not production PITR or cross-failure-domain evidence.

Application rollback may stop serving the new routes only while Schema
`p6a000000003` remains forward-compatible. Downgrading to `p6a000000002` removes the
new audit columns and is destructive to lifecycle attribution; do it only from a
verified pre-migration backup during an approved rollback window. Never reactivate an
archived group or retired role by direct SQL.

## Acceptance evidence

An implementation release must cover Cookie/Origin/CSRF denial, action authorization,
stale session snapshots, version conflicts, idempotent replay/conflict, batch
all-or-nothing behavior, concurrent single-winner archive/retire, session revocation,
Project version invalidation, Outbox secret absence, cross-Tenant PostgreSQL RLS,
legacy-state migration backfill, upgrade/check/downgrade, logical restore replay, wheel
contents, upstream patch replay, and source-intrusion budgets. These are code-contract
gates only; directory federation, production audit export, production restore,
multi-AZ behavior, SLOs, signed images, and commercial acceptance remain separate
`NO-GO` gates.
