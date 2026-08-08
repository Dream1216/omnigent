# ADR-011: Feature flag and configuration governance

- Status: Proposed
- Technical owner: `platform-architecture`
- Candidate: `omnigent-saas-p0-2026-08-09`

## Context

Feature flags and configuration can change authorization, isolation, routing,
metering, recovery, and compatibility without a code deployment. Unowned or
stale flags become permanent divergent execution paths and can let a tenant or
operator weaken a platform security invariant.

## Decision

Every flag and mutable configuration key has a schema, owner, purpose, scope,
safe default, creation and expiry date, rollout and rollback plan, audit event,
and revision identifier. Resolution order is explicit across platform, region,
placement, plan, tenant, and project. Tenant settings cannot weaken platform
security, data residency, RLS, secret, network, audit, billing, or retention
controls.

Security-relevant unknown, expired, unreadable, or conflicting values fail
closed. Request, Run, billing, migration, and support evidence records the
effective configuration revision. Changes use staged rollout, peer approval for
high-risk keys, replica invalidation, drift detection, and automatic expiry
alerts. Permanent behavior graduates into typed configuration or code.

## Consequences and rollback

Emergency toggles are time-bounded and audited. Rollback restores a known
revision and confirms replica convergence; it does not leave shadow values or
allow old clients to select retired behavior.

## Acceptance evidence

- Schema, ownership, safe-default, expiry, and forbidden-override lint passes.
- Stale replica, conflicting scope, cache loss, and unknown security flag fail closed.
- Staged rollout and rollback preserve request and Run revision attribution.
- Expired flags page an owner and cannot remain silently active.

## Owner confirmation

Architecture confirms resolution order, immutable invariants, expiry ownership,
high-risk approval, drift detection, observability, and rollback behavior.
