# ADR-010: Identity and management-web security

- Status: Proposed
- Technical owner: `security`
- Candidate: `omnigent-saas-p0-2026-08-09`

## Context

Tenant administration and Platform Console operations can change identity,
authorization, billing, support access, and production state. Browser cookies,
OIDC identities, API tokens, and Staff identities require separate trust
boundaries; accepting ambiguous credentials or implicit account linking creates
privilege-escalation and account-takeover paths.

## Decision

Human login uses OIDC Authorization Code with S256 PKCE, state, nonce, exact
redirect allowlists, and explicit identity linking. Password credentials, where
enabled, use modern password hashing, breached-password controls, rate limits,
recovery hardening, and revocable server-side sessions. Cookies are Secure,
HttpOnly, SameSite constrained, rotated after authentication and elevation, and
bound to CSRF plus Origin checks.

Human and machine credentials use distinct namespaces. Requests presenting both
Cookie and Bearer credentials are rejected. The Platform Console uses an
independent origin and Staff identity source, requires MFA for privileged
production roles, short-lived JIT grants, separation of duties, content-blind
support by default, tenant-visible access, and append-only audit.

## Consequences and rollback

Account linking and recovery require explicit user-visible steps. Identity
provider degradation fails closed for privileged work. Rollback cannot restore
a vulnerable redirect, session, or mixed-credential behavior.

## Acceptance evidence

- Session fixation, CSRF, CORS, redirect, cache, history, and logout replay fail.
- Identity collision, explicit link, unlink, recovery, and provider removal pass.
- Machine tokens cannot establish browser sessions or inherit user permissions.
- Staff MFA, JIT expiry, dual control, tenant visibility, and break-glass audit pass.

## Owner confirmation

Security confirms identity proofing, session lifecycle, browser controls,
recovery, Staff separation, MFA, support access, and incident procedures.
