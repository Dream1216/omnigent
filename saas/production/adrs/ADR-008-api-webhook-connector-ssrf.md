# ADR-008: API, webhook, connector, and SSRF baseline

- Status: Proposed
- Technical owner: `control-plane`
- Candidate: `omnigent-saas-p0-2026-08-09`

## Context

Public APIs, service accounts, outbound webhooks, and source connectors cross
trust and network boundaries. Human session permissions must not leak into
machine identities, and user-controlled URLs must not become a path to metadata,
private services, credential relays, or cross-tenant resources.

## Decision

Public APIs are explicitly versioned and document idempotency, pagination,
concurrency, error, and deprecation behavior. Service Accounts are non-interactive.
API Keys are shown once, stored only as independently peppered digests, and bind
permissions, Tenant, optional Project, expiry, network policy, and rotation
lineage without inheriting their creator's future privilege.

Webhooks use versioned payloads, event identifiers, timestamps, rotating signing
secrets, exponential retry, replay protection, ordering-tolerant consumers, and
a durable delivery ledger. Connector identities bind installation, repository,
Tenant, Project, and granted resources. Every outbound address, redirect, and
DNS answer is normalized and filtered against metadata, loopback, link-local,
private, control-plane, and disallowed network ranges.

## Consequences and rollback

Clients must handle idempotency and asynchronous delivery. Revocation and app
uninstall immediately block new use while retained delivery and audit facts
remain available. Deprecated versions stay only for the contracted window.

## Acceptance evidence

- Key create, one-time reveal, rotate, revoke, expiry, scope, and network denial pass.
- Webhook signature overlap, replay, retry, reordering, and poison delivery pass.
- Redirect, mixed-encoding IP, DNS rebinding, and direct destination bypass fail.
- Repository transfer, connector reinstallation, and cross-tenant binding fail closed.

## Owner confirmation

The owner confirms API lifecycle, machine identity isolation, delivery semantics,
connector ownership, outbound filtering, and operational support boundaries.
