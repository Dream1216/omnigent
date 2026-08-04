# P0-P6 acceptance evidence

`p0-p6-evidence.json` is the authoritative machine-readable progress ledger.
It deliberately separates implementation evidence from a passed acceptance
gate. A gate may list code and tests while remaining `pending` until the exact
revision has produced the required real infrastructure, browser, recovery, or
external approval evidence.

Run `python -m saas.scripts.check_acceptance_manifest` in CI. A phase cannot be
marked `complete` while any gate is pending, and the release cannot be marked
`GO` until every P0-P6 phase is complete.

Immutable CI records name the verified GitHub Actions run and exact source
revision. `p2-ci-30883002639.json` records the first complete P2 implementation;
`p2-upstream-sync-ci-30883850613.json` records the next official-baseline sync,
including patch shrinkage, expanded official regression tests, and renewed
source-intrusion evidence. `p2-upstream-sync-ci-30884588165.json` records the
following sync to `15dd7bec` and expands the gate to cover the changed CLI and
managed-host tests. Two sync records prove repeatability but do not, by
themselves, close the combined P6 commercial gate.

`p1-oidc-ci-30887476782.json` records the complete OIDC Authorization Code +
S256 PKCE, replica-independent browser transaction, strict ID Token, JWKS
rotation, explicit same-email conflict, and PostgreSQL RLS acceptance on the
exact implementation revision.

`p1-context-shell-ci-30890178928.json` records server-enumerated logical scope
selection, opaque session-bound 60-second Context Snapshots, two independent
API instances sharing PostgreSQL authority, immediate healthy-control-plane
revocation, Outbox invalidation, strict low-risk read degradation, and
fail-closed login/scope/Mutation/WebSocket/new-Run/sensitive-read behavior.
Together with the OIDC record, it closes P1; the overall release remains
`NO-GO` because P0 and P3-P6 still contain pending gates.
