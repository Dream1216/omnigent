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
