# P0-P6 acceptance evidence

`p0-p6-evidence.json` is the authoritative machine-readable progress ledger.
It deliberately separates implementation evidence from a passed acceptance
gate. A gate may list code and tests while remaining `pending` until the exact
revision has produced the required real infrastructure, browser, recovery, or
external approval evidence.

Run `python -m saas.scripts.check_acceptance_manifest` in CI. A phase cannot be
marked `complete` while any gate is pending, and the release cannot be marked
`GO` until every P0-P6 phase is complete.
