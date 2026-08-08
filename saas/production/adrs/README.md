# Omnigent SaaS production ADR set

These eleven records define the P0 production decision boundary for candidate
`omnigent-saas-p0-2026-08-09`. The source of truth for candidate revisions and
the exact decision-file list is `../adr-approval-candidate.json`; its digest is
verified by CI. The compact ADR registry in `../baseline.json` must agree with
these documents.

`Proposed` means the hashed document is reviewable but no immutable approval
record exists yet. The reviewed ADR documents are never edited merely to flip a
status label: the effective status becomes `Accepted` through the baseline
registry plus the digest-bound immutable record. Any material document edit
creates a new decision bundle and requires new Reviews.
