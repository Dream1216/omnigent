# Omnigent SaaS production ADR set

These eleven records define the stable P0 production architecture decisions. The
source of truth for candidate revisions, the exact decision-file list, and the
byte-exact bundle digest is `../adr-approval-candidate.json`; the compact registry
and current production-approval state live in `../baseline.json`.

An ADR's `Decision status` describes the architecture decision, not whether the
current source/schema candidate has production approval. Repository Owner
`Dream1216` selected an explicit `sole-owner-risk-waiver`, assumes all technical
owner roles, and does not claim independent Reviews or separation of duties. The
registry becomes `accepted` only after the exact merged decision PR, exact-head CI,
and Git-object decision bytes are bound into a new immutable waiver record. Any
material document edit creates a new bundle and invalidates that record.
Production verification gates are not waived.
