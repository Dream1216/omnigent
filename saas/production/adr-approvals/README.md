# Immutable ADR approval records

This directory contains machine-verifiable records generated only after the
decision PR is merged. `finalize_adr_approval.py` supports the standard
four-party GitHub Review mode and the explicitly degraded
`sole-owner-risk-waiver` mode. Both bind the merged PR, exact head, successful
required CI, decision bundle, authority snapshot, and immutable record; the
waiver never emits fabricated Reviews or claims separation of duties.

Approval records are append-only. A changed candidate, decision file,
authority mapping, dismissed Review, or Review on a different commit requires
a new decision PR and a new record. CI rejects modification or deletion of an
existing record and revalidates referenced GitHub Reviews when a production
baseline points to a record.

The active waiver binds repository Owner `Dream1216` as the sole accountable
human for all eleven role decisions. It explicitly accepts the lack of
independent Product, Architecture, Security, and SRE review and must be replaced
with standard four-party governance before production GA or by its review due
date. Production verification gates are never waived.
