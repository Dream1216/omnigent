# Immutable ADR approval records

This directory contains machine-verifiable records generated only after the
decision PR is merged. `finalize_adr_approval.py` fetches GitHub PR and Review
metadata, binds every approval to the reviewed commit and decision-bundle
digest, checks the configured role authorities, and refuses to overwrite an
existing record.

Approval records are append-only. A changed candidate, decision file,
authority mapping, dismissed Review, or Review on a different commit requires
a new decision PR and a new record. CI rejects modification or deletion of an
existing record and revalidates referenced GitHub Reviews when a production
baseline points to a record.

No record is present yet because the repository currently has only one human
collaborator. Four-party approval requires four distinct authorized human
GitHub identities; bots, aliases, shared accounts, and role impersonation are
not valid evidence.
