# Customer authentication after a paired restore

Restoring an older product database can make a subsequently revoked opaque
session usable again. Restoring OIDC signing keys does not revoke those local
cookies. Before admitting traffic, invalidate restored customer authentication
state with the one-shot `saas.production.customer_auth_restore` command.

This operation preserves customer IDs, identity mappings, credential ownership,
retained password hashes, memberships and business records. It revokes all
restored customer sessions, fails pending OIDC transactions, increments every
customer security version and places a subject fence on every mapped identity.
Tokens issued at or before the fence cannot issue a local session. It also
invalidates credential-import and synchronization leases and reschedules
unfinished Inbox work without changing original notification facts or attempt
counts. Completed, ignored and dead notifications remain terminal.

## Establish the recovery boundary

Use the approved restore incident and deployment authority. Isolate the target
from user traffic and stop **all** product, import, synchronization and other
database writers. Keep the target isolated through review and apply. The
command serializes concurrent restore operations and locks existing rows; it
does not prevent another writer from inserting new rows. Checking a quiet
endpoint or scaling only one worker to zero is insufficient.

Verify the matched backup manifest and integrity before running the command.
The set must include the product database (including Inbox, provider state,
credential receipts and audit), Casdoor database, signing/encryption keys and
all referenced application, TLS, reader, notification and recovery inputs.
Retain the required historical import-marker verification keys. Verify the
archive's decryption, trusted manifest digest, restore point and storage
integrity using the approved backup system. This command accepts the verified
manifest digest as an audit binding; it does not decrypt or verify the backup.

Restore and verify all four database authorities, service-role bindings, FORCE
RLS catalog, official and SaaS migration heads with the exact installed release.
Generate the sealed migration receipt for the recovered target. Do not use
`create_all`, a superuser application URL, metadata overrides or fabricated
image digests to satisfy startup validation.

Reconcile security facts after the backup up to the incident's accepted cutoff
from an independent retained journal: deleted or disabled users, revoked
identities, membership removals, credential ownership changes and recovery
authorizations. The session barrier cannot reconstruct those facts. Recover
staff sessions, API keys, provider SSO/admin sessions and other credentials
under their own procedures; this command changes only customer authentication.

## Review and invalidate

Use an isolated short-lived maintenance Job with the existing credential-worker
release inputs, public Casdoor pins, public role bindings, the recovered sealed
migration receipt and only the authenticator database URL file. The installed
build and complete database catalog/role boundary are checked before use.
Unknown nonempty `OMNIGENT_SAAS_` inputs, other database URLs, provider keys,
online OIDC secrets, replay keys and Webhook/reader keys are rejected. Give the
Job database-only egress, no public route, no Kubernetes API token or RBAC, and
read-only owner-only input mounts. Do not mount backup decryption keys there.

The maintenance IAM/Job authority and reviewed incident reference authorize
this operation. The review digest provides exact-content binding, not a
reviewer's digital signature or production acceptance.

```sh
python -m saas.production.customer_auth_restore review \
  --restore-id RESTORE_UUID \
  --backup-set-sha256 VERIFIED_BACKUP_MANIFEST_SHA256 \
  --output /operations/new-customer-restore-review.json
```

The new absolute file is mode 0600 and cannot overwrite another file. The
review exposes only counts and digests for the eight authentication tables,
the release, restore UUID and hashed database target binding. Its lifetime is
five minutes. The command prints its canonical `review_sha256`. Check the
exact recovered target, incident, paired manifest and observed counts through
the maintenance review process, then use that exact digest:

```sh
python -m saas.production.customer_auth_restore apply \
  --review-file /operations/new-customer-restore-review.json \
  --review-sha256 REVIEW_SHA256 \
  --review-reference INCIDENT-123
```

Apply rechecks the closed review, target, expiry after lock waits and complete
table snapshots. A changed snapshot needs a new review; do not edit the file
to conceal changes. It inserts one `identity.customer_restore.invalidated`
Outbox audit atomically with all invalidations. The receipt binds the exact
release, backup/review/target digests, restore UUID, incident, cutoff and counts.
Failure rolls back the operation and returns a content-blind diagnostic.
Repeating the identical valid review returns that audit and does not revoke
new sessions. After expiry, inspect the original audit instead of reapplying
under a new restore UUID merely to retrieve a result.

An old migration claim cannot be reused; the normal migration worker detects
its changed security version as a conflict. Resolve and re-prepare a pending
import through the trusted migration workflow. Rescheduled Inbox work still
uses fresh provider readback; a dead letter still requires its separate
reviewed replay authorization. Revoke outstanding offline authorizations and
rotate their verification keys as required by the recovery incident.

## Verify before reopening

Keep ingress isolated while testing a pre-backup cookie, an in-flight OIDC
callback and a previously issued signed token. They must fail. After the fence
cutoff, obtain a fresh real signed OIDC login and verify the original GlobalUser,
tenant membership, workspace, project and task IDs and resource contents.
Confirm a migrated user's retained old local password is denied and the
restored provider accepts the current password. Exercise tenant isolation and
the required account states, restart synchronization and observe real provider
readback, terminal Inbox outcomes and alert resolution. Keep recovery timings,
target identity, negative checks and exact artifact hashes as external evidence.

A local paired snapshot rehearsal does not qualify production RPO/RTO, WAL/PITR,
independent failure domains, an OCI image, staff/API recovery, the accepted
post-backup security journal or release approval. Admit the release only after
those applicable original gates and the recovery acceptance are satisfied.
