# Existing-account credential migration

The current expansion is `cd3b00000001`. It retains GlobalUser IDs, local
credential hashes, and business resources. Importing a provider account does not
by itself move credential authority. The explicit cutover binds the server-read
provider identity, changes authority to Casdoor, and invalidates local sessions.
The legacy password endpoint and session issuer then reject that user's local
password. Native Casdoor accounts have no local password authority.

## Release boundary

Use the release image and the ordinary PostgreSQL migration/receipt process.
The private CLI verifies installed source lineage, the sealed production
configuration, the exact authenticator login, the complete release role graph,
and the source catalog before opening an authenticator Session. It does not migrate schemas, use a database
owner, or execute SET ROLE. An unqualified schema or stale release receipt fails
before any batch operation. Match the product database, provider database and
the identity/key recovery set when restoring; never drop the expansion after
native accounts or migration receipts exist. An empty legacy-only expansion may
be downgraded. A populated expansion requires an application rollback that
understands the retained authority fields.

Before enabling central signup or running cutover, verify that every serving
API replica and authentication worker runs the exact reviewed release revision
with the credential-owner gate and the current sign-in policy checks. Drain older replicas and remove their traffic routes first, including
WebSocket and fallback paths. Advancing the database head does not stop an
already running older process from accepting a retained local password. Record
the observed serving revisions in the rollout evidence; do not start the batch
during an overlap with a release that lacks this gate.

## Private configuration

Create a dedicated Casdoor application in the customer organization. Its API
credential has organization admin authority, so keep it separate from the OIDC
client, restrict its network access, and rotate/remove it after the migration
window. Verify that it cannot read the built-in administrator organization.
The importer uses HTTP Basic authentication, verified HTTPS, fixed get-user and
add-user paths, no redirects, and no ambient proxy settings. It never updates
existing provider accounts or merges by email.

Use a dedicated worker configuration. Mount the release source/upstream/image
values, schema revisions, service-role binding profiles, sealed migration receipt,
`OMNIGENT_SAAS_AUTHENTICATOR_DATABASE_URL_FILE`, and the same public
`OMNIGENT_SAAS_CASDOOR_CONFIG_FILE` used by the web release. The database URL
must use the release-bound login and verified TLS with the pinned CA. The
worker checks the installed revision before opening that login, then verifies
its exact role and the complete live catalog. It opens no other service login.
Do not mount other database URLs, S3 credentials, OIDC client secrets or
transaction keys, or web-server signing keys; the worker rejects these inputs.
The public customer configuration provides pins without those secrets.

For provider operations, mount:

- `OMNIGENT_SAAS_CREDENTIAL_IMPORT_CONFIG_FILE`: JSON with exactly `issuer`,
  `organization`, `customer_application`, `migration_client_id`,
  `source_lock_sha256`, and `policy_revision`. The issuer, organization and
  customer application must match the configured customer OIDC provider.
  The source-lock digest must match the packaged `source-lock.json` bytes.
- `OMNIGENT_SAAS_CREDENTIAL_IMPORT_CLIENT_SECRET_FILE`: the dedicated application
  secret, never a browser credential or administrator session cookie.
- `OMNIGENT_SAAS_CREDENTIAL_IMPORT_MARKER_KEYRING_FILE`: owner-only JSON,
  `{"schema_version":1,"active_key_id":"KEY_ID","keys":{"KEY_ID":"BASE64_KEY"}}`.
  Each key contains at least 32 random bytes. Retain previous keys while any
  pending/imported hash-import receipt may be retried. Rotate by deploying overlapping
  keyrings first, then switching the active key. The policy digest does not
  change when only the active marker key changes. Only hash preparation or a
  process batch containing hash_import requires this keyring; existing-link and
  reconnection operations work without it. show and recover need no provider
  service secret.

Secret and batch files must be absolute, regular, non-symlink files owned by the
process user with mode 0600. Non-secret configuration may be read-only to other
users but cannot be group/other writable. Keep hashes, emails, provider responses
and secret files out of shared logs.

## Bounded batches

A prepare manifest has at most 1000 distinct users, explicitly reviewed source
password versions and per-user idempotency keys:

```json
{
  "schema_version": 1,
  "items": [{
    "user_id": "GLOBAL_USER_UUID",
    "batch_id": "reviewed-batch-v1",
    "expected_password_version": 1,
    "idempotency_key": "reviewed-user-operation-v1"
  }]
}
```

Run `python -m saas.production.credential_migration_cli prepare --batch-file
/run/private/prepare.json`. Save the returned receipt IDs in a process manifest
with `schema_version: 1` and `items: [{"receipt_id":"RECEIPT_UUID"}]`.

Run `process --batch-file /run/private/receipts.json` first. This imports verified,
active normal users and leaves their product password authority on legacy.
Inspect the hash-only receipt using `show --batch-file ...`. Run `process
--batch-file /run/private/receipts.json --cutover` only for the reviewed batch.
Each user commits independently. Any failed or unfinished process result gives
a nonzero exit status; use its receipt ID to resume rather than preparing a new
batch blindly.

A lease and claim token fence each worker. Product password/security/email
changes invalidate the exact source snapshot. If the remote import succeeded
before a local transaction or network failure, a retry reads the HMAC marker
bound to that receipt and source snapshot. It never replaces a password that
has since changed in Casdoor. Unknown accounts, mismatched markers, blocked or
pending identity reviews require the existing explicit identity-link/review
workflow. Missing retained marker keys fail closed and can be restored for a
retry. Errors are bounded, content-free codes; provider error text is not stored.

## Existing provider account or unsupported source hash

The user first reauthenticates through the old login and explicitly connects the
existing Casdoor identity through the normal recent-authentication OIDC flow.
The configured provider must verify its email and have a password set. Never
supply a claimed subject or search for the user by email in a batch.

Use `prepare-linked --batch-file /run/private/linked.json`. Its prepare manifest
has the same fields as prepare plus the existing `connection_id`. This must be
an active, verified Casdoor connection belonging to that GlobalUser. A different
provider UUID is supported through the persisted connection. The service reads
the exact stable ID from the pinned customer organization, checks normal active
status and configured password, and fixes that server-read snapshot in a
mode=existing_link receipt. Its worker claim contains no PHC or source email,
and the provider adapter only calls GET get-user. It cannot import a password
without the import marker keyring. Use the same process staging and explicit
--cutover commands. Source changes, revoked mappings, contact drift or a missing
provider password require a new reviewed attempt rather than overwriting IdP data.

## Controlled fresh-password recovery

Recovery is a separate, offline-authorized operation. The worker holds only
Ed25519 public verification keys in
`OMNIGENT_SAAS_CREDENTIAL_RECOVERY_PUBLIC_KEYS_FILE`:
`{"schema_version":1,"public_keys":{"KEY_ID":"BASE64_RAW_PUBLIC_KEY"}}`.
Keep its private signing key outside the online worker. A grant expires within
five minutes and binds the exact user, completed migration receipt, current
security version, fresh password hash, review reference and reason code. The
reason must be `identity_outage` or `migration_rollback`.

After reviewing the target and current state, create an owner-only request JSON
with `user_id`, `receipt_id`, `expected_security_version`, `review_reference`,
and `reason_code`. On the offline authorization host run:

```sh
python -m saas.production.credential_recovery_grant \
  --request-file /private/reviewed-request.json \
  --password-file /private/fresh-password \
  --signing-key-file /private/offline-ed25519.pem \
  --key-id REVIEW_KEY_ID \
  --output-directory /private/new-recovery-authorization
```

This command has no database or provider connection. It creates a new mode-0700
directory containing the exact request, signed grant and mode-0600 secret file;
it refuses to overwrite an existing directory. Transfer the grant/secret through
the approved secret channel and run on the verified worker:

```sh
python -m saas.production.credential_migration_cli recover \
  --grant-file /run/private/recovery/grant.txt \
  --secret-file /run/private/recovery/secret.json
```

Recovery atomically installs the signed fresh hash, increments password and
security versions, revokes all local sessions and Casdoor identity connections,
and records hash-only evidence. It refuses the retained old password even when
presented in an otherwise valid grant. It does not enable the legacy entry point
in a central-only deployment: any change to the deployment auth mode belongs to
the separately reviewed rollback release. Revoked provider connections cannot
silently provision a replacement user. Repeated identical grants return the
same recovery receipt; changed or stale grants fail.

## Return to unified identity after recovery

The ordinary connection endpoint still rejects revoked identities. A separate
private return procedure can reactivate only the original connection that this
recovery itself revoked while it was active. Recovery evidence records that
eligibility; older receipts without that evidence and identities revoked before
recovery require another approved identity-resolution procedure. Pending or
blocked identity reviews, privacy tombstones and inactive users remain rejected.

Mount independent Ed25519 public keys in
`OMNIGENT_SAAS_CREDENTIAL_RECONNECTION_PUBLIC_KEYS_FILE` using the same public-key
file shape as recovery. Keep the return signing key offline. Request current
server-read facts with:

```sh
python -m saas.production.credential_migration_cli reconnect-request \
  --user-id GLOBAL_USER_UUID --receipt-id RECOVERED_RECEIPT_UUID \
  --review-reference APPROVED_REVIEW_REFERENCE \
  --output-file /run/private/new-return-request.json
```

Review the exact original connection, current password/security versions,
recovery-grant digest and fresh provider snapshot. Sign that request offline:

```sh
python -m saas.production.credential_reconnection_grant \
  --request-file /private/reviewed-return-request.json \
  --signing-key-file /private/offline-return-ed25519.pem \
  --key-id RETURN_KEY_ID --output-directory /private/new-return-authorization
```

Apply it with `credential_migration_cli reconnect --grant-file
/run/private/return/grant.txt`. The five-minute grant uses a distinct signature
domain, binds the exact source and provider facts, and is rechecked after lock
waits. This reactivates only that original identity, invalidates sessions and
keeps fresh local password authority on legacy. It does not alter the original
recovered receipt or overwrite a provider password. An identical replay does
not reactivate a connection revoked again later. Finish with a new
prepare-linked manifest using the current password version, stage and explicit
cutover. After that, both the original and recovery local passwords are denied;
Casdoor remains the credential authority.

## Acceptance

Use owned synthetic accounts first. Cover source hash parameter/Unicode cases,
stage/cutover/replay, an interrupted product commit, source password changes,
provider password reset before retry, foreign/blocked identities, concurrent
lease takeover, restricted PostgreSQL roles, and signed recovery. Verify stable
user/resource IDs, session revocation and old-password rejection using database
and API reads. Run the independent PG16/18 release profiles and the matched
database/provider/key restore rehearsal before qualifying production rollout.
Synthetic source drills are not production approval or signed image evidence.
