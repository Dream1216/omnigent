# Reviewed identity dead-letter recovery

The Inbox preserves exhausted notifications as `dead`. Fix the provider,
configuration or missing trusted mapping before requesting a replay. A replay
only returns the original notification to scheduling; it cannot supply new
identity facts, create an identity or tenant, change membership, or bypass the
worker's fresh provider read and session fences.

`python -m saas.production.identity_replay` is a one-shot operations command.
It has no HTTP endpoint. Its inputs are the existing credential-worker release
pins, public Casdoor application config, role bindings, sealed migration
receipt and the sole authenticator database URL file. It checks installed
build metadata and the complete database catalog/role boundary before use.
Additional authority such as an IdP key, OIDC secret, Webhook key, reader key,
other database URL or signing key is rejected. Use a dedicated, short-lived
operations Job with no API token or RBAC, read-only mounts, owner-only ordinary
input files, and database-only network egress. Do not mount the replay inputs
into the online product, reader or synchronization worker.

Set `OMNIGENT_SAAS_IDENTITY_REPLAY_KEYS_FILE` to an owner-only public verification
keyring:

```json
{"schema_version":1,"keys":{"review-20261101":"<64 lowercase hex characters for an Ed25519 public key>"}}
```

Distribute approved public keys through the operations deployment's trusted
configuration authority. Keep the corresponding private key offline and
separate from recovery, OIDC and release-evidence signing keys. The existing
authenticator remains a trusted database writer; these commands provide an
audited authorization workflow, not a new database-level security boundary
against a compromised authenticator login.

1. List at most 100 scoped dead letters, then inspect one exact receipt:

   ```sh
   python -m saas.production.identity_replay list --limit 50
   python -m saas.production.identity_replay review \
     --inbox-id INBOX_UUID --output /operations/review.json
   ```

   The output file is created with mode 0600 and cannot overwrite an existing
   file. It contains only normalized routing metadata and locator hashes, not
   credentials or the original provider payload. Match its event ID against the
   IdP audit, establish the cause, and verify the repair. An unknown mapping
   must be established by the normal trusted identity workflow; matching an
   email address is insufficient.

2. Transfer the exact review to the offline reviewer. After review, issue a
   five-minute, single-review authorization:

   ```sh
   python -m saas.production.identity_replay_grant \
     --review-file /offline/review.json \
     --signing-key-file /offline/identity-review.pem \
     --key-id review-20261101 --review-reference OPS-123 \
     --reason-code mapping_repaired --output-directory /offline/authorization
   ```

   Supported reasons are `mapping_repaired`, `provider_restored`, and
   `configuration_repaired`. The output directory must be new and absolute;
   it is mode 0700 and its files are 0600. This signer opens no database or
   provider connection. The signature binds the key ID, exact review digest,
   product revision, issuer/organization, Inbox UUID and validity window.

3. Return only `grant.txt` to the one-shot operations Job:

   ```sh
   python -m saas.production.identity_replay replay \
     --grant-file /operations/grant.txt
   ```

   The command locks the original Inbox record and rechecks expiry after any
   lock wait. If its reviewed version, attempt budget, error, routing facts or
   timestamps changed, obtain a new review. Only a terminal dead record can be
   reset. The immutable notification, original receive/occurrence times and
   unique provider event identity are retained. The new attempt budget is
   audited with its preceding count and version.

4. Observe the worker's fresh provider read, terminal Inbox result, local
   session behavior and alert resolution. Inspect the
   `identity.notification.replayed` Outbox receipt: it includes review/grant
   digests, reviewer key ID, ticket, reason and previous state, with no signed
   token or signing material. The audit insert and scheduling change commit
   atomically. Reusing the same grant within its validity window returns the
   existing audit receipt and never resets another dead cycle. A failed audit
   write rolls back the scheduling change.

An authorization is not a production acceptance or release signature. After a
matched restore, rotate/revoke the operations verification key as required by
the restore plan; restoring old Inbox and audit state does not justify reusing
an outstanding authorization. Do not reopen finalized deleted identities or
switch credential authority to make an event processable.
