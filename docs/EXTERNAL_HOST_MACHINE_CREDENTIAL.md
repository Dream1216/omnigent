# External Host machine credential

Long-running external hosts should not keep an Accounts/OIDC session JWT or a
user password. Omnigent can instead issue a finite, host-bound machine
credential that is accepted only by the Host WebSocket tunnel.

## Security and ownership model

- The host must first register through normal user authentication. This binds
  its stable `host_id` to the authenticated `user_id` and workspace.
- `GET /v1/hosts/{host_id}/credentials/v2` returns owner-only, non-secret CAS
  metadata (`generation`, active state, expiry) with `Cache-Control: no-store`.
  `POST` accepts only the SHA-256 digest of a client-generated raw token plus
  the observed generation and a retry-stable operation id. The raw token never
  enters the API/server; PostgreSQL stores only its digest and expiry.
- The token is scoped to that exact host path. It is not an HTTP/API bearer and
  cannot list sessions, read files, administer users, or issue another token.
- Rotating increments `credential_generation` with an atomic compare-and-swap.
  A repeated operation id is idempotent after response loss; concurrent stale
  writers receive `409`. Revoking also requires the expected generation, so a
  failed client's cleanup cannot revoke a newer token. Revocation clears the
  digest without deleting the Host row or its session bindings and does not
  advance Host liveness (`updated_at`). A live token-authenticated tunnel
  revalidates against PostgreSQL every heartbeat and closes within 30 seconds
  after revocation/expiry, even across App replicas.
- External credentials are finite: 1 hour minimum, 365 days maximum; the CLI
  defaults to 90 days. Rotate before expiry rather than using a never-expiring
  secret.
- `sandbox_provider` remains `NULL`, so this Host stays visible in the user's
  external Host picker. Managed sandbox tokens remain under the provider
  lifecycle and cannot be overwritten through this endpoint.
- The original `/credentials` POST/DELETE contract remains available for old
  CLIs during a rolling upgrade. V2 uses the distinct `/credentials/v2` path,
  so a V2 request that lands on an old App replica fails without rotating the
  credential. Deploy the new CLI only after at least one V2-capable replica is
  reachable.

## Issue and install without printing the token

Log in once as the Host owner, then run the issue command as the service user
or an operator that can safely install the destination file:

```bash
omnigent login https://next.example.com
omnigent host credential issue \
  --server https://next.example.com \
  --host-id 0123456789abcdef0123456789abcdef \
  --output /etc/omnigent/host/host-token \
  --ttl-days 90
```

The command generates the raw token locally, sends only its digest, and writes
the token directly into an atomic `0600` file without printing it. It also
writes an owner-only `<credential>.omnigent-meta.json` sidecar binding the
file's digest to its server, host id, and generation. If the
issue response is lost it retries the same operation/digest idempotently. By
default it also removes the stored short-lived Accounts/OIDC JWT (including an
expired record) after the destination file and directory entry are fsynced.
If the host crashes between the raw-file and sidecar commits, log in again and
use `revoke --current` (or reissue) to recover; file-bound revoke deliberately
fails closed when the sidecar is absent.
Databricks workspace/org routing pointers are retained. Use
`--keep-user-token` only for an intentional interactive operator profile.
The destination's immediate parent must be owned by the invoking user and must
not be group/other-writable; an existing destination must be a regular file
owned by that user. If these checks or the atomic write fail, the CLI requests
a generation-conditional server-side revocation. A newer concurrent
generation is preserved.

For systemd, install and adapt
`deploy/systemd/omnigent-external-host.service.example`. The unit uses
`LoadCredential=` and points `OMNIGENT_HOST_TOKEN_FILE` at `%d/host-token`.
The Host rereads its configured file on every reconnect. With systemd
`LoadCredential=`, restart the unit after replacing the source so systemd
refreshes its private credential copy. A direct file configuration (without
`LoadCredential=`) can pick up an atomic replacement on the next reconnect.

Required non-secret entries in `/etc/omnigent/host/identity.env` are:

```text
OMNIGENT_SERVER_URL=https://next.example.com
OMNIGENT_HOST_ID=0123456789abcdef0123456789abcdef
OMNIGENT_HOST_NAME=exec-b
```

Validate before enabling:

```bash
systemd-analyze verify /etc/systemd/system/omnigent-external-host.service
systemctl daemon-reload
systemctl restart omnigent-external-host.service
systemctl show omnigent-external-host.service \
  -p ActiveState -p SubState -p MainPID -p NRestarts
```

Do not print `/proc/$pid/environ`, the systemd credential, the API response, or
the source credential file into an evidence log. Evidence should contain only
the Host id, owner, expiry, file mode, service state, reconnect count, and API
health.

## Rotation acceptance

1. Issue generation N+1 to a temporary `0600` path.
2. Atomically replace the systemd credential source, then restart the Host unit
   (or force one controlled tunnel reconnect).
3. Confirm the same Host id and owner are online and can launch a real Runner.
4. Restart the Host service once; confirm reconnect, Host visibility, and a
   real conversation round-trip.
5. Restart the App service, then restart the Host service a second time;
   confirm the same Host id/owner, `sandbox_provider=NULL`, reconnect, and a
   second conversation round-trip. This is the restart-recovery gate; a single
   warm reconnect is not sufficient evidence.
6. Confirm generation N no longer authenticates. Retain redacted audit
   metadata only; verify the Accounts/OIDC token record was removed and
   destroy any temporary operator login state.

## Revoke and rollback

```bash
omnigent host credential revoke \
  --server https://next.example.com \
  --host-id 0123456789abcdef0123456789abcdef \
  --credential-file /etc/omnigent/host/host-token
```

Log in again as the owner before using the management endpoint. With
`--credential-file`, the CLI sends that file's bound generation and digest;
a stale file receives `409` and cannot revoke a newer generation. Use
`--current` without `--credential-file` only when intentionally revoking
whatever generation is active on the server.

Only the endpoint's exact `204` response is accepted as proof of revocation;
redirects, `200` pages, conflicts, and transport errors preserve the local
credential file. Revocation preserves the Host row but disconnects the
token-authenticated tunnel within one heartbeat. Roll back the deployment by restoring the prior
App image and systemd unit, logging in once with the owner account, and running
the legacy user-bearer Host flow. Never restore an already-revoked token.
