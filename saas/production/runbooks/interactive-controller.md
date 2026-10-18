# Interactive controller deployment contract

The controller remains opt-in with
`OMNIGENT_SAAS_INTERACTIVE_CONTROLLER_ENABLED=true`. This runbook describes
configuration, not production admission. Do not enable tenant models until the
reviewed Fleet/database, PKI, physical runtime, billing, and release gates pass.
The frozen flag also controls managed-session creation and message admission.
When disabled, those paths return `interactive_runtime_disabled` without creating
a session, Task, or Run. Cancellation of previously admitted input remains
available; physical Stop still requires the trusted controller and its receipt.

## Sandbox authority profile

Enable the controller with the reviewed Runner adapter factory
`saas.production.interactive_controller_adapter:build_production_interactive_controller`
and `OMNIGENT_SAAS_PLATFORM_MODEL_CONTROLLER_BOUND=true`. The production loader
freezes the controller selection; ambiguous flags or a different factory fail
startup. Fixed Hosts must receive the same controller-bound setting.

For **both** `agent_sandbox` and `kubernetes`, the reviewed `sandbox:` profile
changes only these authority inputs when the controller is enabled:

- `server_url`: the exact release's `OMNIGENT_SAAS_PUBLIC_ORIGIN`, using HTTPS
  on port 443. The legacy HTTP callback cannot carry the model channel.
- `host_config: {}`: no static provider configuration. Each Run receives its
  frozen publication through the scoped model channel.
- `kubernetes.env`: exactly `OMNIGENT_HOST_WORKSPACE_ID` and
  `OMNIGENT_SAAS_PLATFORM_MODEL_CONTROLLER_BOUND`.
- `kubernetes.secret_mounts: []`: no legacy model signing-key projection.

Keep the reviewed digest-pinned image, namespace, powerless ServiceAccount,
Host entrypoint, resource bounds, node policy and reaper unchanged. Neither
`secret_name`/envFrom nor extra environment names are admitted. Selecting the
controller does not relax image verification or network policy. With the
controller disabled, the existing legacy profile remains the only admitted
Sandbox profile; do not mix these profiles during a rollout.

## Separate control and billing credentials

Runner Control and Billing Metering use distinct purpose-bound client leaves
for the same Runner UUID and connection generation. A leaf fingerprint can be
registered for only one purpose. Never register or configure a Control leaf as
a Metering leaf or weaken either server's purpose check.

The existing `OMNIGENT_SAAS_RUNNER_CONTROL_*_FILE` settings remain exclusive to
Control. The trusted Server controller additionally requires:

| Setting | Value |
| --- | --- |
| `OMNIGENT_SAAS_INTERACTIVE_METERING_URL` | Internal HTTPS metering origin |
| `OMNIGENT_SAAS_INTERACTIVE_METERING_CA_FILE` | Metering server's trusted CA file |
| `OMNIGENT_SAAS_INTERACTIVE_METERING_CLIENT_CERTIFICATE_FILE` | Separate leaf registered as `billing_metering` |
| `OMNIGENT_SAAS_INTERACTIVE_METERING_CLIENT_KEY_FILE` | Matching owner-only private key file |
| `OMNIGENT_SAAS_INTERACTIVE_RECOVERY_DIRECTORY` | Private durable controller journal directory |

Files must be absolute regular files, not symlinks. Certificates and CA files
must not be group/world writable; the key must have no group/world access.
Missing configuration, a foreign Runner identity, the same certificate under
another PEM encoding, or a mismatched key prevents binding. The controller
does not fall back to Control credentials. TLS and durable server-side purpose,
generation, and revocation checks remain mandatory.

These credentials stay in the trusted Server. Do not mount them, the recovery
journal, an App DSN, or signing authority into a Host/Sandbox workload. A Host
receives only the scoped model channel. Keep original metering credentials and
their registered authority available for unresolved usage and recovery; do not
overwrite referenced files or revoke them before the recovery/rotation policy
has reconciled pending records. This configuration change is not a rotation or
retention acceptance receipt.

## Private volume ownership

Use a dedicated trusted-Server PVC, a stable owner UID and
`fsGroupChangePolicy: OnRootMismatch`. The default `Always` can recursively
widen a journal from 0600 to 0660 and credential files from 0400 to 0660 when
a replacement Pod mounts the volume. The controller intentionally rejects
that state; do not make it group-readable to restore service.

On a new directory only, the journal removes an inherited setgid bit after
checking ownership and the opened directory's identity. An existing unsafe
directory is never repaired silently. Verify replacement-Pod mounts with the
selected storage driver: retain journal directories at 0700, records at 0600,
and original credential files at 0400, with identical hashes and exclusive
locking. This is not a credential rotation policy or cross-node HA guarantee;
`local-path` volumes remain node-affine.

## Database admission during a leased Run

Fleet bootstrap and the default direct Runner admission still require the
configured registration status and zero active leases. The interactive
factory's catalog recheck also accepts its pinned single-slot Runner while
online or draining with zero or one active lease. This permits current-Run
authorization, renewal and orphan recovery after the scheduler has reserved
the slot; it does not grant permission to claim another Run.

The live mTLS lease heartbeat, Run/capability/fence, human/project/session
authorization and publication checks remain required before model issuance.
Recovery still requires the exact historical ownership binding and cannot
issue a model credential. Catalog checks retain the same signed Fleet and
exact function, policy, ownership and ACL validation; a foreign incarnation,
offline Runner, expanded capacity or unexpected grant is not admitted.

## Verification boundaries

Run configuration and grant/recovery wiring checks from the checkout root:

```sh
.venv/bin/pytest -q tests/saas/test_interactive_controller_credentials.py
```

`tests/saas/test_interactive_controller_process.py` requires its task-owned
two-container HTTPS/Host harness. Its lifecycle case uses the actual
`ProductionRunnerAgent`, mTLS claim/heartbeat/transition/release, official
Host/Runner/SDK, separate locally registered Control and Metering leaves, and
the existing billing endpoint. It checks persisted reply, one synthetic
upstream call, two Usage facts, terminal Run, released dispatch, zero active
Runner capacity, and an explicit Host stop acknowledgement. No test code sends
manual Run heartbeats in that case.

That case uses synthetic SQLite, PKI, and model transport and does not exercise
the production factory, signed Fleet admission, actual LiteLLM, live suppliers,
or Sandbox variants. Its green result cannot enable production or substitute
for those remaining acceptance checks.
