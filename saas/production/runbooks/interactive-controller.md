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

## Managed creation metadata

Direct Kubernetes and Agent Sandbox launch requires `get` on the specific
execution namespace's token Secrets, in addition to the existing create/delete
rights. The controller reads the one reserved Secret by name to verify its UID
and token digest; it does not list or watch Secrets. Keep this permission in the
dedicated runner namespace, never at cluster scope or in the Server/credential
namespace. Sandbox ServiceAccounts remain powerless and receive no token mount
or `pods/exec`. Missing read permission makes managed launch unavailable.

Private format v4 preserves the actual workload and token Secret UIDs, the
verified token digest and Pod-template hash after SDK creation, before Runner
model admission. Retain the matching private volume and original credentials;
drain older consumers before cutover. Normal v1/v2/v3 records retain their old
encoding. UID observations and read-only revalidation are not deletion or
container-termination receipts. Do not clear pending cleanup based on a missing
object, cancelled coroutine, SDK return or foreground-delete request alone.

Each scoped launcher permits one startup and one workload submission. Repeated
preparation, direct resume/terminate and Agent Sandbox's name-conflict wake are
unavailable until a UID-bound lifecycle can authorize them. SDK best-effort
name-only deletion is suppressed for this instance only. A failed creation ACK
can retain freshly verified workload/Secret facts, but still fails startup;
missing observations remain pending, never stopped. Do not treat these local SDK
barriers as complete resource termination or enable the feature on that basis.

## Unknown managed creation recovery

Private v5 adds write-ahead creation intent; v6 additionally records controller
quiescence. Old consumers reject these newer formats. Stop all old consumers
before cutover and retain matching database/private-volume backups for rollback;
byte-compatible older records do not make a mixed-version rollout safe. An old
contract-only complete v5 without quiescence is not accepted as new stop authority.

For an orphaned direct managed creation with no official Runner ID, recovery
requires the original mTLS Run/fence release check and no active shared-Host
peer. It validates nonce, actual workload/Secret UID, token digest, namespace,
configuration and template before UID/resourceVersion-preconditioned mutations.
The parent and actual Pods retain the controller's own termination finalizer
until their facts are durably acknowledged. Agent Sandbox templates cannot carry
that finalizer: the actual Pod is protected by UID before suspension instead.
Missing or unprotected deleting Pods stay pending; no finalizer is added after
deletion begins.

The controller must observe suspended-parent quiescence and the kubelet's current
terminated state for every declared container, including container IDs and
timestamps. NodeLost, unknown states, lastState, a terminal phase, 404, or accepted
DELETE alone do not prove stop. Parent deletion increments generation once; the
deleting parent's receipt must match exactly the preceding quiesced generation,
not arbitrary drift or a resumed parent. Only after recorded Pods, parent and
Secret are gone can the existing durable physical confirmation clear the barrier.
Only this controller's own finalizer is removed, never other controllers' markers.

This recovery also requires reviewed `patch` rights on Jobs and Pods in the
dedicated execution namespace, alongside the existing Sandbox patch and Secret
get rights. Never grant them in the Server namespace or to a workload SA. Missing
rights leave recovery unavailable; this runbook does not grant production RBAC.
Global legacy name-only start/terminate/resume/suspend are fenced; keepalive is
UID-bound and cannot wake a recorded stop. Safe resume, normal/warm lifecycle
retirement, cross-Pod recovery and production admission remain separate gates.

## Warm managed resource admission

A reused managed Host/Runner is not a new resource creation. Before binding the
next Run's model channel, the driver reads the recorded workload and token Secret,
rechecks nonce, actual UIDs, template and configuration, and resolves that token
against the current Host row. A detached/deleted Host, revoked or expired token,
wrong owner/account generation, replaced resource or pending retirement prevents
admission. The original Run must also pass the existing terminal/released mTLS
check. The private record is checked again after the reads and before binding.

Private v7 stores only a direct origin Run UUID for reuse, not copied creation
intent or invented SDK effects. The reference is immutable and cannot point to
itself or coexist with owned resource facts. Pending references count as peers
even before a replacement Runner has a Host ID, so GC cannot clear their barrier.
Retain the referenced origin and credentials with all dependent records; old
consumers reject v7, and the all-consumer cutover gate still applies. This read-only
admission does not complete dormant resume or normal/warm resource retirement.

## Controller-owned resource retirement

The SaaS Controller installs the original lifespan's optional reaper factory.
Its reaper retains the configured offline age, but enumerates only private,
canonical managed origins and reads each Host under that origin's RuntimeContext.
It does not gain context-free cross-workspace SQL or name-only deletion rights.
Standalone deployments retain the original default reaper.

Preparation or active peers block retirement. Released, finished orphaned peers
may be sealed and quiesced without first waiting for old channel usage to drain.
Historical machine/fence ownership and dispatch release are verified before
mutation. Actual resource UIDs, nonce, template and cluster configuration are
read before initial detachment. Under the admission lock, a Host snapshot and
credential-hash CAS detach only that generation; a heartbeat or credential loser
writes no private stop intent. The intent is durable before any provider write.

Resource deletion uses the same UID/RV, quiescence and kubelet terminal-fact
engine as unknown creation recovery. Only its complete receipt can confirm
physical fences and clear the corresponding Host pending slot. A cancelled
waiter cannot duplicate cleanup. Already confirmed Runner proof bytes remain
unchanged when resource facts are appended. Fixed Hosts never enter this path.

Private v8 adds an immutable complete-origin stop digest to a referenced peer,
including one whose Runner launch ACK was unknown. It binds that peer's own
Run/fence and retains its own metering grant; it never copies creation authority
or replays the input. Pending channel drainage and usage delivery retain the
original grant after physical stop. All old consumers must stop before v8 is
written, and rollback must restore matching private-volume and database state.

These paths still require real Kubernetes/Agent Sandbox and PostgreSQL acceptance.
Dormant resume, cross-Pod recovery and full production admission remain separate
unfinished gates.

## Fresh generation after complete retirement

A cleared managed Host may receive a new generation only after its canonical
origin has a complete resource-retirement receipt and the original Run/fence
passes historical ownership, terminal/released and confirmation checks. The
driver also reads the old workload and token Secret by name: any remaining
object blocks a fresh launch. Absence alone is never a stop receipt. The Host
snapshot, provider, owner/account generation and trusted cluster/namespace must
match. Current image admission still applies to the fresh image.

Private v9 binds only the predecessor Run UUID and immutable complete-stop
digest. The fresh Run retains its own grant, nonce, token, resource UIDs and
channel; it does not borrow the old Run's financial or model authority. The
Host is re-credentialed in the original lifecycle transaction only while the
locked retired snapshot and empty resource/token state still match. A pending
old channel prevents rotation; a closed, physically stopped channel is forgotten
before the fresh channel is bound. Old secrets cannot authorize the fresh Run.

Only a verified, completely stopped ancestor chain can be excluded from the
new generation's peer set. Preparing descendants still block cleanup, and a
foreign, incomplete or ambiguous origin remains unavailable. Historical private
records must stay with their dependent records. v1-v8 canonical encodings stay
unchanged, but old readers reject v9: stop all old consumers before cutover and
retain matching database/private-volume backups for rollback.

This path intentionally creates a new workspace generation after full expiry.
It is not dormant resume: Agent Sandbox resume must preserve its parent and
workspace PVC, which remains a separate implementation and acceptance task.

## Creation-time Agent Sandbox Pod binding

After the SDK observes readiness, a direct Agent Sandbox launch revalidates the
parent, Secret, nonce, template, owner reference and actual running Pod. Before
any Pod mutation it durably records that Pod's UID and name in creation intent.
The finalizer update uses UID/resourceVersion tests and retains other markers;
the same live Pod and marker are read back before startup returns. A failed or
unknown checkpoint/PATCH ACK does not permit a Runner/model launch.

Private v10 carries this immutable Pod observation. v1-v9 records keep their
canonical encodings and old stop-proof bytes; old readers reject v10. All old
consumers must stop before cutover, with matching private-volume/database state
retained for rollback. A Pod UID alone is not a process-stop proof. Recovery
still requires current kubelet terminal facts, quiescence, original fences and
complete resource receipts. New-format cleanup cannot substitute another Pod.

Warm admission and keepalive reject a replaced/deleting Pod or a removed marker.
Legacy records without an initial Pod observation retain their existing guarded
recovery behavior; do not invent a historical UID for them. The retained Pod
object makes later expiry observations possible, but does not itself implement
preserving-parent/PVC suspend/resume, prove workspace contents or admit production.

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

## Retained Agent Sandbox suspension and wake

The Controller has a distinct `managed_suspend` receipt. It revokes the old Host
credential with the existing HostStore CAS, records kubelet termination before
releasing its Pod marker, waits for the old Pod and token Secret to disappear,
and retains the same non-deleting Sandbox UID. Configured workspace claims must
remain Bound with the same UIDs, owner and immutable claim templates. An emptyDir
configuration does not gain durable storage. A suspension is not a complete
resource-retirement receipt.

A new input may use this stopped generation only after all original fences are
released and confirmed. The original HostStore locked, detached-row transaction
issues a new token; the scoped launcher preserves the resource name and uses a
UID/resourceVersion-tested PATCH instead of the legacy name-conflict wake. It
does not replace claim templates or finalizers. The new Run has its own grant,
model channel, Secret, nonce, Pod and Runner, with an immutable suspension link
to its predecessor. It never replays the old input. Ambiguous, changed or
incomplete history stays unavailable. A failed wake must not delete a retained
workspace; unresolved effects remain a recovery barrier.

Private v11 distinguishes these facts from v1-v10. Old canonical bytes and stop
proofs remain unchanged; old readers must stop before v11 is written. Rollback
requires the matching database, private volume, keys and runtime versions, not
an old binary against new private records. The serving SDK needs runner-namespace
PVC `get` permission only; PVC writes, server-namespace access, `pods/exec`, and
Secret list/watch are not required.

Component tests do not prove actual workspace contents across suspension,
replacement-Pod restoration, real suppliers or production readiness. Those
physical and release gates remain required before enabling this feature.

## Verification boundaries

An orphaned Run can finish logically and release its dispatch while its physical
stop remains unknown. The private record remains draining and blocks all new
claims. The background sweeper may retire the finished in-memory handle only
after the original machine/fence/capability passes the existing mTLS terminal
and released-dispatch check, model requests drain, preparation quiesces, and
no execution or dispatch task remains live. Missing verification stays pending.
Only an actual stop acknowledgement and durable recovery confirmation clear
the barrier; logical release never proves physical stop or replays the input.
The Agent continues machine heartbeats and GC while this known barrier is
pending. Other authority failures and poisoned workers still terminate it.

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
