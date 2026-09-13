# Platform default Provider: P0 delivery preparation

Status: **reviewable preparation, not an activated configuration**. This runbook
does not supply a credential or authorize a model call, restart, migration,
release, or production admission. The companion `binding-inputs.example.json`
contains only non-secret input slots; it is not a Kubernetes manifest.

## Scope and upstream contract

One explicitly dedicated Beta execution domain gets an operator-owned default
Anthropic-compatible Provider for Claude-native / Claude SDK. Ordinary users
continue selecting an Agent without another account login. No tenant model
catalog, billing UI, BYOK lifecycle or global credential broker is implemented.
An account subscription is not silently converted into a shared platform key.

Reviewed product: `58bb02f4854fbac48c3f3348062b5cc82c2c649d`.
Pinned upstream: `06c33aeae701d521a3cfacd2daf99441b6d64492`.
Guidance backport: upstream `32f28c0ed69530829eaf9b013a40cf57356e1b31`, #4275.
The latter corrects a dead-end UI instruction; it cannot make an absent Provider
usable. Preserve SDK readiness's unknown-at-launch behavior.

The backport still displays upstream's `omni setup on the host` wording. In a
platform-managed deployment that instruction belongs to an authorized operator,
not an ordinary tenant user. Role-specific UI wording and an administrator entry
point are **not implemented or accepted** by this candidate; do not report them
as done or grant users Host terminal access to work around missing configuration.

Source contracts to recheck against the eventual release SHA:

- `omnigent/onboarding/provider_config.py`: named Providers, `default:
  [anthropic]`, family endpoint/model and `auth_command` / key references.
- `omnigent/harnesses/claude_native/main.py`,
  `_provider_config_for_native_claude`: an Anthropic Provider produces endpoint,
  `apiKeyHelper`, model and routable aliases. Missing usable authorization falls
  back to native CLI login; this is not an acceptable successful activation.
- `_native_claude_terminal_env`: do not combine `apiKeyHelper` with a raw
  `ANTHROPIC_API_KEY` in the terminal; that can trigger an interactive key menu.
- `omnigent/host/connect.py`, `HARNESS_CREDENTIAL_ENV_VARS`: Host-to-Runner
  propagation is explicit, not proof that the final native terminal can call.

## Minimum non-secret operator inputs

Complete every slot before rendering or applying a DCP change. No secret value
belongs in the JSON, Git, a PR, screenshots, chat, shell history or logs.

| Input | Required decision / validation |
| --- | --- |
| Provider and protocol | Named service; `anthropic` protocol; first-party API or compatible gateway, not an arbitrary OpenAI endpoint |
| Endpoint | Exact HTTPS base URL, no userinfo or secret query/fragment; approved CA, DNS and egress destination |
| Model routing | Exact service-supported model ID and only supported aliases; a UI catalog label is not validation |
| Authorization mode | Provider-file helper or explicitly supported gateway bearer env mode; never mix subscription, key and gateway defaults |
| Secret authority | Existing namespace + Secret name/key + immutable version reference, or explicitly authorized OpenBao mount/path/version plus a dedicated reader identity |
| Isolation | Exact tenant/space/Host/workload/uid=10001; confirm this Host is dedicated to the approved Beta principal, not shared across mutually untrusted tenants |
| Cost and activation | Billing owner, approved model-call budget, quota, rollout window, operator and rollback revision |

Absent service choice or reference is an **operations dependency**, not a request
for every Agent user to log in. Do not discover it by searching a developer's
Mac keychain, CLI credentials or home directory. Only inspect named operational
references supplied by the operator. SMTP, Host machine-token and receipt-signing
references are separate authorities and must not be reused for LLM access.

## Preferred delivery: a named Provider with a file-backed helper

Prepare the following in an independent DCP PR only after inputs are complete:

1. Reference a versioned, operator-created Secret. Do not create a plaintext
   Secret manifest. If OpenBao is the source, define a dedicated least-privilege
   reader and an observed delivery mechanism first; existing transit/SMTP tokens
   do not prove that a KV reader or synchronization controller exists.
2. Stage the one credential as uid/gid `10001:10001`, mode `0600`, into a
   memory-backed volume; mount read-only under the approved Host configuration
   directory. Do not place the secret in the home PVC, workspace or image.
3. Supply a non-secret named Provider config, preserving every unrelated field
   in the existing config. Record a restricted rollback copy and compare its
   preimage before any replacement. If an operator changed it, stop on conflict.
   If absent, record that absence rather than inventing a previous working config.

Illustrative Provider fragment (not an activation command):

```yaml
providers:
  platform-beta-default:
    kind: gateway
    default: [anthropic]
    anthropic:
      base_url: https://REPLACE_WITH_APPROVED_ANTHROPIC_ENDPOINT
      auth_command: cat /home/omnigent/.omnigent/provider-credentials/default/key
      models:
        default: REPLACE_WITH_ROUTABLE_MODEL_ID
```

Use `kind: key` for a reviewed first-party key Provider. The helper contains only
a fixed file path, not an inline secret or a shell command copied from input.
Native Claude obtains the token through `apiKeyHelper`; do not log the helper's
stdout. Verify the actual Provider parser and final helper in the deployed
version before allowing a call. Use non-secret model aliases only if served.

The non-secret config remains in the existing persistent config location.
The credential persists by its versioned secret-manager reference and is
restaged after Pod replacement, not by copying a login into the PVC. Mounts must
be reachable by the actual Runner/native helper while still honoring sandbox
boundaries. Prove reachability as a boolean; do not print the file or relax the
sandbox on failure. Check that generated native settings contain only a helper
path, not a literal-key `printf` command. Exclude the secret volume from backups.

**Security limit:** a file accessible to an Agent's uid is not a secretless
multi-tenant solution. The dedicated Beta scope is mandatory for this route.
If the Host executes mutually untrusted tenants, stop and require a separately
reviewed per-session credential proxy; do not expose a shared upstream key.

### Restricted alternative: gateway environment injection

Only when the chosen gateway explicitly supports Claude's bearer-token mode,
use one `secretKeyRef` for `ANTHROPIC_AUTH_TOKEN` and non-secret
`ANTHROPIC_BASE_URL` / `ANTHROPIC_MODEL`. No broad `envFrom`, arbitrary env
passthrough, simultaneous raw API key, or inherited subscription token. This
does not automatically create an Omnigent named default Provider or prove SDK
compatibility; test each enabled harness or leave it out of the activation scope.
Environment snapshots require new affected processes on rotation, and this mode
has the same dedicated-Host limitation. Prefer the named Provider path above.

## Controlled reload and rollback

1. Capture exact source/image digest, DCP and internal GitOps revision, Pod UID,
   Host identity, PVC identity, config preimage/version, active Runner/task IDs,
   all current session bindings and existing receipt hashes. A user-created new
   session is not corruption: compare the original binding subset, not a stale
   hardcoded total. Do not dump message bodies, credentials or `/proc/*/environ`.
2. Check for active turns/native panes before scheduling a singleton Host roll.
   Preserve transcripts and session identities. Drain only through a supported
   mechanism; if no safe drain exists, obtain a coordinated idle window. Never
   run two Host writers against the same identity/home PVC.
3. Dry-run the exact DCP change. Keep image digest, database schema, machine
   credential, RLS and Runtime Partition unchanged for a config-only activation.
   A later guidance-image release is a separate signed-image change.
4. Perform one approved rollout/reload. Config-file refresh, environment refresh
   and existing native-pane refresh are not equivalent. Verify new process
   creation where required; do not assume a readiness refresh updates old panes.
5. Before a model call, check uid/HOME/config-home, readable nonempty helper file,
   permissions, named default/endpoint/model, no conflicting auth source, Host
   heartbeat, same PVC and original session bindings. Report booleans/references
   only. `/readyz` is not evidence of model authorization.
6. On failure, revert only this config/reference revision and perform a planned
   rollback of affected processes. Restore the exact config preimage (or remove
   only the newly created file if it was absent), retain sessions/PVC/receipts.
   Do not replay migrations or restore a database. An absent former Provider
   means rollback restores **connected but model-blocked**, not working chat.
   Credential revocation/rotation is a separate explicitly authorized action.

## Acceptance: staged gates, never inferred success

- Offline: this backport's unit/bridge/executor/readiness suites pass; Patch Queue
  replays byte-for-byte; source budget is explicitly reviewed. No mock result is
  recorded as a real-provider pass.
- Mock web journey: in a disposable execution environment without personal HOME
  or real model variables, test ordinary text then `/login`, `/logout`, and
  mid-turn steering. No auth command reaches tmux/model as escaped prose; error
  guidance appears and original error text remains. The upstream UI fixture can
  read/write `Path.home()/.omnigent/config.yaml` and switches to a real gateway
  when `LLM_API_KEY` is set, so it must not run unisolated on a developer machine.
- Real service: after separate call approval, send one short non-tool request
  through the selected cloud Host/Agent. Capture session/run ID, requested and
  effective model, provider request ID if available, terminal status and usage.
  Observe at least two streaming increments or mark streaming **not observed**;
  an HTTP 200 or a single completed response is insufficient.
- Refresh: same session shows the same user/assistant history without duplicate
  or missing items. Reconnect the browser during a separately approved short
  request, then continue the same session; do not restart the Host to simulate a
  browser reconnect. Record absence of duplicate execution/charging.
- Persistence: in an approved idle window, replacement/restaging retains the
  named Provider and restores callable service without copying personal login.
  Negative checks retain meaningful 401/403/quota errors and reveal no secrets.

Only these observed gates can close Beta conversation acceptance. They do not
close general multi-tenant credential governance or production admission.
