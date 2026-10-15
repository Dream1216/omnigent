# Platform model session authentication

## Runtime contract

- `OMNIGENT_SAAS_PLATFORM_MODEL_TOKEN_TTL_SECONDS` defaults to `28800` (8 hours).
  Accepted operator overrides remain 60–28800 seconds. Fixed Host and both
  dynamic Sandbox providers must receive the same explicit production value.
- A Host-owned loopback relay is created for each Runner. A random local
  capability is delivered in the Runner environment, not the HMAC signing key
  or the shared upstream model-provider credential. It cannot authenticate to
  the remote gateway and is revoked when that Runner exits.
- `OMNIGENT_PROVIDER_LOOPBACK_TRANSPORTS` changes only provider transport
  resolution. Saved inference documents, allowlists, model selection and
  session-initialization hashes are not rewritten. Long-lived Codex and other
  provider-backed harnesses keep their local capability; every outbound model
  request reads the relay's current gateway bearer.
- The existing credential lifecycle refreshes five minutes before expiry
  (one-quarter TTL for short test/operator TTLs), coalesces concurrent refreshes
  and checks credential validity on every request after an idle interval.
- Only `401 / platform_model_authentication_expired` is retried, once, by the
  HTTP transport. The gateway emits that code only after verifying signature,
  issuer, audience, tenant and claim shape, and before budget reservation or
  provider egress. Invalid credentials, upstream authentication failures,
  throttling, network ambiguity and failures after response streaming starts
  are not replayed. The whole user task is never submitted again.
- Successful recovery is transparent. If an explicit expiry reaches the UI,
  it is labelled “会话认证过期，正在恢复”. A failed bounded recovery is labelled
  “会话认证恢复失败”; no CLI-login advice or whole-turn replay button is shown.

## Release and verification

Local tests use accelerated clocks; they are not an eight-hour live canary.
Deploy the updated gateway before (or together with) the new Host image: an old
gateway's generic authentication rejection deliberately does not qualify for
retry. Existing Runner/CLI processes cannot acquire this new transport from a
parent environment change. Preserve their edited workspaces; upgrade through
an orderly stop/resume only after workspace persistence has been verified.
Do not delete a Job-backed Sandbox whose HOME is an ephemeral `emptyDir`.

Before production acceptance, use isolated fixed Host, Kubernetes Sandbox and
Agent Sandbox sessions with a short supported TTL. Continue the same native
Agent across multiple renewals, including after an idle interval. Confirm one
request/body reaches the provider, one reservation is settled, no file/tool
task is replayed, invalid/foreign-session credentials do not refresh, an
interrupted SSE response is not restarted, and the relay closes on Runner exit.
Then canary the explicit eight-hour configuration without changing the
Sandbox lifetime. Production image/digest, signing, SBOM, provenance and
protected CI remain separate release gates.

The requester approved the two newly divergent frontend files on 2026-10-15.
Only the direct-file ceiling changes from 148 to 150; all other source limits
and release gates remain unchanged.

## Local verification — 2026-10-15

- Backend/provider/process-policy/wheel-contract/credential-lifecycle suites:
  177 passed. Includes a separate child process retaining its original local
  credential while the Host renews successive gateway tokens.
- Error-banner and block-renderer suites: 150 passed.
- Desired-state release and model-token contracts: 42 passed.
- Ruff, Pyrefly, frontend TypeScript/lint and production build passed. The
  build retains CSS highlight and bundle-size warnings outside this change.
- All nine upstream patches replay with no source mismatch.
- Before the requester's scope approval, the source intrusion gate failed at
  150 direct upstream files against 148. The explicit 148→150 budget revision
  records that approval, without changing any other gate or claiming a waiver.
- Full protected CI, signed images and live fixed-Host/dual-Sandbox acceptance
  have not run. These are local results, not production approval or evidence
  of a completed eight-hour real-time canary. No existing session was restarted.
