# Aliyun Server profile

The SaaS Server accepts an explicit Aliyun profile through
`OMNIGENT_SAAS_ALIYUN_PROFILE_FILE` and
`OMNIGENT_SAAS_ALIYUN_PROFILE_SHA256`. Without these variables the provider and
Host model broker remain disabled. Partial configuration, unknown activation
variables, digest mismatch and unqualified fields stop startup.

This configuration connects the candidate implementation. It does not replace
image qualification, actual generation-2 template verification, cloud network
checks or production release approval. No production profile has been activated.

## Release and tenant bindings

The profile binds the product commit, Server image digest, digest-pinned Host
image, Hangzhou Team, generation-2 template ID, HTTPS Server origin and model
gateway. The Server commit, image digest and public origin must match the normal
production configuration. The current image policy accepts GHCR; using ACR also
requires an equivalent reviewed registry-policy change.

Each admitted tenant has one positive workspace and one independent model
signing key. There are at most 32 tenants, with no duplicate tenant, workspace,
key file or key material. An unconfigured tenant has no fallback authority.
The broker also checks the current tenant/workspace allowlist for every renewal,
so a previously signed lease cannot bypass a changed workspace configuration.

This human-readable example contains placeholders and is not a deployable file:

```json
{
  "schema_version": 1,
  "product_revision": "<qualified-product-commit>",
  "server_image_digest": "sha256:<qualified-server-digest>",
  "host_image": "ghcr.io/<owner>/<host-image>@sha256:<qualified-host-digest>",
  "region": "cn-hangzhou",
  "team_id": "<canonical-team-uuid>",
  "generation": 2,
  "template_id": "<qualified-template-id>",
  "server_origin": "https://<public-server-host>",
  "model_gateway_url": "https://<controlled-model-host>/v1",
  "lifetime_seconds": 1800,
  "credential_file": "/run/omnigent-aliyun/api-key",
  "lease_key_file": "/run/omnigent-aliyun/lease-key",
  "lease_key_sha256": "<sha256-of-lease-key-bytes>",
  "tenants": [
    {
      "tenant_id": "<canonical-tenant-uuid>",
      "workspace_id": 41,
      "gateway_key_file": "/run/omnigent-aliyun/tenant-model-key",
      "gateway_key_sha256": "<sha256-of-model-key-bytes>"
    }
  ]
}
```

The loader requires canonical JSON: sorted keys, compact separators and one
trailing newline. The environment hash covers those exact bytes. Key hashes
cover the bytes after stripping trailing CR/LF, matching existing secret-file
handling. Never put key contents into this JSON or environment variables.

## Credential delivery

The management file contains one bare E2B API key, rather than the PoC dotenv.
Lease and model signing keys are independent, cryptographically random,
owner-only files with at least 32 bytes. Model signing material must match the corresponding gateway verifier;
that cross-service configuration still requires a real model-request test.
The lease key is shared by admitted Server replicas so a fresh replica can
validate a previously issued lease.

Files must be owned by the Server UID and be regular files, without symlinks or
additional hard links. Keys must have no group/other permissions. Standard
Kubernetes projected Secret symlinks therefore need the existing init-copy
pattern into a private owned volume before the Server reads them. The profile
itself may be readable but must not be group/other writable.

Readiness checks SDK `2.31.0`, the management file and the expected signing-key
hashes locally, including independence after management-key rotation. Readiness
does not make a cloud API call and does not prove API-key validity or network
reachability. The candidate Server recipe includes `kubernetes,e2b`; protected
publication checks the installed E2B version before signing.

Only the Host's own launch token and signed model lease are delivered to a VM.
The model lease uses the VM's cloud creation time and admitted lifetime, so
startup delay and the launch credential's cleanup grace cannot extend model
access beyond the VM deadline. Signing keys and management credentials stay on
the Server. Each model bearer lasts at most 300 seconds and never beyond that
lease. Revocation stops issuance; an already issued bearer can remain usable
until its bounded expiry.

## Server composition and release sequence

1. Qualify and sign the complete Host and Server images. Verify the actual
   generation-2 template references the qualified Host image and is ready.
   This Host image already includes pinned ossfs2, so avoid adding unqualified
   storage-client packages during template construction.
2. Prepare the controlled HTTPS callback and model endpoint. Mount only the
   intended model protocol through the gateway's existing authentication and
   budget checks.
3. Prepare Server-only credential copies and matching gateway tenant verifiers.
   Generate the canonical profile after the immutable image digests are known.
4. Deploy the profile and its hash with the Server release. It appends the
   scoped `e2b` provider to the reviewed deployment and preserves its existing
   default provider. The implementation uses the `e2b` provider ID for Aliyun.
5. Verify the version response's `aliyun_sandbox_profile_sha256`, readiness,
   real Host registration, isolated Runner, model request, fresh Server replica,
   revocation, timeout and resource cleanup. Then complete OSS and P5 acceptance.

The machine middleware enables only the exact model-token POST route. It
rejects mixed user/Host credentials and other Host-machine routes. The broker
revalidates current memberships, project `run.create` permission, runtime
placement, Host credential, session ownership and Host/session binding.

Removing the profile from a new release disables this opt-in. Production
rollback must also stop new Aliyun launches, drain or terminate admitted cloud
Hosts, confirm their removal and restore the prior admitted release; changing
environment variables alone is not a completed rollback.

## Local verification

```bash
.venv/bin/pytest tests/saas/test_aliyun_server_profile.py \
  tests/saas/test_aliyun_server_composition.py \
  tests/saas/test_aliyun_model_broker.py tests/saas/test_aliyun_host_launcher.py \
  tests/saas/test_production_server.py tests/saas/test_production_server_config.py -q
```

Composition tests use the production builder with SQLite stores and a test app
factory. They cover both activation states, model issuance, project/member
revocation and fresh Server composition. They do not prove PostgreSQL RLS,
actual pod restart, public ingress, MicroVM Host isolation or production use.
