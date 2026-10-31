# Session storage candidate

The P4 storage modules are an opt-in candidate. Profile versions 2 and 3 wire
them into the real Server builder and managed Host launcher. Version 3 also
enables persisted output browsing and download. Version 1 leaves storage
disabled. Use version 3 for newly created Volumes: the real Aliyun API limits
Bucket Path to 128 characters. Version 2 serialization is retained, but an
overlong legacy plan is rejected before any signed create request. No production
profile is activated, and cloud storage
acceptance is still pending. Installing the code creates no cloud resources.

`saas/production/aliyun_storage.py` defines immutable, deterministic OSS Volume
plans for one admitted Tenant, physical Workspace, Space and Session. Inputs
mount read-only at `/home/user/workspace/inputs`; outputs mount read-write at
`/home/user/workspace/artifacts`. Each uses a separate session prefix. Git and
dependency working trees remain on local storage. With storage enabled,
repositories live under `/home/user/workspace/repos/`, and the returned workspace
stays at its parent so both mounts remain inside the Runner workspace. Actual
mount visibility through the inner filesystem isolation still needs verification.

The Volume manager requires an authorization callback. It must resolve the real
Session owner and resource binding and freshly validate Tenant, Space, Project,
membership and execution permission. A logging context, caller-supplied Session
ID or missing resource row is not sufficient authority. The Server now supplies
`AliyunStorageSessionAuthorizer`, backed by the real conversation/permission
stores and control-plane resolver. It checks OWNER access, fresh membership and
placement, both Session and native Project mappings, and Project run permission.
Inactive, ambiguous or mismatched mappings fail closed. A mapped Project cannot
fall back to an unbound native Session; no Project authority is inferred from
the logging hint. Before cloud operations and after readiness waits, the manager
rechecks authorization. The final check precedes returning the mount plan.

The authorizer's separate `read(session_id)` entry validates `run.read_content`
for existing outputs. The caller must still own the native Session. A Project
`read` role can pass this content check while remaining unable to start work;
the content-blind `manage` and `operate` roles cannot. For a browser's Space-only
context, the logical Project comes only from matching active Session/native
Project bindings. Conflicting Projects, revoked grants, stale membership or
placement fail closed. Deriving the Project does not mutate the request context
or change execution admission. Reading creates no Volumes or execution processes.

Startup and command/file transport recheck Session metadata and authorization.
Reattachment admission does not create Volumes. A launcher without storage
authority cannot execute in an old storage VM. Persisted Tenant/Workspace cleanup
remains separate so revocation or expired control STS does not block VM teardown.

Volume names include a hash of all immutable mount parameters. Existing cloud
metadata must match the exact Team, Bucket prefix, role, endpoint and read mode.
A timeout during creation triggers a name lookup rather than a blind replay.
Readiness checks are bounded. VM cleanup must retain these Volumes and OSS data;
the manager has no data-deletion operation.

`saas/production/aliyun_volume_control.py` uses generated API models and signing
from `alibabacloud-sandbox20260820==1.2.0`. The optional
`aliyun-sandbox-control` dependency is intended for the Server. The Host image
does not install this extra. The Server recipe selects it, and candidate OCI
runtime checks plus protected publication require version 1.2.0 and the admission
module import. Those real image checks must still pass for the final source.

The selected SDK's default HTTP path inherits proxy environment variables,
can emit signed requests under `DEBUG=sdk`, and follows redirects. This adapter
therefore owns a narrow synchronous HTTP transport for Create/Get/List Volume,
while reusing the SDK's models, serialization and ACS3 signing. It fixes the
Hangzhou HTTPS endpoint, disables ambient proxies, redirects and automatic
retries, bounds response bytes and sanitizes errors. It does not change the SDK
globally. Tests verify the signature against the actual outbound request and
exercise redirection, proxy, debug and ambiguous-creation cases.

The control credential is an explicit private JSON file, reloaded per operation
to support rotation. It accepts only STS credentials, valid for at most one hour;
long-term AccessKeys, unsafe file permissions, symlinks and hardlinks are rejected.
The [STS issuer candidate](sts-issuer.md) can assume a separate Team-scoped
control role using an explicitly configured ECS instance role and atomically
renew this file. Its actual IAM authorization, deployment and unattended
renewal remain unverified. No issuer is activated by the Server profile.
Do not send credentials in chat or commit a populated credential file.

The generated RAM policy is a draft for one Session's two prefixes. It grants
listing under those prefixes, read access to inputs and read/write/multipart
operations for outputs. It does not grant Bucket administration. Generating it does not attach a
role or prove cross-session isolation; production role allocation
and actual STS downscoping must still be checked.

Before enabling storage:

1. Confirm the account and Hangzhou region can create and mount OSS Volumes.
2. Create a dedicated test Bucket and a least-privilege role with the documented
   service trust. Do not reuse production backup, registry or recovery Buckets.
3. Verify authoritative Session admission through the real deployed Server and
   configure rotating STS issuance. Retain cleanup access after revocation.
4. Mount both Volumes in a real MicroVM; prove inputs reject writes and another
   Session/Tenant cannot list, read or write its objects.
5. Write and close outputs, verify durable upload, terminate the VM and read
   identical bytes from a second VM. Test cancellation and upload failure.
6. Validate the version 3 download path against the real deployment and OSS,
   including revocation and cross-session denial. A raw public OSS URL is insufficient.
7. Run the same checks through the complete Host/Runner, including its inner
   filesystem isolation, before marking P4 accepted.

Run the local adapter checks from the repository root after the frozen dev sync:

```bash
uv run pytest tests/saas/test_aliyun_storage.py \
  tests/saas/test_aliyun_volume_control.py \
  tests/saas/test_aliyun_sts_issuer.py \
  tests/saas/test_aliyun_storage_admission.py \
  tests/saas/test_aliyun_artifacts.py \
  tests/saas/test_aliyun_storage_launch.py \
  tests/saas/test_aliyun_server_profile.py \
  tests/saas/test_aliyun_server_composition.py -q
```

These checks use mocks and real pinned SDK code, not live cloud calls. The
separate `test_aliyun_storage_admission_postgresql.py` must run against a
disposable PostgreSQL test service. It uses an actual NOSUPERUSER/NOBYPASSRLS
login to verify Space binding inventory, including Project-bearing rows, and
transaction context clearing. A local skip is not RLS acceptance.

## Version 3 saved outputs

Version 3 retains the version 2 profile fields and requires the additional
`storage.artifact_credential_file` absolute path. The file uses the existing
canonical STS JSON format, must be private (0600), and must contain a separate
short-lived read credential. It cannot share a path or access key ID with
Volume control. The frozen Server extra pins `alibabacloud-oss-v2==1.4.0` and
`defusedxml==0.7.1`; both candidate and published runtime gates require them.
Version 1/2 profiles do not install the artifact HTTP routes.

The Server read role needs only OSS listing under admitted output prefixes and
`oss:GetObject` for their objects. It must not gain input access, writes,
deletes, Bucket administration or sandbox control. Its trust must authorize the
Server's actual workload identity. The FC service trust used by mounted Volumes
does not automatically authorize a Server to assume this role. The current
Volume-control issuer grants no OSS reads and cannot supply this credential.
A dedicated read-role policy, issuer, deployment and unattended rotation still
need real IAM and lifecycle acceptance before production activation.

Version 3 namespaces include the effective logical Project:

```text
/<prefix>/v3/<tenant64>/<space64>/<project64-or-unbound>/<session64>/outputs/
```

Each UUID uses its complete 128 bits encoded as a canonical 22-character
unpadded Base64URL segment. There is no truncation or hashing of identity.
The prefix is limited to 23 characters; even the longest Project-bound output
path, including its leading and trailing slashes, is at most 128 characters.
Zero UUIDs and alternate Base64 spellings are rejected. The actual CreateVolume
API exposed this limit during the PoC; complete textual UUID paths were refused
before any Volume was created.

Inputs use the corresponding `inputs/` suffix. Unbound, Project A and Project B
produce different Volume names and object prefixes. Moving a Session between
Projects therefore does not expose its previous Project's objects under the
new Project's permission. Version 2 names and paths remain unchanged; version 3
does not migrate or automatically expose existing version 2 objects. Any data
migration requires a separate reviewed, authorized operation.

The application endpoints are:

- `GET /v1/sessions/{id}/artifacts/availability`: authenticated capability probe;
  no OSS request or process launch.
- `GET /v1/sessions/{id}/artifacts`: list immediate children with relative
  `prefix`, opaque `cursor`, bounded `limit` and optional `scope` fingerprint.
- `GET /v1/sessions/{id}/artifacts/content`: attachment stream selected by
  relative `path`, listed `etag` and optional `scope` fingerprint.

Native browser downloads additionally carry `tenant_id` and `space_id` query
selectors because browser navigation cannot attach the UI's custom headers.
These selectors apply only to GET artifact content and select routing; current
login, memberships, Session ownership, Project content permission and placement
remain mandatory. Conflicting headers or snapshot context are rejected.

Each operation freshly authorizes access before OSS and after opening the
response. Streaming rechecks authority per 64 KiB chunk and is bounded by its
original STS expiration, including a stalled downstream. Paths cannot select a
Bucket, endpoint or another namespace. The reader uses signed conditional GET,
disables proxies, redirects, compression and automatic replay, bounds listing
XML and forces private, non-inline attachment responses. Provider diagnostics
and credentials are never returned. Download failures after response headers
terminate the stream; the client must not treat a short file as complete.

The existing Files and Changes panels show a collapsible **Saved outputs**
section when capability admission succeeds, including both desktop rail and
mobile drawer. It lists lazily, navigates folders, pages and downloads through
the application independently of Runner/Host liveness. Unsupported version 1/2
servers keep the section hidden. The native workspace and uploaded attachment
FileStore paths remain separate from these saved OSS outputs.

To inspect the UI, use a version 3 test deployment with an admitted Session and
confirmed uploaded output, then open Files and Changes on desktop and mobile.
Stop both Runner and Host, expand Saved outputs, navigate a folder and download.
Compare the downloaded bytes with OSS, revoke access, refresh and verify that
rows disappear and a saved link fails. The sealed Chromium contract tests prove
these UI paths using explicit fixtures, not real OSS persistence or cloud IAM:

```bash
pnpm --filter web run build
uv run pytest tests/browser_ui/files/test_saved_outputs.py \
  --browser-ui-skip-build --video=on --screenshot=on --output=/tmp/omnigent-output-proof
```

Production readiness currently still includes provider credential checks.
Provider-failure isolation, actual IAM/renewal, cloud mounting, cross-VM
persistence and the final deployed permission path remain P4/P5 work.

Primary references:

- [Create OSS Volumes](https://help.aliyun.com/zh/agent-sandbox/create-oss-volume)
- [Mount Volumes](https://help.aliyun.com/zh/agent-sandbox/mount-oss-volume-1)
- [Sandbox RAM roles](https://help.aliyun.com/zh/agent-sandbox/create-ram-role)
