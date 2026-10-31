# Session storage candidate

The P4 storage modules are an opt-in candidate. Profile version 2 wires them
into the real Server builder and managed Host launcher. Version 1 leaves
storage disabled. No production profile is activated, and cloud storage
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
operations for outputs. It does not grant Bucket administration. It is not an
attached role or proof of cross-session isolation; production role allocation
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
6. Implement authenticated artifact download and test permission revocation,
   path traversal and cross-session denial. A raw public OSS URL is insufficient.
7. Run the same checks through the complete Host/Runner, including its inner
   filesystem isolation, before marking P4 accepted.

Run the local adapter checks from the repository root after the frozen dev sync:

```bash
uv run pytest tests/saas/test_aliyun_storage.py \
  tests/saas/test_aliyun_volume_control.py \
  tests/saas/test_aliyun_sts_issuer.py \
  tests/saas/test_aliyun_storage_admission.py \
  tests/saas/test_aliyun_storage_launch.py \
  tests/saas/test_aliyun_server_profile.py \
  tests/saas/test_aliyun_server_composition.py -q
```

These checks use mocks and real pinned SDK code, not live cloud calls. The
separate `test_aliyun_storage_admission_postgresql.py` must run against a
disposable PostgreSQL test service. It uses an actual NOSUPERUSER/NOBYPASSRLS
login to verify Space binding inventory, including Project-bearing rows, and
transaction context clearing. A local skip is not RLS acceptance.

Primary references:

- [Create OSS Volumes](https://help.aliyun.com/zh/agent-sandbox/create-oss-volume)
- [Mount Volumes](https://help.aliyun.com/zh/agent-sandbox/mount-oss-volume-1)
- [Sandbox RAM roles](https://help.aliyun.com/zh/agent-sandbox/create-ram-role)
