# Session storage candidate

The P4 storage modules are an inactive candidate. They are not wired into the
Server profile or Host launcher and do not satisfy cloud storage acceptance.
No Bucket, RAM role, STS credential or Volume is created by installing them.

`saas/production/aliyun_storage.py` defines immutable, deterministic OSS Volume
plans for one admitted Tenant, physical Workspace, Space and Session. Inputs
mount read-only at `/home/user/workspace/inputs`; outputs mount read-write at
`/home/user/workspace/artifacts`. Each uses a separate session prefix. Git and
dependency working trees remain on local storage. These are planned mounts;
their visibility inside the actual Host/Runner still needs verification.

The Volume manager requires an authorization callback. It must resolve the real
Session owner and resource binding and freshly validate Tenant, Space, Project,
membership and execution permission. A logging context, caller-supplied Session
ID or missing resource row is not sufficient authority. No production callback
is implemented yet. Before cloud operations and after readiness waits, the
manager checks both the callback result and current runtime context. Revocation
stops further operations. The final check precedes returning the mount plan.

Volume names include a hash of all immutable mount parameters. Existing cloud
metadata must match the exact Team, Bucket prefix, role, endpoint and read mode.
A timeout during creation triggers a name lookup rather than a blind replay.
Readiness checks are bounded. VM cleanup must retain these Volumes and OSS data;
the manager has no data-deletion operation.

`saas/production/aliyun_volume_control.py` uses generated API models and signing
from `alibabacloud-sandbox20260820==1.2.0`. The optional
`aliyun-sandbox-control` dependency is intended for the Server. The Host image
does not install this extra. The current Server image also needs to select and
verify the extra before storage can be enabled.

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
An issuer/renewal process and its real authorization remain to be implemented.
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
3. Implement authoritative Session admission, Server configuration and rotating
   STS issuance. Retain cleanup access when execution permission is revoked.
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
  tests/saas/test_aliyun_volume_control.py -q
```

The checks use mocks and real pinned SDK code. They do not make live cloud calls.

Primary references:

- [Create OSS Volumes](https://help.aliyun.com/zh/agent-sandbox/create-oss-volume)
- [Mount Volumes](https://help.aliyun.com/zh/agent-sandbox/mount-oss-volume-1)
- [Sandbox RAM roles](https://help.aliyun.com/zh/agent-sandbox/create-ram-role)
