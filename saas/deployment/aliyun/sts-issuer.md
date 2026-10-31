# Volume control STS issuer candidate

`saas.production.aliyun_sts_issuer` renews the private STS file consumed by
profile-v2 storage. It is an explicit, separately operated process. Installing
the code does not start it or change IAM, an instance role, Kubernetes or the
production Server. Cloud issuance and unattended renewal still need acceptance.

## Identity and permission boundary

The issuer reads one explicitly named ECS instance role through IMDSv2 at the
fixed link-local endpoint. It uses that temporary identity to assume a separate
RAM role through the fixed Hangzhou HTTPS STS endpoint. The target credentials
last 900 seconds. Every request supplies a session policy containing only
`sandbox:CreateVolume`, `sandbox:GetVolume` and `sandbox:ListVolumes` for the
configured Hangzhou Team's Volume resources. It also supplies the canonical
Team UUID as `ExternalId` and a random, non-user role session name.

The source role must be explicitly authorized to assume that exact target role.
The target trust policy must accept only the reviewed source role and require
the exact `ExternalId`. Its attached permission policy should be the same
Team-scoped policy. Do not attach broad STS or Sandbox administration policies.

The source role's additional permission is limited to this target:

```json
{"Version":"1","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"<target-control-role-arn>"}]}
```

The target role's trust policy uses the reviewed source ARN and Team UUID:

```json
{"Version":"1","Statement":[{"Effect":"Allow","Principal":{"RAM":["<reviewed-source-role-arn>"]},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"<canonical-team-uuid>"}}}]}
```

These are three distinct identities:

| Identity | Purpose | Required permission |
|---|---|---|
| Source instance role | Bootstrap the issuer | Assume the one reviewed control role |
| Target control role | Server's Volume metadata calls | Create/Get/List Volumes for one Team |
| Sandbox mount role | MicroVM's OSS access | Restricted input/output object prefixes; trust `fc.aliyuncs.com` |

The source credentials stay in issuer memory. The Server receives only the
downscoped target credentials. The Host receives neither identity. VM teardown
continues through its existing E2B management identity and does not require this
issuer or delete Volumes.

## Explicit configuration and operation

Create an owner-only canonical JSON configuration with these exact fields.
Values below are examples; use reviewed deployment identities and the same
Team and credential path as the Server profile:

```json
{
  "schema_version": 1,
  "source_role_name": "reviewed-source-role",
  "role_arn": "acs:ram::1234567890123456:role/omnigent-volume-control",
  "team_id": "11111111-2222-4333-8444-555555555555",
  "credential_file": "/run/omnigent-aliyun/private/storage-sts.json"
}
```

Canonical bytes are sorted-key compact UTF-8 JSON followed by one newline.
Pin their SHA-256 in the process command. The configuration must be an
owner-only regular file without symlinks or hardlinks. Create the output parent
directory separately, with mode 0700 and the same numeric UID as the issuer and
Server. The Server mounts this directory read-only; the issuer has write access.
Do not project credentials with Kubernetes Secret symlinks.

Run from the qualified Server runtime, which selects the
`aliyun-sandbox-control` extra and pins both management SDKs:

```bash
python -m saas.production.aliyun_sts_issuer \
  --config /etc/omnigent/aliyun-sts-issuer.json \
  --config-sha256 <reviewed-config-sha256> --once

python -m saas.production.aliyun_sts_issuer \
  --config /etc/omnigent/aliyun-sts-issuer.json \
  --config-sha256 <reviewed-config-sha256>
```

The one-shot command must succeed before activating the storage profile.
Continuous mode refreshes every 300 seconds, retries failures after 30 seconds,
and stops on SIGINT/SIGTERM. Operate it under the deployment's process supervisor;
its failure and credential-readiness checks require monitoring. Exit status 0
from the following command proves only that the local file is currently valid:

```bash
python -m saas.production.aliyun_sts_issuer \
  --config /etc/omnigent/aliyun-sts-issuer.json \
  --config-sha256 <reviewed-config-sha256> --check
```

The process holds a nonblocking per-file lock while refreshing. It refuses an
unsafe output directory, symlinks, extra hardlinks, permissive files and unrelated
existing content. A temporary mode-0600 file is flushed and atomically renamed;
the directory is then synchronized. Network failures and failures before rename
retain the previous file. A failure synchronizing the directory after rename is
reported as a durability failure, even though a complete new file may be visible.
The consumer always validates the complete file and expiry before each cloud
operation. Expired credentials fail closed.

No SDK default credential chain, environment proxy, redirect or automatic HTTP
retry is used. Metadata access requires IMDSv2; there is no IMDSv1 fallback.
Source credentials must be temporary and currently valid, and the returned role
session ARN must match the requested target and session. Responses are bounded
to 32 KiB and accepted tokens to 16 KiB. Unexpected provider formats are rejected.
Logs contain refresh status and expiry, with fixed credential-free errors.

Before any cloud operation, render the exact target permission policy for review:

```bash
python -m saas.production.aliyun_sts_issuer \
  --config /etc/omnigent/aliyun-sts-issuer.json \
  --config-sha256 <reviewed-config-sha256> --print-policy
```

This command only validates the pinned configuration and prints its Team policy.
It does not read instance credentials, create a role or write an STS file.

## Deployment prerequisites and acceptance

1. Review the source-role grant and target-role trust/permissions before enabling
   the process. An existing instance role may belong to another service; a role
   name discovered on the node is not permission to repurpose it.
2. Verify IMDSv2 access from the actual issuer process. Restrict metadata access
   to the issuer; the Server and untrusted workloads must not receive the source
   role credentials. Endpoint reachability from SSH alone is insufficient.
3. Verify the target Team is enabled for Volumes and the SDK can perform its
   allowed operations. Confirm another Team and DeleteVolume are denied by IAM.
4. Verify initial publication, repeated refresh, Server restart and expiry
   without renewal. Confirm an outage leaves a complete file, readiness fails
   before invalid use, and VM cleanup remains available.
5. Revoke the source assumption grant and target role to verify denial. Restore
   only the reviewed grants and re-run the real storage lifecycle acceptance.

The current production cluster advertises an internal Kubernetes issuer/JWKS
endpoint. Its default ServiceAccount token cannot be assumed to work with
Alibaba Cloud OIDC. No control-plane issuer change or instance-role update has
been made. The account security verification and actual IAM setup remain open.

Local checks use the real pinned STS SDK/models/signing and mocked HTTP:

```bash
uv run pytest tests/saas/test_aliyun_sts_issuer.py \
  tests/saas/test_aliyun_volume_control.py -q
```

References: [ECS instance roles](https://help.aliyun.com/zh/ecs/user-guide/attach-an-instance-ram-role-to-an-ecs-instance),
[AssumeRole](https://help.aliyun.com/zh/ram/developer-reference/api-sts-2015-04-01-assumerole),
[Volume Team permissions](https://help.aliyun.com/zh/agent-sandbox/create-oss-volume).
