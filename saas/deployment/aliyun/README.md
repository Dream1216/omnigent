# Aliyun MicroVM Host candidate

This directory starts the P2 Host image work for the Aliyun sandbox integration.
It is a candidate build input, not a production admission or an activated provider.

On 2026-11-02 the project owner authorized advisory vulnerability counts for this
Aliyun integration. `--scope aliyun-host` retains the complete original Grype
report, Critical/High counts, scanner exit code, archive/report hashes and a fresh
database; findings produce a visible warning rather than a failed qualification.
Scanner errors, missing/malformed reports, ignored findings and a stale database
still fail. This does not qualify a template, change authentication, source or
signature checks, or replace real cloud/business and rollback acceptance.
The existing `complete` and `server-preflight` release scopes retain their policy.

The current boot experiment follows Aliyun support's recommendation to disable
chrony autostart after the complete ACR image reached system initialization and
timed out starting `chrony.service`. The package, binary and original unit remain
installed; the build verifies the unit is disabled, without masking it. A new
version and template must verify the actual clock, strict TLS and complete Host
tools. Explicit platform startup can still start a disabled unit, so this change
does not establish a root cause or qualify production use. Keep the failed
template for comparison.

The candidate uses a digest-pinned Debian sid rootfs with a hash-checked, signed
snapshot index dated 2026-10-30. It installs the required systemd, sshd, sudo,
chronyd, FUSE and iptables components, plus Git, tmux and bubblewrap. Python
3.13.18 and Node 22.23.4 come from digest-pinned official runtime images.
The official ossfs2 2.0.10 Debian artifact is SHA-256 pinned. Compiler and
development headers are confined to the builder rather than inherited by the
runtime. Debian's package database and real OS identity remain intact.

The original Aliyun Base template remains available as prerequisite evidence:
its generation-2 runtime, UID 1000 and namespace support were verified in cloud.
The new minimal candidate has only passed an isolated Docker runtime probe;
its MicroVM boot, storage mount and complete Host behavior remain unverified.
The original vendor-base candidates failed the raw vulnerability gate.

The old npm tree is removed before copying the pinned npm tree. Overlaying the
two versions left stale modules and made npm's install command fail, even while
`npm --version` still worked. The shared Node stage checks the install module.
That build-only npm check disables Node's compilation cache; V8 cache bytes
otherwise persisted in the shared base and differed between independent builds.
The candidate reuses the npm 12.2.0 materializer and SHA-512-locked security
overlays, including undici 6.29.1. The npm 10 graph from the Node image is not
retained. Python and CLI dependency repairs preserve the existing dependency
cooldown and frozen-lock checks.

The Host CLI stage reuses the repository's existing `.github/ci-deps` importer
and complete pnpm lock. It installs the reviewed CLI graph and checks Pi and
Codex readiness instead of downloading an unpinned harness at runtime. Their
presence does not constitute business acceptance for every installed harness.

The application is installed non-editably from the repository's frozen lock.
The source revision must be a real frozen candidate commit; the existing build
revision binder is used rather than claiming that a dirty context is production.
Server-only E2B management credentials, model credentials and private deployment
files are never copied into the image.

Build from the repository root, after the candidate source is committed:

```bash
build_output_root=$(mktemp -d /tmp/omnigent-aliyun-host.XXXXXX)
docker buildx build --platform linux/amd64 \
  -f saas/deployment/aliyun/Dockerfile.host \
  --build-arg SOURCE_REVISION="$(git rev-parse HEAD)" \
  --build-arg SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)" \
  -t omnigent-aliyun-host:candidate \
  --output "type=oci,dest=${build_output_root}/host.oci.tar,rewrite-timestamp=true" .
```

Use a bounded builder, retain its actual process/job handle, and record the image
config digest and registry manifest digest separately. Never restart a build
because its observation call timed out.

Remaining qualification:

- Repair the raw vulnerability findings. CI run 41137386035 passed independent
  rebuild comparison but reported 24 Critical and 233 High matches plus 929
  ignored Linux-header matches in the preceding vendor-base image. The minimal
  `runtime-base` diagnostic reports 10 High, zero Critical and zero ignored
  matches; it excludes the application, Node and harness layers and does not
  qualify the complete Host. The remaining Debian Perl, Expat and Kerberos
  findings have no fixed version in that scan. The then-required zero-High/zero-Critical
  and no-ignored gates remain unchanged.
- CI runs 41143681301 (`0d9b444bc`), 41148992698 (`1f19ebd3a`) and
  41151484102 (`73b992158`)
  passed repeat-build equality, provenance/SPDX and runtime checks for the
  complete minimal Host image. These historical scans reported
  zero Critical, 10 High matches for four CVEs, and zero ignored matches.
  Run 41182409678 on `50a4db091` also passed repeat-build comparison, but its
  newer raw scan reported zero Critical, 13 High and zero ignored matches;
  three glibc matches were added. The complete image has not passed P2 admission.
- Run real Host and bubblewrap checks in an Aliyun MicroVM.
- Check all linked libraries and the target harness under the non-root identity.
- Produce the required SBOM, scan, source provenance and repeat-build evidence.
- Publish to a reachable, appropriately scoped registry and verify digest.
- Create a new Host template; preserve the already-tested Base template.
- Complete SaaS provider/tenant/model-channel integration before production use.

The candidate [Server profile](server-profile.md) wires the scoped provider and
model broker into the production builder. Its optional model ingress reuses the
Server HTTPS origin with short bearer authentication and a fixed internal
gateway. It is disabled unless the profile selects that exact path. Actual
image/deployment, public streaming, cloud Host/Runner, storage and release
acceptance remain required.

The Aliyun Host uses the existing Claude hook retry extension with a fixed
12-consecutive-hard-failure limit, injected directly at Runner spawn. The
generic Host default remains 8. This keeps an approval pending through the
qualified 150-second connection refusal without enabling arbitrary environment
passthrough. The managed process policy, authorization rejection, token lifetime,
model revalidation and hook failure behavior remain in force. Twelve immediate
connection failures allow 211 seconds of backoff before failure; connection
attempt time adds to that value, so this is a retry-count limit, not an exact
211-second wall-clock timeout or an unlimited outage guarantee.

Reproduce the local approval recovery qualification with the frozen CLI versions
on `PATH` (Claude Code 2.1.266, Codex 0.139.0, tmux):

```bash
OMNIGENT_E2E_RESILIENCE_FULL=1 \
  .venv/bin/python -m pytest -o addopts= \
  -p tests.saas.aliyun_recovery_profile \
  tests/e2e/resilience/scenarios/test_s5_host_offline_user_acts.py \
  -k approve --runxfail -vv
```

The opt-in plugin applies the same fixed setting through the local lab's
explicit forwarding mechanism. It uses real local Host/Runner/CLI processes
and a mock model, and retains the original scenario assertions. It does not
exercise the cloud Host's launch authority, model relay or Aliyun network;
those still require cloud qualification. `--runxfail` makes the generic
Claude 150-second known gap a hard failure if this profile does not recover.

The opt-in [session storage candidate](storage.md) adds immutable Volume
planning, an STS-only control adapter and real Server/launcher admission behind
profile version 2; version 3 adds Project-scoped saved output listing and
authenticated download in desktop/mobile Files and Changes. Separate console
probes verified read-only input mounts and output persistence between two
disposable vendor Base VMs. A third disposable Base VM also verified a generated
79-byte UTF-8 input by exact hash under UID 1000, with writes refused by EROFS.
All three probe VMs were released. Managed Host mounts, deployed download authorization,
STS issuance and full P4 acceptance remain pending.

The separate [STS issuer candidate](sts-issuer.md) supplies 15-minute,
Team-scoped control credentials through an explicitly reviewed instance-role
chain. The profile can consume its atomically renewed file, but no issuer or
IAM grant is enabled by these changes. Source credentials stay outside the
Server and Host processes; actual renewal and permission denial need cloud proof.

`.github/workflows/saas-aliyun-host-candidate.yml` builds two independent amd64
archives, checks non-root runtime against their exact OCI config/rootfs, requires
SLSA v1 plus SPDX, compares executable manifests/configs, and scans the exact
archive with a fresh vulnerability database. The Aliyun profile is separate
from the existing dual-architecture Server/Host profiles. The minimal profile
requires exactly three first-party labels and Linux amd64; it does not accept
the vendor base's inherited labels. Normal builds have read-only permissions.
The explicit `promote-reviewed-gen2` dispatch takes an exact `source_revision`
and `source_run`. It requires a successful Gen2 build from this repository and
candidate branch, including both runtime jobs and the comparison/scan job.
It transfers the two original OCI artifacts selected from that native run,
verifies their source/run/attempt identities and native ZIP digests,
repeats the exact rebuild comparison, scans with a fresh database, and binds raw
scan/image identities before publishing to the private `omnigent-aliyun-host`
GHCR package. It verifies full registry readback and signs a promotion receipt
with the publisher workflow identity; the receipt retains the original build
revision and SLSA/SPDX. No image is rebuilt or relabeled. This dispatch has only
the registry and attestation writes it needs, and no production deploy step.
A signature from this candidate branch proves its publisher identity; it does
not substitute for protected production source acceptance or real cloud tests.
The target package must already exist and its live visibility must be `private`
before transfer and after registry readback. The publisher never assumes registry
defaults or creates a package with unchecked visibility. The first publication
exposed this missing check; the owner-scoped package was corrected to private
and independently verified with the dedicated read-only credential before any
Aliyun template submission.

The opt-in `qualify-poc-alias` dispatch works around the observed Hangzhou Gen2
builder requesting `/manifests/latest` despite a fixed source tag in the stored
template. It verifies the existing promotion signature for the exact 8b5a34db
index and the private package, then creates `latest` only if it is absent or
already resolves to that same index. A different existing alias is rejected.
Both the fixed source tag and alias are checked after the operation. This is a
bounded template compatibility probe, with a retained receipt and no rebuild,
new image identity, vulnerability suppression or production deployment.

Historical zero-finding rejection decisions below reflect the policy at the time.
The 13-High complete Gen2 candidate can now advance to a fresh advisory scan and
publication/template validation with its original source identity; those findings
have not been fixed or removed. The stable-base experiment with more findings is
not selected for this accelerated path.

Package installation generates SSH host keys and a machine identity. The
Dockerfile removes those keys and resets the identity in the installation layer;
it also clears package logs and normalizes the installed Python tree. The initial
service-complete `98910699b` artifact predates those changes and cannot be
published as the qualified template. Rebuild the frozen repaired source and
compare independent rebuilds with timestamp rewriting enabled.

No production configuration or existing deployment is changed by these files.

The initial `b2a5b3167` build and constrained local runtime checks are recorded
under `saas/acceptance/aliyun/2026-10-31/`. Those checks do not qualify MicroVM
boot or full Host isolation. Namespace creation was refused by the constrained
local Docker kernel, but a separate prerequisite probe using the same bwrap
binary passed under UID 1000 in the original generation-2 Base MicroVM. That
probe's sandbox was terminated and absence confirmed. The temporary template
created through the generic E2B Template
SDK used generation 1 and has been deleted. An explicitly verified generation-2
template is still required.
