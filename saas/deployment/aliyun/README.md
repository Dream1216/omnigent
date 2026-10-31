# Aliyun MicroVM Host candidate

This directory starts the P2 Host image work for the Aliyun sandbox integration.
It is a candidate build input, not a production admission or an activated provider.

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
  findings have no fixed version in that scan. The raw zero-High/zero-Critical
  and no-ignored gates remain unchanged.
- CI runs 41143681301 (`0d9b444bc`), 41148992698 (`1f19ebd3a`) and
  41151484102 (`73b992158`)
  passed repeat-build equality, provenance/SPDX and runtime checks for the
  complete minimal Host image. The latest raw scan has
  zero Critical, 10 High matches for four CVEs, and zero ignored matches. The
  same Perl, Expat and Kerberos findings block release; the complete image has
  not passed P2 admission.
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

The inactive [session storage candidate](storage.md) adds immutable Volume
planning and an STS-only control adapter. Server/launcher admission, real cloud
mounts, persistence, download authorization and P4 acceptance remain pending.

`.github/workflows/saas-aliyun-host-candidate.yml` builds two independent amd64
archives, checks non-root runtime against their exact OCI config/rootfs, requires
SLSA v1 plus SPDX, compares executable manifests/configs, and scans the exact
archive with a fresh vulnerability database. The Aliyun profile is separate
from the existing dual-architecture Server/Host profiles. The minimal profile
requires exactly three first-party labels and Linux amd64; it does not accept
the vendor base's inherited labels. The workflow has no
registry write or production deployment permissions.

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
