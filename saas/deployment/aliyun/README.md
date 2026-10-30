# Aliyun MicroVM Host candidate

This directory starts the P2 Host image work for the Aliyun sandbox integration.
It is a candidate build input, not a production admission or an activated provider.

The pinned Aliyun base was inspected in a real cloud sandbox and an isolated
Docker probe. The original Base template is generation 2, verified through the
console GetTemplate response. Its inventory is Debian 13.4, Python
3.13.13, non-root UID 1000, Node 20.20.2 and ossfs2. The image lacks Omnigent,
tmux and bubblewrap. The initial candidate also lacked sshd, chronyd and iptables,
although the cloud sandbox exposed additional system services. The Dockerfile
now installs the required MicroVM packages explicitly, uses signed Debian
snapshot indexes dated 2026-10-30, and checks their executables at build time.
It copies Node from a pinned amd64 Node 22 image to meet the Node 22.13 floor.

The application is installed non-editably from the repository's frozen lock.
The source revision must be a real frozen candidate commit; the existing build
revision binder is used rather than claiming that a dirty context is production.
Server-only E2B management credentials, model credentials and private deployment
files are never copied into the image.

Build from the repository root, after the candidate source is committed:

```bash
docker buildx build --platform linux/amd64 \
  -f saas/deployment/aliyun/Dockerfile.host \
  --build-arg SOURCE_REVISION="$(git rev-parse HEAD)" \
  --build-arg SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)" \
  -t omnigent-aliyun-host:candidate --load .
```

Use a bounded builder, retain its actual process/job handle, and record the image
config digest and registry manifest digest separately. Never restart a build
because its observation call timed out.

Remaining qualification:

- Build and verify the repaired candidate with the pinned Debian snapshot inputs.
- Run real Host and bubblewrap checks in an Aliyun MicroVM.
- Check all linked libraries and the target harness under the non-root identity.
- Produce the required SBOM, scan, source provenance and repeat-build evidence.
- Publish to a reachable, appropriately scoped registry and verify digest.
- Create a new Host template; preserve the already-tested Base template.
- Complete SaaS provider/tenant/model-channel integration before production use.

No production configuration or existing deployment is changed by these files.

The initial `b2a5b3167` build and constrained local runtime checks are recorded
under `saas/acceptance/aliyun/2026-10-31/`. Those checks do not qualify MicroVM
boot or bubblewrap: namespace creation was refused by the constrained local
Docker kernel. The temporary template created through the generic E2B Template
SDK used generation 1 and has been deleted. An explicitly verified generation-2
template is still required.
