# Aliyun MicroVM Host candidate

This directory starts the P2 Host image work for the Aliyun sandbox integration.
It is a candidate build input, not a production admission or an activated provider.

The pinned Aliyun base was inspected in a real MicroVM and an isolated Docker
probe: Debian 13.4, Python 3.13.13, non-root UID 1000, Node 20.20.2. It contains
the MicroVM system services and ossfs2, but no Omnigent, tmux or bubblewrap. Node
20 also falls below Omnigent's Node 22.13 floor. The candidate retains the base,
adds the missing tools and copies Node from a pinned amd64 Node 22 image.

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

- Resolve and freeze the Debian package/snapshot inputs after the initial build.
- Run real Host and bubblewrap checks in an Aliyun MicroVM.
- Check all linked libraries and the target harness under the non-root identity.
- Produce the required SBOM, scan, source provenance and repeat-build evidence.
- Publish to a reachable, appropriately scoped ACR repository and verify digest.
- Create a new Host template; preserve the already-tested Base template.
- Complete SaaS provider/tenant/model-channel integration before production use.

No production configuration or existing deployment is changed by these files.
