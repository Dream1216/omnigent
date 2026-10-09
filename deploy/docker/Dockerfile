# Omnigent images: server (default target) + host (`--target host`).
#
# The default/final target builds the server image (external-runner
# mode): the FastAPI / WebSocket coordinator — HTTP + SSE routes, the
# runner WebSocket tunnel acceptor, and the SQLAlchemy stores. It does
# NOT execute agent harnesses — runners run on the user's local machine
# and dial in via WS /v1/runner/tunnel.
#
# The image also supplies the SaaS worker and Runner control-plane processes.
# Git is required there for sealed repository mirror provisioning, while tmux
# and harness SDK runtime requirements remain host-only. The omnigent package is
# installed in full (its pyproject pulls claude-agent-sdk +
# openai-agents transitively), so the bits are on disk; they are
# simply never imported because HarnessProcessManager is never
# invoked in this deployment mode.
#
# The `host` target is the inverse: a prebaked Omnigent HOST image for
# remote sandboxes (e.g. `omnigent sandbox create --provider modal`)
# and server-launched managed hosts. It bakes the full omnigent
# install plus the tools a host needs at runtime — git (workspaces /
# worktrees), tmux (terminal sessions spawned by native harnesses),
# and the coding-harness CLIs (claude / codex / pi, via Node; kiro-cli via
# Kiro's installer) — and
# skips everything server-only: no SPA bundle, no psycopg, no
# uvicorn entrypoint. Modal's `Image.from_registry` requirements shape
# it: `python` + `pip` on $PATH, and CMD-only (an ENTRYPOINT that
# doesn't exec its args would block Modal's own runtime from running).
#
# Both images publish multi-arch (linux/amd64 + linux/arm64) — see
# .github/workflows/oss-publish-images.yml — so they run natively on
# arm64 hosts (Apple Silicon laptops, arm64 clusters) as well as amd64.
# Nothing below is arch-specific: the python/node base images are
# multi-arch and apt/pip/npm/COPY-from-node all resolve per-arch under
# buildx. Amd64-only consumers (Modal, Daytona, CoreWeave) keep pulling
# the amd64 variant from the manifest list, unchanged.
#
# Build (from repo root):
#
#   docker build -t omnigent-server:latest \
#                -f deploy/docker/Dockerfile .
#
#   docker build -t omnigent-host:latest --target host \
#                -f deploy/docker/Dockerfile .
#
# To bake extra harness CLIs into a host image beyond the default set, build
# with EXTRA_HARNESS_CLIS="goose jcode opencode" — harness names, optional
# @version pins, or npm:<pkg-spec> entries (see deploy/docker/README.md and
# deploy/docker/install-harness-cli.sh for the supported names).
#
# Behind corporate package proxies (the host target also installs the
# harness CLIs from npm, so it needs the npm proxy too):
#
#   docker build -t omnigent-server:latest \
#                -f deploy/docker/Dockerfile \
#                --build-arg PYPI_INDEX_URL=https://pypi-proxy.example.com/simple \
#                --build-arg NPM_CONFIG_REGISTRY=https://npm-proxy.example.com .
#
# Or just use the bundled compose file (Postgres included):
#
#   cd deploy/docker && docker compose up -d

# Must satisfy pyproject requires-python (>=3.12); 3.11 fails dependency resolution.
ARG PYTHON_VERSION=3.12
ARG NODE_VERSION=22
ARG UV_VERSION=0.12.1
ARG PNPM_VERSION=12.10.1
ARG NPM_VERSION=12.2.0
ARG PYTHON_IMAGE=python:${PYTHON_VERSION}-slim
ARG RUNTIME_IMAGE=debian:sid-slim
ARG RUNTIME_APT_SNAPSHOT=20261009T000000Z
ARG NODE_IMAGE=node:${NODE_VERSION}-slim
ARG SOURCE_DATE_EPOCH=1580601600
ARG SOURCE_REVISION=unknown
ARG UPSTREAM_REVISION=unknown
ARG CONTROL_PLANE_SCHEMA_REVISION=unknown
ARG ADAPTER_CONTRACT_VERSION=unknown

# ── Web UI builder ──────────────────────────────────────
# Builds the web SPA so `docker build` works from a clean checkout —
# no separate `cd web && npm run build` step, no "SPA bundle missing"
# hard-fail. vite.config emits to ../omnigent/server/static/web-ui
# (relative to web/), so from /web/web the bundle lands at
# /web/omnigent/server/static/web-ui, which the server builder overlays.
# Server-only: the host target never reaches this stage.
#
# Behind a corporate npm proxy, pass it through:
#   --build-arg NPM_CONFIG_REGISTRY=https://npm-proxy.example.com
FROM --platform=$BUILDPLATFORM ${NODE_IMAGE} AS web-builder
ARG NPM_CONFIG_REGISTRY=
ARG PNPM_VERSION
ENV NPM_CONFIG_REGISTRY=${NPM_CONFIG_REGISTRY}
WORKDIR /web

# Workspace manifests + lockfile first so the install layer caches across pure
# source edits. The electron package JSON is included so the root workspace is
# structurally complete, but we --filter web to avoid downloading Electron.
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY web/package.json ./web/
COPY web/electron/package.json ./web/electron/

RUN npm install -g "pnpm@${PNPM_VERSION}" \
 && test "$(pnpm --version)" = "${PNPM_VERSION}"
RUN pnpm install --frozen-lockfile --filter web

COPY web/ ./web/
RUN pnpm --filter web run build

# The login is an isolated Next.js / React 18 export; no Node service is added.
FROM --platform=$BUILDPLATFORM ${NODE_IMAGE} AS login-web-builder
ARG NPM_CONFIG_REGISTRY=
ARG SOURCE_DATE_EPOCH
ARG SOURCE_REVISION
ENV NPM_CONFIG_REGISTRY=${NPM_CONFIG_REGISTRY} \
    NEXT_TELEMETRY_DISABLED=1 \
    OMNIGENT_SOURCE_REVISION=${SOURCE_REVISION}
WORKDIR /login/saas/login_web
COPY saas/login_web/package.json saas/login_web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY saas/login_web/ ./
RUN case "${SOURCE_DATE_EPOCH}" in *[!0-9]*|'') exit 2 ;; esac \
 && npm run build \
 && find /login/saas/login_ui/static -depth -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

# ── Python builder (shared: server + host) ──────────────
# Installs the package (and its transitive native-extension deps) into
# a virtualenv the runtime stages copy verbatim. Keeps build-essential
# out of the shipped images. Deliberately SPA-free and psycopg-free so
# the host target can build without node; the server-only additions
# live in server-builder below.
FROM ${PYTHON_IMAGE} AS python-runtime

FROM python-runtime AS builder

ARG PYPI_INDEX_URL=https://pypi.org/simple
ARG SOURCE_DATE_EPOCH
ARG SOURCE_REVISION
ARG UV_VERSION

ENV PYTHONDONTWRITEBYTECODE=1 \
    UV_NO_INSTALLER_METADATA=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

# Docker Official Images records the exact Debian archive snapshots used to
# assemble python-slim as comments beside its rolling URIs. Activate only those
# base-matched snapshots and fail closed if that two-archive contract changes.
RUN export DEBIAN_FRONTEND=noninteractive; \
    case "${SOURCE_DATE_EPOCH}" in *[!0-9]*|'') exit 2 ;; esac; \
    python -B -c 'import platform, re; from pathlib import Path; path=Path("/etc/apt/sources.list.d/debian.sources"); source=path.read_text(encoding="utf-8"); pattern=re.compile(r"(?m)^# (http://snapshot[.]debian[.]org/archive/(?:debian|debian-security)/[0-9]{8}T[0-9]{6}Z)\nURIs: http://deb[.]debian[.]org/(?:debian|debian-security)$"); normalized,count=pattern.subn(lambda match: f"# {match.group(1)}\nURIs: {match.group(1)}", source); assert count == 2, f"expected two Debian snapshot sources, found {count}"; uris=re.findall(r"(?m)^URIs: (\S+)$", normalized); assert len(uris) == 2 and all(re.fullmatch(r"http://snapshot[.]debian[.]org/archive/(?:debian|debian-security)/[0-9]{8}T[0-9]{6}Z", uri) for uri in uris), uris; assert sum("/archive/debian/" in uri for uri in uris) == 1 and sum("/archive/debian-security/" in uri for uri in uris) == 1, uris; codename=platform.freedesktop_os_release()["VERSION_CODENAME"]; suites=re.findall(r"(?m)^Suites: (.+)$", normalized); assert len(suites) == 2 and set(suites) == {f"{codename} {codename}-updates", f"{codename}-security"}, suites; path.write_text(normalized, encoding="utf-8"); print(f"Debian snapshot coordinates ({codename}): {uris}")' \
 && python -B -c 'from pathlib import Path; primary=Path("/etc/apt/sources.list.d/debian.sources"); root=primary.parent; candidates=[Path("/etc/apt/sources.list"), *sorted(root.glob("*.list")), *sorted(root.glob("*.sources"))]; unexpected=[str(candidate) for candidate in candidates if candidate != primary and candidate.is_file() and any(line.strip() and not line.lstrip().startswith("#") for line in candidate.read_text(encoding="utf-8", errors="replace").splitlines())]; assert not unexpected, f"unexpected additional apt sources: {unexpected}"; assert "deb.debian.org" not in primary.read_text(encoding="utf-8"), "rolling Debian mirror remains enabled"' \
 && apt-get -o Acquire::Check-Valid-Until=false -o Acquire::Retries=10 -o Acquire::http::Timeout=30 update \
 && apt-get -o Acquire::Check-Valid-Until=false -o Acquire::Retries=10 -o Acquire::http::Timeout=30 install -y --no-install-recommends \
      build-essential \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/* \
 && find /var/log -type f -delete \
 && rm -f /var/cache/ldconfig/aux-cache \
      /var/log/alternatives.log /var/log/dpkg.log \
      /var/log/apt/eipp.log.xz /var/log/apt/history.log /var/log/apt/term.log

RUN pip install --index-url ${PYPI_INDEX_URL} --no-cache-dir "uv==${UV_VERSION}" \
 && case "$(uv --version)" in "uv ${UV_VERSION}"|"uv ${UV_VERSION} "*) ;; \
      *) echo "ERROR: uv version mismatch" >&2; exit 1 ;; esac

WORKDIR /build

# Manifests + SDK path-deps first so the install layer caches across
# pure source edits.
COPY pyproject.toml setup.py uv.lock ./
# License + third-party attribution travel into the published images (the host
# and runtime targets COPY /build below), since the image redistributes the
# dependency bytes baked in by the install step.
COPY LICENSE NOTICE ./
COPY sdks/ ./sdks/
COPY omnigent/ ./omnigent/
COPY saas/ ./saas/
COPY integrations/slack/ ./integrations/slack/
# The built-in polly agent's packaged bundle (omnigent/resources/examples/
# polly) is a symlink into the top-level examples/ tree. Ship examples/ so the
# symlink resolves at boot; without it the new-session picker silently drops
# polly (the seeder skips it when its bundle is absent). ~120K of YAML.
COPY examples/ ./examples/

# Standalone venv we can copy out as a single directory. VIRTUAL_ENV
# tells uv to install into this venv (not the slim image's system
# Python) — without it, uv falls back to system Python and the
# copied /opt/venv lands in the runtime stage empty.
# Keep ensurepip's deterministic seed bytecode, reject volatile installer state,
# then normalize the installed venv, materialize a metadata-free canonical
# export tree for the host COPY layer, and normalize /build.
RUN python -m venv /opt/venv \
 && python -B -I -c 'import hashlib; from pathlib import Path; root=Path("/opt/venv"); print("\n".join(f"{path.relative_to(root)} {hashlib.sha256(path.read_bytes()).hexdigest()}" for path in sorted(root.rglob("*.pyc"))))' \
      > /tmp/venv-seed-pyc.sha256
ENV VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:${PATH}"

# The Dockerfile-specific context intentionally excludes ``.github/``. The
# repository uv workspace declares ``.github/triage_v2`` there, so blindly
# invoking uv would fail workspace discovery even though that automation
# package is not part of either runtime image. Remove only the workspace
# discovery stanza from the copied (image-local) manifest; the committed lock
# remains authoritative and ``--package omnigent`` selects the root package.
RUN sed -i '/^\[tool\.uv\.workspace\]$/,/^$/d' pyproject.toml

# Consume the committed lock without resolution. ``--active`` binds the sync
# to /opt/venv and ``--no-editable`` makes the root package and SDK path deps
# self-contained, so the host image never needs a second dependency-resolving
# pip install to escape /build/*.pth references.
RUN uv sync --frozen --active --package omnigent --no-dev --no-editable --no-cache \
 && if [ "${SOURCE_REVISION}" != "unknown" ]; then \
      /opt/venv/bin/python -B -I /build/saas/scripts/bind_runtime_build_revision.py \
        --source-revision "${SOURCE_REVISION}" \
        --source-date-epoch "${SOURCE_DATE_EPOCH}"; \
    fi \
 && python -B -I -c 'import hashlib; from pathlib import Path; root=Path("/opt/venv"); bad=sorted(root.rglob("uv_cache.json")); assert not bad, bad; print("\n".join(f"{path.relative_to(root)} {hashlib.sha256(path.read_bytes()).hexdigest()}" for path in sorted(root.rglob("*.pyc"))))' \
      > /tmp/venv-core-pyc.sha256 \
 && cmp -s /tmp/venv-seed-pyc.sha256 /tmp/venv-core-pyc.sha256 \
 && python -B -I /build/saas/scripts/normalize_host_cli_tree.py --root /opt/venv --source-date-epoch "${SOURCE_DATE_EPOCH}" && tar --sort=name --format=gnu --mtime="@${SOURCE_DATE_EPOCH}" --owner=0 --group=0 --numeric-owner -C /opt -cf /tmp/venv.tar venv && mkdir /opt/venv-export && tar -C /opt/venv-export --strip-components=1 -xf /tmp/venv.tar && rm -f /tmp/venv.tar \
 && find /build -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

# ── Server builder ──────────────────────────────────────
# Server-only additions on top of the shared builder: the SPA bundle
# and the Postgres driver.
FROM builder AS server-builder

ARG PYPI_INDEX_URL=https://pypi.org/simple
ARG PSYCOPG_VERSION=3.3.4
ARG SOURCE_REVISION

# Overlay the SPA bundle built in the web-builder stage, so a clean
# checkout (with no prebuilt bundle on the host) still produces a
# complete image. This replaces the old "prebuild or hard-fail" check.
COPY --from=web-builder /web/omnigent/server/static/web-ui ./omnigent/server/static/web-ui
COPY --from=login-web-builder /login/saas/login_ui/static ./saas/login_ui/static
RUN test -f ./omnigent/server/static/web-ui/index.html \
    || (echo "ERROR: SPA bundle missing after web-builder stage — check the web build." && exit 1)

# Optional managed-sandbox provider extras for the SERVER (the launcher imports
# the provider SDK — e.g. the kubernetes client for `sandbox.provider:
# kubernetes`). Off by default; the runner host image needs none of these. Build
# with `--build-arg OMNIGENT_EXTRAS=kubernetes` (comma-separate for several).
ARG OMNIGENT_EXTRAS=
RUN set -eu; \
    set -- --extra saas; \
    if [ -n "${OMNIGENT_EXTRAS}" ]; then \
        extras="$(printf '%s' "${OMNIGENT_EXTRAS}" | tr ',' ' ')"; \
        for extra in ${extras}; do \
            case "${extra}" in \
              *[!A-Za-z0-9_-]*|'') \
                echo "ERROR: invalid OMNIGENT_EXTRAS entry '${extra}'" >&2; exit 1 ;; \
            esac; \
            set -- "$@" --extra "${extra}"; \
        done; \
    fi; \
    uv sync --frozen --active --package omnigent --no-dev --no-editable \
      --no-cache --reinstall-package omnigent "$@"; \
    if [ "${SOURCE_REVISION}" != "unknown" ]; then \
      /opt/venv/bin/python -B -I /build/saas/scripts/bind_runtime_build_revision.py \
        --source-revision "${SOURCE_REVISION}" \
        --source-date-epoch "${SOURCE_DATE_EPOCH}"; \
    fi; \
    installed="$(python -c 'import importlib.metadata as m; print(m.version("psycopg"))')"; \
    [ "${installed}" = "${PSYCOPG_VERSION}" ] || { \
      echo "ERROR: uv.lock installed psycopg ${installed}, expected ${PSYCOPG_VERSION}." >&2; \
      exit 1; \
    }; \
    python -B -I -c 'import hashlib; from pathlib import Path; root=Path("/opt/venv"); bad=sorted(root.rglob("uv_cache.json")); assert not bad, bad; print("\n".join(f"{path.relative_to(root)} {hashlib.sha256(path.read_bytes()).hexdigest()}" for path in sorted(root.rglob("*.pyc"))))' \
      > /tmp/venv-server-pyc.sha256; \
    cmp -s /tmp/venv-seed-pyc.sha256 /tmp/venv-server-pyc.sha256; \
    python -B -I ./saas/scripts/normalize_host_cli_tree.py \
      --root=/opt/venv --source-date-epoch="${SOURCE_DATE_EPOCH}"; \
    find /opt/venv /build -depth -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +; tar --sort=name --format=gnu --mtime="@${SOURCE_DATE_EPOCH}" --owner=0 --group=0 --numeric-owner -C /opt -cf /tmp/server-venv.tar venv; mkdir /opt/server-venv-export; tar -C /opt/server-venv-export --strip-components=1 -xf /tmp/server-venv.tar; rm -f /tmp/server-venv.tar

# ── Authenticated runtime security overlays ──────────────
# Build the narrow remediations against the same Sid runtime used by the final
# images. Every source artifact is hash-pinned, upstream keys are fingerprint-
# bound, and signatures are verified before compilation; the build script also
# runs each upstream suite.
FROM ${RUNTIME_IMAGE} AS runtime-security-builder
ARG SOURCE_DATE_EPOCH
ARG RUNTIME_APT_SNAPSHOT
# Bind the parent layer to this revision before any COPY. A cached COPY from a
# previous revision otherwise retains that revision's rewritten OCI mtime.
RUN case "${SOURCE_DATE_EPOCH}" in *[!0-9]*|'') exit 2 ;; esac; \
    install -d /opt /runtime-security-input \
 && touch -h -d "@${SOURCE_DATE_EPOCH}" /opt /runtime-security-input
COPY --from=python-runtime /usr/local /usr/local
COPY saas/scripts/activate_debian_sid_snapshot.py /runtime-security-input/activate_debian_sid_snapshot.py
RUN export DEBIAN_FRONTEND=noninteractive; \
    case "${SOURCE_DATE_EPOCH}" in *[!0-9]*|'') exit 2 ;; esac; \
    python -B /runtime-security-input/activate_debian_sid_snapshot.py --snapshot "${RUNTIME_APT_SNAPSHOT}" \
 && python -B -c 'from pathlib import Path; primary=Path("/etc/apt/sources.list.d/debian.sources"); root=primary.parent; candidates=[Path("/etc/apt/sources.list"), *sorted(root.glob("*.list")), *sorted(root.glob("*.sources"))]; unexpected=[str(candidate) for candidate in candidates if candidate != primary and candidate.is_file() and any(line.strip() and not line.lstrip().startswith("#") for line in candidate.read_text(encoding="utf-8", errors="replace").splitlines())]; assert not unexpected, f"unexpected additional apt sources: {unexpected}"; assert "deb.debian.org" not in primary.read_text(encoding="utf-8"), "rolling Debian mirror remains enabled"' \
 && apt-get -o Acquire::Check-Valid-Until=false -o Acquire::Retries=10 -o Acquire::http::Timeout=30 update \
 && apt-get -o Acquire::Check-Valid-Until=false -o Acquire::Retries=10 -o Acquire::http::Timeout=30 install -y --no-install-recommends \
      autoconf automake build-essential ca-certificates curl dpkg-dev gnupg gpgv \
      libtool patch perl pkg-config xz-utils \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/* \
 && find /var/log -type f -delete \
 && rm -f /var/cache/ldconfig/aux-cache \
      /var/log/alternatives.log /var/log/dpkg.log \
      /var/log/apt/eipp.log.xz /var/log/apt/history.log /var/log/apt/term.log
COPY saas/scripts/build_runtime_security_overlays.sh /runtime-security-input/build.sh
COPY saas/supply_chain/gcc-aligned-new-runtime-boundary.cc /runtime-security-input/gcc-aligned-new-runtime-boundary.cc
RUN /runtime-security-input/build.sh /opt/runtime-security \
 && rm -rf /runtime-security-input

# Runtime-only base. Python comes from the immutable official Python image;
# distro packages and all security overlays come from the immutable Sid image.
FROM ${RUNTIME_IMAGE} AS secured-python-runtime
ARG SOURCE_DATE_EPOCH
ARG RUNTIME_APT_SNAPSHOT
# Invalidate cached COPY layers when the source revision's epoch changes.
RUN case "${SOURCE_DATE_EPOCH}" in *[!0-9]*|'') exit 2 ;; esac; \
    install -d /opt /tmp \
 && touch -h -d "@${SOURCE_DATE_EPOCH}" /opt /tmp
COPY --from=python-runtime /usr/local /usr/local
COPY --from=runtime-security-builder /opt/runtime-security /opt/runtime-security
COPY saas/scripts/activate_debian_sid_snapshot.py /tmp/activate_debian_sid_snapshot.py
RUN export DEBIAN_FRONTEND=noninteractive; \
    case "${SOURCE_DATE_EPOCH}" in *[!0-9]*|'') exit 2 ;; esac; \
    python -B /tmp/activate_debian_sid_snapshot.py --snapshot "${RUNTIME_APT_SNAPSHOT}" \
 && python -B -c 'from pathlib import Path; primary=Path("/etc/apt/sources.list.d/debian.sources"); root=primary.parent; candidates=[Path("/etc/apt/sources.list"), *sorted(root.glob("*.list")), *sorted(root.glob("*.sources"))]; unexpected=[str(candidate) for candidate in candidates if candidate != primary and candidate.is_file() and any(line.strip() and not line.lstrip().startswith("#") for line in candidate.read_text(encoding="utf-8", errors="replace").splitlines())]; assert not unexpected, f"unexpected additional apt sources: {unexpected}"; assert "deb.debian.org" not in primary.read_text(encoding="utf-8"), "rolling Debian mirror remains enabled"' \
 && apt-get -o Acquire::Check-Valid-Until=false -o Acquire::Retries=10 -o Acquire::http::Timeout=30 update \
 && apt-get -o Acquire::Check-Valid-Until=false -o Acquire::Retries=10 -o Acquire::http::Timeout=30 install -y --no-install-recommends \
      ca-certificates curl libbz2-1.0 libexpat1 libffi8 liblzma5 \
      libreadline8t64 libsqlite3-0 libstdc++6 perl zlib1g \
 && multiarch="$(python -B -c 'import sysconfig; print(sysconfig.get_config_var("MULTIARCH"))')" \
 && install -m 0644 /opt/runtime-security/zlib/libz.so.1.3.2 "/usr/lib/${multiarch}/libz.so.1.3.2" \
 && install -d /usr/local/share/perl/5.42.3/Pod \
 && cp -a /opt/runtime-security/perl/Pod/. /usr/local/share/perl/5.42.3/Pod/ \
 && cp /opt/runtime-security/pyexpat/pyexpat*.so /usr/local/lib/python3.12/lib-dynload/ \
 && ldconfig \
 && test ! -d /usr/include/c++ \
 && /opt/runtime-security/gcc/aligned-new-runtime-boundary \
 && python -B -I -c 'import bz2, ctypes, lzma, pyexpat, readline, sqlite3, ssl, zlib; assert pyexpat.EXPAT_VERSION == "expat_2.9.0", pyexpat.EXPAT_VERSION; assert zlib.ZLIB_RUNTIME_VERSION == "1.3.2", zlib.ZLIB_RUNTIME_VERSION' \
 && perl -MPod::Text -e 'die unless $Pod::Text::VERSION eq q(v6.1.1)' \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/* /opt/runtime-security \
 && find /var/log -type f -delete \
 && rm -f /tmp/activate_debian_sid_snapshot.py \
 && rm -f /var/cache/ldconfig/aux-cache \
      /var/log/alternatives.log /var/log/dpkg.log \
      /var/log/apt/eipp.log.xz /var/log/apt/history.log /var/log/apt/term.log

# ── Node alias stage ─────────────────────────────────────
# Pure alias so the host stage can COPY node out of a version-pinned
# image; contributes no layers of its own.
FROM ${NODE_IMAGE} AS node-runtime

# Replace the base image's bundled npm graph with a content-pinned release.
FROM builder AS npm-builder
ARG NPM_VERSION
ARG NPM_INTEGRITY=sha512-ZsJjKpTnlmSXOLLXiU1xDCzC4Wlok4IwZmh/aw2KUuXytU7q6qMv/cUT7MoeSf95Slwuw/lRXYefGzGCspHPNQ==
ARG SOURCE_DATE_EPOCH
RUN python -B -I /build/saas/scripts/materialize_npm_release.py \
      --version "${NPM_VERSION}" --integrity "${NPM_INTEGRITY}" \
      --security-lock /build/saas/supply_chain/npm-122-security-lock.json \
      --destination /opt/npm-export \
 && python -B -I /build/saas/scripts/normalize_host_cli_tree.py \
      --root /opt/npm-export --source-date-epoch "${SOURCE_DATE_EPOCH}"

# Materialize the pinned GitHub CLI outside the host rootfs. The final host
# receives only this fixed-content, fixed-mode file through a COPY layer.
FROM builder AS gh-builder
ARG TARGETARCH
ARG SOURCE_DATE_EPOCH
ARG GH_VERSION=2.102.0
ARG GH_SHA256_AMD64=bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386
ARG GH_SHA256_ARM64=7862c86c72f43df3a2d93ddde6f473285b4e2af61b494849846827e513ef6484
RUN set -eu; \
    downloaded=; \
    for attempt in 1 2 3 4 5; do \
      if python -B -c 'import hashlib, io, os, sys, tarfile, urllib.request; from pathlib import Path; arch, version, amd64_sha, arm64_sha, epoch_raw=sys.argv[1:]; expected={"amd64": amd64_sha, "arm64": arm64_sha}[arch]; asset=f"gh_{version}_linux_{arch}.tar.gz"; data=urllib.request.urlopen(f"https://github.com/cli/cli/releases/download/v{version}/{asset}", timeout=120).read(); actual=hashlib.sha256(data).hexdigest(); assert actual == expected, f"gh archive sha256 {actual} does not match {expected}"; archive=tarfile.open(fileobj=io.BytesIO(data), mode="r:gz"); member=archive.getmember(f"gh_{version}_linux_{arch}/bin/gh"); assert member.isfile(); stream=archive.extractfile(member); assert stream is not None; binary=stream.read(); archive.close(); out=Path("/opt/gh-export/gh"); out.parent.mkdir(parents=True); out.write_bytes(binary); out.chmod(0o755); epoch=int(epoch_raw); os.utime(out, (epoch, epoch)); os.utime(out.parent, (epoch, epoch))' "${TARGETARCH}" "${GH_VERSION}" "${GH_SHA256_AMD64}" "${GH_SHA256_ARM64}" "${SOURCE_DATE_EPOCH}"; then \
        downloaded=1; \
        break; \
      fi; \
      rm -rf /opt/gh-export; \
      [ "$attempt" -lt 5 ] || break; \
      sleep "$((attempt * 2))"; \
    done; \
    [ "$downloaded" = 1 ] \
 && installed="$(/opt/gh-export/gh --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)" \
 && [ "$installed" = "$GH_VERSION" ] \
 && echo "gh ${GH_VERSION} pinned (sha256 verified)"

# ── Host runtime (`--target host`) ──────────────────────
# Prebaked Omnigent host for remote sandboxes: full omnigent install,
# git + tmux for harness runtime needs, procps + lsof so the antigravity-native
# executor can discover agy's connect-RPC port (antigravity_native_rpc.py uses
# `pgrep` in _list_agy_pids to find agy processes — with a /proc-scan fallback if
# pgrep is absent — then `lsof` in resolve_language_server_port to read their
# loopback ports; lsof has NO fallback, so a missing lsof silently yields "no
# port" and breaks web-turn injection), bubblewrap to OS-sandbox the
# native harness terminals (mandatory and fail-loud on Linux), curl + CA
# certificates for outbound HTTPS and in-sandbox downloads, plus the
# coding-harness CLIs (claude / codex / pi / kiro-cli) so claude-sdk,
# claude-native, codex, pi, and kiro-native agents can run in managed
# sandboxes without an in-sandbox install. No SPA, no psycopg, no server
# entrypoint.
#
# Also carries two additions required only by the NVIDIA OpenShell provider
# (deploy/openshell/README.md) and inert for the root-based providers
# (Modal / Daytona / CoreWeave):
#   - iproute2 / nftables: OpenShell puts each sandbox in its own network
#     namespace and routes egress through a policy proxy; the supervisor
#     shells out to `ip` to build that netns and refuses to start a sandbox
#     without it. The other providers create no namespaces, so it sits unused.
#   - a non-root `sandbox` user/group: OpenShell drops privileges to a user
#     literally named `sandbox` before running the agent (defense in depth)
#     and fails closed if it is absent. The other providers run as root and
#     never reference it.
FROM secured-python-runtime AS host
ARG NPM_CONFIG_REGISTRY=
ARG PNPM_VERSION
ARG NPM_VERSION
ARG SOURCE_DATE_EPOCH
ARG CLAUDE_CODE_VERSION=2.1.266
ARG CODEX_CLI_VERSION=0.139.0
ARG PI_CODING_AGENT_VERSION=0.84.2
ARG KIMI_CODE_VERSION=0.43.1
ARG QWEN_CODE_VERSION=0.23.4
ARG OPENCODE_VERSION=1.18.31
ARG SOURCE_REVISION
ARG UPSTREAM_REVISION
ARG CONTROL_PLANE_SCHEMA_REVISION
ARG ADAPTER_CONTRACT_VERSION
ENV NPM_CONFIG_REGISTRY=${NPM_CONFIG_REGISTRY}

LABEL org.opencontainers.image.revision=${SOURCE_REVISION} \
      ai.omnigent.upstream.revision=${UPSTREAM_REVISION} \
      ai.omnigent.saas.schema-revision=${CONTROL_PLANE_SCHEMA_REVISION} \
      ai.omnigent.saas.adapter-contract-version=${ADAPTER_CONTRACT_VERSION}

# IS_SANDBOX: devcontainer-convention flag consulted by Claude Code —
# it refuses --dangerously-skip-permissions under root without it, and
# sandbox containers run as root. The host forwards it to runners (see
# _RUNNER_ENV_ALLOWLIST in omnigent/host/connect.py) so the
# claude-sdk harness can start. Only this image sets it; laptops never
# have it.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:${PATH}" \
    IS_SANDBOX=1

# bzip2 is required for optional goose CLI archives (.tar.bz2). make/g++ are
# transient build inputs for the locked node-pty fallback when its package has
# no prebuild for the selected Node/architecture; they are purged in the same
# later layer that installs and verifies the Host CLI graph.
RUN export DEBIAN_FRONTEND=noninteractive; \
    case "${SOURCE_DATE_EPOCH}" in *[!0-9]*|'') exit 2 ;; esac; \
    apt-get -o Acquire::Check-Valid-Until=false -o Acquire::Retries=10 -o Acquire::http::Timeout=30 update \
 && apt-get -o Acquire::Check-Valid-Until=false -o Acquire::Retries=10 -o Acquire::http::Timeout=30 install -y --no-install-recommends \
      git tmux procps lsof bubblewrap curl ca-certificates unzip bzip2 make g++ \
      iproute2 nftables \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/* \
 && find /var/log -type f -delete \
 && : > /etc/machine-id \
 && rm -f /var/cache/ldconfig/aux-cache \
      /var/log/alternatives.log /var/log/dpkg.log \
      /var/log/apt/eipp.log.xz /var/log/apt/history.log /var/log/apt/term.log

# OpenShell-required non-root user (see the header note). UID/GID in the high
# range per OpenShell's bring-your-own-container guidance, so that without
# user-namespace remapping the sandbox user maps to an unprivileged, unused
# host id. Unused by the root-based providers.
RUN groupadd -g 1000660000 sandbox \
 && useradd -m -d /sandbox -u 1000660000 -g sandbox sandbox

# Git credential helper for private repositories over HTTPS: answers
# `git credential get` from GIT_TOKEN / GIT_USERNAME in the
# environment (injected via Modal secrets — see deploy/modal/README.md
# "Git credentials"), so the managed launch's repository clone AND the
# agent's later fetch/push authenticate without writing credentials to
# disk. Emits nothing when GIT_TOKEN is unset, leaving anonymous
# clones of public repositories untouched. GIT_USERNAME defaults to
# x-access-token (GitHub's token-auth username; GitLab users set
# GIT_USERNAME=oauth2). --system so it applies to any sandbox user.
RUN git config --system credential.helper \
      '!f() { [ "$1" = get ] || return 0; [ -n "$GIT_TOKEN" ] || return 0; printf "username=%s\npassword=%s\n" "${GIT_USERNAME:-x-access-token}" "$GIT_TOKEN"; }; f'

# Node runtime for the harness CLIs, copied from the official image
# (same Debian base as python-slim, so the binary is ABI-compatible)
# rather than apt — keeps the version pinned to NODE_IMAGE and skips
# nodesource setup. npm/npx are symlinks into npm's node_modules.
# (`node-runtime` is the alias stage below — COPY --from does not
# expand build args, so the FROM line resolves ${NODE_IMAGE}.)
COPY --from=node-runtime /usr/local/bin/node /usr/local/bin/node
COPY --from=npm-builder /opt/npm-export/package /usr/local/lib/node_modules/npm
RUN export HOME=/tmp/npm-version-home \
           XDG_CACHE_HOME=/tmp/npm-version-home/xdg-cache \
           XDG_CONFIG_HOME=/tmp/npm-version-home/xdg-config \
           XDG_STATE_HOME=/tmp/npm-version-home/xdg-state; \
    install -d "$HOME" "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" "$XDG_STATE_HOME" \
 && ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
 && node -e 'const v=process.versions.node.split(".").map(Number); if(v[0]!==22 || v[1]<22 || (v[1]===22 && v[2]<2)) throw Error("npm requires Node >=22.22.2 in the pinned Node 22 image")' \
 && test "$(npm_config_cache=/tmp/npm-version-cache npm --version)" = "${NPM_VERSION}" \
 && rm -rf /tmp/npm-version-cache /tmp/npm-version-home /tmp/node-compile-cache \
      /root/.npm /root/.cache

# The harness CLI set mirrors omnigent/onboarding/harness_install.py. The
# repository's ``.github/ci-deps`` importer already records the independently
# tested direct versions and their full transitive graph in pnpm-lock.yaml.
# ``.github`` is excluded from this Docker build context, so materialize only
# that tiny importer from the exact build args below; --frozen-lockfile then
# fails closed if either the importer or any transitive material drifts.
WORKDIR /opt/omnigent-host-cli
ENV PATH="/opt/omnigent-host-cli/.github/ci-deps/node_modules/.bin:${PATH}"
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY saas/scripts/normalize_host_cli_tree.py /tmp/normalize_host_cli_tree.py
# npm/pnpm installers and CLI probes may write wall-clock or reify metadata.
# Keep all installer state under one disposable prefix, retain only the pinned
# pnpm package and project tree, then normalize both retained roots last.
RUN export OMNIGENT_CLI_STATE=/tmp/omnigent-cli-state \
           HOME=/tmp/omnigent-cli-state/home \
           TMPDIR=/tmp/omnigent-cli-state/tmp \
           XDG_CACHE_HOME=/tmp/omnigent-cli-state/xdg-cache \
           XDG_CONFIG_HOME=/tmp/omnigent-cli-state/xdg-config \
           XDG_DATA_HOME=/tmp/omnigent-cli-state/xdg-data \
           XDG_STATE_HOME=/tmp/omnigent-cli-state/xdg-state \
           XDG_RUNTIME_DIR=/tmp/omnigent-cli-state/xdg-runtime \
           CODEX_HOME=/tmp/omnigent-cli-state/codex \
           CLAUDE_CONFIG_DIR=/tmp/omnigent-cli-state/claude \
           PI_CODING_AGENT_DIR=/tmp/omnigent-cli-state/pi \
           npm_config_cache=/tmp/omnigent-cli-state/npm-cache \
           npm_config_fetch_retries=5 \
           npm_config_fetch_retry_factor=2 \
           npm_config_fetch_retry_mintimeout=1000 \
           npm_config_fetch_retry_maxtimeout=120000 \
           DEBIAN_FRONTEND=noninteractive; \
    export PATH="$OMNIGENT_CLI_STATE/pnpm-prefix/bin:$PATH"; \
    install -d "$HOME" "$TMPDIR" "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" \
      "$XDG_DATA_HOME" "$XDG_STATE_HOME" "$CODEX_HOME" \
      "$CLAUDE_CONFIG_DIR" "$PI_CODING_AGENT_DIR" \
 && install -d -m 0700 "$XDG_RUNTIME_DIR" \
 && npm install --prefix "$OMNIGENT_CLI_STATE/pnpm-prefix" --global \
      --no-audit --no-fund --allow-scripts=pnpm "pnpm@${PNPM_VERSION}" \
 && test "$(pnpm --version)" = "${PNPM_VERSION}" \
 && mkdir -p .github/ci-deps \
 && printf '%s\n' \
      '{' \
      '  "name": "e2e-ci-deps",' \
      '  "version": "0.0.0",' \
      '  "private": true,' \
      '  "dependencies": {' \
      "    \"@anthropic-ai/claude-code\": \"${CLAUDE_CODE_VERSION}\"," \
      "    \"@earendil-works/pi-coding-agent\": \"${PI_CODING_AGENT_VERSION}\"," \
      '    "@modelcontextprotocol/sdk": "1.32.0",' \
      "    \"@moonshot-ai/kimi-code\": \"${KIMI_CODE_VERSION}\"," \
      "    \"@openai/codex\": \"${CODEX_CLI_VERSION}\"," \
      "    \"@qwen-code/qwen-code\": \"${QWEN_CODE_VERSION}\"," \
      "    \"opencode-ai\": \"${OPENCODE_VERSION}\"" \
      '  }' \
      '}' > .github/ci-deps/package.json \
 && pnpm install --frozen-lockfile --prod --filter e2e-ci-deps \
      --store-dir /tmp/pnpm-store --package-import-method=copy \
      --network-concurrency=4 \
 && SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" python -B -c 'import email.utils, json, os, re; from pathlib import Path; epoch=int(os.environ["SOURCE_DATE_EPOCH"]); assert epoch >= 0; modules=Path("node_modules/.modules.yaml"); source=modules.read_text(encoding="utf-8"); count=len(re.findall(r"(?m)^\s*\"prunedAt\"\s*:", source)); assert count == 1, f"expected exactly one pnpm JSON prunedAt field, found {count}"; data=json.loads(source); assert type(data) is dict and type(data.get("prunedAt")) is str and data["prunedAt"], "pnpm JSON prunedAt field missing or invalid"; data["prunedAt"]=email.utils.formatdate(epoch, usegmt=True); modules.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)+"\n", encoding="utf-8"); print("pnpm prunedAt fields normalized: 1"); state=Path("node_modules/.pnpm-workspace-state-v1.json"); state_data=json.loads(state.read_text(encoding="utf-8")) if state.exists() else None; assert state_data is None or (type(state_data.get("lastValidatedTimestamp")) is int and state_data["lastValidatedTimestamp"] >= 0), f"pnpm validation timestamp missing or invalid: {state_data!r}"; state.unlink(missing_ok=True); state_status="present" if state_data is not None else "absent"; print(f"pnpm workspace state normalized: {state_status}")' \
 && for cli in claude codex pi kimi qwen opencode; do \
      test -x ".github/ci-deps/node_modules/.bin/$cli" || { \
        echo "ERROR: host CLI executable missing: $cli" >&2; exit 1; \
      }; \
    done \
 && if [ ! -f node_modules/.pnpm/node-pty@1.1.0/node_modules/node-pty/build/Release/pty.node ]; then \
      echo "ERROR: node-pty native module missing" >&2; exit 1; \
    fi \
 && case "$(claude --version 2>&1)" in *"${CLAUDE_CODE_VERSION}"*) ;; \
      *) echo "ERROR: claude CLI version mismatch" >&2; exit 1 ;; esac \
 && case "$(codex --version 2>&1)" in *"${CODEX_CLI_VERSION}"*) ;; \
      *) echo "ERROR: codex CLI version mismatch" >&2; exit 1 ;; esac \
 && case "$(pi --version 2>&1)" in *"${PI_CODING_AGENT_VERSION}"*) ;; \
      *) echo "ERROR: pi CLI version mismatch" >&2; exit 1 ;; esac \
 && case "$(kimi --version 2>&1)" in *"${KIMI_CODE_VERSION}"*) ;; \
      *) echo "ERROR: kimi CLI version mismatch" >&2; exit 1 ;; esac \
 && case "$(qwen --version 2>&1)" in *"${QWEN_CODE_VERSION}"*) ;; \
      *) echo "ERROR: qwen CLI version mismatch" >&2; exit 1 ;; esac \
 && case "$(opencode --version 2>&1)" in *"${OPENCODE_VERSION}"*) ;; \
      *) echo "ERROR: opencode CLI version mismatch" >&2; exit 1 ;; esac \
 && mkdir -p /usr/local/lib/node_modules \
 && cp -a "$OMNIGENT_CLI_STATE/pnpm-prefix/lib/node_modules/pnpm" \
      /usr/local/lib/node_modules/pnpm \
 && ln -s ../lib/node_modules/pnpm/pn /usr/local/bin/pn \
 && ln -s ../lib/node_modules/pnpm/pnpm /usr/local/bin/pnpm \
 && ln -s ../lib/node_modules/pnpm/pnx /usr/local/bin/pnx \
 && ln -s ../lib/node_modules/pnpm/pnpx /usr/local/bin/pnpx \
 && rm -rf "$OMNIGENT_CLI_STATE" /tmp/pnpm-store \
      /root/.npm /root/.cache /root/.local/share/pnpm \
 && test "$(readlink /usr/local/bin/pn)" = "../lib/node_modules/pnpm/pn" \
 && test "$(readlink /usr/local/bin/pnpm)" = "../lib/node_modules/pnpm/pnpm" \
 && test "$(readlink /usr/local/bin/pnx)" = "../lib/node_modules/pnpm/pnx" \
 && test "$(readlink /usr/local/bin/pnpx)" = "../lib/node_modules/pnpm/pnpx" \
 && test -x /usr/local/bin/pnpm \
 && test "$(/usr/local/bin/pnpm --version)" = "$PNPM_VERSION" \
 && rm -rf "$OMNIGENT_CLI_STATE" \
 && test ! -e "$OMNIGENT_CLI_STATE" \
 && test ! -e node_modules/.pnpm-workspace-state-v1.json \
 && for path in /tmp/pnpm-store /root/.npm /root/.cache \
      /root/.local/share/pnpm; do test ! -e "$path"; done \
 && python -B /tmp/normalize_host_cli_tree.py \
      --source-date-epoch "$SOURCE_DATE_EPOCH" \
      --root /opt/omnigent-host-cli \
      --root /usr/local/lib/node_modules/pnpm \
 && apt-get purge -y --auto-remove make g++ \
 && ! command -v make \
 && ! command -v g++ \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/* \
 && find /var/log -type f -delete \
 && rm -f /var/cache/ldconfig/aux-cache \
      /var/log/alternatives.log /var/log/dpkg.log \
      /var/log/apt/eipp.log.xz /var/log/apt/history.log /var/log/apt/term.log \
 && rm -f /tmp/normalize_host_cli_tree.py \
 && find /tmp -mindepth 1 -depth -delete && find /root -depth -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} + && touch -h -d "@${SOURCE_DATE_EPOCH}" \
      /usr/local/bin/pn /usr/local/bin/pnpm /usr/local/bin/pnx /usr/local/bin/pnpx \
      /usr/local/bin /usr/local/lib/node_modules /tmp /root

# Kiro CLI is not published as an npm package, and its installer has NO version
# flag — `curl …/install | bash` always fetches `latest`, so the image was
# non-deterministic. The kiro-native harness is behaviorally coupled to a
# specific kiro-cli build (Escape-interrupt leaves an empty composer, the
# bracketed-paste multi-line path, the session-JSONL layout — all verified
# against 2.10.0; grep `kiro-cli 2.10.0`). So pin it the same way as `agy` below:
# fetch the immutable per-arch zip from the versioned CDN path and verify its
# sha256, run the package's own (network-free) install.sh, then copy the binaries
# onto a system PATH dir every sandbox user shares. A trailing `kiro-cli
# --version` check asserts the unpacked binary really is the pinned version — a
# cheap sanity guard atop the sha256. To adopt a new kiro-cli: re-verify the
# coupled behavior, then bump KIRO_CLI_VERSION + both
# SHA256s (the `sha256` fields in
# https://prod.download.cli.kiro.dev/stable/latest/manifest.json). Keep in sync
# with deploy/docker/Dockerfile.ubi.
ARG KIRO_CLI_VERSION=2.10.0
ARG KIRO_CLI_SHA256_AMD64=be9d8b6d7c44f93a83ca22466043d98ad058e6ed3c12fffd068f3fb8a60b3b70
ARG KIRO_CLI_SHA256_ARM64=0afb37399b9e2847c2f2e3f5d9052c8bc52bbf1e30401ea284a602661bce34bc
RUN set -eu; \
    case "$(uname -m)" in \
      x86_64)  asset="kirocli-x86_64-linux.zip";  sha="$KIRO_CLI_SHA256_AMD64" ;; \
      aarch64) asset="kirocli-aarch64-linux.zip"; sha="$KIRO_CLI_SHA256_ARM64" ;; \
      *) echo "ERROR: unsupported arch '$(uname -m)' for kiro-cli" >&2; exit 1 ;; \
    esac; \
    curl -fsSL --retry 5 --retry-all-errors --retry-delay 2 \
      --connect-timeout 30 --max-time 300 -o /tmp/kiro.zip \
      "https://prod.download.cli.kiro.dev/stable/${KIRO_CLI_VERSION}/${asset}"; \
    echo "${sha}  /tmp/kiro.zip" | sha256sum -c -; \
    unzip -q /tmp/kiro.zip -d /tmp/kiro; \
    KIRO_CLI_SKIP_SETUP=1 sh /tmp/kiro/kirocli/install.sh; \
    install -m 0755 /root/.local/bin/kiro-cli /usr/local/bin/kiro-cli; touch -h -d "@${SOURCE_DATE_EPOCH}" /usr/local/bin/kiro-cli /usr/local/bin; \
    if [ -f /root/.local/bin/kiro-cli-chat ]; then \
      install -m 0755 /root/.local/bin/kiro-cli-chat /usr/local/bin/kiro-cli-chat; touch -h -d "@${SOURCE_DATE_EPOCH}" /usr/local/bin/kiro-cli-chat; \
    fi; \
    rm -rf /tmp/kiro /tmp/kiro.zip; \
    installed="$(/usr/local/bin/kiro-cli --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"; \
    [ "$installed" = "$KIRO_CLI_VERSION" ] || { \
      echo "ERROR: kiro-cli reports '${installed:-<none>}', expected '$KIRO_CLI_VERSION'." >&2; exit 1; }; \
    echo "kiro-cli ${KIRO_CLI_VERSION} pinned (sha256 verified)"
# Antigravity CLI (`agy`) — the antigravity-native harness shells out to `agy`
# on the host, launching it in a tmux pane (see omnigent/antigravity_native*.py),
# so a managed host image must carry it. It is NOT an npm package
# (harness_install.py lists agy as a non-npm, installer-script harness), so it
# can't join the `npm install -g` set above. The tarball holds a single
# self-contained ``antigravity`` binary; install it as ``agy`` on a system PATH
# dir every user shares (its bootstrapper default ~/.local/bin is per-user and
# off the venv PATH). ``test -x`` fails the build loudly if the layout changes.
#
# Version + integrity pin: the native harness is behaviorally coupled to a
# specific agy build (out-of-order transcript writes, connect-RPC quirks, and TUI
# injection are all verified against 1.1.16 — grep ``agy 1.1.16`` under
# omnigent/antigravity_native*). The official ``install.sh`` bootstrapper has NO
# version flag — it always fetches the LATEST build from an auto-updater manifest
# and old builds are not retained at any stable, reconstructable URL — so it
# cannot pin anything. Instead we fetch the exact, immutable per-arch release
# asset from GitHub and verify its SHA256: this both holds the verified version
# AND fails the build if the bytes ever change underneath us, which is the actual
# supply-chain control (a version-string check alone is not). To adopt a new agy:
# re-verify the coupled behavior, then bump AGY_VERSION and both SHA256s (from
# https://github.com/google-antigravity/antigravity-cli/releases).
ARG AGY_VERSION=1.1.16
ARG AGY_SHA256_AMD64=7742953b7835b457e9102f1357a493913657dfd147435584f609d58356ec085a
ARG AGY_SHA256_ARM64=c71599bb548cf72dfe7a8f6c411b3c7a3623cd4b0f6276bae89c69f769d6c92d
# Exported for install-harness-cli.sh's agy row, so a build that adds
# EXTRA_HARNESS_CLIS=agy pins the same version + sha256 as the install above
# (and UBI — which has no baked agy — pins the same values).
ENV AGY_VERSION=${AGY_VERSION} \
    AGY_SHA256_AMD64=${AGY_SHA256_AMD64} \
    AGY_SHA256_ARM64=${AGY_SHA256_ARM64}
RUN set -eu; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) asset="agy_cli_linux_x64.tar.gz"; sha="$AGY_SHA256_AMD64" ;; \
      arm64) asset="agy_cli_linux_arm64.tar.gz"; sha="$AGY_SHA256_ARM64" ;; \
      *) echo "ERROR: unsupported arch '$arch' for agy" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/google-antigravity/antigravity-cli/releases/download/${AGY_VERSION}/${asset}"; \
    curl -fsSL --retry 5 --retry-all-errors --retry-delay 2 \
      --connect-timeout 30 --max-time 300 -o /tmp/agy.tar.gz "$url"; \
    echo "${sha}  /tmp/agy.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/agy.tar.gz -C /tmp antigravity; \
    install -m 0755 /tmp/antigravity /usr/local/bin/agy; touch -h -d "@${SOURCE_DATE_EPOCH}" /usr/local/bin/agy /usr/local/bin; \
    rm -f /tmp/agy.tar.gz /tmp/antigravity; \
    test -x /usr/local/bin/agy; \
    installed="$(/usr/local/bin/agy --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"; \
    if [ "$installed" != "$AGY_VERSION" ]; then \
      echo "ERROR: agy reports '${installed:-<unparseable>}', expected '$AGY_VERSION'." >&2; \
      exit 1; \
    fi; \
    echo "agy ${AGY_VERSION} pinned (sha256 verified)"

# The read-only GitHub side panel shells out to this SHA-verified CLI.
COPY --from=gh-builder --chown=0:0 --chmod=0755 /opt/gh-export/gh /usr/local/bin/gh

# Copy only the canonical self-contained venv export. The non-editable install
# keeps package and license bytes in site-packages, so retaining /build would
# add unused source and cache-dependent metadata to the runtime image.
COPY --from=builder /opt/venv-export /opt/venv
RUN ! grep -R --include='*.pth' --include='*.egg-link' -nE '/build(/|$)' /opt/venv/lib/python*/site-packages
RUN if [ "${SOURCE_REVISION}" != "unknown" ]; then \
      /opt/venv/bin/python -B -I -c 'import sys; from omnigent import _build_info; expected=sys.argv[1]; actual=_build_info.COMMIT_SHA; assert actual == expected, f"runtime build revision {actual!r} does not match {expected!r}"' "${SOURCE_REVISION}"; \
    fi

# Sandbox launchers exec commands through `bash -lc`, and Debian's
# /etc/profile unconditionally resets PATH for login shells — the ENV
# PATH above would silently drop off and `omnigent` / `pip` would
# resolve to the system Python instead of the venv. profile.d snippets
# are sourced after that reset, so restore both the pinned Harness CLI
# directory and the venv before the system paths.
RUN echo 'export PATH="/opt/omnigent-host-cli/.github/ci-deps/node_modules/.bin:/opt/venv/bin:${PATH}"' > /etc/profile.d/omnigent-venv.sh

# Optional extra harness CLIs: the SaaS wrapper adds fleet-only pinned rows,
# then delegates standard names to install-harness-cli.sh. See both scripts
# and deploy/docker/README.md. Kept at the end of the stage so script churn
# doesn't bust the layers above. `set -f` stops glob expansion in the unquoted
# arg list (npm specs may contain *). The script is removed after use.
ARG EXTRA_HARNESS_CLIS=
COPY deploy/docker/install-harness-cli.sh saas/scripts/install-saas-harness-cli.sh saas/scripts/normalize_host_cli_tree.py /tmp/
RUN if [ -n "${EXTRA_HARNESS_CLIS}" ]; then \
        set -f; \
        bash /tmp/install-saas-harness-cli.sh ${EXTRA_HARNESS_CLIS}; \
    fi; \
    rm -f /tmp/install-harness-cli.sh /tmp/install-saas-harness-cli.sh /tmp/normalize_host_cli_tree.py

WORKDIR /root

# CMD only — Modal's `Image.from_registry` (and the sandbox launchers
# generally) supply their own entrypoint command; an ENTRYPOINT here
# would hijack it. The hold-open default mirrors what `omnigent
# sandbox create` runs so a bare `docker run` behaves the same way.
CMD ["sleep", "infinity"]

# ── Server runtime (default target) ─────────────────────
FROM secured-python-runtime AS runtime

ARG SOURCE_DATE_EPOCH
ARG SOURCE_REVISION
ARG UPSTREAM_REVISION
ARG CONTROL_PLANE_SCHEMA_REVISION
ARG ADAPTER_CONTRACT_VERSION

LABEL org.opencontainers.image.revision=${SOURCE_REVISION} \
      ai.omnigent.upstream.revision=${UPSTREAM_REVISION} \
      ai.omnigent.saas.schema-revision=${CONTROL_PLANE_SCHEMA_REVISION} \
      ai.omnigent.saas.adapter-contract-version=${ADAPTER_CONTRACT_VERSION}

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:${PATH}"

# Git provisions the sealed repository mirrors used by Runner agents. Curl and
# ca-certificates serve the health check and outbound HTTPS integrations.
RUN export DEBIAN_FRONTEND=noninteractive; \
    case "${SOURCE_DATE_EPOCH}" in *[!0-9]*|'') exit 2 ;; esac; \
    apt-get -o Acquire::Check-Valid-Until=false -o Acquire::Retries=10 -o Acquire::http::Timeout=30 update \
 && apt-get -o Acquire::Check-Valid-Until=false -o Acquire::Retries=10 -o Acquire::http::Timeout=30 install -y --no-install-recommends \
      git curl ca-certificates \
 && test -x /usr/bin/git \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/* \
 && find /var/log -type f -delete \
 && rm -f /var/cache/ldconfig/aux-cache \
      /var/log/alternatives.log /var/log/dpkg.log \
      /var/log/apt/eipp.log.xz /var/log/apt/history.log /var/log/apt/term.log

# Copy the canonical venv export and preserve /build/ — editable-install
# .pth files reference /build/omnigent and /build/sdks/* by absolute
# path. Copying these to /app/ would break the import paths silently.
COPY --from=server-builder /opt/server-venv-export /opt/venv
COPY --from=server-builder /build /build
COPY deploy/docker/entrypoint.py /app/entrypoint.py
RUN if [ "${SOURCE_REVISION}" != "unknown" ]; then \
      /opt/venv/bin/python -B -I -c 'import sys; from omnigent import _build_info; expected=sys.argv[1]; actual=_build_info.COMMIT_SHA; assert actual == expected, f"runtime build revision {actual!r} does not match {expected!r}"' "${SOURCE_REVISION}"; \
    fi

WORKDIR /app

# /data is mounted as a persistent volume by docker-compose for the
# artifact store.
RUN mkdir -p /data/artifacts

ENV PORT=8000 \
    HOST=0.0.0.0 \
    ARTIFACT_DIR=/data/artifacts

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/health" || exit 1

CMD ["python", "/app/entrypoint.py"]
