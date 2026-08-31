# Omnigent images: server (default target) + host (`--target host`).
#
# The default/final target builds the server image (external-runner
# mode): the FastAPI / WebSocket coordinator — HTTP + SSE routes, the
# runner WebSocket tunnel acceptor, and the SQLAlchemy stores. It does
# NOT execute agent harnesses — runners run on the user's local machine
# and dial in via WS /v1/runner/tunnel.
#
# As a consequence: no tmux, no git, no harness SDK runtime
# requirements in the final image. The omnigent package is still
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
ARG PNPM_VERSION=11.15.1
ARG PYTHON_IMAGE=python:${PYTHON_VERSION}-slim
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
FROM ${NODE_IMAGE} AS web-builder
ARG NPM_CONFIG_REGISTRY=
ARG PNPM_VERSION
ENV NPM_CONFIG_REGISTRY=${NPM_CONFIG_REGISTRY}
WORKDIR /web

# Workspace manifests + lockfile first so the install layer caches across pure
# source edits. The electron package JSON is included so the root workspace is
# structurally complete, but we --filter web to avoid downloading Electron.
COPY pnpm-workspace.yaml pnpm-lock.yaml ./
COPY web/package.json ./web/
COPY web/electron/package.json ./web/electron/

RUN npm install -g "pnpm@${PNPM_VERSION}" \
 && test "$(pnpm --version)" = "${PNPM_VERSION}"
RUN pnpm install --frozen-lockfile --filter web

COPY web/ ./web/
RUN pnpm --filter web run build

# ── Python builder (shared: server + host) ──────────────
# Installs the package (and its transitive native-extension deps) into
# a virtualenv the runtime stages copy verbatim. Keeps build-essential
# out of the shipped images. Deliberately SPA-free and psycopg-free so
# the host target can build without node; the server-only additions
# live in server-builder below.
FROM ${PYTHON_IMAGE} AS builder

ARG PYPI_INDEX_URL=https://pypi.org/simple
ARG SOURCE_DATE_EPOCH
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
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get -o Acquire::Check-Valid-Until=false install -y --no-install-recommends \
      build-essential \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/* \
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
# Keep ensurepip's deterministic seed bytecode, then prove neither uv nor any
# isolated smoke import adds timestamp-based bytecode to the copied venv.
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
 && python -B -I -c 'import hashlib; from pathlib import Path; root=Path("/opt/venv"); bad=sorted(root.rglob("uv_cache.json")); assert not bad, bad; print("\n".join(f"{path.relative_to(root)} {hashlib.sha256(path.read_bytes()).hexdigest()}" for path in sorted(root.rglob("*.pyc"))))' \
      > /tmp/venv-core-pyc.sha256 \
 && cmp -s /tmp/venv-seed-pyc.sha256 /tmp/venv-core-pyc.sha256

# ── Server builder ──────────────────────────────────────
# Server-only additions on top of the shared builder: the SPA bundle
# and the Postgres driver.
FROM builder AS server-builder

ARG PYPI_INDEX_URL=https://pypi.org/simple
ARG PSYCOPG_VERSION=3.3.4

# Overlay the SPA bundle built in the web-builder stage, so a clean
# checkout (with no prebuilt bundle on the host) still produces a
# complete image. This replaces the old "prebuild or hard-fail" check.
COPY --from=web-builder /web/omnigent/server/static/web-ui ./omnigent/server/static/web-ui
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
    installed="$(python -c 'import importlib.metadata as m; print(m.version("psycopg"))')"; \
    [ "${installed}" = "${PSYCOPG_VERSION}" ] || { \
      echo "ERROR: uv.lock installed psycopg ${installed}, expected ${PSYCOPG_VERSION}." >&2; \
      exit 1; \
    }; \
    python -B -I -c 'import hashlib; from pathlib import Path; root=Path("/opt/venv"); bad=sorted(root.rglob("uv_cache.json")); assert not bad, bad; print("\n".join(f"{path.relative_to(root)} {hashlib.sha256(path.read_bytes()).hexdigest()}" for path in sorted(root.rglob("*.pyc"))))' \
      > /tmp/venv-server-pyc.sha256; \
    cmp -s /tmp/venv-seed-pyc.sha256 /tmp/venv-server-pyc.sha256

# ── Node alias stage ─────────────────────────────────────
# Pure alias so the host stage can COPY node out of a version-pinned
# image; contributes no layers of its own.
FROM ${NODE_IMAGE} AS node-runtime

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
FROM ${PYTHON_IMAGE} AS host
ARG NPM_CONFIG_REGISTRY=
ARG PNPM_VERSION
ARG SOURCE_DATE_EPOCH
ARG CLAUDE_CODE_VERSION=2.1.212
ARG CODEX_CLI_VERSION=0.139.0
ARG PI_CODING_AGENT_VERSION=0.84.2
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

RUN export DEBIAN_FRONTEND=noninteractive; \
    case "${SOURCE_DATE_EPOCH}" in *[!0-9]*|'') exit 2 ;; esac; \
    python -B -c 'import platform, re; from pathlib import Path; path=Path("/etc/apt/sources.list.d/debian.sources"); source=path.read_text(encoding="utf-8"); pattern=re.compile(r"(?m)^# (http://snapshot[.]debian[.]org/archive/(?:debian|debian-security)/[0-9]{8}T[0-9]{6}Z)\nURIs: http://deb[.]debian[.]org/(?:debian|debian-security)$"); normalized,count=pattern.subn(lambda match: f"# {match.group(1)}\nURIs: {match.group(1)}", source); assert count == 2, f"expected two Debian snapshot sources, found {count}"; uris=re.findall(r"(?m)^URIs: (\S+)$", normalized); assert len(uris) == 2 and all(re.fullmatch(r"http://snapshot[.]debian[.]org/archive/(?:debian|debian-security)/[0-9]{8}T[0-9]{6}Z", uri) for uri in uris), uris; assert sum("/archive/debian/" in uri for uri in uris) == 1 and sum("/archive/debian-security/" in uri for uri in uris) == 1, uris; codename=platform.freedesktop_os_release()["VERSION_CODENAME"]; suites=re.findall(r"(?m)^Suites: (.+)$", normalized); assert len(suites) == 2 and set(suites) == {f"{codename} {codename}-updates", f"{codename}-security"}, suites; path.write_text(normalized, encoding="utf-8"); print(f"Debian snapshot coordinates ({codename}): {uris}")' \
 && python -B -c 'from pathlib import Path; primary=Path("/etc/apt/sources.list.d/debian.sources"); root=primary.parent; candidates=[Path("/etc/apt/sources.list"), *sorted(root.glob("*.list")), *sorted(root.glob("*.sources"))]; unexpected=[str(candidate) for candidate in candidates if candidate != primary and candidate.is_file() and any(line.strip() and not line.lstrip().startswith("#") for line in candidate.read_text(encoding="utf-8", errors="replace").splitlines())]; assert not unexpected, f"unexpected additional apt sources: {unexpected}"; assert "deb.debian.org" not in primary.read_text(encoding="utf-8"), "rolling Debian mirror remains enabled"' \
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get -o Acquire::Check-Valid-Until=false install -y --no-install-recommends \
      git tmux procps lsof bubblewrap curl ca-certificates unzip \
      iproute2 nftables \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/* \
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
COPY --from=node-runtime /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

# The harness CLI set mirrors omnigent/onboarding/harness_install.py. The
# repository's ``.github/ci-deps`` importer already records the independently
# tested direct versions and their full transitive graph in pnpm-lock.yaml.
# ``.github`` is excluded from this Docker build context, so materialize only
# that tiny importer from the exact build args below; --frozen-lockfile then
# fails closed if either the importer or any transitive material drifts.
WORKDIR /opt/omnigent-host-cli
ENV PATH="/opt/omnigent-host-cli/.github/ci-deps/node_modules/.bin:${PATH}"
COPY pnpm-workspace.yaml pnpm-lock.yaml ./
# pnpm records wall-clock validation fields and its store records access times.
# Normalize the one runtime metadata field, remove the disposable state/store,
# and isolate CLI version probes from the final root home.
RUN export npm_config_cache=/tmp/npm-cache; \
    npm install -g --no-audit --no-fund "pnpm@${PNPM_VERSION}" \
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
      "    \"@openai/codex\": \"${CODEX_CLI_VERSION}\"" \
      '  }' \
      '}' > .github/ci-deps/package.json \
 && pnpm install --frozen-lockfile --prod --filter e2e-ci-deps \
      --store-dir /tmp/pnpm-store --package-import-method=copy \
 && SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" python -B -c 'import email.utils, json, os, re; from pathlib import Path; epoch=int(os.environ["SOURCE_DATE_EPOCH"]); assert epoch >= 0; modules=Path("node_modules/.modules.yaml"); normalized,count=re.subn(r"(?m)^prunedAt: .*$", f"prunedAt: {email.utils.formatdate(epoch, usegmt=True)}", modules.read_text(encoding="utf-8")); assert count == 1, f"expected one pnpm prunedAt field, found {count}"; modules.write_text(normalized, encoding="utf-8"); state=Path("node_modules/.pnpm-workspace-state-v1.json"); state_data=json.loads(state.read_text(encoding="utf-8")); assert isinstance(state_data.get("lastValidatedTimestamp"), int), "pnpm validation timestamp missing"; state.unlink()' \
 && test -x .github/ci-deps/node_modules/.bin/claude \
 && test -x .github/ci-deps/node_modules/.bin/codex \
 && test -x .github/ci-deps/node_modules/.bin/pi \
 && mkdir -p /tmp/omnigent-cli-home /tmp/omnigent-cli-cache \
 && case "$(HOME=/tmp/omnigent-cli-home XDG_CACHE_HOME=/tmp/omnigent-cli-cache claude --version 2>&1)" in *"${CLAUDE_CODE_VERSION}"*) ;; \
      *) echo "ERROR: claude CLI version mismatch" >&2; exit 1 ;; esac \
 && case "$(HOME=/tmp/omnigent-cli-home XDG_CACHE_HOME=/tmp/omnigent-cli-cache codex --version 2>&1)" in *"${CODEX_CLI_VERSION}"*) ;; \
      *) echo "ERROR: codex CLI version mismatch" >&2; exit 1 ;; esac \
 && case "$(HOME=/tmp/omnigent-cli-home XDG_CACHE_HOME=/tmp/omnigent-cli-cache pi --version 2>&1)" in *"${PI_CODING_AGENT_VERSION}"*) ;; \
      *) echo "ERROR: pi CLI version mismatch" >&2; exit 1 ;; esac \
 && rm -rf /tmp/npm-cache /tmp/pnpm-store \
      /tmp/omnigent-cli-home /tmp/omnigent-cli-cache \
      /root/.npm /root/.cache /root/.local/share/pnpm \
 && test ! -e node_modules/.pnpm-workspace-state-v1.json \
 && for path in /tmp/npm-cache /tmp/pnpm-store /tmp/omnigent-cli-home \
      /tmp/omnigent-cli-cache /root/.npm /root/.cache \
      /root/.local/share/pnpm; do test ! -e "$path"; done

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
    curl -fsSL -o /tmp/kiro.zip "https://prod.download.cli.kiro.dev/stable/${KIRO_CLI_VERSION}/${asset}"; \
    echo "${sha}  /tmp/kiro.zip" | sha256sum -c -; \
    unzip -q /tmp/kiro.zip -d /tmp/kiro; \
    KIRO_CLI_SKIP_SETUP=1 sh /tmp/kiro/kirocli/install.sh; \
    install -m 0755 /root/.local/bin/kiro-cli /usr/local/bin/kiro-cli; \
    if [ -f /root/.local/bin/kiro-cli-chat ]; then \
      install -m 0755 /root/.local/bin/kiro-cli-chat /usr/local/bin/kiro-cli-chat; \
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
RUN set -eu; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) asset="agy_cli_linux_x64.tar.gz"; sha="$AGY_SHA256_AMD64" ;; \
      arm64) asset="agy_cli_linux_arm64.tar.gz"; sha="$AGY_SHA256_ARM64" ;; \
      *) echo "ERROR: unsupported arch '$arch' for agy" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/google-antigravity/antigravity-cli/releases/download/${AGY_VERSION}/${asset}"; \
    curl -fsSL -o /tmp/agy.tar.gz "$url"; \
    echo "${sha}  /tmp/agy.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/agy.tar.gz -C /tmp antigravity; \
    install -m 0755 /tmp/antigravity /usr/local/bin/agy; \
    rm -f /tmp/agy.tar.gz /tmp/antigravity; \
    test -x /usr/local/bin/agy; \
    installed="$(/usr/local/bin/agy --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"; \
    if [ "$installed" != "$AGY_VERSION" ]; then \
      echo "ERROR: agy reports '${installed:-<unparseable>}', expected '$AGY_VERSION'." >&2; \
      exit 1; \
    fi; \
    echo "agy ${AGY_VERSION} pinned (sha256 verified)"

# Copy the venv and source tree. The editable install's .pth files reference
# /build/omnigent and /build/sdks/* -- both denied by the k8s Landlock LSM
# policy. Re-install without -e so the package bytes land in the venv's
# site-packages and imports no longer require /build at runtime.
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /build /build
RUN ! grep -R --include='*.pth' --include='*.egg-link' -nE '/build(/|$)' /opt/venv/lib/python*/site-packages

# Sandbox launchers exec commands through `bash -lc`, and Debian's
# /etc/profile unconditionally resets PATH for login shells — the ENV
# PATH above would silently drop off and `omnigent` / `pip` would
# resolve to the system Python instead of the venv. profile.d snippets
# are sourced after that reset, so this puts the venv back in front.
RUN echo 'export PATH="/opt/venv/bin:${PATH}"' > /etc/profile.d/omnigent-venv.sh

WORKDIR /root

# CMD only — Modal's `Image.from_registry` (and the sandbox launchers
# generally) supply their own entrypoint command; an ENTRYPOINT here
# would hijack it. The hold-open default mirrors what `omnigent
# sandbox create` runs so a bare `docker run` behaves the same way.
CMD ["sleep", "infinity"]

# ── Server runtime (default target) ─────────────────────
FROM ${PYTHON_IMAGE} AS runtime

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

# curl + ca-certificates only — for the HEALTHCHECK and for outbound
# HTTPS to LLM gateways / external services.
RUN export DEBIAN_FRONTEND=noninteractive; \
    case "${SOURCE_DATE_EPOCH}" in *[!0-9]*|'') exit 2 ;; esac; \
    python -B -c 'import platform, re; from pathlib import Path; path=Path("/etc/apt/sources.list.d/debian.sources"); source=path.read_text(encoding="utf-8"); pattern=re.compile(r"(?m)^# (http://snapshot[.]debian[.]org/archive/(?:debian|debian-security)/[0-9]{8}T[0-9]{6}Z)\nURIs: http://deb[.]debian[.]org/(?:debian|debian-security)$"); normalized,count=pattern.subn(lambda match: f"# {match.group(1)}\nURIs: {match.group(1)}", source); assert count == 2, f"expected two Debian snapshot sources, found {count}"; uris=re.findall(r"(?m)^URIs: (\S+)$", normalized); assert len(uris) == 2 and all(re.fullmatch(r"http://snapshot[.]debian[.]org/archive/(?:debian|debian-security)/[0-9]{8}T[0-9]{6}Z", uri) for uri in uris), uris; assert sum("/archive/debian/" in uri for uri in uris) == 1 and sum("/archive/debian-security/" in uri for uri in uris) == 1, uris; codename=platform.freedesktop_os_release()["VERSION_CODENAME"]; suites=re.findall(r"(?m)^Suites: (.+)$", normalized); assert len(suites) == 2 and set(suites) == {f"{codename} {codename}-updates", f"{codename}-security"}, suites; path.write_text(normalized, encoding="utf-8"); print(f"Debian snapshot coordinates ({codename}): {uris}")' \
 && python -B -c 'from pathlib import Path; primary=Path("/etc/apt/sources.list.d/debian.sources"); root=primary.parent; candidates=[Path("/etc/apt/sources.list"), *sorted(root.glob("*.list")), *sorted(root.glob("*.sources"))]; unexpected=[str(candidate) for candidate in candidates if candidate != primary and candidate.is_file() and any(line.strip() and not line.lstrip().startswith("#") for line in candidate.read_text(encoding="utf-8", errors="replace").splitlines())]; assert not unexpected, f"unexpected additional apt sources: {unexpected}"; assert "deb.debian.org" not in primary.read_text(encoding="utf-8"), "rolling Debian mirror remains enabled"' \
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get -o Acquire::Check-Valid-Until=false install -y --no-install-recommends \
      curl ca-certificates \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/* \
 && rm -f /var/cache/ldconfig/aux-cache \
      /var/log/alternatives.log /var/log/dpkg.log \
      /var/log/apt/eipp.log.xz /var/log/apt/history.log /var/log/apt/term.log

# Preserve /build/ in the runtime stage — the venv's editable install
# .pth files reference /build/omnigent and /build/sdks/* by absolute
# path. Copying these to /app/ would break the import paths silently.
COPY --from=server-builder /opt/venv /opt/venv
COPY --from=server-builder /build /build
COPY deploy/docker/entrypoint.py /app/entrypoint.py

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
