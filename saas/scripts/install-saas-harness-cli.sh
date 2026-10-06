#!/usr/bin/env bash
# SaaS-only Host image CLI rows. Standard names are delegated to the upstream
# installer so fleet additions do not widen the maintained upstream delta.

set -euo pipefail

BIN_DIR="${BIN_DIR:-/usr/local/bin}"
DEVIN_VERSION="3000.11.3"
DEVIN_SHA256_AMD64="83b3b113c01bf2a3e9e100db08d77e6b086806a7754f091e20831bdfe215157e"
DEVIN_SHA256_ARM64="21a2d7a8dea67987067cde7eb3fe7193a48daa8f8c3d50d414c603c4a2b67f15"

die() { echo "ERROR: $*" >&2; exit 1; }

verify() {
    local binary="$1" probe
    probe="$(mktemp -d)"
    HOME="$probe" "$binary" --version
    rm -rf "$probe"
    if id sandbox >/dev/null 2>&1; then
        probe="$(mktemp -d)"
        chown sandbox "$probe"
        runuser -u sandbox -- env HOME="$probe" "$binary" --version
        rm -rf "$probe"
    fi
}

install_devin() {
    local requested="$1" target sha archive
    if [ -n "$requested" ] && [ "$requested" != "$DEVIN_VERSION" ]; then
        die "devin is pinned to $DEVIN_VERSION; got $requested"
    fi
    case "$(uname -m)" in
        x86_64) target="x86_64-unknown-linux"; sha="$DEVIN_SHA256_AMD64" ;;
        aarch64) target="aarch64-unknown-linux"; sha="$DEVIN_SHA256_ARM64" ;;
        *) die "unsupported architecture '$(uname -m)' for devin" ;;
    esac
    archive="/tmp/devin-${DEVIN_VERSION}.tar.gz"
    curl -fsSL -o "$archive" \
        "https://static.devin.ai/cli/${DEVIN_VERSION}/devin-${DEVIN_VERSION}-${target}.tar.gz"
    echo "$sha  $archive" | sha256sum -c -
    rm -rf /opt/devin
    mkdir -p /opt/devin
    tar -xzf "$archive" -C /opt/devin
    chmod -R a+rX /opt/devin
    ln -sf /opt/devin/bin/devin "$BIN_DIR/devin"
    rm -f "$archive"
    verify devin
}

[ "$#" -gt 0 ] || die "usage: install-saas-harness-cli.sh NAME[@VERSION]..."
for spec in "$@"; do
    case "$spec" in
        devin@*) install_devin "${spec#*@}" ;;
        devin) install_devin "" ;;
        *) bash /tmp/install-harness-cli.sh "$spec" ;;
    esac
done
