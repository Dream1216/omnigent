#!/usr/bin/env bash
# Fixed SaaS Host CLI assets; other names use the unchanged upstream installer.

set -euo pipefail

# Delegated installers can invoke gh with the retained harness HOME.
# Disable build-time telemetry before gh allocates a random device identity.
export GH_TELEMETRY=false

BIN_DIR="${BIN_DIR:-/usr/local/bin}"
JCODE_HOME="${JCODE_HOME:-/opt/jcode}"
JCODE_VERSION="0.90.1"
JCODE_SHA256_AMD64="9a46e0cd4b66416177e78384614787323be7a9d195832733664e8f0354a9927b"
JCODE_SHA256_ARM64="85c095f6ec90bdf06cce2ee9666fa40fc74d05c6aca65e475bc12978af45f16e"
DEVIN_VERSION="3000.11.3"
DEVIN_SHA256_AMD64="83b3b113c01bf2a3e9e100db08d77e6b086806a7754f091e20831bdfe215157e"
DEVIN_SHA256_ARM64="21a2d7a8dea67987067cde7eb3fe7193a48daa8f8c3d50d414c603c4a2b67f15"

die() { echo "ERROR: $*" >&2; exit 1; }

verify() {
    local binary="$1" binary_path probe
    probe="$(mktemp -d)"
    HOME="$probe" "$binary" --version
    rm -rf "$probe"
    if id sandbox >/dev/null 2>&1; then
        probe="$(mktemp -d)"
        chown sandbox "$probe"
        binary_path="$(command -v "$binary")"
        if command -v runuser >/dev/null 2>&1; then
            runuser -u sandbox -- env HOME="$probe" "$binary_path" --version \
                || { rm -rf "$probe"; die "$binary --version failed as sandbox"; }
        elif command -v su >/dev/null 2>&1; then
            su -s /bin/sh -c "HOME='$probe' exec '$binary_path' --version" sandbox \
                || { rm -rf "$probe"; die "$binary --version failed as sandbox"; }
        else
            rm -rf "$probe"
            die "cannot verify $binary as sandbox: runuser/su missing"
        fi
        rm -rf "$probe"
    fi
}

install_jcode() (
    local requested="${1#v}" target sha stage builds version_dir expected
    if [ -n "$requested" ] && [ "$requested" != "$JCODE_VERSION" ]; then
        die "jcode is pinned to $JCODE_VERSION; got $requested"
    fi
    case "$(uname -m)" in
        x86_64) target="jcode-linux-x86_64"; sha="$JCODE_SHA256_AMD64" ;;
        aarch64) target="jcode-linux-aarch64"; sha="$JCODE_SHA256_ARM64" ;;
        *) die "unsupported architecture '$(uname -m)' for jcode" ;;
    esac
    stage="$(mktemp -d)"
    trap 'rm -rf -- "$stage"' EXIT
    curl -fsSL --retry 5 --retry-all-errors --retry-delay 2 \
        --connect-timeout 30 --max-time 300 -o "$stage/jcode.tar.gz" \
        "https://github.com/1jehuang/jcode/releases/download/v${JCODE_VERSION}/${target}.tar.gz"
    echo "$sha  $stage/jcode.tar.gz" | sha256sum -c -
    expected="$target"
    if [ "$target" = "jcode-linux-x86_64" ]; then
        expected="$(printf '%s\n%s' "$target" "$target.bin")"
    fi
    [ "$(tar -tzf "$stage/jcode.tar.gz")" = "$expected" ] \
        || die "unexpected jcode release archive layout"
    tar -xzf "$stage/jcode.tar.gz" -C "$stage"
    builds="$JCODE_HOME/.jcode/builds"
    version_dir="$builds/versions/$JCODE_VERSION"
    mkdir -p "$version_dir" "$builds/stable" "$builds/current" "$BIN_DIR"
    install -m 0755 "$stage/$target" "$version_dir/jcode"
    if [ -f "$stage/$target.bin" ]; then
        install -m 0755 "$stage/$target.bin" "$version_dir/$target.bin"
    fi
    ln -sfn "$version_dir/jcode" "$builds/stable/jcode"
    printf '%s\n' "$JCODE_VERSION" > "$builds/stable-version"
    ln -sfn "$builds/stable/jcode" "$BIN_DIR/jcode"
    chmod -R a+rX "$JCODE_HOME"
    verify jcode
)

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
    curl -fsSL --retry 5 --retry-all-errors --retry-delay 2 \
        --connect-timeout 30 --max-time 300 -o "$archive" \
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
        jcode@*) install_jcode "${spec#*@}" ;;
        jcode) install_jcode "" ;;
        devin@*) install_devin "${spec#*@}" ;;
        devin) install_devin "" ;;
        *) bash /tmp/install-harness-cli.sh "$spec" ;;
    esac
done

# Version probes can write logs and a background session-pruning marker.
# Remove probe state before normalizing the retained executable tree.
rm -rf -- /opt/jcode/.jcode/logs
rm -f -- /opt/jcode/.jcode/sessions-bak-prune.stamp
test ! -e /opt/jcode/.jcode/sessions-bak-prune.stamp

# Installer-created hard links and timestamps must be stable across rebuilds.
roots=()
for root in /opt/jcode /opt/devin; do
    if [ -d "$root" ]; then
        roots+=(--root "$root")
    fi
done
if [ "${#roots[@]}" -gt 0 ]; then
    [ -n "${SOURCE_DATE_EPOCH:-}" ] || die "SOURCE_DATE_EPOCH is required"
    python -B /tmp/normalize_host_cli_tree.py \
        --source-date-epoch "$SOURCE_DATE_EPOCH" "${roots[@]}"
    touch -h -d "@${SOURCE_DATE_EPOCH}" /opt /usr/local/bin /tmp
fi
