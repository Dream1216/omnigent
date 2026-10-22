#!/bin/sh
set -eu

output=${1:-/opt/runtime-security}
work=/tmp/runtime-security-build
rm -rf "$work"
mkdir -p "$work"
trap 'rm -rf "$work"' EXIT HUP INT TERM

download() {
  url=$1
  destination=$2
  curl --fail --location --silent --show-error --retry 5 \
    --retry-all-errors --output "$destination" "$url"
}

verify_fingerprint() {
  keyring=$1
  fingerprint=$2
  gpg --batch --show-keys --with-colons "$keyring" 2>/dev/null \
    | awk -F: '$1 == "fpr" {print $10}' \
    | grep -Fx "$fingerprint" >/dev/null
}

mkdir -p "$output/zlib" "$output/perl" "$output/pyexpat" "$output/gcc"

# zlib 1.3.2 plus the upstream CVE-2026-85091 fix.
download https://zlib.net/zlib-1.3.2.tar.xz "$work/zlib-1.3.2.tar.xz"
download https://zlib.net/zlib-1.3.2.tar.xz.asc "$work/zlib-1.3.2.tar.xz.asc"
download https://keys.openpgp.org/vks/v1/by-fingerprint/5ED46A6721D365587791E2AA783FCD8E58BCAFBA "$work/zlib-key.asc"
download https://github.com/madler/zlib/commit/df84af25dc1942490e1d1c899a07619152a46148.patch "$work/zlib-df84af25.patch"
printf '%s  %s\n' \
  d7a0654783a4da529d1bb793b7ad9c3318020af77667bcae35f95d0e42a792f3 "$work/zlib-1.3.2.tar.xz" \
  03ce710347e2f84fa7ed0a6ae6a93467b08031a3022fc296da40220a83b96667 "$work/zlib-1.3.2.tar.xz.asc" \
  1458b5b96dd3904ef1d4cc24d27135dcf3b9abdce4e3689ad58041b482a3bbde "$work/zlib-key.asc" \
  110ff14375733173d8aa54574473424fbd7dfe4b81f1ca34a759c6fe14b15b14 "$work/zlib-df84af25.patch" \
  | sha256sum --check --strict
gpg --batch --yes --dearmor --output "$work/zlib-key.gpg" "$work/zlib-key.asc"
verify_fingerprint "$work/zlib-key.gpg" 5ED46A6721D365587791E2AA783FCD8E58BCAFBA
gpgv --keyring "$work/zlib-key.gpg" "$work/zlib-1.3.2.tar.xz.asc" "$work/zlib-1.3.2.tar.xz"
mkdir "$work/zlib-source"
tar -xJf "$work/zlib-1.3.2.tar.xz" -C "$work/zlib-source" --strip-components=1
patch -d "$work/zlib-source" -p1 --fuzz=0 < "$work/zlib-df84af25.patch"
test "$(grep -c 'state->strm.avail_in = 0' "$work/zlib-source/gzwrite.c")" -eq 1
(
  cd "$work/zlib-source"
  CFLAGS='-O2 -fstack-protector-strong -Wformat -Werror=format-security -fPIC' \
    LDFLAGS='-Wl,-z,relro,-z,now' ./configure --prefix=/usr
  make -j2
  make test
  make DESTDIR="$work/zlib-install" install
)
install -m 0644 "$work/zlib-install/usr/lib/libz.so.1.3.2" "$output/zlib/libz.so.1.3.2"

# Podlators v6.1.1 takes precedence over Debian Perl's vulnerable Pod::Text.
download https://cpan.metacpan.org/authors/id/R/RR/RRA/podlators-v6.1.1.tar.gz "$work/podlators-v6.1.1.tar.gz"
download https://cpan.metacpan.org/authors/id/R/RR/RRA/CHECKSUMS "$work/podlators-CHECKSUMS"
download 'https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x2E66557AB97C19C791AF8E20328DA867450F89EC' "$work/pause-key.asc"
printf '%s  %s\n' \
  709a7dc4a2259683eb2f89e085ec70cf743710d950510e489ec6ddca3eb80c68 "$work/podlators-v6.1.1.tar.gz" \
  f60e73e0db21ae3d59d197534e6d0e7f51b44dfdcedbbaf097c37bbba92df417 "$work/podlators-CHECKSUMS" \
  | sha256sum --check --strict
gpg --batch --yes --dearmor --output "$work/pause-key.gpg" "$work/pause-key.asc"
verify_fingerprint "$work/pause-key.gpg" 2E66557AB97C19C791AF8E20328DA867450F89EC
verify_fingerprint "$work/pause-key.gpg" 4584D789E682F9F53B392F1837D079412CC9032E
gpgv --keyring "$work/pause-key.gpg" "$work/podlators-CHECKSUMS"
python -B - "$work/podlators-CHECKSUMS" <<'PY'
import re
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text(encoding="utf-8")
match = re.search(
    r"'podlators-v6[.]1[.]1[.]tar[.]gz'\s*=>\s*\{(?P<body>.*?)\n\s*\}",
    source,
    re.DOTALL,
)
assert match is not None, "signed CHECKSUMS has no podlators-v6.1.1 entry"
assert re.search(
    r"'sha256'\s*=>\s*'709a7dc4a2259683eb2f89e085ec70cf743710d950510e489ec6ddca3eb80c68'",
    match.group("body"),
), "signed CHECKSUMS does not bind the expected podlators hash"
PY
mkdir "$work/podlators-source"
tar -xzf "$work/podlators-v6.1.1.tar.gz" -C "$work/podlators-source" --strip-components=1
(
  cd "$work/podlators-source"
  perl Makefile.PL
  make -j2
  make test
  test "$(perl -Iblib/lib -MPod::Text -e 'print $Pod::Text::VERSION')" = v6.1.1
)
cp -a "$work/podlators-source/blib/lib/Pod" "$output/perl/Pod"
printf '=over 80\n\n=item X\n\nbody\n\n=back\n' > "$work/cve-2026-82560.pod"
PERL5LIB="$output/perl" timeout 5 perl -MPod::Text -e \
  'Pod::Text->new(width => 80)->parse_from_file($ARGV[0], $ARGV[1])' \
  "$work/cve-2026-82560.pod" "$work/cve-2026-82560.txt"

# CPython 3.12.15 pyexpat rebuilt against authenticated Expat 2.9.0.
download https://deb.debian.org/debian/pool/main/e/expat/expat_2.9.0-1.dsc "$work/expat_2.9.0-1.dsc"
download https://deb.debian.org/debian/pool/main/e/expat/expat_2.9.0.orig.tar.gz "$work/expat_2.9.0.orig.tar.gz"
download https://deb.debian.org/debian/pool/main/e/expat/expat_2.9.0-1.debian.tar.xz "$work/expat_2.9.0-1.debian.tar.xz"
download 'https://keyring.debian.org/pks/lookup?op=get&search=0x7D887DC8BA7BBBA7B835E3BADCE310E7864CC8BF' "$work/expat-key.asc"
download https://www.python.org/ftp/python/3.12.15/Python-3.12.15.tar.xz "$work/Python-3.12.15.tar.xz"
download https://www.python.org/ftp/python/3.12.15/Python-3.12.15.tar.xz.asc "$work/Python-3.12.15.tar.xz.asc"
download https://keys.openpgp.org/vks/v1/by-fingerprint/7169605F62C751356D054A26A821E680E5FA6305 "$work/python-key.asc"
printf '%s  %s\n' \
  b5ad165baca0f2f2ac2a02b6b4b66d68ee890f582df398da9f86399679ca9c29 "$work/expat_2.9.0-1.dsc" \
  6e8ce7b52ebbaa423c59becc7cf1e6875c42e49228c062ac8123c10e700cec27 "$work/expat_2.9.0.orig.tar.gz" \
  d23e632b05f10e269ee5426ff1ea962b4aec17fcd179c4dec14390a6793da764 "$work/expat_2.9.0-1.debian.tar.xz" \
  e6d6acf96e7fbaa752d603fc43b5f96eea06045f53b9c4367a1864519eaff3c2 "$work/expat-key.asc" \
  c2c4321961fab0fb999d66e0cecf521c2ab3994c7992873ea99e306c1094fd5a "$work/Python-3.12.15.tar.xz" \
  e80124b35dabf82264f254dbb291697df96768f6e4ee0e43d7e8f110a9ea50b6 "$work/Python-3.12.15.tar.xz.asc" \
  1de2bbd31e2dd10aab4098c3ab2f937c530d924ddbfa2dd091f0c7cfb2ee182a "$work/python-key.asc" \
  | sha256sum --check --strict
gpg --batch --yes --dearmor --output "$work/expat-key.gpg" "$work/expat-key.asc"
verify_fingerprint "$work/expat-key.gpg" A0DF7E0D3851E0EE45C00BC8ACE1F33CB933BBBB
verify_fingerprint "$work/expat-key.gpg" 7D887DC8BA7BBBA7B835E3BADCE310E7864CC8BF
cp "$work/expat-key.gpg" /usr/share/keyrings/debian-keyring.pgp
dpkg-source --require-valid-signature --require-strong-checksums --no-copy \
  -x "$work/expat_2.9.0-1.dsc" "$work/expat-source"
(
  cd "$work/expat-source/expat"
  autoreconf -fi
  multiarch=$(dpkg-architecture -qDEB_HOST_MULTIARCH)
  ./configure --prefix=/usr --libdir="/usr/lib/$multiarch" --enable-shared --enable-static
  make -j2
  make check
  make DESTDIR="$work/expat-install" install
)
gpg --batch --yes --dearmor --output "$work/python-key.gpg" "$work/python-key.asc"
verify_fingerprint "$work/python-key.gpg" 7169605F62C751356D054A26A821E680E5FA6305
gpgv --keyring "$work/python-key.gpg" "$work/Python-3.12.15.tar.xz.asc" "$work/Python-3.12.15.tar.xz"
mkdir "$work/python-source"
tar -xJf "$work/Python-3.12.15.tar.xz" -C "$work/python-source" --strip-components=1
test "$(python -c 'import platform; print(platform.python_version())')" = 3.12.15
multiarch=$(dpkg-architecture -qDEB_HOST_MULTIARCH)
extension_suffix=$(python3-config --extension-suffix)
gcc $(python3-config --cflags) -fPIC -shared \
  -I/usr/local/include/python3.12/internal -I"$work/expat-install/usr/include" \
  -L"$work/expat-install/usr/lib/$multiarch" \
  "$work/python-source/Modules/pyexpat.c" -lexpat -Wl,-z,relro,-z,now \
  -o "$output/pyexpat/pyexpat${extension_suffix}"
readelf -d "$output/pyexpat/pyexpat${extension_suffix}" \
  | grep -F 'Shared library: [libexpat.so.1]'
PYTHONPATH="$output/pyexpat:$work/python-source/Lib" \
  LD_LIBRARY_PATH="$work/expat-install/usr/lib/$multiarch" \
  python -B -m test -j2 test_pyexpat test_xml_etree test_xml_etree_c test_minidom test_sax

# Build the exact executable later rerun against the final libstdc++ runtime.
g++ -std=c++17 -O2 -Wl,-z,relro,-z,now \
  /runtime-security-input/gcc-aligned-new-runtime-boundary.cc \
  -o "$output/gcc/aligned-new-runtime-boundary"
"$output/gcc/aligned-new-runtime-boundary"

find "$output" -depth -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +
printf '%s\n' 'PASS authenticated zlib, Podlators, pyexpat/Expat, and GCC runtime overlays'
