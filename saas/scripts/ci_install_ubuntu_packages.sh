#!/usr/bin/env bash
# Isolate hosted-runner apt from the Azure mirrorlist; retain signed Ubuntu packages.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_OS:-}" == Linux ]]
[[ "$#" -gt 0 && "${RUNNER_ARCH:-}" == X64 ]]
. /etc/os-release
[[ "$ID" == ubuntu && "$VERSION_ID" == 24.04 && "$VERSION_CODENAME" == noble ]]
if [[ "$1" == --configure-only ]]; then
  [[ "$#" == 1 ]]
else
  for package in "$@"; do [[ "$package" =~ ^[a-z0-9][a-z0-9+.-]*$ ]]; done
fi
# Job-local hosted-runner configuration also covers Playwright's own sudo apt.
# Existing repository signing keys and third-party sources remain unchanged.
if [[ -f /etc/apt/apt-mirrors.txt ]]; then
  printf '%s\n' https://archive.ubuntu.com/ubuntu/ | sudo tee /etc/apt/apt-mirrors.txt >/dev/null
fi
sudo tee /etc/apt/apt.conf.d/99-omnigent-ci-network >/dev/null <<'NETWORK'
Acquire::http::Timeout "20";
Acquire::https::Timeout "20";
Acquire::Retries "2";
Acquire::Languages "none";
APT::Update::Error-Mode "any";
NETWORK
# Keep Ubuntu index requests on the hash named by its signed Release file.
# A mirror publication can replace Packages.xz before all frontend metadata agrees.
# Scope forced by-hash to Ubuntu; third-party sources retain their own settings.
sudo tee /etc/apt/sources.list.d/ubuntu.sources >/dev/null <<'UBUNTU'
Types: deb
URIs: https://archive.ubuntu.com/ubuntu/
Suites: noble noble-updates
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
By-Hash: force

Types: deb
URIs: https://security.ubuntu.com/ubuntu/
Suites: noble-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
By-Hash: force
UBUNTU
if [[ "$1" == --configure-only ]]; then
  [[ "$#" == 1 ]]
  exit 0
fi
sources=$(mktemp "${RUNNER_TEMP:?}/omnigent-ubuntu-sources.XXXXXX")
trap 'rm -f "$sources"' EXIT
chmod 644 "$sources"
cat > "$sources" <<'SOURCES'
deb [by-hash=force signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://archive.ubuntu.com/ubuntu noble main restricted universe multiverse
deb [by-hash=force signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://archive.ubuntu.com/ubuntu noble-updates main restricted universe multiverse
deb [by-hash=force signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://security.ubuntu.com/ubuntu noble-security main restricted universe multiverse
SOURCES
options=(-o "Dir::Etc::sourcelist=$sources" -o Dir::Etc::sourceparts=-
  -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 -o Acquire::Retries=2
  -o Acquire::Languages=none -o APT::Update::Error-Mode=any)
timeout --kill-after=10s 180s sudo apt-get "${options[@]}" update
timeout --kill-after=10s 180s sudo apt-get "${options[@]}" install -y --no-install-recommends "$@"
