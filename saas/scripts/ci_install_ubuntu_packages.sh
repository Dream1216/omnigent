#!/usr/bin/env bash
# Isolate hosted-runner apt from the Azure mirrorlist; retain signed Ubuntu packages.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_OS:-}" == Linux ]]
[[ "$#" -gt 0 ]]
. /etc/os-release
[[ "$ID" == ubuntu && "$VERSION_ID" == 24.04 && "$VERSION_CODENAME" == noble ]]
sources=$(mktemp "${RUNNER_TEMP:?}/omnigent-ubuntu-sources.XXXXXX")
trap 'rm -f "$sources"' EXIT
chmod 644 "$sources"
cat > "$sources" <<'SOURCES'
deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://archive.ubuntu.com/ubuntu noble main restricted universe multiverse
deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://archive.ubuntu.com/ubuntu noble-updates main restricted universe multiverse
deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://security.ubuntu.com/ubuntu noble-security main restricted universe multiverse
SOURCES
options=(-o "Dir::Etc::sourcelist=$sources" -o Dir::Etc::sourceparts=-
  -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 -o Acquire::Retries=2
  -o Acquire::Languages=none -o APT::Update::Error-Mode=any)
timeout --kill-after=10s 180s sudo apt-get "${options[@]}" update
timeout --kill-after=10s 180s sudo apt-get "${options[@]}" install -y --no-install-recommends "$@"
