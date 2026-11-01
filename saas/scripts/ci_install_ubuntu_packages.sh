#!/usr/bin/env bash
# Pin hosted-runner apt to a recent immutable, signed Ubuntu repository view.
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
# Reuse one completed UTC hour throughout this job, including Playwright's apt.
snapshot_uri=$(python3 - "${RUNNER_TEMP:?}/omnigent-ubuntu-snapshot" <<'PY'
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

path = Path(sys.argv[1])
now = datetime.now(timezone.utc)
selected = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
with tempfile.NamedTemporaryFile(mode="w", dir=path.parent) as candidate:
    candidate.write(selected.strftime("%Y%m%dT%H%M%SZ"))
    candidate.flush()
    try:
        os.link(candidate.name, path)
    except FileExistsError:
        pass
snapshot = path.read_text()
selected = datetime.strptime(snapshot, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
if snapshot != selected.strftime("%Y%m%dT%H0000Z") or not timedelta(0) < now - selected <= timedelta(hours=24):
    raise SystemExit("Refusing invalid or stale CI Ubuntu snapshot")
print("https://snapshot.ubuntu.com/ubuntu/" + snapshot + "/")
PY
)
printf 'Ubuntu CI snapshot: %s\n' "$snapshot_uri"
# Existing repository signing keys and third-party sources remain unchanged.
sudo tee /etc/apt/apt.conf.d/99-omnigent-ci-network >/dev/null <<'NETWORK'
Acquire::http::Timeout "20";
Acquire::https::Timeout "20";
Acquire::Retries "2";
Acquire::Languages "none";
APT::Update::Error-Mode "any";
NETWORK
# By-hash can fall back to ordinary paths; both resolve inside this fixed view.
sudo tee /etc/apt/sources.list.d/ubuntu.sources >/dev/null <<UBUNTU
Types: deb
URIs: $snapshot_uri
Suites: noble noble-updates noble-security
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
cat > "$sources" <<SOURCES
deb [by-hash=force signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] $snapshot_uri noble main restricted universe multiverse
deb [by-hash=force signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] $snapshot_uri noble-updates main restricted universe multiverse
deb [by-hash=force signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] $snapshot_uri noble-security main restricted universe multiverse
SOURCES
options=(-o "Dir::Etc::sourcelist=$sources" -o Dir::Etc::sourceparts=-
  -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 -o Acquire::Retries=2
  -o Acquire::Languages=none -o APT::Update::Error-Mode=any)
timeout --kill-after=10s 180s sudo apt-get "${options[@]}" update
timeout --kill-after=10s 180s sudo apt-get "${options[@]}" install -y --no-install-recommends "$@"
