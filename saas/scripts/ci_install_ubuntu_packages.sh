#!/usr/bin/env bash
# Pin hosted-runner apt to a recent immutable, signed Ubuntu repository view.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_OS:-}" == Linux ]]
[[ "$#" -gt 0 && "${RUNNER_ARCH:-}" == X64 ]]
. /etc/os-release
[[ "$ID" == ubuntu && "$VERSION_ID" == 24.04 && "$VERSION_CODENAME" == noble ]]
if [[ "$1" == --configure-only || "$1" == --playwright-chromium ]]; then
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
Acquire::IndexTargets::deb::CNF::DefaultEnabled "false";
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

run_ci_ubuntu_apt() {
  set -euo pipefail
  local attempt log
  local -a statuses
  for attempt in 1 2 3; do
    log=$(mktemp "${RUNNER_TEMP:?}/omnigent-ubuntu-apt-attempt-${attempt}.XXXXXX")
    if "$@" 2>&1 | tee "$log"; then
      return 0
    else
      statuses=("${PIPESTATUS[@]}")
    fi
    # Keep failed output and never retry trust, integrity or configuration failures.
    [[ "${statuses[1]}" == 0 ]] || return "${statuses[1]}"
    [[ "$attempt" -lt 3 ]] || return "${statuses[0]}"
    if [[ "${statuses[0]}" != 100 ]]; then
      # Playwright reports apt's exit code through its own CLI exit status.
      [[ "$1" == uv && "${statuses[0]}" == 1 ]] || return "${statuses[0]}"
      grep -Fxq 'Error: Installation process exited with code: 100' "$log" || return "${statuses[0]}"
    fi
    if grep -Eiq 'NO_PUBKEY|BADSIG|EXPKEYSIG|not signed|does not have a Release file|Hash Sum mismatch|unexpected size|certificate verification failed|Release file.*(expired|not valid yet)' "$log"; then
      return "${statuses[0]}"
    fi
    grep -Eq '(^|[[:space:]])(429|500|502|503|504)[[:space:]]' "$log" || return "${statuses[0]}"
    printf 'Retrying the same signed Ubuntu snapshot after HTTP transport failure (attempt %s/3).\n' "$attempt"
    sleep "$((attempt * 5))"
  done
}
export -f run_ci_ubuntu_apt
if [[ "$1" == --playwright-chromium ]]; then
  # The locked Playwright release owns its complete dependency list.
  timeout --kill-after=10s 360s bash -c 'run_ci_ubuntu_apt "$@"' -- uv run --no-sync playwright install-deps chromium
  exit 0
fi
# One deadline covers all transport attempts; neither operation gains extra time.
timeout --kill-after=10s 180s bash -c 'run_ci_ubuntu_apt "$@"' -- sudo apt-get "${options[@]}" update
timeout --kill-after=10s 180s bash -c 'run_ci_ubuntu_apt "$@"' -- sudo apt-get "${options[@]}" install -y --no-install-recommends "$@"
