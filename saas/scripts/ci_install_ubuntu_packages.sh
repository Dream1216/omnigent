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
archive_recovery=${OMNIGENT_CI_UBUNTU_ARCHIVE_RECOVERY:-0}
[[ "$archive_recovery" == 0 || "$archive_recovery" == 1 ]]
export archive_recovery
archive_index_state="$RUNNER_TEMP/omnigent-ubuntu-archive-index-state"
export archive_index_state
if [[ "$archive_recovery" == 1 ]]; then
  repository_uri=https://archive.ubuntu.com/ubuntu/
  security_uri=https://security.ubuntu.com/ubuntu/
  printf 'Ubuntu CI recovery: official archive/security HTTPS; signed indexes fixed per job.\n'
else
  repository_uri=$snapshot_uri
  security_uri=$snapshot_uri
  printf 'Ubuntu CI snapshot: %s\n' "$snapshot_uri"
fi

verify_archive_index_state() {
  [[ "$archive_recovery" == 1 ]] || return 0
  local hashes
  hashes=$(sudo sha256sum \
    /var/lib/apt/lists/archive.ubuntu.com_ubuntu_dists_noble_InRelease \
    /var/lib/apt/lists/archive.ubuntu.com_ubuntu_dists_noble-updates_InRelease \
    /var/lib/apt/lists/security.ubuntu.com_ubuntu_dists_noble-security_InRelease)
  python3 - "$archive_index_state" "$hashes" <<'STATE'
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

path = Path(sys.argv[1])
hashes = sys.argv[2].splitlines()
if len(hashes) != 3 or any(re.fullmatch(r"[0-9a-f]{64}  /var/lib/apt/lists/[a-zA-Z0-9_.-]+", row) is None for row in hashes):
    raise SystemExit("Refusing incomplete official Ubuntu index state")
now = datetime.now(timezone.utc)
if path.exists():
    prior = json.loads(path.read_text())
    age = now - datetime.fromisoformat(prior["captured_at"])
    if prior["hashes"] != hashes or not timedelta(0) <= age <= timedelta(hours=24):
        raise SystemExit("Refusing changed or stale official Ubuntu signed indexes")
else:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump({"captured_at": now.isoformat(), "hashes": hashes}, stream, sort_keys=True)
print("Ubuntu CI apt-verified signed index state: " + json.dumps(hashes))
STATE
}
export -f verify_archive_index_state
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
if [[ "$archive_recovery" == 1 ]]; then
  sudo tee /etc/apt/sources.list.d/ubuntu.sources >/dev/null <<UBUNTU
Types: deb
URIs: $repository_uri
Suites: noble noble-updates
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
By-Hash: force

Types: deb
URIs: $security_uri
Suites: noble-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
By-Hash: force
UBUNTU
else
  sudo tee /etc/apt/sources.list.d/ubuntu.sources >/dev/null <<UBUNTU
Types: deb
URIs: $snapshot_uri
Suites: noble noble-updates noble-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
By-Hash: force
UBUNTU
fi
if [[ "$1" == --configure-only ]]; then
  [[ "$#" == 1 ]]
  exit 0
fi
sources=$(mktemp "${RUNNER_TEMP:?}/omnigent-ubuntu-sources.XXXXXX")
trap 'rm -f "$sources"' EXIT
chmod 644 "$sources"
cat > "$sources" <<SOURCES
deb [by-hash=force signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] $repository_uri noble main restricted universe multiverse
deb [by-hash=force signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] $repository_uri noble-updates main restricted universe multiverse
deb [by-hash=force signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] $security_uri noble-security main restricted universe multiverse
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
OMNIGENT_CI_PACKAGE_MATERIALIZER="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/materialize_debian_snapshot_packages.py"
export OMNIGENT_CI_PACKAGE_MATERIALIZER
install_ci_ubuntu_packages() {
  set -euo pipefail
  local inputs
  inputs=$(mktemp "${RUNNER_TEMP:?}/omnigent-ubuntu-package-inputs.XXXXXX")
  "$@" -o Acquire::ForceHash=SHA256 --print-uris > "$inputs" || return "$?"
  if grep -q "^'" "$inputs"; then
    local -a recovery_args=(--distribution ubuntu --inputs "$inputs" --output /var/cache/apt/archives)
    if [[ "$archive_recovery" == 1 ]]; then recovery_args+=(--allow-ubuntu-archive); fi
    sudo python3 "$OMNIGENT_CI_PACKAGE_MATERIALIZER" "${recovery_args[@]}" || return "$?"
  fi
  verify_archive_index_state || return "$?"
  "$@" --no-download
}
export -f install_ci_ubuntu_packages
if [[ "$1" == --playwright-chromium ]]; then
  # Playwright owns the package list; the existing installer owns its pinned indexes.
  [[ "$(id -u)" != 0 ]]
  playwright_commands=$(mktemp -d "${RUNNER_TEMP:?}/omnigent-playwright-commands.XXXXXX")
  trap 'rm -f "$sources"; rm -rf -- "$playwright_commands"' EXIT
  export OMNIGENT_CI_UBUNTU_ORIGINAL_PATH="$PATH"
  export OMNIGENT_CI_UBUNTU_PACKAGE_SETUP
  OMNIGENT_CI_UBUNTU_PACKAGE_SETUP="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/$(basename -- "${BASH_SOURCE[0]}")"
  cat > "$playwright_commands/sudo" <<'PLAYWRIGHT'
#!/usr/bin/env python3
import os
import re
import shlex
import sys

if len(sys.argv) != 5 or sys.argv[1:4] != ["--", "sh", "-c"]:
    raise SystemExit("Refusing unexpected Playwright privilege command")
lexer = shlex.shlex(sys.argv[4], posix=True, punctuation_chars=";&|")
lexer.whitespace_split = True
arguments = list(lexer)
prefix = ["apt-get", "update", "&&", "apt-get", "install", "-y", "--no-install-recommends"]
packages = arguments[len(prefix):]
if arguments[:len(prefix)] != prefix or not packages or any(
    re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", package) is None for package in packages
):
    raise SystemExit("Refusing unexpected Playwright dependency command")
environment = dict(os.environ, PATH=os.environ["OMNIGENT_CI_UBUNTU_ORIGINAL_PATH"])
os.execvpe("bash", ["bash", environment["OMNIGENT_CI_UBUNTU_PACKAGE_SETUP"], *packages], environment)
PLAYWRIGHT
  chmod 700 "$playwright_commands/sudo"
  playwright_log=$(mktemp "${RUNNER_TEMP:?}/omnigent-playwright-deps.XXXXXX")
  timeout --kill-after=10s 360s env PATH="$playwright_commands:$PATH" \
    uv run --no-sync playwright install-deps chromium 2>&1 | tee "$playwright_log"
  verify_archive_index_state
  exit 0
fi
# One deadline covers all transport attempts; neither operation gains extra time.
if [[ "$archive_recovery" == 1 && -f "$archive_index_state" ]]; then
  # Reuse this job's apt-verified view instead of resolving against newer indexes.
  verify_archive_index_state
else
  timeout --kill-after=10s 180s bash -c 'run_ci_ubuntu_apt "$@"' -- sudo apt-get "${options[@]}" update
  verify_archive_index_state
fi
timeout --kill-after=10s 180s bash -c 'run_ci_ubuntu_apt install_ci_ubuntu_packages "$@"' -- sudo apt-get "${options[@]}" install -y --no-install-recommends "$@"
