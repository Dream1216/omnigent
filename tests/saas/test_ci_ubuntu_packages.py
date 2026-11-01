"""Exercise bounded CI package setup without invoking sudo or the local package manager."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "saas/scripts/ci_install_ubuntu_packages.sh"


@pytest.mark.parametrize("update_status", [0, 17])
def test_signed_package_setup_stops_on_failed_update(tmp_path, update_status):
    commands = tmp_path / "commands"
    commands.mkdir()
    log = tmp_path / "commands.jsonl"
    environment = tmp_path / "environment.sh"
    environment.write_text(
        "function .() { ID=ubuntu; VERSION_ID=24.04; VERSION_CODENAME=noble; }\n"
    )
    timeout = commands / "timeout"
    timeout.write_text(
        '#!/bin/bash\n[[ "$1 $2" == "--kill-after=10s 180s" ]] || exit 81\nshift 2\nexec "$@"\n'
    )
    sudo = commands / "sudo"
    sudo.write_text(
        "#!/usr/bin/env python3\n"
        "import json,os,sys\nfrom pathlib import Path\n"
        "args=sys.argv[1:]\n"
        "source=next(x.split('=',1)[1] for x in args if x.startswith('Dir::Etc::sourcelist='))\n"
        "row={'args':args,'sources':Path(source).read_text()}\n"
        "with open(os.environ['TEST_APT_LOG'],'a') as f: f.write(json.dumps(row)+'\\n')\n"
        "sys.exit(int(os.environ['TEST_APT_UPDATE_STATUS']) if args[-1]=='update' else 0)\n"
    )
    timeout.chmod(0o755)
    sudo.chmod(0o755)
    result = subprocess.run(
        ["bash", str(SCRIPT), "ripgrep", "bubblewrap", "tmux"],
        env={
            **os.environ,
            "PATH": str(commands) + os.pathsep + os.environ["PATH"],
            "BASH_ENV": str(environment),
            "GITHUB_ACTIONS": "true",
            "RUNNER_OS": "Linux",
            "RUNNER_TEMP": str(tmp_path),
            "TEST_APT_LOG": str(log),
            "TEST_APT_UPDATE_STATUS": str(update_status),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == update_status, result.stderr
    rows = [json.loads(line) for line in log.read_text().splitlines()]
    assert len(rows) == (1 if update_status else 2)
    for row in rows:
        assert row["args"][0] == "apt-get"
        assert "Acquire::https::Timeout=20" in row["args"]
        assert "APT::Update::Error-Mode=any" in row["args"]
        assert "Dir::Etc::sourceparts=-" in row["args"]
        assert (
            row["sources"].count("signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg") == 3
        )
        assert "http:" not in row["sources"] and "azure" not in row["sources"]
    if not update_status:
        assert rows[1]["args"][-6:] == [
            "install",
            "-y",
            "--no-install-recommends",
            "ripgrep",
            "bubblewrap",
            "tmux",
        ]
    assert not list(tmp_path.glob("omnigent-ubuntu-sources.*"))


def test_local_execution_refuses_before_any_privileged_command(tmp_path):
    result = subprocess.run(
        ["bash", str(SCRIPT), "tmux"],
        env={**os.environ, "GITHUB_ACTIONS": "false", "RUNNER_TEMP": str(tmp_path)},
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert not list(tmp_path.iterdir())
