"""Exercise bounded CI package setup without invoking sudo or the local package manager."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "saas/scripts/ci_install_ubuntu_packages.sh"


@pytest.mark.parametrize(
    "update_status,configure_only", [(0, False), (17, False), (100, False), (0, True)]
)
def test_signed_package_setup_stops_on_failed_update(tmp_path, update_status, configure_only):
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
        "if args[0]=='tee':\n"
        " row={'args':args,'content':sys.stdin.read()}\n"
        " with open(os.environ['TEST_APT_LOG'],'a') as f: f.write(json.dumps(row)+'\\n')\n"
        " sys.exit(0)\n"
        "source=next(x.split('=',1)[1] for x in args if x.startswith('Dir::Etc::sourcelist='))\n"
        "row={'args':args,'sources':Path(source).read_text()}\n"
        "with open(os.environ['TEST_APT_LOG'],'a') as f: f.write(json.dumps(row)+'\\n')\n"
        "sys.exit(int(os.environ['TEST_APT_UPDATE_STATUS']) if args[-1]=='update' else 0)\n"
    )
    timeout.chmod(0o755)
    sudo.chmod(0o755)
    result = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            *(["--configure-only"] if configure_only else ["ripgrep", "bubblewrap", "tmux"]),
        ],
        env={
            **os.environ,
            "PATH": str(commands) + os.pathsep + os.environ["PATH"],
            "BASH_ENV": str(environment),
            "GITHUB_ACTIONS": "true",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_TEMP": str(tmp_path),
            "TEST_APT_LOG": str(log),
            "TEST_APT_UPDATE_STATUS": str(update_status),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == update_status, result.stderr
    commands = [json.loads(line) for line in log.read_text().splitlines()]
    configs = [row for row in commands if row["args"][0] == "tee"]
    assert any(
        row["args"][1] == "/etc/apt/apt.conf.d/99-omnigent-ci-network"
        and 'Acquire::https::Timeout "20";' in row["content"]
        for row in configs
    )
    ubuntu = next(
        row["content"]
        for row in configs
        if row["args"][1] == "/etc/apt/sources.list.d/ubuntu.sources"
    )
    assert ubuntu.count("By-Hash: force") == 2
    assert ubuntu.count("Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg") == 2
    assert "Suites: noble noble-updates\n" in ubuntu
    assert "Suites: noble-security\n" in ubuntu
    assert "trusted=yes" not in ubuntu and "http:" not in ubuntu
    assert all(
        row["args"][1]
        in {
            "/etc/apt/apt-mirrors.txt",
            "/etc/apt/apt.conf.d/99-omnigent-ci-network",
            "/etc/apt/sources.list.d/ubuntu.sources",
        }
        for row in configs
    )
    rows = [row for row in commands if row["args"][0] == "apt-get"]
    assert len(rows) == (0 if configure_only else 1 if update_status else 2)
    for row in rows:
        assert row["args"][0] == "apt-get"
        assert "Acquire::https::Timeout=20" in row["args"]
        assert "APT::Update::Error-Mode=any" in row["args"]
        assert "Dir::Etc::sourceparts=-" in row["args"]
        assert (
            row["sources"].count("signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg") == 3
        )
        assert row["sources"].count("by-hash=force") == 3
        assert "http:" not in row["sources"] and "azure" not in row["sources"]
    if not update_status and not configure_only:
        assert rows[1]["args"][-6:] == [
            "install",
            "-y",
            "--no-install-recommends",
            "ripgrep",
            "bubblewrap",
            "tmux",
        ]
    assert not list(tmp_path.glob("omnigent-ubuntu-sources.*"))


@pytest.mark.parametrize(
    "invalid", [{"GITHUB_ACTIONS": "false"}, {"RUNNER_OS": "Darwin"}, {"RUNNER_ARCH": "ARM64"}]
)
def test_local_execution_refuses_before_any_privileged_command(tmp_path, invalid):
    result = subprocess.run(
        ["bash", str(SCRIPT), "tmux"],
        env={
            **os.environ,
            "GITHUB_ACTIONS": "true",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_TEMP": str(tmp_path),
            **invalid,
        },
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert not list(tmp_path.iterdir())


def test_all_release_ci_apt_and_browser_dependency_entries_use_bounded_setup():
    import yaml

    root = SCRIPT.parents[2]
    paths = [
        ".github/workflows/ci.yml",
        ".github/workflows/e2e-ui.yml",
        ".github/workflows/saas-upstream-compat.yml",
        ".github/actions/e2e-run/action.yml",
        ".github/actions/integration-run/action.yml",
        ".github/actions/compat-smoke-run/action.yml",
        ".github/actions/compat-smoke-ui-run/action.yml",
    ]
    browser_installs = 0
    for name in paths:
        content = yaml.safe_load((root / name).read_text())
        groups = list(content["jobs"].values()) if "jobs" in content else [content["runs"]]
        for group in groups:
            for step in group.get("steps", []):
                command = step.get("run", "")
                assert "sudo apt-get" not in command, (name, step.get("name"))
                if "playwright install --with-deps" in command:
                    browser_installs += 1
                    assert command.index(
                        "ci_install_ubuntu_packages.sh --configure-only"
                    ) < command.index("playwright install --with-deps")
    assert browser_installs == 4
