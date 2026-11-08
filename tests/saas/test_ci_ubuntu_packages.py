"""Exercise bounded CI package setup without invoking sudo or the local package manager."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "saas/scripts/ci_install_ubuntu_packages.sh"


@pytest.mark.parametrize(
    "command,accepted",
    [
        (
            "apt-get update&& apt-get install -y --no-install-recommends "
            "libasound2t64 fonts-liberation",
            True,
        ),
        ("apt-get update && apt-get install -y --allow-unauthenticated tmux", False),
        ("apt-get update && apt-get install -y --no-install-recommends", False),
        ("apt-get update && apt-get install -y --no-install-recommends tmux; reboot", False),
        ("apt-get update && apt-get install -y --no-install-recommends $(reboot)", False),
        ("apt-get update || apt-get install -y --no-install-recommends tmux", False),
    ],
)
def test_playwright_handoff_only_accepts_its_exact_package_command(command, accepted, monkeypatch):
    source = SCRIPT.read_text().split("<<'PLAYWRIGHT'\n", 1)[1].split("\nPLAYWRIGHT", 1)[0]
    monkeypatch.setattr(sys, "argv", ["sudo", "--", "sh", "-c", command])
    monkeypatch.setenv("OMNIGENT_CI_UBUNTU_ORIGINAL_PATH", "/original/path")
    monkeypatch.setenv("OMNIGENT_CI_UBUNTU_PACKAGE_SETUP", "/approved/installer.sh")
    with patch("os.execvpe") as execute:
        if not accepted:
            with pytest.raises(SystemExit, match="Refusing unexpected"):
                exec(compile(source, "playwright-sudo-handoff", "exec"), {})
            execute.assert_not_called()
        else:
            exec(compile(source, "playwright-sudo-handoff", "exec"), {})
            executable, arguments, environment = execute.call_args.args
            assert executable == "bash"
            assert arguments == [
                "bash",
                "/approved/installer.sh",
                "libasound2t64",
                "fonts-liberation",
            ]
            assert environment["PATH"] == "/original/path"


@pytest.mark.parametrize("entry", ["packages", "playwright"])
@pytest.mark.parametrize(
    "update_status,configure_only,reuse,update_errors,install_errors,updates,installs,status,archive_recovery,index_state",
    [
        (0, False, False, (), (), 1, 1, 0, False, None),
        (0, False, True, (), (), 1, 1, 0, False, None),
        (17, False, False, (), (), 1, 0, 17, False, None),
        (100, False, False, (), (), 1, 0, 100, False, None),
        (0, True, False, (), (), 0, 0, 0, False, None),
        (0, False, False, ("502 Bad Gateway",), (), 2, 1, 0, False, None),
        (0, False, False, ("503 Service Unavailable",) * 2, (), 3, 1, 0, False, None),
        (0, False, False, ("503 Service Unavailable",) * 3, (), 3, 0, 100, False, None),
        (0, False, False, ("502 Bad Gateway\nHash Sum mismatch",), (), 1, 0, 100, False, None),
        (0, False, False, ("503 Service Unavailable\nNO_PUBKEY",), (), 1, 0, 100, False, None),
        (0, False, False, ("404 Not Found",), (), 1, 0, 100, False, None),
        (0, False, False, (), ("502 Bad Gateway",), 1, 2, 0, False, None),
        (0, False, False, (), ("503 Service Unavailable",) * 3, 1, 3, 100, False, None),
        (0, False, False, (), ("500 Internal Server Error",) * 3, 1, 3, 100, False, None),
        (
            0,
            False,
            False,
            (),
            ("503 Service Unavailable\nHash Sum mismatch",),
            1,
            1,
            100,
            False,
            None,
        ),
        (0, False, False, (), ("503 Service Unavailable\nNO_PUBKEY",), 1, 1, 100, False, None),
        (
            0,
            False,
            False,
            ("503 Service Unavailable",),
            ("502 Bad Gateway",),
            2,
            2,
            0,
            False,
            None,
        ),
        (0, False, False, (), (), 1, 1, 0, True, None),
        (0, False, True, (), (), 0, 1, 0, True, "valid"),
        (0, False, True, (), (), 0, 0, 1, True, "changed"),
        (0, False, True, (), (), 0, 0, 1, True, "stale"),
        (0, False, False, ("503 Service Unavailable\nNO_PUBKEY",), (), 1, 0, 100, True, None),
        (0, False, False, ("502 Bad Gateway\nHash Sum mismatch",), (), 1, 0, 100, True, None),
    ],
)
def test_signed_package_setup_stops_on_failed_update(
    tmp_path,
    entry,
    update_status,
    configure_only,
    reuse,
    update_errors,
    install_errors,
    updates,
    installs,
    status,
    archive_recovery,
    index_state,
):
    snapshot_path = tmp_path / "omnigent-ubuntu-snapshot"
    cached = (datetime.now(UTC) - timedelta(hours=3)).strftime("%Y%m%dT%H0000Z")
    if reuse:
        snapshot_path.write_text(cached)
    if index_state is not None:
        names = [
            "/var/lib/apt/lists/archive.ubuntu.com_ubuntu_dists_noble_InRelease",
            "/var/lib/apt/lists/archive.ubuntu.com_ubuntu_dists_noble-updates_InRelease",
            "/var/lib/apt/lists/security.ubuntu.com_ubuntu_dists_noble-security_InRelease",
        ]
        hashes = [hashlib.sha256(name.encode()).hexdigest() + "  " + name for name in names]
        if index_state == "changed":
            hashes[0] = "0" * 64 + "  " + names[0]
        captured = datetime.now(UTC) - timedelta(hours=25 if index_state == "stale" else 0)
        (tmp_path / "omnigent-ubuntu-archive-index-state").write_text(
            json.dumps({"captured_at": captured.isoformat(), "hashes": hashes})
        )
    commands = tmp_path / "commands"
    commands.mkdir()
    (commands / "python3").symlink_to(sys.executable)
    log = tmp_path / "commands.jsonl"
    environment = tmp_path / "environment.sh"
    environment.write_text(
        "function .() { ID=ubuntu; VERSION_ID=24.04; VERSION_CODENAME=noble; }\n"
    )
    timeout = commands / "timeout"
    timeout.write_text(
        "#!/bin/bash\n"
        '[[ "$1" == --kill-after=10s && ( "$2" == 180s || "$2" == 360s ) ]] || exit 81\n'
        'shift 2\nexec "$@"\n'
    )
    uv = commands / "uv"
    uv.write_text(
        f"#!{sys.executable}\nimport subprocess,sys\n"
        "assert sys.argv[1:]==['run','--no-sync','playwright','install-deps','chromium']\n"
        "result=subprocess.run(['sudo','--','sh','-c',"
        "'apt-get update&& apt-get install -y --no-install-recommends ripgrep bubblewrap tmux'])\n"
        "sys.exit(0 if result.returncode==0 else 1)\n"
    )
    uv.chmod(0o755)
    sudo = commands / "sudo"
    sudo.write_text(
        f"#!{sys.executable}\n"
        "import hashlib,io,json,os,runpy,sys,urllib.request\nfrom pathlib import Path\n"
        "args=sys.argv[1:]\n"
        "if args[0]=='tee':\n"
        " row={'args':args,'content':sys.stdin.read()}\n"
        " with open(os.environ['TEST_APT_LOG'],'a') as f: f.write(json.dumps(row)+'\\n')\n"
        " sys.exit(0)\n"
        "if args[0]=='sha256sum':\n"
        " for name in args[1:]: print(hashlib.sha256(name.encode()).hexdigest()+'  '+name)\n"
        " sys.exit(0)\n"
        "if args[0]=='python3':\n"
        " with open(os.environ['TEST_APT_LOG'],'a') as f: "
        "f.write(json.dumps({'args':args})+'\\n')\n"
        " args[args.index('--output')+1]=os.environ['TEST_APT_CACHE']\n"
        " urllib.request.urlopen=lambda *a,**k: io.BytesIO(b'locked Ubuntu package')\n"
        " sys.argv=args[1:]\n runpy.run_path(args[1],run_name='__main__')\n sys.exit(0)\n"
        "source=next(x.split('=',1)[1] for x in args if x.startswith('Dir::Etc::sourcelist='))\n"
        "row={'args':args,'sources':Path(source).read_text()}\n"
        "op='update' if args[-1]=='update' else 'install'\n"
        "prior=[json.loads(line) for line in "
        "Path(os.environ['TEST_APT_LOG']).read_text().splitlines()]\n"
        "calls=sum(x['args'][0]=='apt-get' and "
        "'--print-uris' not in x['args'] and "
        "(x['args'][-1]=='update')==(op=='update') for x in prior)\n"
        "with open(os.environ['TEST_APT_LOG'],'a') as f: f.write(json.dumps(row)+'\\n')\n"
        "if '--print-uris' in args:\n"
        " root=next(x for x in row['sources'].split() "
        "if x.startswith('https://'))\n"
        " payload=b'locked Ubuntu package'\n"
        ' print("\'"+root+"pool/main/t/tool/tool_1.0_amd64.deb\' '
        'tool_1.0_amd64.deb "+str(len(payload))+" SHA256:"+'
        "hashlib.sha256(payload).hexdigest())\n sys.exit(0)\n"
        "if op=='install':\n"
        " assert '--no-download' in args\n"
        " assert (Path(os.environ['TEST_APT_CACHE'])/'tool_1.0_amd64.deb').read_bytes() "
        "==b'locked Ubuntu package'\n"
        "errors=json.loads(os.environ['TEST_APT_'+op.upper()+'_ERRORS'])\n"
        "if calls<len(errors):\n print(errors[calls],file=sys.stderr)\n sys.exit(100)\n"
        "sys.exit(int(os.environ['TEST_APT_UPDATE_STATUS']) if args[-1]=='update' else 0)\n"
    )
    sleep = commands / "sleep"
    sleep.write_text(
        "#!/usr/bin/env python3\nimport json,os,sys\n"
        "with open(os.environ['TEST_APT_LOG'],'a') as f: "
        "f.write(json.dumps({'args':['sleep',*sys.argv[1:]]})+'\\n')\n"
    )
    timeout.chmod(0o755)
    sudo.chmod(0o755)
    sleep.chmod(0o755)
    selection_started = datetime.now(UTC)
    result = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            *(
                ["--configure-only"]
                if configure_only
                else ["--playwright-chromium"]
                if entry == "playwright"
                else ["ripgrep", "bubblewrap", "tmux"]
            ),
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
            "TEST_APT_UPDATE_ERRORS": json.dumps(update_errors),
            "TEST_APT_INSTALL_ERRORS": json.dumps(install_errors),
            "TEST_APT_CACHE": str(tmp_path / "prefetched-packages"),
            "OMNIGENT_CI_UBUNTU_ARCHIVE_RECOVERY": str(int(archive_recovery)),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    selection_completed = datetime.now(UTC)
    expected_status = int(status != 0) if entry == "playwright" and not configure_only else status
    assert result.returncode == expected_status, result.stdout + result.stderr
    snapshot = snapshot_path.read_text()
    selected = datetime.strptime(snapshot, "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
    if reuse:
        assert snapshot == cached
    else:
        earliest = selection_started.replace(minute=0, second=0, microsecond=0) - timedelta(
            hours=1
        )
        latest = selection_completed.replace(minute=0, second=0, microsecond=0) - timedelta(
            hours=1
        )
        assert earliest <= selected <= latest
    uri = f"https://snapshot.ubuntu.com/ubuntu/{snapshot}/"
    if archive_recovery:
        assert "Ubuntu CI recovery: official archive/security HTTPS" in result.stdout
    else:
        assert f"Ubuntu CI snapshot: {uri}" in result.stdout
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
    assert ubuntu.count("By-Hash: force") == (2 if archive_recovery else 1)
    assert ubuntu.count("Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg") == (
        2 if archive_recovery else 1
    )
    if archive_recovery:
        assert "URIs: https://archive.ubuntu.com/ubuntu/\n" in ubuntu
        assert "URIs: https://security.ubuntu.com/ubuntu/\n" in ubuntu
        assert "Suites: noble noble-updates\n" in ubuntu
        assert "Suites: noble-security\n" in ubuntu
    else:
        assert f"URIs: {uri}\n" in ubuntu
        assert "Suites: noble noble-updates noble-security\n" in ubuntu
    assert "trusted=yes" not in ubuntu and "http:" not in ubuntu
    assert all(
        row["args"][1]
        in {
            "/etc/apt/apt.conf.d/99-omnigent-ci-network",
            "/etc/apt/sources.list.d/ubuntu.sources",
        }
        for row in configs
    )
    rows = [
        row
        for row in commands
        if row["args"][0] == "apt-get" and "--print-uris" not in row["args"]
    ]
    plans = [row for row in commands if "--print-uris" in row["args"]]
    materializations = [row for row in commands if row["args"][0] == "python3"]
    assert len(plans) == len(materializations) == installs
    assert all(
        ("--allow-ubuntu-archive" in row["args"]) == archive_recovery for row in materializations
    )
    assert all("Acquire::ForceHash=SHA256" in row["args"] for row in plans)
    assert all(
        row["args"][2:] and row["args"][2:4] == ["--distribution", "ubuntu"]
        for row in materializations
    )
    assert len(rows) == updates + installs
    assert sum(row["args"][-1] == "update" for row in rows) == updates
    assert sum("install" in row["args"] for row in rows) == installs
    assert all(row["args"][1] in {"5", "10"} for row in commands if row["args"][0] == "sleep")
    attempt_logs = list(tmp_path.glob("omnigent-ubuntu-apt-attempt-*"))
    assert len(attempt_logs) == updates + installs
    retained_output = "\n".join(path.read_text() for path in attempt_logs)
    if update_errors:
        assert update_errors[0] in retained_output
    if install_errors:
        assert install_errors[0] in retained_output
    for row in rows:
        assert row["args"][0] == "apt-get"
        assert "Acquire::https::Timeout=20" in row["args"]
        assert "APT::Update::Error-Mode=any" in row["args"]
        assert "Dir::Etc::sourceparts=-" in row["args"]
        assert (
            row["sources"].count("signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg") == 3
        )
        assert row["sources"].count("by-hash=force") == 3
        if archive_recovery:
            assert row["sources"].count("https://archive.ubuntu.com/ubuntu/") == 2
            assert row["sources"].count("https://security.ubuntu.com/ubuntu/") == 1
        else:
            assert row["sources"].count(uri) == 3
            assert "archive.ubuntu.com" not in row["sources"]
            assert "security.ubuntu.com" not in row["sources"]
        assert "http:" not in row["sources"] and "azure" not in row["sources"]
    assert "Check-Valid-Until" not in ubuntu
    assert "AllowInsecure" not in "\n".join(str(row) for row in commands)
    for row in rows:
        if "install" not in row["args"]:
            continue
        assert row["args"][-7:] == [
            "install",
            "-y",
            "--no-install-recommends",
            "ripgrep",
            "bubblewrap",
            "tmux",
            "--no-download",
        ]
    assert not list(tmp_path.glob("omnigent-ubuntu-sources.*"))


@pytest.mark.parametrize("invalid", ["malformed", "stale", "future", "non-hour"])
def test_invalid_cached_snapshot_refuses_before_privileged_commands(tmp_path, invalid):
    now = datetime.now(UTC)
    snapshot = {
        "malformed": "not-a-snapshot",
        "stale": (now - timedelta(hours=25)).strftime("%Y%m%dT%H0000Z"),
        "future": (now + timedelta(hours=2)).strftime("%Y%m%dT%H0000Z"),
        "non-hour": (now - timedelta(hours=2)).strftime("%Y%m%dT%H0100Z"),
    }[invalid]
    cache = tmp_path / "omnigent-ubuntu-snapshot"
    cache.write_text(snapshot)
    environment = tmp_path / "environment.sh"
    environment.write_text(
        "function .() { ID=ubuntu; VERSION_ID=24.04; VERSION_CODENAME=noble; }\n"
        'function sudo() { touch "$RUNNER_TEMP/unexpected-privileged-command"; return 81; }\n'
    )
    result = subprocess.run(
        ["bash", str(SCRIPT), "tmux"],
        env={
            **os.environ,
            "BASH_ENV": str(environment),
            "GITHUB_ACTIONS": "true",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_TEMP": str(tmp_path),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert cache.read_text() == snapshot
    assert not (tmp_path / "unexpected-privileged-command").exists()


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
        ".github/workflows/saas-image-candidate.yml",
        ".github/actions/e2e-run/action.yml",
        ".github/actions/integration-run/action.yml",
        ".github/actions/compat-smoke-run/action.yml",
        ".github/actions/compat-smoke-ui-run/action.yml",
        ".github/workflows/server-compat.yml",
        ".github/workflows/integration.yml",
    ]
    browser_installs = 0
    for name in paths:
        content = yaml.safe_load((root / name).read_text())
        groups = list(content["jobs"].values()) if "jobs" in content else [content["runs"]]
        for group in groups:
            for step in group.get("steps", []):
                command = step.get("run", "")
                if "jobs" in content and step.get("uses") in {
                    "./.github/actions/e2e-run",
                    "./.github/actions/integration-run",
                    "./.github/actions/compat-smoke-run",
                    "./.github/actions/compat-smoke-ui-run",
                }:
                    environment = {
                        **content.get("env", {}),
                        **group.get("env", {}),
                        **step.get("env", {}),
                    }
                    assert environment.get("OMNIGENT_CI_UBUNTU_ARCHIVE_RECOVERY") == "1"
                assert "sudo apt-get" not in command, (name, step.get("name"))
                if name in paths[:5] and "ci_install_ubuntu_packages.sh" in command:
                    environment = {
                        **content.get("env", {}),
                        **group.get("env", {}),
                        **step.get("env", {}),
                    }
                    assert environment.get("OMNIGENT_CI_UBUNTU_ARCHIVE_RECOVERY") == "1"
                if "playwright install chromium" in command:
                    browser_installs += 1
                    assert command.index(
                        "ci_install_ubuntu_packages.sh --playwright-chromium"
                    ) < command.index("playwright install chromium")
                    assert "--with-deps" not in command
    assert browser_installs == 5


@pytest.mark.parametrize("archive_recovery", [False, True])
@pytest.mark.parametrize(
    "errors,apt_failure,calls,status",
    [
        (["502 Bad Gateway"], True, 1, 1),
        (["500 Internal Server Error"] * 3, True, 1, 1),
        (["503 Service Unavailable\nHash Sum mismatch"], True, 1, 1),
        (["503 Service Unavailable\nNO_PUBKEY"], True, 1, 1),
        (["502 Bad Gateway"], False, 1, 1),
    ],
)
def test_locked_playwright_dependency_transport_is_bounded(
    tmp_path, errors, apt_failure, calls, status, archive_recovery
):
    environment = tmp_path / "environment.sh"
    environment.write_text(
        "function .() { ID=ubuntu; VERSION_ID=24.04; VERSION_CODENAME=noble; }\n"
        'function sudo() { if [[ "$1" == tee ]]; then cat >/dev/null; '
        'elif [[ "$1" == sha256sum ]]; then shift; for name in "$@"; do '
        'printf "%064d  %s\\n" 0 "$name"; done; else return 81; fi; }\n'
        'function timeout() { [[ "$1 $2" == "--kill-after=10s 360s" ]] || return 81; '
        'shift 2; "$@"; }\n'
        'function sleep() { [[ "$1" == 5 || "$1" == 10 ]]; }\n'
    )
    uv = tmp_path / "uv"
    uv.write_text(
        "#!/usr/bin/env python3\nimport json,os,sys\nfrom pathlib import Path\n"
        "assert sys.argv[1:]==['run','--no-sync','playwright','install-deps','chromium']\n"
        "counter=Path(os.environ['RUNNER_TEMP'])/'calls'\n"
        "count=int(counter.read_text()) if counter.exists() else 0\n"
        "counter.write_text(str(count+1))\n"
        "errors=json.loads(os.environ['TEST_ERRORS'])\n"
        "if count<len(errors):\n print(errors[count])\n"
        " if os.environ['TEST_APT_FAILURE']=='true':\n"
        "  print('Error: Installation process exited with code: 100')\n"
        " sys.exit(1)\n"
    )
    uv.chmod(0o755)
    result = subprocess.run(
        ["bash", str(SCRIPT), "--playwright-chromium"],
        env={
            **os.environ,
            "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
            "BASH_ENV": str(environment),
            "GITHUB_ACTIONS": "true",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_TEMP": str(tmp_path),
            "TEST_ERRORS": json.dumps(errors),
            "TEST_APT_FAILURE": str(apt_failure).lower(),
            "OMNIGENT_CI_UBUNTU_ARCHIVE_RECOVERY": str(int(archive_recovery)),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == status, result.stdout + result.stderr
    assert int((tmp_path / "calls").read_text()) == calls
    logs = list(tmp_path.glob("omnigent-playwright-deps.*"))
    assert len(logs) == calls
    assert errors[0] in "\n".join(path.read_text() for path in logs)
