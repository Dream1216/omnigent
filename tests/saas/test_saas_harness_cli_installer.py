from __future__ import annotations

import hashlib
import io
import json
import os
import shlex
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest


@pytest.mark.parametrize("parent_telemetry", [None, "enabled", "log"])
def test_saas_harness_build_disables_gh_telemetry_before_delegation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, parent_telemetry: str | None
) -> None:
    repo = Path(__file__).resolve().parents[2]
    installer = (repo / "saas/scripts/install-saas-harness-cli.sh").read_text(encoding="utf-8")
    install_phase = installer[: installer.index("# Version probes can write logs")]
    delegate = tmp_path / "upstream installer.sh"
    delegate.write_text(
        'printf "%s:%s\\n" "$1" "$GH_TELEMETRY"\n'
        'bash -euc \'printf "child:%s\\n" "$GH_TELEMETRY"\'\n',
        encoding="utf-8",
    )
    if parent_telemetry is None:
        monkeypatch.delenv("GH_TELEMETRY", raising=False)
    else:
        monkeypatch.setenv("GH_TELEMETRY", parent_telemetry)

    result = subprocess.run(
        [
            "bash",
            "-euc",
            install_phase.replace("/tmp/install-harness-cli.sh", shlex.quote(str(delegate))),
            "installer",
            "goose@1.38.0",
            "cursor@1.0.0",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout.splitlines() == [
        "goose@1.38.0:false",
        "child:false",
        "cursor@1.0.0:false",
        "child:false",
    ]


@pytest.mark.parametrize(
    ("cli", "architecture", "fault"),
    [
        (cli, architecture, fault)
        for cli in ("jcode", "devin")
        for architecture in ("x86_64", "aarch64")
        for fault in (None, "hash", "download", "version", "smoke", "layout")
    ]
    + [("devin", architecture, "manifest") for architecture in ("x86_64", "aarch64")]
    + [(cli, "s390x", None) for cli in ("jcode", "devin")],
)
def test_fixed_extra_cli_assets_preserve_layout_and_dual_user_checks(
    tmp_path: Path, cli: str, architecture: str, fault: str | None
) -> None:
    repo = Path(__file__).resolve().parents[2]
    installer = (repo / "saas/scripts/install-saas-harness-cli.sh").read_text()
    phase = installer[: installer.index("# Version probes can write logs")]
    version = "0.90.1" if cli == "jcode" else "3000.11.3"
    target = "jcode-linux-" + architecture if cli == "jcode" else "package/bin/devin"
    archive = tmp_path / "release.tar.gz"
    main = b'#!/bin/sh\nprintf "%s\\n" "${PROBE_USER:-root}" >> "$PROBE_LOG"\n'
    main += (f'[ "${{FAIL_SMOKE:-0}}" != 1 ] || exit 1\nprintf "{cli} v{version}\\n"\n').encode()
    members = {target: main}
    if cli == "jcode" and architecture == "x86_64":
        members[target + ".bin"] = b"actual native binary fixture"
    if cli == "devin":
        platform = "x64" if architecture == "x86_64" else "arm64"
        members["package/package.json"] = json.dumps(
            {
                "name": "devin",
                "version": "wrong" if fault == "manifest" else f"{version}-linux-{platform}",
            }
        ).encode()
    if fault == "layout":
        members["../unexpected"] = b"not in the fixed release"
    with tarfile.open(archive, "w:gz") as bundle:
        for name, body in members.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(body), 0o755
            bundle.addfile(info, io.BytesIO(body))
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    for name in (f"{cli.upper()}_SHA256_AMD64", f"{cli.upper()}_SHA256_ARM64"):
        prefix = name + '="'
        old = phase.split(prefix, 1)[1].split('"', 1)[0]
        phase = phase.replace(prefix + old + '"', prefix + checksum + '"')
    if fault == "hash":
        archive.write_bytes(archive.read_bytes() + b"changed transport")
    commands = tmp_path / "commands"
    commands.mkdir()
    scripts = {
        "uname": 'printf "%s\\n" "$INSTALL_ARCH"\n',
        "id": "exit 0\n",
        "chown": "exit 0\n",
        "runuser": 'shift 3\nPROBE_USER=sandbox exec "$@"\n',
        "curl": 'printf "%s\\n" "$@" >> "$CURL_LOG"\n'
        '[ "${FAIL_DOWNLOAD:-0}" != 1 ] || exit 22\n'
        'while [ "$1" != -o ]; do shift; done\ncp "$RELEASE_ARCHIVE" "$2"\n',
    }
    if shutil.which("sha256sum") is None:
        scripts["sha256sum"] = 'exec shasum -a 256 "$@"\n'
    for name, body in scripts.items():
        path = commands / name
        path.write_text("#!/bin/sh\nset -eu\n" + body)
        path.chmod(0o755)
    home, binaries = tmp_path / "cli home", tmp_path / "bin"
    if cli == "devin":
        phase = phase.replace("/opt/devin", shlex.quote(str(home)))
    binaries.mkdir()
    probe, curl = tmp_path / "probes", tmp_path / "curl arguments"
    spec = f"{cli}@wrong" if fault == "version" else f"{cli}@{version}"
    if fault is None and architecture == "x86_64":
        spec = cli
    result = subprocess.run(
        ["bash", "-euc", phase, "installer", spec],
        env={
            **os.environ,
            "PATH": f"{commands}:{binaries}:{os.environ['PATH']}",
            "JCODE_HOME": str(home),
            "BIN_DIR": str(binaries),
            "INSTALL_ARCH": architecture,
            "RELEASE_ARCHIVE": str(archive),
            "PROBE_LOG": str(probe),
            "CURL_LOG": str(curl),
            "FAIL_SMOKE": "1" if fault == "smoke" else "0",
            "FAIL_DOWNLOAD": "1" if fault == "download" else "0",
        },
        capture_output=True,
        text=True,
        check=False,
    )
    if fault or architecture == "s390x":
        assert result.returncode != 0
        if fault != "smoke":
            assert not (binaries / cli).exists()
            assert not probe.exists()
        assert "cargo" not in result.stderr and "building from source" not in result.stdout
        return
    assert result.returncode == 0, result.stderr
    installed = home / ".jcode/builds/versions/0.90.1" if cli == "jcode" else home / "bin"
    assert (binaries / cli).resolve() == installed / cli
    assert (installed / cli).read_bytes() == main
    if cli == "jcode":
        assert (home / ".jcode/builds/stable-version").read_text() == "0.90.1\n"
        if architecture == "x86_64":
            assert (installed / (target + ".bin")).read_bytes() == members[target + ".bin"]
    assert probe.read_text().splitlines() == ["root", "sandbox"]
    assert "--retry-all-errors" in curl.read_text()
    if cli == "jcode":
        assert f"/v0.90.1/{target}.tar.gz" in curl.read_text()
    else:
        assert f"/devin/-/devin-{version}-linux-{platform}.tgz" in curl.read_text()


@pytest.mark.parametrize("prune_marker_present", [False, True])
def test_saas_harness_installer_removes_only_jcode_probe_state(
    tmp_path: Path, prune_marker_present: bool
) -> None:
    repo = Path(__file__).resolve().parents[2]
    installer = (repo / "saas/scripts/install-saas-harness-cli.sh").read_text(encoding="utf-8")
    start = installer.index("rm -rf -- /opt/jcode/.jcode/logs")
    end = installer.index("# Installer-created hard links and timestamps")
    assert installer.index("done\n") < start < end
    assert end < installer.index("python -B /tmp/normalize_host_cli_tree.py")
    cleanup = installer[start:end]
    root = tmp_path / "jcode home"
    state = root / ".jcode"
    logs = state / "logs"
    logs.mkdir(parents=True)
    (logs / "probe.log").write_text("wall-clock probe log", encoding="utf-8")
    marker = state / "sessions-bak-prune.stamp"
    if prune_marker_present:
        marker.touch()
    binary = state / "builds" / "v0.90.1" / "jcode"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"pinned executable")
    current = root / "jcode"
    current.symlink_to(binary.relative_to(root))
    session = state / "sessions" / "retained.json"
    session.parent.mkdir()
    session.write_bytes(b"retained session")

    subprocess.run(
        ["bash", "-euc", cleanup.replace("/opt/jcode", shlex.quote(str(root)))],
        check=True,
        capture_output=True,
        text=True,
    )

    assert not logs.exists()
    assert not marker.exists()
    assert binary.read_bytes() == b"pinned executable"
    assert current.is_symlink() and current.read_bytes() == b"pinned executable"
    assert session.read_bytes() == b"retained session"
