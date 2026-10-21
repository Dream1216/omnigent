from __future__ import annotations

import shlex
import subprocess
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
            "jcode@0.90.1",
            "cursor@1.0.0",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout.splitlines() == [
        "jcode@0.90.1:false",
        "child:false",
        "cursor@1.0.0:false",
        "child:false",
    ]


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
