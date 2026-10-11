from __future__ import annotations

import shlex
import subprocess
from pathlib import Path

import pytest


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
