"""The privileged snapshot job must not extract arbitrary PR-produced tar members."""

from __future__ import annotations

import io
import re
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/ui-snapshot-update.yml"
SNAPSHOTS = Path("tests/e2e_ui/visual/snapshots")


def _restore_script() -> str:
    workflow = yaml.safe_load(WORKFLOW.read_text())
    step = next(
        step
        for step in workflow["jobs"]["commit"]["steps"]
        if step.get("name") == "Restore the regenerated baselines"
    )
    match = re.search(r"python - \"\$tgz\" <<'PY'\n(.*?)\nPY\n", step["run"], re.S)
    assert match is not None
    return match.group(1)


def _run_restore(tmp_path: Path, malicious: str | None = None) -> subprocess.CompletedProcess[str]:
    root = tmp_path / SNAPSHOTS
    root.mkdir(parents=True)
    (root / "old.png").write_bytes(b"old")
    archive_path = tmp_path / "snapshots.tgz"
    with tarfile.open(archive_path, "w:gz") as archive:
        content = b"\x89PNG\r\n\x1a\nnew"
        member = tarfile.TarInfo(f"{SNAPSHOTS}/new.png")
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
        if malicious is not None:
            member = tarfile.TarInfo(f"{SNAPSHOTS}/{malicious}")
            member.type = tarfile.SYMTYPE if malicious == "escape" else tarfile.REGTYPE
            member.linkname = "../../../../outside" if malicious == "escape" else ""
            archive.addfile(member, io.BytesIO(b"") if member.isfile() else None)
    return subprocess.run(
        [sys.executable, "-c", _restore_script(), str(archive_path)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )


def test_snapshot_archive_replaces_only_expected_pngs(tmp_path: Path) -> None:
    result = _run_restore(tmp_path)
    assert result.returncode == 0, result.stderr
    assert not (tmp_path / SNAPSHOTS / "old.png").exists()
    assert (tmp_path / SNAPSHOTS / "new.png").read_bytes().startswith(b"\x89PNG")


@pytest.mark.parametrize("malicious", ["escape", "../../outside.png"])
def test_snapshot_archive_rejects_unsafe_members_without_replacing_baselines(
    tmp_path: Path, malicious: str
) -> None:
    result = _run_restore(tmp_path, malicious)
    assert result.returncode != 0
    assert (tmp_path / SNAPSHOTS / "old.png").read_bytes() == b"old"
    assert not (tmp_path / "outside.png").exists()
