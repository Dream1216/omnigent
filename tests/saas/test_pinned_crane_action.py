"""The official API route preserves the exact release and fails closed on bad bytes."""

import hashlib
import io
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
import yaml

from tests.saas.test_n1_merge_gate import _run_full_gate

ROOT = Path(__file__).resolve().parents[2]
ACTION = ROOT / "saas/actions/setup-pinned-crane/action.yml"


@pytest.mark.parametrize(
    "fault", [None, "digest", "size", "version", "download", "platform", "entry"]
)
def test_exact_archive_install_checks_bytes_platform_and_executable_before_PATH(tmp_path, fault):
    action = yaml.load(ACTION.read_text(), Loader=yaml.BaseLoader)
    step = action["runs"]["steps"][0]
    version = "v0.21.5" if fault == "version" else "v0.21.6"
    body = f"#!/bin/sh\nprintf '%s\\n' '{version}'\n".encode()
    archive = tmp_path / "fixture.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        member = tarfile.TarInfo("other" if fault == "entry" else "crane")
        member.mode, member.size = 0o755, len(body)
        bundle.addfile(member, io.BytesIO(body))
    tools = tmp_path / "tools"
    tools.mkdir()
    gh = tools / "gh"
    gh.write_text(
        "#!/bin/sh\n"
        'printf "%s\\n" "$*" > "$CRANE_REQUEST_RECORD"\n'
        + ("exit 22\n" if fault == "download" else 'cat "$CRANE_TEST_ARCHIVE"\n')
    )
    gh.chmod(0o755)
    record, path_output = tmp_path / "request.txt", tmp_path / "github-path.txt"
    environment = {
        **os.environ,
        **step["env"],
        "PATH": os.pathsep.join(
            [str(tools), str(Path(sys.executable).parent), os.environ["PATH"]]
        ),
        "GH_TOKEN": "unit-test-only",
        "RUNNER_OS": "macOS" if fault == "platform" else "Linux",
        "RUNNER_ARCH": "X64",
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_PATH": str(path_output),
        "CRANE_TEST_ARCHIVE": str(archive),
        "CRANE_REQUEST_RECORD": str(record),
        "CRANE_ARCHIVE_SIZE": str(archive.stat().st_size + (fault == "size")),
        "CRANE_ARCHIVE_SHA256": "0" * 64
        if fault == "digest"
        else hashlib.sha256(archive.read_bytes()).hexdigest(),
    }
    result = subprocess.run(
        ["bash", "-c", step["run"]], cwd=tmp_path, env=environment, capture_output=True, text=True
    )
    if fault:
        assert result.returncode != 0
        assert not path_output.exists()
        if fault == "platform":
            assert not record.exists()
    else:
        assert result.returncode == 0, result.stderr
        installed = Path(path_output.read_text().strip()) / "crane"
        assert installed.read_bytes() == body
        assert os.access(installed, os.X_OK)
        assert "repos/google/go-containerregistry/releases/assets/423559783" in record.read_text()
        assert "Accept: application/octet-stream" in record.read_text()


def test_release_identity_is_fixed_and_only_required_workflows_use_the_shared_installer():
    action = yaml.load(ACTION.read_text(), Loader=yaml.BaseLoader)
    assert "inputs" not in action
    step = action["runs"]["steps"][0]
    assert step["env"]["CRANE_VERSION"] == "v0.21.6"
    assert step["env"]["CRANE_ASSET_ID"] == "423559783"
    assert step["env"]["CRANE_ARCHIVE_SIZE"] == "16463798"
    assert (
        step["env"]["CRANE_ARCHIVE_SHA256"]
        == "7ebbdcd05b652345c1f5105f8475e518534b90d66f3bdb50017be63f426ea435"
    )
    assert "continue-on-error" not in step
    for workflow_path, expected_count in [
        (".github/workflows/saas-oci-promotion-accepted-m165.yml", 3),
        (".github/workflows/saas-n1-compat-image.yml", 2),
    ]:
        workflow = yaml.load((ROOT / workflow_path).read_text(), Loader=yaml.BaseLoader)
        callers = [
            step
            for job in workflow["jobs"].values()
            for step in job.get("steps", [])
            if step.get("uses") == "./saas/actions/setup-pinned-crane"
        ]
        assert len(callers) == expected_count
        assert all(
            "with" not in caller
            and "continue-on-error" not in caller
            and caller["timeout-minutes"] == "3"
            for caller in callers
        )


def test_main_gate_rejects_candidate_installer_byte_drift(tmp_path):
    result = _run_full_gate(
        tmp_path,
        trusted_input_override=("saas/actions/setup-pinned-crane/action.yml", "0" * 64),
    )
    assert result.returncode == 1
    assert "trusted input drift: saas/actions/setup-pinned-crane/action.yml" in result.stdout
