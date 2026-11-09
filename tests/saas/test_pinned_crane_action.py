"""The official API route preserves the exact release and fails closed on bad bytes."""

import hashlib
import io
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
ACTION = ROOT / "saas/actions/setup-pinned-crane/action.yml"


@pytest.mark.parametrize(
    ("asset", "fault"),
    [
        ("crane", fault)
        for fault in [None, "digest", "size", "version", "download", "platform", "entry"]
    ]
    + [("v8", fault) for fault in [None, "digest", "size", "download", "platform"]],
)
def test_exact_archive_install_checks_bytes_platform_and_executable_before_PATH(
    tmp_path, asset, fault
):
    action_path = (
        ACTION if asset == "crane" else ROOT / "saas/actions/setup-pinned-parity-v8/action.yml"
    )
    action = yaml.load(action_path.read_text(), Loader=yaml.BaseLoader)
    step = action["runs"]["steps"][0]
    version = "v0.21.5" if fault == "version" else "v0.21.6"
    body = f"#!/bin/sh\nprintf '%s\\n' '{version}'\n".encode()
    archive = tmp_path / "fixture.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        member = tarfile.TarInfo("other" if fault == "entry" else "crane")
        member.mode, member.size = 0o755, len(body)
        bundle.addfile(member, io.BytesIO(body))
    if asset == "v8":
        archive.write_bytes(b"unit fixture for the fixed archive transport")
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
    prefix = "CRANE" if asset == "crane" else "V8"
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
        "GITHUB_ENV": str(path_output),
        "CRANE_TEST_ARCHIVE": str(archive),
        "CRANE_REQUEST_RECORD": str(record),
        f"{prefix}_ARCHIVE_SIZE": str(archive.stat().st_size + (fault == "size")),
        f"{prefix}_ARCHIVE_SHA256": "0" * 64
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
        if asset == "crane":
            installed = Path(path_output.read_text().strip()) / "crane"
            assert installed.read_bytes() == body
            assert os.access(installed, os.X_OK)
            assert (
                "repos/google/go-containerregistry/releases/assets/423559783" in record.read_text()
            )
        else:
            key, value = path_output.read_text().strip().split("=", 1)
            assert key == "RUSTY_V8_ARCHIVE"
            assert Path(value).read_bytes() == archive.read_bytes()
            assert "repos/denoland/rusty_v8/releases/assets/429513990" in record.read_text()
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
    policy = (ROOT / ".github/actions/compat-smoke-saas-n1-gate/evaluate.sh").read_text()
    action_inputs = re.search(r"POSTGRESQL_N1_ACTION_INPUTS=\(\n(.*?)\n\)", policy, re.S)
    assert action_inputs is not None
    assert action_inputs.group(1).strip() == (
        '"saas/actions/setup-pinned-crane/action.yml|'
        + hashlib.sha256(ACTION.read_bytes()).hexdigest()
        + '"'
    )
    for workflow_path, expected_count in [
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


def test_parity_archive_and_original_cargo_callers_keep_exact_version_and_cache_scope():
    action_path = ROOT / "saas/actions/setup-pinned-parity-v8/action.yml"
    action = yaml.load(action_path.read_text(), Loader=yaml.BaseLoader)
    assert "inputs" not in action
    step = action["runs"]["steps"][0]
    assert step["env"]["V8_ASSET_ID"] == "429513990"
    assert step["env"]["V8_ARCHIVE_SIZE"] == "38519314"
    assert (
        step["env"]["V8_ARCHIVE_SHA256"]
        == "8aed98637db7e77dc8bfb8bb4759ec5bde472d0bf7943f58e0e62a350945c559"
    )
    for relative in [".github/workflows/ci.yml", ".github/workflows/e2e-ui.yml"]:
        workflow = yaml.load((ROOT / relative).read_text(), Loader=yaml.BaseLoader)
        callers = [
            (job, index)
            for job in workflow["jobs"].values()
            for index, caller in enumerate(job.get("steps", []))
            if caller.get("uses") == "./saas/actions/setup-pinned-parity-v8"
        ]
        assert len(callers) == 1
        job, index = callers[0]
        caller, build = job["steps"][index : index + 2]
        assert caller["if"] == build["if"] == "steps.sidecar-cache.outputs.cache-hit != 'true'"
        assert caller["timeout-minutes"] == "3"
        assert "with" not in caller and "continue-on-error" not in caller
        assert build["name"] == "Build parity sidecar"
        assert build["run"] == (
            "cargo build \\\n"
            "  --manifest-path tests/codex_parity/sidecar/Cargo.toml \\\n"
            "  --target-dir .tmp-codex-parity-target\n"
        )
