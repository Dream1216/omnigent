"""Exercise the actual SDK workflow script with controlled Docker responses."""

from __future__ import annotations

import builtins
import copy
import hashlib
import io
import json
import secrets
import subprocess
import tarfile
from pathlib import Path

import pytest
import yaml

from saas.scripts import compare_oci_rebuilds
from saas.scripts.check_image_supply_chain import validate_candidate_build_contract

_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOW = ".github/workflows/saas-image-candidate.yml"
_STEP = "Verify executable Server candidate SDK on both architectures"
_INDEX = "sha256:" + "1" * 64
_REVISION = "2" * 40
_PLATFORMS = ("linux/amd64", "linux/arm64")
_OWNER = "a" * 32


def _runtime_script() -> str:
    workflow = yaml.safe_load((_ROOT / _WORKFLOW).read_text())
    step = next(s for s in workflow["jobs"]["build-candidate"]["steps"] if s.get("name") == _STEP)
    return step["run"].split("python - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]


class DockerResponses:
    def __init__(self, archive: Path):
        self.archive = archive
        self.facts = {
            "platforms": {
                platform: {
                    "manifest_digest": "sha256:" + str(i) * 64,
                    "config_digest": "sha256:" + str(i + 2) * 64,
                    "rootfs_diff_ids": ["sha256:" + str(i + 4) * 64],
                }
                for i, platform in enumerate(_PLATFORMS, start=3)
            }
        }
        self.index_metadata = {"Id": _INDEX, "Descriptor": {"digest": _INDEX}}
        self.platform_metadata = {
            platform: {
                "Id": facts["manifest_digest"],
                "Descriptor": {"digest": facts["manifest_digest"]},
                "RootFS": {"Layers": facts["rootfs_diff_ids"]},
            }
            for platform, facts in self.facts["platforms"].items()
        }
        self.events = []
        self.runtime_failure = None
        self.cleanup_failure = False
        self.container_cleanup_failure = False
        self.containers = {}

    def inspect_archive(self, archive, *, label_profile):
        assert archive == self.archive and label_profile == "executable"
        return copy.deepcopy(self.facts)

    def check_output(self, command, *, text=False, timeout=None):
        if command[:3] == ["docker", "container", "ls"]:
            assert text is True and timeout == 30
            name_filter = command[command.index("--filter") + 1]
            name = name_filter.removeprefix("name=^/").removesuffix("$")
            assert name in {f"omnigent-sdk-{_OWNER}-{arch}" for arch in ("amd64", "arm64")}
            assert command == [
                "docker",
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--filter",
                f"name=^/{name}$",
                "--filter",
                f"label=io.omnigent.sdk-probe={_OWNER}",
                "--format",
                "{{.ID}}",
            ]
            return self.containers.get(name, "") + ("\n" if name in self.containers else "")
        assert text is False and timeout is None
        if command == ["docker", "image", "inspect", _INDEX]:
            self.events.append(("inspect-index", _INDEX))
            return json.dumps([self.index_metadata]).encode()
        assert command[:4] == ["docker", "image", "inspect", "--platform"]
        platform = command[4]
        assert platform in _PLATFORMS and command[5:] == [_INDEX]
        self.events.append(("inspect-platform", platform))
        return json.dumps([self.platform_metadata[platform]]).encode()

    def run(self, command, *, check, timeout=None):
        assert check is True
        if command == ["docker", "load", "-i", str(self.archive)]:
            assert timeout is None
            self.events.append(("load", _INDEX))
        elif command == ["docker", "image", "rm", _INDEX]:
            assert timeout == 30
            self.events.append(("cleanup", _INDEX))
            if self.cleanup_failure or self.containers:
                raise subprocess.CalledProcessError(1, command)
        elif command[:4] == ["docker", "container", "rm", "--force"]:
            assert timeout == 30 and len(command) == 5
            name = next(
                name for name, identifier in self.containers.items() if identifier == command[4]
            )
            self.events.append(("cleanup-container", name))
            if self.container_cleanup_failure:
                raise subprocess.CalledProcessError(1, command)
            del self.containers[name]
        else:
            platform = command[command.index("--platform") + 1]
            assert platform in _PLATFORMS and timeout == 180
            assert command[:5] == ["docker", "run", "--pull", "never", "--platform"]
            assert "--rm" not in command and "--no-healthcheck" in command
            name = command[command.index("--name") + 1]
            assert name == f"omnigent-sdk-{_OWNER}-{platform.split('/')[-1]}"
            assert command[command.index("--label") + 1] == f"io.omnigent.sdk-probe={_OWNER}"
            for option, value in (
                ("--network", "none"),
                ("--user", "1000:1000"),
                ("--cap-drop", "ALL"),
                ("--security-opt", "no-new-privileges:true"),
                ("--tmpfs", "/tmp:rw,nosuid,nodev,size=64m,mode=1777"),
                ("--pids-limit", "128"),
                ("--memory", "512m"),
                ("--cpus", "1"),
                ("--entrypoint", "/opt/venv/bin/python"),
            ):
                assert command[command.index(option) + 1] == value
            assert "--read-only" in command
            entrypoint = command.index("--entrypoint")
            assert command[entrypoint + 2 : entrypoint + 6] == [_INDEX, "-B", "-I", "-c"]
            assert command[-1] == _REVISION
            self.events.append(("sdk", platform))
            if self.runtime_failure == (platform, "create"):
                raise subprocess.CalledProcessError(1, command)
            self.containers[name] = "c" * 63 + str(_PLATFORMS.index(platform) + 1)
            if self.runtime_failure == (platform, "exit"):
                raise subprocess.CalledProcessError(1, command)
            if self.runtime_failure == (platform, "timeout"):
                raise subprocess.TimeoutExpired(command, timeout)
        return subprocess.CompletedProcess(command, 0)


@pytest.fixture
def docker_responses(tmp_path, monkeypatch):
    archive = tmp_path / "server-1.tar"
    index = json.dumps({"manifests": [{"digest": _INDEX}]}).encode()
    with tarfile.open(archive, "w") as stream:
        info = tarfile.TarInfo("index.json")
        info.size = len(index)
        stream.addfile(info, io.BytesIO(index))
    (tmp_path / "artifacts").mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("CANDIDATE_REVISION", _REVISION)
    docker = DockerResponses(archive)
    monkeypatch.setattr(secrets, "token_hex", lambda size: _OWNER if size == 16 else None)
    monkeypatch.setattr(compare_oci_rebuilds, "inspect_oci_archive", docker.inspect_archive)
    monkeypatch.setattr(subprocess, "check_output", docker.check_output)
    monkeypatch.setattr(subprocess, "run", docker.run)
    return docker


def _execute():
    exec(compile(_runtime_script(), _WORKFLOW, "exec"), {})


def _assert_rejected(docker, exception):
    with pytest.raises(exception):
        _execute()
    assert docker.events.count(("cleanup", _INDEX)) == 1
    assert not Path("artifacts/server-candidate-runtime.json").exists()


def test_sdk_probe_binds_index_and_each_platform_before_runtime(docker_responses):
    docker = docker_responses
    _execute()
    assert docker.events == [
        ("load", _INDEX),
        ("inspect-index", _INDEX),
        ("inspect-platform", "linux/amd64"),
        ("sdk", "linux/amd64"),
        ("inspect-platform", "linux/arm64"),
        ("sdk", "linux/arm64"),
        ("cleanup-container", f"omnigent-sdk-{_OWNER}-amd64"),
        ("cleanup-container", f"omnigent-sdk-{_OWNER}-arm64"),
        ("cleanup", _INDEX),
    ]
    receipt = json.loads(Path("artifacts/server-candidate-runtime.json").read_text())
    assert receipt == {
        "schema_version": 1,
        "source_revision": _REVISION,
        "archive_sha256": hashlib.sha256(docker.archive.read_bytes()).hexdigest(),
        "root_digest": _INDEX,
        "e2b_version": "2.31.0",
        "platforms": [
            {
                "platform": platform,
                "config_digest": facts["config_digest"],
                "manifest_digest": facts["manifest_digest"],
            }
            for platform, facts in docker.facts["platforms"].items()
        ],
        "passed": True,
    }


@pytest.mark.parametrize("fault", ["id", "descriptor", "missing-id", "missing-descriptor"])
def test_sdk_probe_rejects_wrong_imported_index(docker_responses, fault):
    docker = docker_responses
    if fault == "id":
        docker.index_metadata["Id"] = docker.facts["platforms"][_PLATFORMS[0]]["config_digest"]
    elif fault == "descriptor":
        docker.index_metadata["Descriptor"]["digest"] = "sha256:" + "9" * 64
    else:
        del docker.index_metadata["Id" if fault == "missing-id" else "Descriptor"]
    _assert_rejected(docker, (AssertionError, KeyError))
    assert docker.events == [("load", _INDEX), ("inspect-index", _INDEX), ("cleanup", _INDEX)]


@pytest.mark.parametrize("platform", _PLATFORMS)
@pytest.mark.parametrize(
    "fault", ["index", "other-platform", "config-id", "descriptor", "layers", "missing-descriptor"]
)
def test_sdk_probe_rejects_wrong_selected_platform(docker_responses, platform, fault):
    docker = docker_responses
    actual = docker.platform_metadata[platform]
    facts = docker.facts["platforms"][platform]
    if fault in {"index", "other-platform"}:
        digest = (
            _INDEX
            if fault == "index"
            else docker.facts["platforms"][next(p for p in _PLATFORMS if p != platform)][
                "manifest_digest"
            ]
        )
        actual["Id"] = actual["Descriptor"]["digest"] = digest
    elif fault == "config-id":
        actual["Id"] = facts["config_digest"]
    elif fault == "descriptor":
        actual["Descriptor"]["digest"] = "sha256:" + "9" * 64
    elif fault == "layers":
        actual["RootFS"]["Layers"] = ["sha256:" + "9" * 64]
    else:
        del actual["Descriptor"]
    _assert_rejected(docker, (AssertionError, KeyError))
    assert ("inspect-platform", platform) in docker.events
    assert ("sdk", platform) not in docker.events
    assert [("sdk", p) for p in _PLATFORMS[: _PLATFORMS.index(platform)]] == [
        e for e in docker.events if e[0] == "sdk"
    ]


@pytest.mark.parametrize("platform", _PLATFORMS)
@pytest.mark.parametrize("fault", ["create", "exit", "timeout"])
def test_sdk_execution_failure_cannot_produce_pass_receipt(docker_responses, platform, fault):
    docker = docker_responses
    docker.runtime_failure = (platform, fault)
    _assert_rejected(docker, (subprocess.CalledProcessError, subprocess.TimeoutExpired))
    assert ("sdk", platform) in docker.events
    assert docker.containers == {}
    if platform == "linux/amd64":
        assert ("inspect-platform", "linux/arm64") not in docker.events


def test_cleanup_failure_cannot_produce_pass_receipt(docker_responses):
    docker = docker_responses
    docker.cleanup_failure = True
    _assert_rejected(docker, subprocess.CalledProcessError)
    assert [("sdk", p) for p in _PLATFORMS] == [e for e in docker.events if e[0] == "sdk"]


def test_timeout_retains_primary_error_when_container_and_image_cleanup_fail(docker_responses):
    docker = docker_responses
    docker.runtime_failure = ("linux/amd64", "timeout")
    docker.container_cleanup_failure = True
    with pytest.raises(builtins.ExceptionGroup) as caught:
        _execute()
    assert isinstance(caught.value.exceptions[0], subprocess.TimeoutExpired)
    assert any(
        isinstance(error, subprocess.CalledProcessError) for error in caught.value.exceptions[1:]
    )
    assert docker.events.count(("cleanup", _INDEX)) == 1
    assert not Path("artifacts/server-candidate-runtime.json").exists()


def test_timeout_retains_primary_error_when_image_cleanup_fails(docker_responses):
    docker = docker_responses
    docker.runtime_failure = ("linux/arm64", "timeout")
    docker.cleanup_failure = True
    with pytest.raises(builtins.ExceptionGroup) as caught:
        _execute()
    assert isinstance(caught.value.exceptions[0], subprocess.TimeoutExpired)
    assert isinstance(caught.value.exceptions[-1], subprocess.CalledProcessError)
    assert docker.containers == {}
    assert not Path("artifacts/server-candidate-runtime.json").exists()


@pytest.mark.parametrize("identifier", ["--all", "sha256:" + "c" * 64])
def test_cleanup_rejects_non_container_identifiers(docker_responses, monkeypatch, identifier):
    docker = docker_responses
    original = docker.check_output

    def inspect(command, **kwargs):
        if command[:3] == ["docker", "container", "ls"]:
            return identifier + "\n"
        return original(command, **kwargs)

    monkeypatch.setattr(subprocess, "check_output", inspect)
    _assert_rejected(docker, builtins.ExceptionGroup)
    assert not any(event[0] == "cleanup-container" for event in docker.events)


@pytest.mark.parametrize(
    "target",
    [
        'actual["Descriptor"]["digest"] == root and actual["Id"] == root',
        'actual["Descriptor"]["digest"] == actual["Id"] == expected["manifest_digest"]',
        '"--no-healthcheck"',
        '"--filter", f"name=^/{name}$"',
        '"--filter", f"label=io.omnigent.sdk-probe={owner}"',
        'assert re.fullmatch(r"[0-9a-f]{64}", identifier)',
        '"docker", "container", "rm", "--force", identifier',
        'raise BaseExceptionGroup("SDK verification and cleanup failed", errors)',
    ],
)
def test_candidate_contract_requires_both_identity_checks(tmp_path, target):
    for relative in (
        _WORKFLOW,
        ".github/workflows/saas-n1-compat-image.yml",
        "saas/actions/build-oci-candidate/action.yml",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((_ROOT / relative).read_bytes())
    workflow = tmp_path / _WORKFLOW
    source = workflow.read_text()
    assert target in source
    workflow.write_text(source.replace(target, "removed_identity_gate", 1))
    assert (
        "candidate workflow must verify the exact Server SDK on both platforms"
        in validate_candidate_build_contract(tmp_path)
    )
