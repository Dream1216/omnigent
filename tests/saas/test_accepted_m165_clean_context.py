"""One retained parent, exact source bytes, and an actual independent Server pair."""

import copy
import io
import json
import shutil
import tarfile
from pathlib import Path

import pytest
import yaml

from saas.scripts import accepted_m165_clean_context as clean
from saas.scripts import accepted_oci_recovery as recovery
from tests.saas.test_oci_promotion import candidate


@pytest.mark.parametrize("product_profile", ["M165", "M8c"])
@pytest.mark.parametrize("fault", [None, "tree", "workspace", "batch-identity"])
def test_frozen_git_source_and_only_original_Dockerfile_transform_are_expected(
    tmp_path, monkeypatch, fault, product_profile
):
    source = b"[project]\nname='source'\n\n[tool.uv.workspace]\nmembers=[]\n\n[tool.pytest]\n"
    if fault == "workspace":
        source = b"[project]\nname='source'\n"
    blob = "a" * 40

    def git(command, **_kwargs):
        if command[1] == "rev-parse":
            assert (
                command[2]
                == (recovery.M8C_PRODUCT if product_profile == "M8c" else recovery.PRODUCT)
                + "^{tree}"
            )
            return (
                "wrong"
                if fault == "tree"
                else (recovery.M8C_TREE if product_profile == "M8c" else clean.TREE)
            )
        if command[1] == "ls-tree":
            return f"100644 blob {blob}\tpyproject.toml\0".encode()
        identity = "b" * 40 if fault == "batch-identity" else blob
        return f"{identity} blob {len(source)}\n".encode() + source + b"\n"

    monkeypatch.setattr(clean.subprocess, "check_output", git)
    if fault:
        with pytest.raises(ValueError):
            clean.source_inputs(tmp_path, product_profile=product_profile)
    else:
        assert clean.source_inputs(tmp_path, product_profile=product_profile) == {
            "pyproject.toml": ("100644", b"[project]\nname='source'\n\n[tool.pytest]\n")
        }


def test_clean_confirmation_uses_one_actual_uncached_Server_and_original_Host_bytes():
    root = Path(__file__).resolve().parents[2]
    workflow = yaml.load((root / recovery.WORKFLOW).read_text(), Loader=yaml.BaseLoader)
    build = workflow["jobs"]["build-accepted-product"]
    steps = build["steps"]
    independent = next(step for step in steps if step.get("id") == "independent-server")
    assert independent["if"] == "inputs.phase == 'confirm-server'"
    assert independent["with"] == {"artifact": "server", "target": "runtime", "attempt": "2"}
    assert all(
        step.get("if") == "inputs.phase == 'build'"
        for step in steps
        if step.get("with", {}).get("artifact") == "host"
    )
    retain = next(step for step in steps if step.get("id") == "retained")
    assert "accepted_m165_clean_context prepare" in retain["run"]
    assert 'git archive "$GITHUB_SHA" saas' in retain["run"]
    assert any('accepted_m165_clean_context.py" confirm' in step.get("run", "") for step in steps)
    scan = workflow["jobs"]["scan-and-admit-same-oci"]
    assert not any("build-oci-candidate" in step.get("uses", "") for step in scan["steps"])
    assert any("--comparison-profile" in step.get("run", "") for step in scan["steps"])


def test_unknown_comparison_profile_cannot_start_native_download(tmp_path, monkeypatch):
    monkeypatch.setattr(
        recovery, "api", lambda _endpoint: pytest.fail("must reject before native I/O")
    )
    with pytest.raises(ValueError, match="unknown comparison profile"):
        recovery.download_raw(1, 2, "a" * 64, "b" * 40, tmp_path, comparison_profile="other")


@pytest.mark.parametrize("fault", [None, "Host", "other-layer", "labels", "history"])
def test_first_proof_requires_exact_Host_and_limits_Server_change_to_the_copied_layer(
    tmp_path, monkeypatch, fault
):
    platform = {
        "manifest_digest": "old-manifest",
        "config_digest": "old-config",
        "layers": [{"digest": "old"}] * 4,
        "rootfs_diff_ids": ["old"] * 4,
        "labels": {"source": "frozen"},
        "history": [{"created": "fixed"}],
    }
    old_facts = {"platforms": {"linux/amd64": platform}, "attestations": {"linux/amd64": True}}
    pair = {
        "first": old_facts,
        "second": old_facts,
        "matching_platform_manifest_and_config": True,
        "history_created_by_equal": True,
    }
    original = {
        "images": {f"omnigent-saas-{role}": copy.deepcopy(pair) for role in ("server", "host")}
    }
    actual = {role: copy.deepcopy(old_facts) for role in ("server", "host")}
    server = actual["server"]["platforms"]["linux/amd64"]
    server.update(manifest_digest="current-manifest", config_digest="current-config")
    server["layers"][3] = {"digest": "sha256:" + "a" * 64}
    server["rootfs_diff_ids"][3] = "current"
    if fault == "Host":
        actual["host"]["attestations"] = {}
    elif fault == "other-layer":
        server["layers"][0] = {"digest": "different-runtime"}
    elif fault == "labels":
        server["labels"] = {"source": "other"}
    elif fault == "history":
        server["history"] = []
    monkeypatch.setattr(recovery, "original_report", lambda _path: copy.deepcopy(original))
    monkeypatch.setattr(
        clean, "inspect_oci_archive", lambda path, **_kwargs: actual[path.name.split("-")[0]]
    )
    monkeypatch.setattr(clean, "source_inputs", lambda _repo: {})
    monkeypatch.setattr(
        clean, "verify_context_layer", lambda _stream, _inputs: {"tracked_inputs": 2064}
    )
    with tarfile.open(tmp_path / "server-1.tar", "w") as archive:
        member = tarfile.TarInfo("blobs/sha256/" + "a" * 64)
        member.size = 5
        archive.addfile(member, io.BytesIO(b"layer"))
    (tmp_path / "host-1.tar").write_bytes(b"host")
    if fault:
        with pytest.raises(ValueError):
            clean.verify_first(tmp_path, Path.cwd())
    else:
        result = clean.verify_first(tmp_path, Path.cwd())
        assert result["parent_raw_checkpoint"] == clean.PARENT
        assert result["old_Server_byte_identity_claimed"] is False
        assert result["source_proofs"]["linux/amd64"]["tracked_inputs"] == 2064


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "source",
        "mode",
        "symlink",
        "UI-copy",
        "UI-link",
        "missing-entry",
        "duplicate",
        "pyc",
        "pyo",
        "cache-directory",
    ],
)
def test_actual_context_requires_tracked_bytes_modes_links_and_complete_UI(fault):
    expected = {
        "pyproject.toml": ("100644", b"reviewed project"),
        "saas/entry.sh": ("100755", b"reviewed executable"),
        "omnigent/resources/examples/polly": ("120000", b"../../../examples/polly"),
    }
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as bundle:
        for name, (mode, body) in expected.items():
            item = tarfile.TarInfo("build/" + name)
            item.mode = 0o755 if mode == "100755" else 0o644
            if fault == "mode" and name.endswith("entry.sh"):
                item.mode = 0o644
            if mode == "120000":
                item.type = tarfile.SYMTYPE
                item.linkname = "foreign" if fault == "symlink" else body.decode()
                bundle.addfile(item)
            else:
                data = b"different" if fault == "source" and name == "pyproject.toml" else body
                item.size = len(data)
                bundle.addfile(item, io.BytesIO(data))
        for base in ("build/", "build/build/lib/"):
            for prefix, names in (
                ("omnigent/server/static/web-ui/", ["index.html"]),
                (
                    "saas/login_ui/static/",
                    ["login.html", "signup.html", "signup-verify.html", "signup-status.html"],
                ),
            ):
                for name in names:
                    if fault == "missing-entry" and name == "signup.html":
                        continue
                    data = (
                        b"different" if fault == "UI-copy" and base == "build/" else b"generated"
                    )
                    item = tarfile.TarInfo(base + prefix + name)
                    item.size = len(data)
                    if fault == "UI-link" and name == "index.html":
                        item.type, item.linkname, item.size = tarfile.SYMTYPE, "foreign", 0
                    bundle.addfile(item, io.BytesIO(data) if item.isfile() else None)
        if fault == "duplicate":
            bundle.addfile(tarfile.TarInfo("build/pyproject.toml"))
        if fault in {"pyc", "pyo", "cache-directory"}:
            name = (
                "build/omnigent/__pycache__"
                if fault == "cache-directory"
                else "build/omnigent/contamination." + fault
            )
            item = tarfile.TarInfo(name)
            if fault == "cache-directory":
                item.type = tarfile.DIRTYPE
            bundle.addfile(item)
    stream.seek(0)
    if fault:
        with pytest.raises(ValueError):
            clean.verify_context_layer(stream, expected, forbid_bytecode=True)
    else:
        result = clean.verify_context_layer(stream, expected, forbid_bytecode=True)
        assert result["tracked_inputs"] == 3
        assert result["generated_UI"]["omnigent/server/static/web-ui/"]["files"] == 1
        assert result["generated_UI"]["saas/login_ui/static/"]["files"] == 4


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "parent-green",
        "wrong-controller",
        "different-run",
        "self-hosted",
        "wrong-job",
        "other-failure",
        "failed-build",
        "expired",
        "digest",
        "artifact-head",
    ],
)
def test_only_the_actual_failed_parent_and_successful_retained_build_steps_are_inputs(fault):
    run = {
        "id": clean.PARENT["run_id"],
        "head_sha": clean.PARENT["controller_revision"],
        "path": recovery.WORKFLOW,
        "event": "workflow_dispatch",
        "head_branch": "main",
        "run_attempt": 1,
        "status": "completed",
        "conclusion": "failure",
        "repository": {"full_name": recovery.REPOSITORY},
    }
    names = [
        "Recover Server using its existing first-attempt build cache",
        "Recover Host using its existing first-attempt build cache",
        "Stage actual OCI before any cleanup or inspection can fail",
        "Preserve actual OCI before any fresh vulnerability scan",
    ]
    job = {
        "id": clean.PARENT["job_id"],
        "run_id": clean.PARENT["run_id"],
        "run_attempt": 1,
        "name": "build-accepted-product",
        "status": "completed",
        "conclusion": "failure",
        "runner_group_name": "GitHub Actions",
        "labels": ["ubuntu-24.04"],
        "steps": [{"name": name, "conclusion": "success"} for name in names]
        + [{"name": clean.COMPARE_STEP, "conclusion": "failure"}],
    }
    artifact = {
        "id": clean.PARENT["artifact_id"],
        "name": f"accepted-raw-{recovery.PRODUCT}-{clean.PARENT['run_id']}",
        "size_in_bytes": clean.PARENT["artifact_bytes"],
        "digest": f"sha256:{clean.PARENT['artifact_sha256']}",
        "expired": False,
        "workflow_run": {
            "id": clean.PARENT["run_id"],
            "head_sha": clean.PARENT["controller_revision"],
        },
    }
    if fault == "parent-green":
        run["conclusion"] = "success"
    elif fault == "wrong-controller":
        run["head_sha"] = "a" * 40
    elif fault == "different-run":
        run["id"] += 1
    elif fault == "self-hosted":
        job["labels"] = ["self-hosted"]
    elif fault == "wrong-job":
        job["id"] += 1
    elif fault == "other-failure":
        job["steps"].append({"name": "other", "conclusion": "failure"})
    elif fault == "failed-build":
        job["steps"][0]["conclusion"] = "failure"
    elif fault == "expired":
        artifact["expired"] = True
    elif fault == "digest":
        artifact["digest"] = "sha256:" + "0" * 64
    elif fault == "artifact-head":
        artifact["workflow_run"]["head_sha"] = "a" * 40
    if fault:
        with pytest.raises(ValueError, match="retained failed parent"):
            clean.verify_parent(run, job, artifact)
    else:
        clean.verify_parent(run, job, artifact)


@pytest.mark.parametrize("fault", [None, "missing-second", "first-facts", "first-proof"])
def test_confirmation_compares_two_actual_Server_archives_and_preserves_Host_history(
    tmp_path, monkeypatch, fault
):
    candidate(tmp_path)
    old = json.loads((tmp_path / "saas-image-candidate.json").read_text())
    first = {
        "kind": clean.KIND,
        "parent_raw_checkpoint": clean.PARENT,
        "old_Server_byte_identity_claimed": False,
        "facts": {
            role: old["images"][f"omnigent-saas-{role}"]["first"] for role in ("server", "host")
        },
    }
    if fault == "first-facts":
        first["facts"]["server"] = {}
    monkeypatch.setattr(clean, "verify_first", lambda _root, _repo: copy.deepcopy(first))
    monkeypatch.setattr(recovery, "original_report", lambda _path: copy.deepcopy(old))
    recorded = copy.deepcopy(first)
    if fault == "first-proof":
        recorded["parent_raw_checkpoint"] = {}
    (tmp_path / "clean-context-first.json").write_text(json.dumps(recorded))
    if fault != "missing-second":
        shutil.copyfile(tmp_path / "server-1.tar", tmp_path / "server-2.tar")
    if fault:
        with pytest.raises((ValueError, FileNotFoundError)):
            clean.confirm(tmp_path, Path.cwd())
    else:
        result = clean.confirm(tmp_path, Path.cwd())
        assert result["images"]["omnigent-saas-host"] == old["images"]["omnigent-saas-host"]
        assert (
            result["images"]["omnigent-saas-server"]["matching_platform_manifest_and_config"]
            is True
        )
        assert (
            result["clean_context_reproducibility"]["Host_rebuilt_in_this_confirmation"] is False
        )
        assert (
            result["clean_context_reproducibility"]["parent_raw_checkpoint"]["job_conclusion"]
            == "failure"
        )


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "bytecode",
        "tracked-source",
        "SDK-archive",
        "SDK-index",
        "SDK-platform",
        "SDK-config",
        "SDK-failed",
        "origin",
        "old-archive",
        "source-label",
    ],
)
def test_new_clean_M8c_first_requires_own_SDK_and_exact_cache_free_source(
    tmp_path, monkeypatch, fault
):
    expected = {"pyproject.toml": ("100644", b"frozen project")}
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w:gz") as bundle:
        files = {
            "build/pyproject.toml": b"changed" if fault == "tracked-source" else b"frozen project"
        }
        for base in ("build/", "build/build/lib/"):
            for prefix, names in (
                ("omnigent/server/static/web-ui/", ["index.html"]),
                (
                    "saas/login_ui/static/",
                    ["login.html", "signup.html", "signup-verify.html", "signup-status.html"],
                ),
            ):
                files.update({base + prefix + name: b"generated" for name in names})
        if fault == "bytecode":
            files["build/omnigent/__pycache__/__init__.cpython-312.pyc"] = b"host cache"
        for name, body in files.items():
            item = tarfile.TarInfo(name)
            item.mode, item.size = 0o644, len(body)
            bundle.addfile(item, io.BytesIO(body))
    body = layer.getvalue()
    digest = clean.hashlib.sha256(body).hexdigest()
    with tarfile.open(tmp_path / "server-1.tar", "w") as archive:
        item = tarfile.TarInfo("blobs/sha256/" + digest)
        item.size = len(body)
        archive.addfile(item, io.BytesIO(body))
    archive_sha = recovery.file_sha256(tmp_path / "server-1.tar")
    facts = {
        "platforms": {
            platform: {
                "manifest_digest": "sha256:" + "a" * 64,
                "config_digest": "sha256:" + "b" * 64,
                "labels": {"org.opencontainers.image.revision": recovery.M8C_PRODUCT},
                "layers": [{"digest": "sha256:" + digest}] * 4,
            }
            for platform in ("linux/amd64", "linux/arm64")
        }
    }
    sdk = {
        "source_revision": recovery.M8C_PRODUCT,
        "passed": True,
        "e2b_version": "2.31.0",
        "archive_sha256": archive_sha,
        "root_digest": "sha256:" + "c" * 64,
        "platforms": [
            {"platform": platform, **{k: row[k] for k in ("manifest_digest", "config_digest")}}
            for platform, row in facts["platforms"].items()
        ],
    }
    origin = {
        "kind": "accepted_M8c_original_Server/v1",
        "product_revision": recovery.M8C_PRODUCT,
        "product_tree": recovery.M8C_TREE,
        "source_date_epoch": recovery.M8C_EPOCH,
        "original_run_id": recovery.M8C_RUN,
        "original_job_id": recovery.M8C_JOB,
        "first_archive_sha256": recovery.M8C_FIRST_SHA256,
    }
    if fault == "SDK-archive":
        sdk["archive_sha256"] = "f" * 64
    elif fault == "SDK-index":
        sdk["root_digest"] = "sha256:" + "f" * 64
    elif fault == "SDK-platform":
        sdk["platforms"].pop()
    elif fault == "SDK-config":
        sdk["platforms"][0]["config_digest"] = "sha256:" + "f" * 64
    elif fault == "SDK-failed":
        sdk["passed"] = False
    elif fault == "origin":
        origin["product_tree"] = "f" * 40
    elif fault == "old-archive":
        monkeypatch.setattr(recovery, "M8C_FIRST_SHA256", archive_sha)
        origin["first_archive_sha256"] = archive_sha
    elif fault == "source-label":
        facts["platforms"]["linux/amd64"]["labels"]["org.opencontainers.image.revision"] = "f" * 40
    for name, value in (
        ("server-candidate-runtime.json", sdk),
        ("m8c-retained-origin.json", origin),
    ):
        (tmp_path / name).write_text(json.dumps(value))
    monkeypatch.setattr(clean, "inspect_oci_archive", lambda *_args, **_kwargs: facts)
    monkeypatch.setattr(recovery, "archive_index_digest", lambda _path: "sha256:" + "c" * 64)
    monkeypatch.setattr(
        clean,
        "source_inputs",
        lambda _repo, **kwargs: (
            expected
            if kwargs == {"product_profile": "M8c"}
            else pytest.fail("wrong source profile")
        ),
    )
    if fault:
        with pytest.raises(ValueError):
            clean.verify_m8c_first(tmp_path, Path.cwd())
    else:
        proof = clean.verify_m8c_first(tmp_path, Path.cwd())
        assert proof["archive_sha256"] == archive_sha
        assert proof["host_bytecode_members"] == 0 and proof["original_Server_promoted"] is False
        assert set(proof["source_proofs"]) == {"linux/amd64", "linux/arm64"}
        assert proof["SDK_sha256"] == recovery.file_sha256(
            tmp_path / "server-candidate-runtime.json"
        )
