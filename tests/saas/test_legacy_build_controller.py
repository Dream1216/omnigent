"""Exercise fresh wheel staging and native artifact transfer without signing."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
for name in (
    "legacy_native_evidence",
    "protected_legacy_initial_build",
    "legacy_source_ci",
    "legacy_pr_candidate",
    "legacy_artifact_download",
    "legacy_build_controller",
):
    qualified = "saas.scripts." + name
    if name == "legacy_native_evidence" and qualified in sys.modules:
        continue
    specification = importlib.util.spec_from_file_location(
        qualified, ROOT / "saas/scripts" / (name + ".py")
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[qualified] = module
    specification.loader.exec_module(module)
core = sys.modules["saas.scripts.protected_legacy_initial_build"]
controller = sys.modules["saas.scripts.legacy_build_controller"]
download = sys.modules["saas.scripts.legacy_artifact_download"]
CONTROL = "c" * 40
LOGIN_METADATA_PATHS = (
    "saas/login_web/package.json",
    "saas/login_web/package-lock.json",
)


def login_metadata_bytes(path):
    fixtures = Path(__file__).parent / "resources/legacy_login_metadata"
    return tuple(
        (fixtures / (side + "-" + Path(path).name)).read_bytes() for side in ("before", "after")
    )


@pytest.mark.parametrize("path", LOGIN_METADATA_PATHS)
@pytest.mark.parametrize("fault", [None, "before", "after", "same-old", "extra", "duplicate"])
def test_reviewed_login_metadata_requires_the_exact_before_and_after_bytes(path, fault):
    before, after = login_metadata_bytes(path)
    if fault == "before":
        before += b" "
    elif fault == "after":
        after += b" "
    elif fault == "same-old":
        after = before
    elif fault == "extra":
        changed = json.loads(after)
        changed["unreviewed_metadata_field"] = True
        after = json.dumps(changed).encode()
    elif fault == "duplicate":
        after = b'{"unreviewed": 1, "unreviewed": 2}'
    if fault:
        with pytest.raises(
            ValueError, match=r"reviewed byte transition|duplicate source metadata"
        ):
            core.verify_metadata_delta(path, before, after, {})
    else:
        core.verify_metadata_delta(path, before, after, {})


@pytest.mark.parametrize("path", LOGIN_METADATA_PATHS)
@pytest.mark.parametrize("fault", [None, "before_mode", "after_mode", "before_hash", "after_hash"])
def test_login_metadata_profile_keeps_exact_hashes_and_nonexecutable_modes(product, path, fault):
    _, original = product
    profile = copy.deepcopy(original)
    before, after = login_metadata_bytes(path)
    row = {
        "path": path,
        "before": {"mode": "100644", "sha256": hashlib.sha256(before).hexdigest()},
        "after": {"mode": "100644", "sha256": hashlib.sha256(after).hexdigest()},
    }
    if fault:
        side, field = fault.split("_")
        row[side]["mode" if field == "mode" else "sha256"] = (
            "100755" if field == "mode" else "0" * 64
        )
    profile["source_delta"].append(row)
    if fault:
        with pytest.raises(ValueError, match=r"source metadata mode|reviewed byte transition"):
            core.validate_profile(profile, "Core")
    else:
        core.validate_profile(profile, "Core")


@pytest.mark.parametrize(
    "path",
    [
        "saas/login_web/pages/index.tsx",
        "saas/login_web/unreviewed-package.json",
        "saas/control_plane/models.py",
        "omnigent/runtime/workflow.py",
        "examples/extensions/hello-page/web/package.json",
        "examples/extensions/hello-page/web/package-lock.json",
        "examples/extensions/unreviewed/web/package.json",
        "web/src/shell/archiveUndoToast.tsx",
        "web/src/shell/unreviewed.test.tsx",
    ],
)
def test_login_metadata_exception_does_not_admit_application_schema_or_other_metadata(
    product, path
):
    _, original = product
    profile = copy.deepcopy(original)
    profile["source_delta"].append(
        {
            "path": path,
            "before": {"mode": "100644", "sha256": "1" * 64},
            "after": {"mode": "100644", "sha256": "2" * 64},
        }
    )
    error = (
        "source metadata differs from the exact reviewed byte transition"
        if path == "examples/extensions/hello-page/web/package.json"
        else "legacy patch changes application or schema code"
    )
    with pytest.raises(ValueError, match=error):
        core.validate_profile(profile, "Core")


APPROVED_NEW_BLOBS = {
    "examples/extensions/hello-page/web/package.json": "legacy_example_metadata/package.json",
    "web/src/shell/archiveUndoToast.test.tsx": ("legacy_approved_toast/archiveUndoToast.test.tsx"),
}


def approved_source_bytes(path):
    resource = Path(__file__).parent / "resources" / APPROVED_NEW_BLOBS[path]
    return tuple(
        resource.with_name(side + "-" + resource.name).read_bytes() for side in ("before", "after")
    )


@pytest.mark.parametrize("path", APPROVED_NEW_BLOBS)
@pytest.mark.parametrize(
    "fault", [None, "before-byte", "after-byte", "same-old", "before-mode", "after-mode"]
)
def test_approved_hello_and_toast_require_exact_raw_pairs_and_modes(product, path, fault):
    _, original = product
    profile = copy.deepcopy(original)
    before, after = approved_source_bytes(path)
    if fault == "before-byte":
        before += b" "
    elif fault == "after-byte":
        after += b" "
    elif fault == "same-old":
        after = before
    row = {
        "path": path,
        "before": {"mode": "100644", "sha256": hashlib.sha256(before).hexdigest()},
        "after": {"mode": "100644", "sha256": hashlib.sha256(after).hexdigest()},
    }
    if fault in {"before-mode", "after-mode"}:
        row[fault.split("-")[0]]["mode"] = "100755"
    profile["source_delta"].append(row)
    if fault:
        with pytest.raises(ValueError, match=r"source metadata mode|reviewed byte transition"):
            core.validate_profile(profile, "Core")
    else:
        core.validate_profile(profile, "Core")
        if path.endswith("package.json"):
            core.verify_metadata_delta(path, before, after, profile)


@pytest.mark.parametrize("cap", [None, True, 150, 165, 166, 167, 168, "167"])
def test_approved_source_budget_accepts_only_exact_integer167(product, cap):
    _, original = product
    profile = copy.deepcopy(original)
    before = b'{"source_intrusion_budget":{"max_direct_upstream_files":150}}'
    after = b'{"source_intrusion_budget":{"max_direct_upstream_files":167}}'
    profile["source_delta"].append(
        {
            "path": "saas/upstream-baseline.json",
            "before": {"mode": "100644", "sha256": hashlib.sha256(before).hexdigest()},
            "after": {"mode": "100644", "sha256": hashlib.sha256(after).hexdigest()},
        }
    )
    if cap is not None:
        profile["budget_file_cap"] = cap
    if type(cap) is int and cap == 167:
        core.validate_profile(profile, "Core")
        core.verify_metadata_delta("saas/upstream-baseline.json", before, after, profile)
    else:
        with pytest.raises(ValueError, match=r"budget change lacks|budget differs"):
            core.validate_profile(profile, "Core")


@pytest.mark.parametrize("fault", [None, "old165", "after165", "after168", "extra"])
def test_approved_budget_keeps_original150_and_only_the_cap_field_transition(fault):
    before = {
        "source_intrusion_budget": {"max_direct_upstream_files": 150, "max_active_patches": 9}
    }
    after = copy.deepcopy(before)
    after["source_intrusion_budget"]["max_direct_upstream_files"] = 167
    if fault == "old165":
        before["source_intrusion_budget"]["max_direct_upstream_files"] = 165
    elif fault == "after165":
        after["source_intrusion_budget"]["max_direct_upstream_files"] = 165
    elif fault == "after168":
        after["source_intrusion_budget"]["max_direct_upstream_files"] = 168
    elif fault == "extra":
        after["source_intrusion_budget"]["max_active_patches"] = 10
    arguments = (
        "saas/upstream-baseline.json",
        json.dumps(before).encode(),
        json.dumps(after).encode(),
        {"budget_file_cap": 167},
    )
    if fault:
        with pytest.raises(ValueError, match=r"original or approved cap|outside the exact"):
            core.verify_metadata_delta(*arguments)
    else:
        core.verify_metadata_delta(*arguments)


@pytest.fixture
def approved_metadata_product(product, monkeypatch):
    source, original = product

    def git(*arguments):
        return subprocess.check_output(["git", *arguments], cwd=source).decode().strip()

    git("checkout", "--detach", "-q", original["baseline_revision"])
    for path in APPROVED_NEW_BLOBS:
        target = source / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(approved_source_bytes(path)[0])
    budget = source / "saas/upstream-baseline.json"
    before = {
        "source_intrusion_budget": {"max_direct_upstream_files": 150, "max_active_patches": 9}
    }
    budget.write_text(json.dumps(before))
    git("add", ".")
    git("commit", "-qm", "owned fixture original source with approved material paths")
    baseline = git("rev-parse", "HEAD")
    for path in APPROVED_NEW_BLOBS:
        (source / path).write_bytes(approved_source_bytes(path)[1])
    before["source_intrusion_budget"]["max_direct_upstream_files"] = 167
    budget.write_text(json.dumps(before))
    git("add", ".")
    git("commit", "-qm", "owned fixture exact approved source metadata transitions")
    revision = git("rev-parse", "HEAD")
    profile = copy.deepcopy(original)
    profile.update(
        {
            "baseline_revision": baseline,
            "product_revision": revision,
            "product_tree": git("rev-parse", "HEAD^{tree}"),
            "source_date_epoch": int(git("show", "-s", "--format=%ct", revision)),
            "budget_file_cap": 167,
            "source_delta": [],
        }
    )
    for path in git("diff", "--name-only", baseline, revision).splitlines():
        row = {"path": path}
        for side, commit in (("before", baseline), ("after", revision)):
            body = subprocess.check_output(
                ["git", "cat-file", "blob", commit + ":" + path], cwd=source
            )
            row[side] = {"mode": "100644", "sha256": hashlib.sha256(body).hexdigest()}
        profile["source_delta"].append(row)
    monkeypatch.setitem(core.BASELINES, "Core", baseline)
    return source, profile


@pytest.mark.parametrize(
    "fault", [None, "omitted", "tree", "epoch", "product-sha", "dirty-hello", "dirty-toast"]
)
def test_approved_source_git_binding_is_complete_and_never_executes_toast(
    approved_metadata_product, monkeypatch, fault
):
    source, original = approved_metadata_product
    profile = copy.deepcopy(original)
    actual_metadata = core.verify_metadata_delta
    seen = []

    def metadata(path, *arguments):
        assert path != "web/src/shell/archiveUndoToast.test.tsx"
        seen.append(path)
        return actual_metadata(path, *arguments)

    monkeypatch.setattr(core, "verify_metadata_delta", metadata)
    if fault == "omitted":
        profile["source_delta"].pop()
    elif fault == "tree":
        profile["product_tree"] = "0" * 40
    elif fault == "epoch":
        profile["source_date_epoch"] += 1
    elif fault == "product-sha":
        profile["product_revision"] = "0" * 40
    elif fault in {"dirty-hello", "dirty-toast"}:
        path = tuple(APPROVED_NEW_BLOBS)[0 if fault == "dirty-hello" else 1]
        with (source / path).open("ab") as stream:
            stream.write(b" ")
    if fault:
        with pytest.raises(ValueError):
            core.verify_source_delta(source, profile)
    else:
        core.verify_source_delta(source, profile)
        assert set(seen) == {
            "examples/extensions/hello-page/web/package.json",
            "saas/upstream-baseline.json",
        }


@pytest.mark.parametrize("fault", [None, "short", "long", "digest", "exit", "timeout", "spawn"])
def test_native_download_streams_real_child_and_closes_failed_transfers(
    tmp_path, monkeypatch, fault
):
    original_popen = subprocess.Popen
    expected = b"exact original native artifact"
    actual = (
        expected[:-1] if fault == "short" else expected + b"extra" if fault == "long" else expected
    )
    command = "import os,time; os.write(1," + repr(actual) + ")"
    if fault == "exit":
        command += ";raise SystemExit(17)"
    if fault == "timeout":
        command += ";time.sleep(3)"
    processes = []

    def spawn(arguments, **kwargs):
        assert arguments == [
            "gh",
            "api",
            "repos/Dream1216/omnigent/actions/artifacts/121/zip",
        ]
        assert kwargs["stderr"] == subprocess.DEVNULL
        if fault == "spawn":
            raise OSError("synthetic spawn failure")
        process = original_popen([sys.executable, "-c", command], **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(download.subprocess, "Popen", spawn)
    if fault == "timeout":
        monkeypatch.setattr(download, "DOWNLOAD_TIMEOUT_SECONDS", 0.05)
    path = tmp_path / "native.zip"
    arguments = {
        "artifact_id": 121,
        "destination": path,
        "expected_size": len(expected),
        "expected_sha256": "0" * 64 if fault == "digest" else hashlib.sha256(expected).hexdigest(),
    }
    if fault:
        with pytest.raises((ValueError, OSError)):
            download.download_artifact_bytes(**arguments)
        assert not path.exists()
    else:
        download.download_artifact_bytes(**arguments)
        assert path.read_bytes() == expected
        assert path.stat().st_mode & 0o777 == 0o600
    assert all(process.poll() is not None and process.stdout.closed for process in processes)


def test_native_download_cannot_overwrite_existing_or_symlink_path(tmp_path):
    existing = tmp_path / "existing"
    existing.write_bytes(b"preserve")
    linked = tmp_path / "link"
    linked.symlink_to(existing)
    for path in (existing, linked):
        with pytest.raises(FileExistsError):
            download.download_artifact_bytes(1, path, expected_size=1, expected_sha256="f" * 64)
    assert existing.read_bytes() == b"preserve" and linked.is_symlink()
    with pytest.raises(ValueError):
        download.download_artifact_bytes(
            "121/options", tmp_path / "bad", expected_size=1, expected_sha256="f" * 64
        )


@pytest.fixture
def product(tmp_path, monkeypatch):
    # The catalog has no immutable Git-fixture primitive. This test owns two
    # local commits so both actual Git guards and static manifest reads execute.
    path = tmp_path / "product"
    path.mkdir()

    def git(*args):
        return subprocess.check_output(["git", *args], cwd=path, text=True).strip()

    git("init", "-q")
    git("config", "user.name", "Local contract test")
    git("config", "user.email", "contract@example.invalid")
    git("config", "commit.gpgsign", "false")
    script = path / "saas/scripts/check_wheel_contents.py"
    script.parent.mkdir(parents=True)
    script.write_text(
        'REQUIRED_WHEEL_PATHS = ("saas/application.py", "sa'
        'as/upstream-baseline.json")\nraise RuntimeError("mu'
        'st never execute manifest code")\n'
    )
    (path / "pyproject.toml").write_text(
        '[build-system]\nrequires=["setuptools>=68.0"]\nbuild'
        '-backend="setuptools.build_meta"\n[project]\nname="o'
        'mnigent"\nversion="0.18.0.dev20261006"\n'
    )
    fixture = Path(__file__).parent / "resources/legacy_backend.toml"
    (path / "uv.lock").write_bytes(fixture.read_bytes())
    before, after = (
        b'prerelease="if-necessary"\n',
        b'prerelease="if-necessary"\nresolution="lowest-direct"\n',
    )
    (path / "uv.toml").write_bytes(before)
    git("add", ".")
    git("commit", "-qm", "fixture baseline")
    baseline = git("rev-parse", "HEAD")
    (path / "uv.toml").write_bytes(after)
    git("add", "uv.toml")
    git("commit", "-qm", "fixture material update")
    revision = git("rev-parse", "HEAD")
    tree = git("rev-parse", "HEAD^{tree}")
    monkeypatch.setitem(core.BASELINES, "Core", baseline)
    profile = {
        "schema_version": 1,
        "repository": core.REPOSITORY,
        "component": "Core",
        "baseline_revision": baseline,
        "product_revision": revision,
        "product_tree": tree,
        "source_date_epoch": int(git("show", "-s", "--format=%ct", revision)),
        "application_version": "0.18.0.dev20261006",
        "source_delta": [
            {
                "path": "uv.toml",
                "before": {
                    "mode": "100644",
                    "sha256": hashlib.sha256(before).hexdigest(),
                },
                "after": {
                    "mode": "100644",
                    "sha256": hashlib.sha256(after).hexdigest(),
                },
            }
        ],
    }
    return path, profile


def make_wheel(path, profile, *, fault=None):
    path.mkdir()
    filename = path / "omnigent-0.18.0.dev20261006-py3-none-any.whl"
    files = dict.fromkeys(controller.STATIC_WHEEL_PATHS, b"fixture content")
    files.update(
        {
            "saas/application.py": b'raise RuntimeError("wheel code must never execute")',
            "saas/upstream-baseline.json": b"{}",
            "omnigent/server/static/web-ui/assets/app.js": b"spa",
            "saas/login_ui/static/_next/static/app.js": b"login",
            "omnigent-0.18.0.dev20261006.dist-info/METADATA": (
                b"Name: omnigent\nVersion: 0.18.0.dev20261006\n"
            ),
            "omnigent/_build_info.py": (
                f"COMMIT_SHA = {profile['product_revision']!r}\n"
                f"BUILD_TIME_EPOCH = {profile['source_date_epoch']}\n"
            ).encode(),
        }
    )
    if fault == "old_wheel":
        files["omnigent/_build_info.py"] = b"COMMIT_SHA = 'old'\nBUILD_TIME_EPOCH = 1\n"
    if fault == "missing_original":
        files.pop("saas/application.py")
    if fault == "missing_login":
        files.pop("saas/login_ui/static/login.html")
    if fault == "missing_chunks":
        files.pop("saas/login_ui/static/_next/static/app.js")
    if fault == "empty_UI":
        files["omnigent/server/static/web-ui/index.html"] = b""
    with zipfile.ZipFile(filename, "w") as bundle:
        for name, data in files.items():
            bundle.writestr(name, data)
    return filename


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "old_wheel",
        "missing_original",
        "missing_login",
        "missing_chunks",
        "empty_UI",
        "dirty_source",
    ],
)
def test_fresh_wheel_manifest_uses_original_Git_and_never_executes_wheel_or_manifest(
    product, tmp_path, fault
):
    source, profile = product
    wheel = make_wheel(tmp_path / "dist", profile, fault=fault)
    if fault == "dirty_source":
        (source / "uv.toml").write_text("unsealed\n")
    if fault:
        with pytest.raises(ValueError):
            controller.stage_wheel(source, wheel.parent, tmp_path / "stage", profile, CONTROL)
    else:
        facts = controller.stage_wheel(source, wheel.parent, tmp_path / "stage", profile, CONTROL)
        assert facts["original_required_path_count"] == 2
        assert facts["product_revision"] == profile["product_revision"]
        assert (tmp_path / "stage" / wheel.name).read_bytes() == wheel.read_bytes()


@pytest.mark.parametrize("fault", [None, "manifest", "checksum", "extra", "zip_digest"])
def test_fresh_wheel_native_payload_roundtrip_recomputes_facts(product, tmp_path, fault):
    source, profile = product
    wheel = make_wheel(tmp_path / "dist", profile)
    stage = tmp_path / "stage"
    facts = controller.stage_wheel(source, wheel.parent, stage, profile, CONTROL)
    if fault == "manifest":
        data = json.loads((stage / "wheel-source.json").read_text())
        data["product_tree"] = "f" * 40
        (stage / "wheel-source.json").write_text(json.dumps(data))
    if fault == "checksum":
        (stage / "SHA256SUMS").write_text("wrong\n")
    archive = tmp_path / "wheel.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        for file in stage.iterdir():
            bundle.write(file, file.name)
        if fault == "extra":
            bundle.writestr("unreviewed.py", "extra")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    kwargs = {
        "archive": archive,
        "destination": tmp_path / "received",
        "product": source,
        "profile": profile,
        "control_revision": CONTROL,
        "zip_sha256": "0" * 64 if fault == "zip_digest" else digest,
    }
    if fault:
        with pytest.raises(ValueError):
            controller.verify_wheel_bundle(**kwargs)
    else:
        assert controller.verify_wheel_bundle(**kwargs) == facts


def register_control(tmp_path, product, monkeypatch):
    _, profile = product
    path = tmp_path / "control"
    store = path / "saas/supply_chain"
    store.mkdir(parents=True)
    (store / "legacy-security-build-profiles.json").write_text(
        json.dumps({"schema_version": 1, "profiles": {"Core": profile}})
    )
    transfer = {
        "component": "Core",
        "pull_number": 9001,
        "base_ref": "codex/legacy-validation-core-dc1e9a97",
        "workflow_sha256": "f" * 64,
        "actor": "Dream1216",
    }
    (store / "legacy-security-transfer-profiles.json").write_text(
        json.dumps({"schema_version": 1, "profiles": {"Core": transfer}})
    )

    def git(*args):
        return subprocess.check_output(["git", *args], cwd=path, text=True).strip()

    git("init", "-q")
    git("config", "user.name", "Control fixture")
    git("config", "user.email", "control@example.invalid")
    git("config", "commit.gpgsign", "false")
    git("add", ".")
    git("commit", "-qm", "frozen control fixture")
    revision = git("rev-parse", "HEAD")
    for key, value in {
        "GITHUB_REPOSITORY": core.REPOSITORY,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_SHA": revision,
    }.items():
        monkeypatch.setenv(key, value)
    return path, revision


@pytest.mark.parametrize("fault", [None, "ref", "repository", "event", "sha", "dirty"])
def test_selection_requires_native_main_and_clean_frozen_control(
    product, tmp_path, monkeypatch, fault
):
    control, revision = register_control(tmp_path, product, monkeypatch)
    fields = {
        "ref": "GITHUB_REF",
        "repository": "GITHUB_REPOSITORY",
        "event": "GITHUB_EVENT_NAME",
        "sha": "GITHUB_SHA",
    }
    if fault in fields:
        monkeypatch.setenv(fields[fault], "wrong")
    if fault == "dirty":
        (control / "extra").write_text("unsealed")
    if fault:
        with pytest.raises(ValueError):
            controller.select_product(control, "Core", revision)
    else:
        selected = controller.select_product(control, "Core", revision)
        assert selected["product_revision"] == product[1]["product_revision"]
        assert selected["control_revision"] == revision


def test_native_CLI_outputs_hash_fields_and_original_lock_build_constraints(
    product, tmp_path, monkeypatch
):
    control, revision = register_control(tmp_path, product, monkeypatch)
    output = tmp_path / "github-output"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "controller",
            "select",
            "--control",
            str(control),
            "--component",
            "Core",
            "--control-revision",
            revision,
            "--github-output",
            str(output),
        ],
    )
    assert controller.main() == 0
    assert "profile_sha256=" in output.read_text()
    constraints = tmp_path / "constraints.txt"
    digest = controller.write_build_constraints(product[0], product[1], constraints)
    assert digest == hashlib.sha256(constraints.read_bytes()).hexdigest()
    assert constraints.read_text().startswith("setuptools==83.0.0 --hash=sha256:")
    assert constraints.read_text().count("--hash=") == 2


def test_worker_workflow_is_unprivileged_and_forces_fresh_UI_and_hashed_backend():
    path = ROOT / ".github/workflows/saas-legacy-security-build.yml"
    workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
    assert workflow["permissions"] == {"contents": "read"}
    assert set(workflow["on"]) == {"workflow_dispatch"}
    assert workflow["on"]["workflow_dispatch"]["inputs"]["component"]["options"] == [
        "Core",
        "Gateway",
        "Model",
    ]
    assert set(workflow["jobs"]) == {
        "build-initial",
        "qualify-source",
        "verify-product-pg",
        "collect-product-pg",
        "prepare-publication",
        "publish-exact-oci",
        "verify-published-runtime",
        "attest-exact-inputs",
        "independent-readback",
    }
    job = workflow["jobs"]["build-initial"]
    assert job["permissions"] == {"contents": "read"} and "environment" not in job
    assert "refs/heads/main" in job["if"] and "workflow_dispatch" in job["if"]
    steps = {step["name"]: step for step in job["steps"]}
    build = steps["Build fresh product wheel and SPA"]
    assert (
        build["env"]["OMNIGENT_SKIP_WEB_UI"] == "false"
        and build["env"]["OMNIGENT_BUILD_WEB_UI"] == "1"
    )
    assert "--require-hashes" in build["run"] and "--build-constraints" in build["run"]
    assert steps["Build fresh SaaS login export"]["working-directory"] == "product/saas/login_web"
    assert "npm ci" in steps["Build fresh SaaS login export"]["run"]
    assert not any(
        "attest" in step.get("uses", "") or "docker/login" in step.get("uses", "")
        for step in job["steps"]
    )
    assert "secrets." not in json.dumps(job) and "id-token" not in job["permissions"]
    verify = list(steps).index("Verify complete source before executing product build")
    build_position = list(steps).index("Build fresh SaaS login export")
    assert verify < build_position


def test_default_worker_registrations_are_empty_deny(tmp_path):
    store = tmp_path / "saas/supply_chain"
    store.mkdir(parents=True)
    for name in (
        "legacy-security-build-profiles.json",
        "legacy-security-transfer-profiles.json",
        "legacy-security-ci-profiles.json",
        "legacy-source-qualification-profiles.json",
        "legacy-security-pg-profiles.json",
    ):
        empty = {"schema_version": 1, "profiles": {}}
        (store / name).write_text(json.dumps(empty))
        assert json.loads((store / name).read_text()) == empty
    empty_inputs = {"schema_version": 1, "inputs": {}}
    (store / "legacy-security-original-inputs.json").write_text(json.dumps(empty_inputs))
    assert json.loads((store / "legacy-security-original-inputs.json").read_text()) == empty_inputs
    with pytest.raises(ValueError, match="no approved profile"):
        core.load_profile(tmp_path, "Core")
    with pytest.raises(ValueError, match="no reviewed exact-product binding"):
        controller.load_original_inputs(
            tmp_path,
            {"component": "Core", "product_revision": "a" * 40, "product_tree": "b" * 40},
        )


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "old_attempt",
        "expired_after_download",
        "failed_after_download",
        "wrong_actor",
    ],
)
def test_native_fresh_wheel_download_binds_control_run_and_rechecks_after_transfer(
    product, tmp_path, monkeypatch, fault
):
    _, profile = product
    run = {
        "id": 42,
        "run_attempt": 1,
        "head_sha": CONTROL,
        "head_branch": "main",
        "event": "workflow_dispatch",
        "path": core.WORKFLOW,
        "repository": {"full_name": core.REPOSITORY},
        "actor": {"login": "Dream1216"},
        "triggering_actor": {"login": "Dream1216"},
        "status": "in_progress",
        "conclusion": None,
    }
    job = {
        "id": 88,
        "run_id": 42,
        "run_attempt": 1,
        "name": "build-initial",
        "status": "completed",
        "conclusion": "success",
        "runner_group_name": "GitHub Actions",
        "labels": ["ubuntu-latest"],
    }
    data = b"native ZIP"
    digest = hashlib.sha256(data).hexdigest()
    metadata = {
        "id": 122,
        "name": f"legacy-initial-Core-{profile['product_revision']}-{CONTROL}-42-1",
        "expired": False,
        "size_in_bytes": len(data),
        "digest": "sha256:" + digest,
        "workflow_run": {"id": 42, "head_sha": CONTROL},
    }
    if fault == "wrong_actor":
        run["actor"]["login"] = "other"
    current_reads = 0
    artifact_reads = 0

    def native(endpoint):
        nonlocal current_reads, artifact_reads
        if "/jobs/" in endpoint:
            return copy.deepcopy(job)
        if "/artifacts/" in endpoint:
            artifact_reads += 1
            value = copy.deepcopy(metadata)
            if fault == "expired_after_download" and artifact_reads == 2:
                value["expired"] = True
            return value
        value = copy.deepcopy(run)
        if endpoint.endswith("/runs/42"):
            current_reads += 1
            if current_reads == 2:
                if fault == "old_attempt":
                    value["run_attempt"] = 2
                if fault == "failed_after_download":
                    value.update(status="completed", conclusion="failure")
        return value

    def download_bytes(identifier, path, **kwargs):
        assert identifier == 122 and kwargs == {
            "expected_size": len(data),
            "expected_sha256": digest,
        }
        path.write_bytes(data)

    monkeypatch.setattr(controller, "api", native)
    monkeypatch.setattr(controller, "download_artifact_bytes", download_bytes)
    kwargs = {
        "profile": profile,
        "control_revision": CONTROL,
        "run_id": 42,
        "attempt": 1,
        "job_id": 88,
        "actor": "Dream1216",
        "artifact_id": 122,
        "zip_size": len(data),
        "zip_sha256": digest,
        "destination": tmp_path / "received",
    }
    if fault:
        with pytest.raises(ValueError):
            controller.download_fresh_wheel(**kwargs)
    else:
        result = controller.download_fresh_wheel(**kwargs)
        assert current_reads == 2 and artifact_reads == 2
        assert result["native_run"]["head_sha"] == CONTROL


@pytest.mark.parametrize("fault", [None, "artifact_drift", "new_attempt", "moved_PR"])
def test_original_OCI_download_rechecks_native_artifact_run_and_frozen_PR(
    product, tmp_path, monkeypatch, fault
):
    control, _ = register_control(tmp_path, product, monkeypatch)
    _, profile = product
    repo = {"full_name": core.REPOSITORY}
    merge = "d" * 40
    pull = {
        "number": 9001,
        "state": "open",
        "draft": False,
        "head": {"sha": profile["product_revision"], "repo": repo},
        "base": {
            "sha": profile["baseline_revision"],
            "ref": "codex/legacy-validation-core-dc1e9a97",
            "repo": repo,
        },
        "merge_commit_sha": merge,
    }
    commit = {
        "sha": merge,
        "tree": {"sha": profile["product_tree"]},
        "parents": [
            {"sha": profile["baseline_revision"]},
            {"sha": profile["product_revision"]},
        ],
    }
    run = {
        "id": 41,
        "run_attempt": 1,
        "head_sha": profile["product_revision"],
        "event": "pull_request",
        "path": ".github/workflows/saas-image-candidate.yml",
        "status": "completed",
        "conclusion": "success",
    }
    metadata = {
        "id": 121,
        "name": "frozen",
        "size_in_bytes": 5,
        "digest": "sha256:" + "1" * 64,
        "expired": False,
        "workflow_run": {"id": 41},
    }
    result = {
        "native_artifact": metadata,
        "native_run": run,
        "native_merge_commit": commit,
    }

    def collect(*args, **kwargs):
        kwargs["destination"].mkdir()
        return copy.deepcopy(result)

    def native(endpoint):
        if "/artifacts/" in endpoint:
            value = copy.deepcopy(metadata)
            if fault == "artifact_drift":
                value["expired"] = True
            return value
        if "/pulls/" in endpoint:
            value = copy.deepcopy(pull)
            if fault == "moved_PR":
                value["base"]["sha"] = CONTROL
            return value
        value = copy.deepcopy(run)
        if fault == "new_attempt":
            value["run_attempt"] = 2
        return value

    monkeypatch.setattr(controller, "collect_native_pr_oci", collect)
    monkeypatch.setattr(controller, "api", native)
    monkeypatch.setattr(
        controller,
        "download_artifact_bytes",
        lambda _id, path, **kwargs: path.write_bytes(b"exact"),
    )
    kwargs = {
        "control": control,
        "component": "Core",
        "run_id": 41,
        "attempt": 1,
        "artifact_id": 121,
        "zip_size": 5,
        "zip_sha256": "1" * 64,
        "seal_sha256": "2" * 64,
        "destination": tmp_path / "original",
    }
    if fault:
        with pytest.raises(ValueError):
            controller.download_original_oci(**kwargs)
    else:
        assert controller.download_original_oci(**kwargs) == result


@pytest.mark.parametrize(
    "fault", [None, "missing", "product", "boolean_attempt", "extra", "digest"]
)
def test_original_inputs_only_read_exact_frozen_control_coordinates(product, tmp_path, fault):
    _, profile = product
    store = tmp_path / "saas/supply_chain"
    store.mkdir(parents=True)
    original = {
        "run_id": 41,
        "attempt": 1,
        "artifact_id": 121,
        "zip_size": 5,
        "zip_sha256": "1" * 64,
        "seal_sha256": "2" * 64,
    }
    data = {key: profile[key] for key in ("component", "product_revision", "product_tree")}
    data["original_pr_oci"] = original
    if fault == "product":
        data["product_revision"] = "f" * 40
    if fault == "boolean_attempt":
        original["attempt"] = True
    if fault == "extra":
        original["arbitrary_url"] = "https://other.invalid"
    if fault == "digest":
        original["zip_sha256"] = "tag"
    (store / "legacy-security-original-inputs.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "inputs": {} if fault == "missing" else {"Core": data},
            }
        )
    )
    if fault:
        with pytest.raises(ValueError):
            controller.load_original_inputs(tmp_path, profile)
    else:
        assert controller.load_original_inputs(tmp_path, profile) == original


def test_collect_original_CLI_uses_committed_profile_not_caller_run_or_source_inputs(
    product, tmp_path, monkeypatch
):
    control, _ = register_control(tmp_path, product, monkeypatch)
    _, profile = product
    original = {
        "run_id": 41,
        "attempt": 1,
        "artifact_id": 121,
        "zip_size": 5,
        "zip_sha256": "1" * 64,
        "seal_sha256": "2" * 64,
    }
    data = {key: profile[key] for key in ("component", "product_revision", "product_tree")}
    data["original_pr_oci"] = original
    (control / "saas/supply_chain/legacy-security-original-inputs.json").write_text(
        json.dumps({"schema_version": 1, "inputs": {"Core": data}})
    )
    subprocess.run(["git", "add", "."], cwd=control, check=True)
    subprocess.run(
        ["git", "commit", "-qm", "exact fixture artifact binding"],
        cwd=control,
        check=True,
    )
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=control, text=True
    ).strip()
    monkeypatch.setenv("GITHUB_SHA", revision)
    calls = []

    def native_download(path, component, **kwargs):
        assert path == control and component == "Core"
        assert kwargs == original | {"destination": tmp_path / "collected"}
        calls.append(kwargs)
        return {"native_artifact": {"digest": "sha256:" + "1" * 64}}

    monkeypatch.setattr(controller, "download_original_oci", native_download)
    output = tmp_path / "github-output"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "controller",
            "collect-original",
            "--control",
            str(control),
            "--component",
            "Core",
            "--control-revision",
            revision,
            "--destination",
            str(tmp_path / "collected"),
            "--github-output",
            str(output),
        ],
    )
    assert controller.main() == 0 and len(calls) == 1
    assert "original_oci_sha256=" + "1" * 64 in output.read_text()


def test_source_and_pg_jobs_preserve_control_identity_and_read_only_boundaries():
    path = ROOT / ".github/workflows/saas-legacy-security-build.yml"
    workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
    for job_name in ("build-initial", "qualify-source", "verify-product-pg", "collect-product-pg"):
        job = workflow["jobs"][job_name]
        assert job["env"]["CONTROL_REVISION"] == "${{ github.sha }}"
        assert "refs/heads/main" in job["if"]
        assert "environment" not in job
        assert set(job["permissions"].values()) == {"read"}
        if job_name == "collect-product-pg":
            assert job["needs"] == "verify-product-pg"
        else:
            assert "needs" not in job
        assert "GITHUB_SHA=" not in json.dumps(job)
        for step in job["steps"]:
            if "uses" in step:
                assert re.fullmatch(r".+@[0-9a-f]{40}", step["uses"])
            assert "GITHUB_SHA" not in step.get("env", {})
    source = workflow["jobs"]["qualify-source"]
    source_steps = {step["name"]: step for step in source["steps"]}
    assert (
        "legacy_source_qualification"
        in source_steps["Qualify complete reviewed source CI and original policy state"]["run"]
    )
    assert source_steps["Retain original source CI bytes and refusal evidence"]["if"] == "always()"
    assert (
        source_steps["Retain original source CI bytes and refusal evidence"]["with"][
            "retention-days"
        ]
        == "90"
    )
    pg = workflow["jobs"]["verify-product-pg"]
    assert {row["major"] for row in pg["strategy"]["matrix"]["include"]} == {"16", "18"}
    assert all("@sha256:" in row["image"] for row in pg["strategy"]["matrix"]["include"])
    assert pg["services"]["postgres"]["image"] == "${{ matrix.image }}"
    steps = {step["name"]: step for step in pg["steps"]}
    names = list(steps)
    assert names.index("Verify complete component PG input fingerprints") < names.index(
        "Install locked product contract dependencies without build hooks"
    )
    install = steps["Install locked product contract dependencies without build hooks"]["run"]
    assert "uv sync --frozen" in install and "--no-install-local --no-config" in install
    execution = steps["Execute original exact-source PostgreSQL contracts"]["run"]
    assert "--reruns 0" in execution and "-n 0" in execution
    assert "test_pg16_runner_direct_authority_is_fail_closed" in execution.split("elif")[0]
    assert "test_pg16_runner_direct_authority_is_fail_closed" not in execution.split("elif")[1]
    assert (
        "SHOW server_version_num" in steps["Capture actual disposable PostgreSQL version"]["run"]
    )
    assert (
        "verify-results" in steps["Reverify source and exact PostgreSQL result inventory"]["run"]
    )
    assert steps["Retain exact-source PG evidence"]["if"] == "always()"
    assert steps["Retain exact-source PG evidence"]["with"]["retention-days"] == "90"


# Model source fixtures are raw approved blobs, never imported or executed.
MODEL_READER_CLOSE_PATHS = (
    "dev/benchmarks/omnigent/environment.py",
    "tests/benchmarks/test_benchmark_smoke.py",
)


def model_reader_close_bytes(path):
    resource = Path(__file__).parent / "resources/legacy_model_reader_close" / Path(path).name
    return tuple(
        resource.with_name(side + "-" + resource.name).read_bytes() for side in ("before", "after")
    )


def model_budget_bytes(cap=169):
    return tuple(
        json.dumps({"source_intrusion_budget": {"max_direct_upstream_files": value}}).encode()
        for value in (150, cap)
    )


@pytest.fixture
def model_reader_close_profile(product, monkeypatch):
    _, original = product
    profile = copy.deepcopy(original)
    profile.update(component="Model", budget_file_cap=169)
    monkeypatch.setitem(core.BASELINES, "Model", profile["baseline_revision"])
    for path in (*MODEL_READER_CLOSE_PATHS, "saas/upstream-baseline.json"):
        before, after = (
            model_budget_bytes()
            if path == "saas/upstream-baseline.json"
            else model_reader_close_bytes(path)
        )
        profile["source_delta"].append(
            {
                "path": path,
                "before": {"mode": "100644", "sha256": hashlib.sha256(before).hexdigest()},
                "after": {"mode": "100644", "sha256": hashlib.sha256(after).hexdigest()},
            }
        )
    return profile


@pytest.mark.parametrize("cap", [None, True, 150, 167, 168, 169, 170, "169", 169.0])
def test_model_reader_close_requires_only_exact_integer169(model_reader_close_profile, cap):
    profile = copy.deepcopy(model_reader_close_profile)
    if cap is None:
        profile.pop("budget_file_cap")
    else:
        profile["budget_file_cap"] = cap
    if type(cap) is int and cap == 169:
        core.validate_profile(profile, "Model")
        core.verify_metadata_delta("saas/upstream-baseline.json", *model_budget_bytes(), profile)
    else:
        with pytest.raises(ValueError, match=r"budget change lacks|budget differs"):
            core.validate_profile(profile, "Model")


@pytest.mark.parametrize("path", MODEL_READER_CLOSE_PATHS)
@pytest.mark.parametrize(
    "fault",
    [
        None,
        "before-byte",
        "after-byte",
        "same-old",
        "swapped",
        "before-mode",
        "after-mode",
        "missing-before-mode",
        "missing-after-mode",
    ],
)
def test_model_reader_close_binds_each_raw_pair_and_both_modes(
    model_reader_close_profile, path, fault
):
    profile = copy.deepcopy(model_reader_close_profile)
    row = next(r for r in profile["source_delta"] if r["path"] == path)
    before, after = model_reader_close_bytes(path)
    if fault in {"before-byte", "after-byte"}:
        side = fault.split("-")[0]
        raw = before if side == "before" else after
        row[side]["sha256"] = hashlib.sha256(raw + b" ").hexdigest()
    elif fault == "same-old":
        row["after"]["sha256"] = row["before"]["sha256"]
    elif fault == "swapped":
        row["before"]["sha256"], row["after"]["sha256"] = (
            row["after"]["sha256"],
            row["before"]["sha256"],
        )
    elif fault in {"before-mode", "after-mode"}:
        row[fault.split("-")[0]]["mode"] = "100755"
    elif fault in {"missing-before-mode", "missing-after-mode"}:
        row[fault.split("-")[1]].pop("mode")
    if fault:
        with pytest.raises(
            ValueError,
            match=(
                r"invalid legacy source blob|source metadata mode|"
                r"reviewed byte transition"
            ),
        ):
            core.validate_profile(profile, "Model")
    else:
        core.validate_profile(profile, "Model")


@pytest.mark.parametrize("omitted", ["environment", "test", "both"])
def test_model_reader_close_denies_either_missing_approved_path(
    model_reader_close_profile, omitted
):
    profile = copy.deepcopy(model_reader_close_profile)
    missing = (
        {MODEL_READER_CLOSE_PATHS[0] if omitted == "environment" else MODEL_READER_CLOSE_PATHS[1]}
        if omitted != "both"
        else set(MODEL_READER_CLOSE_PATHS)
    )
    profile["source_delta"] = [r for r in profile["source_delta"] if r["path"] not in missing]
    with pytest.raises(ValueError, match="Model reader-close source paths are incomplete"):
        core.validate_profile(profile, "Model")


@pytest.mark.parametrize("component", ["Core", "Gateway"])
@pytest.mark.parametrize("cap", [167, 169])
@pytest.mark.parametrize("reserved_path", [None, *MODEL_READER_CLOSE_PATHS])
def test_core_gateway_keep167_and_cannot_use_model_pair_or_generic_test_bypass(
    model_reader_close_profile, monkeypatch, component, cap, reserved_path
):
    profile = copy.deepcopy(model_reader_close_profile)
    profile.update(component=component, budget_file_cap=cap)
    monkeypatch.setitem(core.BASELINES, component, profile["baseline_revision"])
    profile["source_delta"] = [
        row
        for row in profile["source_delta"]
        if row["path"] not in MODEL_READER_CLOSE_PATHS or row["path"] == reserved_path
    ]
    budget = next(r for r in profile["source_delta"] if r["path"] == "saas/upstream-baseline.json")
    budget["after"]["sha256"] = hashlib.sha256(model_budget_bytes(cap)[1]).hexdigest()
    if cap == 167 and reserved_path is None:
        core.validate_profile(profile, component)
        core.verify_metadata_delta(
            "saas/upstream-baseline.json", *model_budget_bytes(cap), profile
        )
    else:
        with pytest.raises(
            ValueError, match=r"budget differs|application or schema|reader-close source paths"
        ):
            core.validate_profile(profile, component)


@pytest.mark.parametrize(
    "path",
    [
        "dev/benchmarks/omnigent/environment_extra.py",
        "dev/benchmarks/omnigent/other.py",
        "omnigent/runtime/workflow.py",
    ],
)
def test_model_reader_close_does_not_open_adjacent_application_paths(
    model_reader_close_profile, path
):
    profile = copy.deepcopy(model_reader_close_profile)
    profile["source_delta"].append(
        {
            "path": path,
            "before": {"mode": "100644", "sha256": "a" * 64},
            "after": {"mode": "100644", "sha256": "b" * 64},
        }
    )
    with pytest.raises(ValueError, match="application or schema"):
        core.validate_profile(profile, "Model")


@pytest.mark.parametrize("fault", [None, "original167", "after167", "float", "extra"])
def test_model_budget_metadata_retains_original150_and_single_field_only(fault):
    before, after = (json.loads(raw) for raw in model_budget_bytes())
    profile = {"component": "Model", "budget_file_cap": 169}
    if fault == "original167":
        before["source_intrusion_budget"]["max_direct_upstream_files"] = 167
    elif fault == "after167":
        after["source_intrusion_budget"]["max_direct_upstream_files"] = 167
    elif fault == "float":
        profile["budget_file_cap"] = 169.0
    elif fault == "extra":
        after["source_intrusion_budget"]["max_active_patches"] = 10
    args = (
        "saas/upstream-baseline.json",
        json.dumps(before).encode(),
        json.dumps(after).encode(),
        profile,
    )
    if fault:
        with pytest.raises(ValueError, match=r"original or approved cap|outside the exact"):
            core.verify_metadata_delta(*args)
    else:
        core.verify_metadata_delta(*args)


@pytest.fixture
def model_reader_close_git_product(product, monkeypatch):
    source, original = product

    def git(*args):
        return subprocess.check_output(["git", *args], cwd=source).decode().strip()

    git("checkout", "--detach", "-q", original["baseline_revision"])
    for path in MODEL_READER_CLOSE_PATHS:
        target = source / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(model_reader_close_bytes(path)[0])
    budget = source / "saas/upstream-baseline.json"
    budget.write_bytes(model_budget_bytes()[0])
    git("add", ".")
    git("commit", "-qm", "owned Model original reader-close blob fixture")
    baseline = git("rev-parse", "HEAD")
    for path in MODEL_READER_CLOSE_PATHS:
        (source / path).write_bytes(model_reader_close_bytes(path)[1])
    budget.write_bytes(model_budget_bytes()[1])
    git("add", ".")
    git("commit", "-qm", "owned Model exact reader-close blob fixture")
    profile = copy.deepcopy(original)
    profile.update(
        component="Model",
        baseline_revision=baseline,
        product_revision=git("rev-parse", "HEAD"),
        product_tree=git("rev-parse", "HEAD^{tree}"),
        source_date_epoch=int(git("show", "-s", "--format=%ct", "HEAD")),
        budget_file_cap=169,
        source_delta=[],
    )
    for path in git("diff", "--name-only", baseline, "HEAD").splitlines():
        row = {"path": path}
        for side, revision in (("before", baseline), ("after", "HEAD")):
            raw = subprocess.check_output(
                ["git", "cat-file", "blob", revision + ":" + path], cwd=source
            )
            row[side] = {"mode": "100644", "sha256": hashlib.sha256(raw).hexdigest()}
        profile["source_delta"].append(row)
    monkeypatch.setitem(core.BASELINES, "Model", baseline)
    return source, profile


@pytest.mark.parametrize("fault", [None, "omitted", "tree", "epoch", "dirty-env", "dirty-test"])
def test_model_exact_git_delta_never_parses_or_executes_reader_source(
    model_reader_close_git_product, monkeypatch, fault
):
    source, original = model_reader_close_git_product
    profile = copy.deepcopy(original)
    actual_metadata = core.verify_metadata_delta
    seen = []

    def metadata(path, *args):
        assert path not in MODEL_READER_CLOSE_PATHS
        seen.append(path)
        return actual_metadata(path, *args)

    monkeypatch.setattr(core, "verify_metadata_delta", metadata)
    if fault == "omitted":
        profile["source_delta"].pop()
    elif fault == "tree":
        profile["product_tree"] = "0" * 40
    elif fault == "epoch":
        profile["source_date_epoch"] += 1
    elif fault in {"dirty-env", "dirty-test"}:
        path = MODEL_READER_CLOSE_PATHS[0 if fault == "dirty-env" else 1]
        with (source / path).open("ab") as stream:
            stream.write(b" ")
    if fault:
        with pytest.raises(ValueError):
            core.verify_source_delta(source, profile)
    else:
        core.verify_source_delta(source, profile)
        assert seen == ["saas/upstream-baseline.json"]


@pytest.mark.parametrize(
    "filename",
    [
        "legacy-security-build-profiles.json",
        "legacy-security-ci-profiles.json",
        "legacy-security-original-inputs.json",
        "legacy-security-pg-profiles.json",
        "legacy-security-transfer-profiles.json",
        "legacy-source-qualification-profiles.json",
    ],
)
def test_actual_registered_source_slots_and_reviewed_hashes(filename):
    expected = json.loads(
        (
            Path(__file__).parent / "resources/legacy_registered_source_expectations.json"
        ).read_text()
    )
    table = expected["tables"][filename]
    store = json.loads((ROOT / "saas/supply_chain" / filename).read_text())
    assert set(store) == {"schema_version", table["key"]}
    assert type(store["schema_version"]) is int and store["schema_version"] == 1
    records = store[table["key"]]
    assert set(records) == set(expected["sources"]) == {"Core", "Gateway", "Model"}
    for component, identity in expected["sources"].items():
        record = records[component]
        assert record["component"] == component
        if filename != "legacy-security-transfer-profiles.json":
            assert all(record[field] == value for field, value in identity.items())
        reviewed = table["record_sha256"][component]
        assert re.fullmatch(r"[0-9a-f]{64}", reviewed), (
            "MISSING exact actual registration fingerprint: " + filename + "/" + component
        )
        assert (
            hashlib.sha256(
                json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            == reviewed
        )
        if filename == "legacy-security-build-profiles.json":
            assert core.load_profile(ROOT, component) == record


@pytest.mark.parametrize("component", ["unknown", "core", "Root019"])
def test_populated_build_store_keeps_unknown_components_closed(component):
    with pytest.raises(ValueError, match="no approved profile"):
        core.load_profile(ROOT, component)


@pytest.mark.parametrize("component", ["Core", "Gateway", "Model"])
def test_populated_original_inputs_reject_another_product_revision(component):
    profile = copy.deepcopy(core.load_profile(ROOT, component))
    profile["product_revision"] = "a" * 40
    with pytest.raises(ValueError, match="no reviewed exact-product binding"):
        controller.load_original_inputs(ROOT, profile)
