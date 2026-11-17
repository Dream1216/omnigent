"""Original failure, four retained archives and new producer remain distinct."""

import copy
import json
import shutil
import tarfile
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from saas.scripts import accepted_m165_promotion as promotion
from saas.scripts import main22_retained_recovery as recovery
from saas.scripts.oci_promotion import MANIFEST_NAME, archive_index_digest, seal_candidate
from tests.saas import test_oci_promotion as oci


def job(identifier, name, conclusion="success", *, run_id=None, controller=None):
    return {
        "id": identifier,
        "name": name,
        "run_id": run_id or recovery.PARENT["run_id"],
        "run_attempt": 1,
        "head_sha": controller or recovery.PRODUCT,
        "status": "completed",
        "conclusion": conclusion,
        "labels": ["ubuntu-24.04"],
        "runner_group_name": "GitHub Actions",
        "started_at": "2026-11-17T04:00:46Z",
        "completed_at": "2026-11-17T06:58:07Z",
    }


@pytest.fixture
def parent():
    run = {
        "id": recovery.PARENT["run_id"],
        "head_sha": recovery.PRODUCT,
        "head_branch": "main",
        "event": "push",
        "path": recovery.SOURCE_WORKFLOW,
        "run_attempt": 1,
        "status": "completed",
        "conclusion": "failure",
        "created_at": "2026-11-17T04:00:44Z",
        "repository": {"full_name": recovery.REPOSITORY},
    }
    jobs = [
        job(133807912798, "source-context"),
        job(133808078611, "verify-candidate-preflight"),
        job(133808078759, "verify-production-migration-replay (postgres:18.6)"),
        job(133808078896, "verify-production-migration-replay (postgres:16.14)"),
    ]
    builder = job(recovery.PARENT["job_id"], "build-candidate", "failure")
    names = [
        "Run current-revision OSS and SaaS regressions",
        "Verify migrations and downstream compatibility",
        "Verify executable Server candidate SDK on both architectures",
        "Preflight scan exact server candidate on both architectures",
        "Compare repeated executable image facts",
        "Retain unqualified OCI after failed candidate build",
        "Upload candidate evidence",
        *[
            f"Build {role} candidate attempt {number}"
            for role in ("server", "host")
            for number in (1, 2)
        ],
    ]
    builder["steps"] = [
        {
            "name": name,
            "conclusion": "success",
            "started_at": "2026-11-17T04:00:46Z",
            "completed_at": "2026-11-17T06:58:07Z",
        }
        for name in names
    ]
    builder["steps"] += [
        {"name": "Scan exact OCI candidates on both architectures", "conclusion": "failure"}
    ]
    builder["steps"] += [
        {"name": name, "conclusion": "skipped"}
        for name in (
            "Prepare immutable runtime evidence data for candidate",
            "Seal exact admitted OCI archives and raw scan evidence",
            "Upload immutable admitted OCI bytes",
        )
    ]
    jobs.append(builder)
    artifacts = []
    for coordinate, name in (
        (recovery.RAW, f"unqualified-oci-{recovery.PRODUCT}-{run['id']}-1"),
        (recovery.REPORT, f"saas-image-candidate-{recovery.PRODUCT}"),
    ):
        artifacts.append(
            {
                "id": coordinate[0],
                "size_in_bytes": coordinate[1],
                "digest": "sha256:" + coordinate[2],
                "name": name,
                "expired": False,
                "created_at": "2026-11-17T06:57:31Z",
                "workflow_run": {"id": run["id"], "head_sha": recovery.PRODUCT},
            }
        )
    return run, jobs, *artifacts


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "parent-pass",
        "wrong-head",
        "wrong-event",
        "attempt",
        "other-failure",
        "second-host-incomplete",
        "sdk-missing",
        "seal-pass",
        "overlay",
        "wrong-raw",
        "artifact-outside-step",
        "expired",
        "wrong-labels",
        "duplicate-job",
    ],
)
def test_original_scan_failure_is_not_relabelled(parent, fault):
    run, jobs, raw, report = parent
    if fault == "parent-pass":
        run["conclusion"] = "success"
    if fault == "wrong-head":
        run["head_sha"] = "b" * 40
    if fault == "wrong-event":
        run["event"] = "workflow_dispatch"
    if fault == "attempt":
        run["run_attempt"] = 2
    if fault == "other-failure":
        jobs[-1]["steps"][0]["conclusion"] = "failure"
    if fault == "second-host-incomplete":
        next(
            step for step in jobs[-1]["steps"] if step["name"] == "Build host candidate attempt 2"
        )["conclusion"] = "skipped"
    if fault == "sdk-missing":
        jobs[-1]["steps"] = [
            step for step in jobs[-1]["steps"] if not step["name"].startswith("Verify executable")
        ]
    if fault == "seal-pass":
        jobs[-1]["steps"][-2]["conclusion"] = "success"
    if fault == "overlay":
        jobs[-1]["steps"][-3]["conclusion"] = "success"
    if fault == "wrong-raw":
        raw["digest"] = "sha256:" + "b" * 64
    if fault == "artifact-outside-step":
        raw["created_at"] = "2026-11-17T03:00:00Z"
    if fault == "expired":
        raw["expired"] = True
    if fault == "wrong-labels":
        jobs[-1]["labels"] = ["self-hosted"]
    if fault == "duplicate-job":
        jobs.append(jobs[-1])
    if fault:
        with pytest.raises(ValueError):
            recovery.validate_parent(run, jobs, raw, report)
    else:
        origin = recovery.validate_parent(run, jobs, raw, report)
        assert (
            origin["native_run"]["conclusion"] == origin["native_job"]["conclusion"] == "failure"
        )
        assert len(origin["native_prerequisites"]) == 4


@pytest.fixture
def original_files(tmp_path, monkeypatch):
    monkeypatch.setattr(oci, "REVISION", recovery.PRODUCT)
    monkeypatch.setattr(oci, "EPOCH", recovery.EPOCH)
    labels, now = oci.candidate(tmp_path)
    monkeypatch.setattr(recovery, "expected_labels", lambda repo, revision: labels)
    for role in ("server", "host"):
        shutil.copyfile(tmp_path / f"{role}-1.tar", tmp_path / f"{role}-2.tar")
    first = recovery.inspect_oci_archive(tmp_path / "server-1.tar", label_profile="executable")
    sdk = {
        "schema_version": 1,
        "passed": True,
        "source_revision": recovery.PRODUCT,
        "e2b_version": "2.31.0",
        "archive_sha256": recovery.file_sha256(tmp_path / "server-1.tar"),
        "root_digest": archive_index_digest(tmp_path / "server-1.tar"),
        "platforms": [
            {
                "platform": platform,
                **{key: row[key] for key in ("config_digest", "manifest_digest")},
            }
            for platform, row in sorted(first["platforms"].items())
        ],
    }
    oci.write_json(tmp_path / "server-candidate-runtime.json", sdk)
    (tmp_path / "server-regressions.junit.xml").write_text(
        "<testsuites><testsuite>"
        + "<testcase/>" * 8192
        + "<testcase><skipped/></testcase>" * 38
        + "</testsuite></testsuites>"
    )
    return tmp_path, labels, now


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "second-host-bytes",
        "second-server-missing",
        "comparison",
        "sdk-source",
        "sdk-platform",
        "sdk-sha",
        "junit-fail",
        "junit-missing",
    ],
)
def test_all_four_original_archives_sdk_and_regressions_are_reused(original_files, fault):
    root, _, _ = original_files
    if fault == "second-host-bytes":
        (root / "host-2.tar").write_bytes(b"not OCI")
    if fault == "second-server-missing":
        (root / "server-2.tar").unlink()
    if fault in {"comparison", "sdk-source", "sdk-platform", "sdk-sha"}:
        path = root / (
            "saas-image-candidate.json"
            if fault == "comparison"
            else "server-candidate-runtime.json"
        )
        value = json.loads(path.read_text())
        if fault == "comparison":
            value["product_revision"] = "b" * 40
        if fault == "sdk-source":
            value["source_revision"] = "b" * 40
        if fault == "sdk-platform":
            value["platforms"].pop()
        if fault == "sdk-sha":
            value["archive_sha256"] = "a" * 64
        oci.write_json(path, value)
    if fault == "junit-fail":
        path = root / "server-regressions.junit.xml"
        path.write_text(
            path.read_text().replace("<testcase/>", "<testcase><failure/></testcase>", 1)
        )
    if fault == "junit-missing":
        (root / "server-regressions.junit.xml").unlink()
    if fault:
        with pytest.raises((ValueError, OSError, tarfile.ReadError, recovery.zipfile.BadZipFile)):
            recovery.verify_original_files(root, all_four=True)
    else:
        evidence = recovery.verify_original_files(root, all_four=True)
        assert set(evidence["archives"]) == recovery.ARCHIVES
        assert evidence["regressions"] == {"total": 8230, "skipped": 38, "failed": 0}


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "failed-run",
        "parent-as-producer",
        "wrong-path",
        "wrong-head",
        "missing-scan",
        "fake-build",
        "duplicate-scan",
    ],
)
def test_successful_recovery_has_its_own_actual_jobs(fault):
    controller = "c" * 40
    run = {
        "id": 71,
        "head_sha": controller,
        "head_branch": "main",
        "event": "workflow_dispatch",
        "path": recovery.WORKFLOW,
        "run_attempt": 1,
        "status": "completed",
        "conclusion": "success",
        "repository": {"full_name": recovery.REPOSITORY},
    }
    jobs = [
        job(81, "retain-original-four", run_id=71, controller=controller),
        job(82, "scan-and-admit-main22", run_id=71, controller=controller),
    ]
    if fault == "failed-run":
        run["conclusion"] = "failure"
    if fault == "parent-as-producer":
        run["id"] = recovery.PARENT["run_id"]
    if fault == "wrong-path":
        run["path"] = recovery.SOURCE_WORKFLOW
    if fault == "wrong-head":
        run["head_sha"] = recovery.PRODUCT
    if fault == "missing-scan":
        jobs.pop()
    if fault == "fake-build":
        jobs[0]["name"] = "build-candidate"
    if fault == "duplicate-scan":
        jobs.append(jobs[-1])
    if fault:
        with pytest.raises(ValueError):
            recovery.recovered_run(run, jobs, controller, completed=True)
    else:
        assert set(recovery.recovered_run(run, jobs, controller, completed=True)) == {
            "retain-original-four",
            "scan-and-admit-main22",
        }


@pytest.mark.parametrize("fault", [None, "runtime", "unregistered", "delete", "rename", "empty"])
def test_controller_skip_is_finite_and_fail_closed(fault):
    changes = {recovery.WORKFLOW: "A", "saas/scripts/main22_retained_recovery.py": "A"}
    registered = set(changes)
    if fault == "runtime":
        changes["omnigent/server/routers/hosts.py"] = "M"
        registered = set(changes)
    if fault == "unregistered":
        changes["saas/scripts/unreviewed.py"] = "A"
    if fault == "delete":
        changes[recovery.WORKFLOW] = "D"
    if fault == "rename":
        changes[recovery.WORKFLOW] = "R100"
    if fault == "empty":
        changes.clear()
        registered.clear()
    if fault:
        with pytest.raises(ValueError):
            recovery.validate_control_changes(changes, registered)
    else:
        recovery.validate_control_changes(changes, registered)


def test_exact_profile_is_opt_in_and_original_defaults_are_preserved():
    previous = promotion.PROFILE
    try:
        promotion.configure_product_profile(recovery.PROFILE)
        assert (promotion.PRODUCT, promotion.EPOCH) == (recovery.PRODUCT, recovery.EPOCH)
        assert promotion._current_scan_product() and not promotion._m8c()
        with pytest.raises(ValueError):
            promotion.configure_product_profile("Main22")
        promotion.configure_product_profile("M165")
        assert promotion.PRODUCT == promotion.recovery.PRODUCT
        assert not promotion._current_scan_product()
    finally:
        promotion.configure_product_profile(previous)


def test_recovery_never_builds_and_publisher_keeps_protected_oidc():
    root = Path(__file__).resolve().parents[2]
    text = (root / recovery.WORKFLOW).read_text()
    workflow = yaml.safe_load(text)
    assert set(workflow["jobs"]) == {
        "verify-contract",
        "retain-original-four",
        "scan-and-admit-main22",
    }
    assert "docker build" not in text and "buildx" not in text
    assert "retention-days: 30" in text
    publisher = yaml.safe_load((root / promotion.WORKFLOW).read_text())
    assert publisher["jobs"]["publish-signed"]["environment"] == "production-image"
    assert publisher["jobs"]["publish-signed"]["permissions"]["id-token"] == "write"
    assert "verify-published-source" in publisher["jobs"]


def test_retained_seal_validates_normal_scans_and_original_bytes(original_files, monkeypatch):
    root, labels, now = original_files
    retained = recovery.verify_original_files(root, all_four=True)
    origin = {"recovery_profile": recovery.PROFILE, "retained_bytes": retained}
    oci.write_json(root / recovery.ORIGIN, origin)
    monkeypatch.setattr(recovery, "native_origin", lambda: {"recovery_profile": recovery.PROFILE})
    manifest = seal_candidate(root, labels=labels, source_date_epoch=recovery.EPOCH, now=now)
    oci.write_json(root / MANIFEST_NAME, manifest)
    scan_job = {"started_at": now.isoformat(), "completed_at": datetime.now(UTC).isoformat()}
    assert recovery.report_binding(root, scan_job) == manifest
    changed = copy.deepcopy(manifest)
    changed["images"]["host"]["archive_sha256"] = "0" * 64
    oci.write_json(root / MANIFEST_NAME, changed)
    with pytest.raises(ValueError):
        recovery.report_binding(root, scan_job)


def test_original_native_zip_rejects_crc_or_digest_mismatch(tmp_path, monkeypatch):
    archive = tmp_path / "native.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("evidence.json", "{}")
    metadata = {"id": 1, "size_in_bytes": archive.stat().st_size, "digest": "sha256:" + "0" * 64}

    def download(identifier, destination, **kwargs):
        shutil.copyfile(archive, destination)

    monkeypatch.setattr(recovery, "download_artifact_bytes", download)
    with pytest.raises(ValueError, match="digest"):
        recovery.transfer(metadata, tmp_path / "output")


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "extended-cap",
        "parent-pass",
        "root-as-source",
        "rebuilt",
        "old-mode",
        "old-core",
        "scan-failed",
    ],
)
def test_split_binding_keeps_original_clocks_source_and_failures(parent, fault, monkeypatch):
    run, jobs, raw, report = parent
    origin = recovery.validate_parent(run, jobs, raw, report)
    core = {
        path: {**run, "id": identifier, "path": path, "conclusion": "success"}
        for identifier, path in recovery.CORE.items()
    }
    controller = "c" * 40
    native = {
        **run,
        "id": 71,
        "head_sha": controller,
        "path": recovery.WORKFLOW,
        "event": "workflow_dispatch",
        "conclusion": "success",
    }
    value = {
        "schema_version": 1,
        "repository": recovery.REPOSITORY,
        "recovery_profile": recovery.PROFILE,
        "producer_binding_mode": recovery.MODE,
        "product_revision": recovery.PRODUCT,
        "product_tree": recovery.TREE,
        "source_date_epoch": recovery.EPOCH,
        "candidate_run_id": 71,
        "candidate_run_attempt": 1,
        "parent_raw_checkpoint": recovery.PARENT,
        "candidate_controller_revision": controller,
        "rebuilt": False,
        "signing_rebuilt_oci": False,
        "production_authority": False,
        "native_run": native,
        "candidate_build_job_id": 81,
        "native_builder_job": job(81, "retain-original-four", run_id=71, controller=controller),
        "native_scan_job": job(82, "scan-and-admit-main22", run_id=71, controller=controller),
        "recovery_source_qualification": {
            "recovery_profile": recovery.PROFILE,
            "producer_binding_mode": recovery.MODE,
            "product_revision": recovery.PRODUCT,
            "product_tree": recovery.TREE,
            "failed_parent": origin,
            "original_Main_CI": core,
            "hard_caps": recovery.hard_caps(origin, core),
            "source_thread": recovery.SOURCE_THREAD,
            "source_actor_handoff_sha256": recovery.HANDOFF,
        },
    }
    qualification = value["recovery_source_qualification"]
    if fault == "extended-cap":
        qualification["hard_caps"] = {
            key: (recovery.instant(stamp) + timedelta(hours=24)).isoformat()
            for key, stamp in qualification["hard_caps"].items()
        }
    if fault == "parent-pass":
        qualification["failed_parent"]["native_run"]["conclusion"] = "success"
    if fault == "root-as-source":
        qualification["source_thread"] = "01a1db4c-a4d7-7693-96b6-af294b9aed8b"
    if fault == "rebuilt":
        value["rebuilt"] = True
    if fault == "old-mode":
        value["producer_binding_mode"] = "fixed-main16-ci-only"
    if fault == "old-core":
        qualification["original_Main_CI"][next(iter(core))]["id"] = 1
    if fault == "scan-failed":
        value["native_scan_job"]["conclusion"] = "failure"
    if fault:
        with pytest.raises(ValueError):
            recovery.validate_binding(value, 71)
    else:
        recovery.validate_binding(value, 71)


def test_original_evidence_cap_expires_without_refreshing(parent, monkeypatch):
    run, jobs, raw, report = parent
    origin = recovery.validate_parent(run, jobs, raw, report)
    core = {"ci": run}
    cap = recovery.hard_caps(origin, core)["effective_not_after"]

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return recovery.instant(cap)

    monkeypatch.setattr(recovery, "datetime", Clock)
    with pytest.raises(ValueError, match="expired"):
        recovery.hard_caps(origin, core)
