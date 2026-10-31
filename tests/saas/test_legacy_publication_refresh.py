"""35-day same-OCI preparation path; native APIs/transfers/scanner are mock boundaries."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import shutil
import subprocess
import sys
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from saas.scripts import legacy_initial_publisher as publisher
from saas.scripts.oci_promotion import expected_labels, verify_candidate
from tests.saas import test_oci_promotion as oci
from tests.saas.test_legacy_build_controller import product as product
from tests.saas.test_legacy_initial_publisher import publication_data as publication_data


@pytest.fixture
def old_material(request, monkeypatch):
    # Every Git commit below belongs to the temporary test fixture.
    monkeypatch.setenv("GIT_AUTHOR_DATE", "2026-08-01T00:00:00Z")
    monkeypatch.setenv("GIT_COMMITTER_DATE", "2026-08-01T00:00:00Z")
    source, profile = request.getfixturevalue("product")
    # Static metadata matches the existing executable OCI fixture labels.
    metadata = {
        "saas/upstream-baseline.json": {
            "upstream_revision": "u" * 40,
            "adapter_contract_version": "adapter-v1",
        },
        "saas/production/baseline.json": {
            "revision_contract": {"control_plane_schema_revision": "p0s000000003"}
        },
    }
    for name, value in metadata.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))
    (source / "uv.toml").write_bytes(b'prerelease="if-necessary"\n')

    def git(*args):
        return subprocess.check_output(["git", *args], cwd=source, text=True).strip()

    git("add", ".")
    git("commit", "-qm", "fixture owned baseline label metadata")
    profile["baseline_revision"] = git("rev-parse", "HEAD")
    (source / "uv.toml").write_bytes(b'prerelease="if-necessary"\nresolution="lowest-direct"\n')
    git("add", "uv.toml")
    git("commit", "-qm", "fixture owned material transition")
    profile.update(
        product_revision=git("rev-parse", "HEAD"), product_tree=git("rev-parse", "HEAD^{tree}")
    )
    data = request.getfixturevalue("publication_data")
    # Restore the real static metadata parser overridden by the reused fixture.
    monkeypatch.setattr(publisher, "expected_labels", expected_labels)
    now = datetime.now(UTC)
    old = now - timedelta(days=35)
    oci.refresh_scan_time(data["candidate"], old)
    labels = expected_labels(source, profile["product_revision"])
    manifest = oci.seal(data["candidate"], labels, old)
    oci.write_json(data["candidate"] / "oci-promotion-manifest.json", manifest)
    with zipfile.ZipFile(data["archive"], "w", compression=zipfile.ZIP_STORED) as bundle:
        for item in sorted(data["candidate"].rglob("*")):
            if item.is_file() and "-layout" not in str(item.relative_to(data["candidate"])):
                bundle.write(item, str(item.relative_to(data["candidate"])))
    coordinate = data["admission"]["original_pr_oci"]
    coordinate.update(
        zip_size=data["archive"].stat().st_size,
        zip_sha256=publisher.file_sha256(data["archive"]),
        seal_sha256=publisher.file_sha256(data["candidate"] / "oci-promotion-manifest.json"),
    )
    data.update(manifest=manifest, old=old, now=now, labels=labels)
    return data


def native_original(data, destination, monkeypatch, *, expired=False):
    """Use the complete original collector; mock authenticated network/process boundaries."""
    profile, original = data["profile"], data["admission"]["original_pr_oci"]
    transfer = data["admission"]["transfer_profile"]
    workflow = b"fixture exact candidate workflow bytes\n"
    transfer["workflow_sha256"] = hashlib.sha256(workflow).hexdigest()
    original["workflow_sha256"] = transfer["workflow_sha256"]
    control = destination / "control"
    records = {
        "legacy-security-build-profiles.json": ("profiles", profile),
        "legacy-security-transfer-profiles.json": ("profiles", transfer),
        "legacy-security-original-inputs.json": (
            "inputs",
            {
                **{key: profile[key] for key in ("component", "product_revision", "product_tree")},
                "original_pr_oci": {
                    key: original[key]
                    for key in (
                        "run_id",
                        "attempt",
                        "artifact_id",
                        "zip_size",
                        "zip_sha256",
                        "seal_sha256",
                    )
                },
            },
        ),
    }
    for name, (key, value) in records.items():
        path = control / "saas/supply_chain" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"schema_version": 1, key: {"Core": value}}))
    repository = {"full_name": publisher.REPOSITORY}
    api_url = "https://api.github.com/repos/" + publisher.REPOSITORY
    head = {"sha": profile["product_revision"], "ref": "fixture-source", "repo": repository}
    base = {"sha": profile["baseline_revision"], "ref": transfer["base_ref"], "repo": repository}
    pull = {
        "number": transfer["pull_number"],
        "state": "open",
        "draft": False,
        "merge_commit_sha": original["merge_revision"],
        "head": head,
        "base": base,
    }
    commit = {
        "sha": original["merge_revision"],
        "tree": {"sha": profile["product_tree"]},
        "parents": [{"sha": base["sha"]}, {"sha": head["sha"]}],
    }
    association = {
        "number": transfer["pull_number"],
        "url": f"{api_url}/pulls/{transfer['pull_number']}",
        "head": {"sha": head["sha"], "repo": {"url": api_url}},
        "base": {"sha": base["sha"], "repo": {"url": api_url}},
    }
    run = {
        "id": original["run_id"],
        "run_attempt": original["attempt"],
        "head_sha": profile["product_revision"],
        "head_branch": head["ref"],
        "event": "pull_request",
        "path": original["workflow_path"],
        "repository": repository,
        "head_repository": repository,
        "status": "completed",
        "conclusion": "success",
        "pull_requests": [association],
        "actor": {"login": transfer["actor"]},
        "triggering_actor": {"login": transfer["actor"]},
    }
    collector = publisher.download_original_oci.__globals__["collect_native_pr_oci"]
    verifier = collector.__globals__["verify_pr_oci_artifact"]
    step_names = verifier.__globals__["_REQUIRED_STEPS"]
    steps = []
    for number, name in enumerate(step_names, 1):
        start = data["old"] + timedelta(minutes=number)
        steps.append(
            {
                "number": number,
                "name": name,
                "status": "completed",
                "conclusion": "success",
                "started_at": start.isoformat(),
                "completed_at": (start + timedelta(seconds=20)).isoformat(),
            }
        )
    job = {
        "id": original["job_id"],
        "name": "build-candidate",
        "run_id": run["id"],
        "run_attempt": run["run_attempt"],
        "head_sha": profile["product_revision"],
        "status": "completed",
        "conclusion": "success",
        "runner_group_name": "GitHub Actions",
        "labels": ["ubuntu-latest"],
        "steps": steps,
    }
    metadata = {
        "id": original["artifact_id"],
        "expired": expired,
        "name": (
            f"legacy-validation-oci-Core-{profile['product_revision']}-"
            f"{run['id']}-{run['run_attempt']}"
        ),
        "size_in_bytes": original["zip_size"],
        "digest": "sha256:" + original["zip_sha256"],
        "workflow_run": {"id": run["id"], "head_sha": profile["product_revision"]},
        "created_at": steps[-1]["started_at"],
    }
    calls = []

    def api(endpoint):
        calls.append(endpoint)
        if "/pulls/" in endpoint:
            return copy.deepcopy(pull)
        if "/git/commits/" in endpoint:
            return copy.deepcopy(commit)
        if "/contents/" in endpoint:
            return {
                "path": original["workflow_path"],
                "encoding": "base64",
                "size": len(workflow),
                "content": base64.b64encode(workflow).decode(),
            }
        if "/jobs?" in endpoint:
            return {"jobs": [copy.deepcopy(job)], "total_count": 1}
        if "/actions/jobs/" in endpoint:
            return copy.deepcopy(job)
        if "/artifacts/" in endpoint:
            return copy.deepcopy(metadata)
        if "/actions/runs/" in endpoint:
            return copy.deepcopy(run)
        raise AssertionError(endpoint)

    monkeypatch.setitem(publisher.api.__globals__, "_native_api", api)
    checkout = verifier.__globals__["checkout_commit"]
    pin = checkout.__globals__["CHECKOUT_REVISION"]
    time = steps[0]["started_at"]
    log = (
        f"{time} ##[group]Run actions/checkout@{pin}\n{time} [command]git log -1 --format=%H\n"
        f"{time} {profile['product_revision']}\n"
    ).encode()
    popen = subprocess.Popen

    def spawn(arguments, **kwargs):
        if arguments[:2] == ["gh", "api"]:
            endpoint = arguments[2]
            if endpoint.endswith("/logs"):
                command = "import os;os.write(1," + repr(log) + ")"
            else:
                assert endpoint.endswith(f"/artifacts/{original['artifact_id']}/zip")
                command = "import sys;sys.stdout.buffer.write(open(sys.argv[1],'rb').read())"
            return popen([sys.executable, "-c", command, str(data["archive"])], **kwargs)
        return popen(arguments, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", spawn)
    return control, calls


@pytest.mark.parametrize("fault", [None, "expired", "stale_new_DB", "high", "different_OCI"])
def test_native_original_to_actual_producer_prepare_after_35_days(
    old_material, tmp_path, monkeypatch, fault
):
    data = old_material
    original = copy.deepcopy(data["admission"]["original_pr_oci"])
    control, calls = native_original(
        data, tmp_path / "native", monkeypatch, expired=fault == "expired"
    )
    if fault == "expired":
        with pytest.raises(ValueError, match="artifact"):
            publisher.collect_original_input(control, data["profile"], tmp_path / "original")
        return
    observed = publisher.collect_original_input(control, data["profile"], tmp_path / "original")
    # Workflow hash belongs to mocked network identity, not the immutable candidate seal.
    original["workflow_sha256"] = observed["workflow_sha256"]
    assert observed == original
    assert any("/attempts/2" in endpoint for endpoint in calls)
    root = tmp_path / "transferred"
    publisher.unpack_original(tmp_path / "original/download/original-oci.zip", observed, root)
    before = {
        name: publisher.file_sha256(root / name)
        for name in ("server-1.tar", "host-1.tar", "oci-promotion-manifest.json")
    }
    with pytest.raises(ValueError, match="older than 24 hours"):
        verify_candidate(
            root,
            manifest_sha256=observed["seal_sha256"],
            labels=data["labels"],
            source_date_epoch=data["profile"]["source_date_epoch"],
        )
    run = subprocess.run
    scanner_calls = []

    def scanner(arguments, **kwargs):
        if "saas.scripts.scan_oci_candidates" not in arguments:
            return run(arguments, **kwargs)
        scanner_calls.append(arguments)
        target = Path(arguments[arguments.index("--output") + 1]).parent
        shutil.copytree(root / "grype", target / "grype")
        oci.refresh_scan_time(
            target, data["old"] if fault == "stale_new_DB" else datetime.now(UTC)
        )
        path = target / "grype/server-amd64-grype.json"
        raw = json.loads(path.read_text())
        if fault == "high":
            raw["matches"] = [{"vulnerability": {"id": "fixture-high", "severity": "High"}}]
        if fault == "different_OCI":
            raw["source"]["target"]["imageID"] = "sha256:" + "0" * 64
        oci.write_json(path, raw)
        summary_path = target / "grype/candidate-scan-summary.json"
        summary = json.loads(summary_path.read_text())
        summary["images"][0]["report_sha256"] = publisher.file_sha256(path)
        oci.write_json(summary_path, summary)
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(subprocess, "run", scanner)
    arguments = (control, root, data["admission"], data["source"], tmp_path / "preparation")
    if fault:
        with pytest.raises(ValueError):
            publisher.prepare_current_manifest(*arguments)
    else:
        actual = publisher.prepare_current_manifest(*arguments)
        assert actual == data["manifest"]
        assert publisher.image_references(data["admission"], actual) == publisher.image_references(
            data["admission"], data["manifest"]
        )
    assert len(scanner_calls) == 1
    assert before == {name: publisher.file_sha256(root / name) for name in before}
    assert (
        data["profile"]["product_revision"]
        == data["admission"]["fresh_control_wheel"]["product_revision"]
    )
    assert (
        publisher.file_sha256(data["wheel"])
        == data["admission"]["fresh_control_wheel"]["wheel_sha256"]
    )
