"""Reuse the original native operator's identity and isolation refusal cases."""

import copy
import hashlib
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
import yaml

from saas.scripts.observe_arm64_startup import validate_imported_image, validate_native
from tests.saas.test_compat018_recovered_input import m, recovery
from tests.saas.test_compat018_recovered_input import native_origin as native_origin

ROOT = Path(__file__).resolve().parents[2]
SUPPORT = ROOT / "saas/supply_chain/compat018-startup-diagnostic"
BINDINGS = json.loads((SUPPORT / "bindings.json").read_text())


@pytest.mark.parametrize("fault", [None, "descriptor", "id", "layers"])
def test_docker_identity_checks_descriptor_id_and_layers_independently(fault):
    selected = {"manifest_digest": "sha256:" + "a" * 64, "rootfs_diff_ids": ["sha256:" + "b" * 64]}
    actual = {
        "Descriptor": {"digest": selected["manifest_digest"]},
        "Id": selected["manifest_digest"],
        "RootFS": {"Layers": selected["rootfs_diff_ids"]},
    }
    if fault == "descriptor":
        actual["Descriptor"]["digest"] = "sha256:" + "c" * 64
    elif fault == "id":
        actual["Id"] = "sha256:" + "c" * 64
    elif fault == "layers":
        actual["RootFS"]["Layers"] = []
    if fault is None:
        validate_imported_image(actual, selected)
    else:
        with pytest.raises(ValueError, match=r"differs|differ"):
            validate_imported_image(actual, selected)


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "source",
        "platform",
        "libc",
        "installed_files",
        "uid",
        "roles",
        "duplicate_role",
        "locale",
        "encoding",
        "controls",
        "mocked",
        "lifecycle",
        "High",
        "expiry",
    ],
)
def test_native_observation_is_component_only_and_exactly_bound(fault):
    native = {
        "kind": "installed-production-startup-locale/v1",
        "source_revision": BINDINGS["source_revision"],
        "platform": "linux/arm64",
        "actual_loaded_libc": {"sha256": BINDINGS["libc_sha256"]},
        "installed_files": copy.deepcopy(BINDINGS["installed_files"]),
        "uid": 1000,
        "gid": 1000,
        "mocked_exec": False,
        "production_source_modified": False,
        "whole_service_lifecycle_qualified": False,
        "High_disposition": False,
        "expires_at": "2026-11-11T10:40:00Z",
        "actual_controls": {
            "no_new_privileges": True,
            "all_capabilities_empty": True,
            "rootfs_readonly": True,
            "interfaces": ["lo"],
            "non_loopback_routes": 0,
        },
        "entries": [
            {
                "role": role,
                "effective_LC_MESSAGES": "C.UTF-8",
                "effective_encoding": "UTF-8",
                "five_locale_inputs": {
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "LC_MESSAGES": "C.UTF-8",
                    "LANGUAGE": None,
                    "LOCPATH": None,
                },
            }
            for role in (
                "server",
                "worker",
                "runner_control",
                "runner_agent",
                "preview_edge",
                "preview_owner",
            )
        ],
    }
    if fault in {"source", "platform", "uid", "expiry"}:
        native[
            {
                "source": "source_revision",
                "platform": "platform",
                "uid": "uid",
                "expiry": "expires_at",
            }[fault]
        ] = "wrong"
    elif fault == "libc":
        native["actual_loaded_libc"]["sha256"] = "a" * 64
    elif fault == "installed_files":
        native["installed_files"].pop(next(iter(native["installed_files"])))
    elif fault == "roles":
        native["entries"].pop()
    elif fault == "duplicate_role":
        native["entries"][-1] = copy.deepcopy(native["entries"][0])
    elif fault == "locale":
        native["entries"][0]["five_locale_inputs"]["LOCPATH"] = "/workspace/catalog"
    elif fault == "encoding":
        native["entries"][0]["effective_encoding"] = "ASCII"
    elif fault == "controls":
        native["actual_controls"]["interfaces"].append("eth0")
    elif fault in {"mocked", "lifecycle", "High"}:
        native[
            {
                "mocked": "mocked_exec",
                "lifecycle": "whole_service_lifecycle_qualified",
                "High": "High_disposition",
            }[fault]
        ] = True
    if fault is None:
        validate_native(native, BINDINGS)
    else:
        with pytest.raises(ValueError, match="protected bindings"):
            validate_native(native, BINDINGS)


def test_local_interpreter_cannot_manufacture_native_image_proof():
    process = subprocess.run(
        [sys.executable, "-I", "-B", str(SUPPORT / "probe.py")],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert process.returncode != 0
    assert "requires actual Linux ARM64 userspace" in process.stderr or (
        "requires installed image virtualenv" in process.stderr
    )


def test_current_c2_native_operator_keeps_original_scope_and_probe_bytes():
    from saas.scripts.compat018_oci_recovery import registered_profile

    assert BINDINGS["source_revision"] == registered_profile()["product_revision"]
    assert len(BINDINGS["installed_files"]) == 24
    assert hashlib.sha256((SUPPORT / "probe.py").read_bytes()).hexdigest() == (
        "26b946d4c38c84a440dd919d73d595f6825da9bc30b8a222e547d96999192304"
    )
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/saas-compat018-oci-recovery.yml").read_text()
    )
    job = workflow["jobs"]["observe-registered-c2-arm64"]
    assert job["runs-on"] == "ubuntu-24.04-arm"
    assert job["permissions"] == {"contents": "read", "actions": "read"}
    assert "inputs.policy_revision == github.sha" in job["if"]
    assert "inputs.phase == 'observe-reviewed-arm64'" in job["if"]
    assert "setup-qemu" not in json.dumps(job)
    commands = "\n".join(step.get("run", "") for step in job["steps"])
    assert '--scan-run "$SCAN_RUN"' in commands
    assert 'test "$(uname -m)" = aarch64' in commands


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "extra",
        "duplicate",
        "profile",
        "proof",
        "archive",
        "source",
        "caller",
        "libc",
        "inventory-duplicate",
        "type",
        "manifest",
        "history",
    ],
)
def test_first_server_transport_binds_own_source_archive_and_installed_boundaries(
    tmp_path, monkeypatch, fault
):
    from saas.scripts import compat018_native_input as inputs
    from saas.scripts.compat018_oci_recovery import registered_profile

    profile = registered_profile()
    image = b"synthetic OCI bytes; actual tar audit is covered by original clean-context tests"
    selected = {
        "manifest_digest": "manifest",
        "config_digest": "config",
        "labels": {"org.opencontainers.image.revision": profile["product_revision"]},
    }
    facts = {"platforms": {"linux/arm64": selected}}
    inventory = [
        {"path": path, "type": "0", "sha256": digest}
        for path, digest in {
            **BINDINGS["installed_files"],
            "usr/lib/libc.so.6": BINDINGS["libc_sha256"],
        }.items()
    ]
    first = {
        "kind": "registered_compat018_first_pair_actual_source_facts/v1",
        **{key: profile[key] for key in ("product_revision", "product_tree", "source_date_epoch")},
        "profile_sha256": hashlib.sha256(
            json.dumps(profile, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest(),
        "historical_4e_byte_identity_claimed": False,
        "independent_rebuild_or_runtime_or_High_or_signature_qualified": False,
        "images": {
            "server": {
                "archive_sha256": hashlib.sha256(image).hexdigest(),
                "facts": copy.deepcopy(facts),
                "targets": {
                    "linux/arm64": {
                        "manifest_digest": "manifest",
                        "config_digest": "config",
                        "installed_component_inventory": inventory,
                    }
                },
            }
        },
    }
    if fault == "proof":
        first["product_revision"] = "4e11681dd3809febeb42cb5d752d423b5f751f82"
    if fault == "archive":
        image += b"changed"
    if fault == "source":
        selected["labels"]["org.opencontainers.image.revision"] = "0" * 40
    if fault == "caller":
        inventory[0]["sha256"] = "0" * 64
    if fault == "libc":
        inventory[-1]["sha256"] = "0" * 64
    if fault == "inventory-duplicate":
        inventory.append(copy.deepcopy(inventory[0]))
    if fault == "type":
        inventory[0]["type"] = "2"
    if fault == "manifest":
        first["images"]["server"]["targets"]["linux/arm64"]["manifest_digest"] = "other"
    if fault == "history":
        first["historical_4e_byte_identity_claimed"] = True
    bodies = {
        "server-1.tar": image,
        "registered-source-profile.json": json.dumps(
            {} if fault == "profile" else profile
        ).encode(),
        "reviewed-subject-image-facts.json": json.dumps(first).encode(),
    }
    archive = tmp_path / "first.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        for name, body in bodies.items():
            bundle.writestr(name, body)
        if fault == "extra":
            bundle.writestr("../outside", b"rejected")
        if fault == "duplicate":
            bundle.writestr("server-1.tar", image)
    output = tmp_path / "received"
    output.mkdir()
    monkeypatch.setattr(inputs, "inspect_oci_archive", lambda *_a, **_kw: copy.deepcopy(facts))
    if fault:
        with pytest.raises(ValueError):
            inputs.first_payload(archive, output, profile, BINDINGS)
    else:
        actual = inputs.first_payload(archive, output, profile, BINDINGS)
        assert actual.read_bytes() == image


@pytest.mark.parametrize("fault", [None, "manifest", "config", "missing", "duplicate", "matches"])
def test_original_arm_raw_report_keeps_actual_target_and_transport_identity(tmp_path, fault):
    from saas.scripts.compat018_native_input import scan_report

    target = {"manifest_digest": "manifest", "config_digest": "config"}
    report = {
        "source": {"target": {"manifestDigest": "manifest", "imageID": "config"}},
        "matches": [],
    }
    if fault in {"manifest", "config"}:
        report["source"]["target"]["manifestDigest" if fault == "manifest" else "imageID"] = (
            "other"
        )
    if fault == "matches":
        report.pop("matches")
    archive = tmp_path / "scan.zip"
    raw = json.dumps(report).encode()
    with zipfile.ZipFile(archive, "w") as bundle:
        name = "other.json" if fault == "missing" else "grype/server-arm64-grype.json"
        bundle.writestr(name, raw)
        if fault == "duplicate":
            bundle.writestr(name, raw)
    if fault:
        with pytest.raises(ValueError):
            scan_report(archive, target)
    else:
        assert scan_report(archive, target) == raw


@pytest.mark.parametrize("native_origin", [True], indirect=True)
@pytest.mark.parametrize(
    "fault",
    [
        None,
        "rejected-scan",
        "first-source",
        "expired",
        "upload-time",
        "scan-branch",
        "scan-download",
        "scan-runner",
        "scan-code",
        "report-target",
    ],
)
def test_native_input_derives_actual_original_transports_and_refuses_mixed_coordinates(
    native_origin, tmp_path, monkeypatch, fault
):
    from saas.scripts import compat018_native_input as inputs

    control, _archive, data, _calls, _downloaded, prefix = native_origin
    monkeypatch.setattr(inputs, "recovered", m)
    profile = recovery.registered_profile()
    support = control / "saas/supply_chain/compat018-startup-diagnostic"
    support.mkdir(parents=True)
    for path in SUPPORT.iterdir():
        shutil.copyfile(path, support / path.name)
    raw_job = data[prefix + "jobs/301"]
    upload = "Retain the audited first Server for the existing native startup operator"
    raw_job["steps"].insert(3, {**raw_job["steps"][2], "name": upload})
    for number, step in enumerate(raw_job["steps"], 1):
        step["number"] = number
    first = tmp_path / "first-native.zip"
    first.write_bytes(b"native transport fixture; payload validator covered separately")
    first_meta = {
        **copy.deepcopy(data[prefix + "artifacts/501"]),
        "id": 504,
        "name": f"compat018-native-startup-{profile['product_revision']}-101",
        "size_in_bytes": first.stat().st_size,
        "digest": "sha256:" + hashlib.sha256(first.read_bytes()).hexdigest(),
    }
    if fault == "first-source":
        first_meta["name"] = first_meta["name"].replace(
            profile["product_revision"], recovery.PRODUCT
        )
    if fault == "expired":
        first_meta["expired"] = True
    if fault == "upload-time":
        first_meta["created_at"] = "2026-11-08T10:10:00Z"
    data[prefix + "artifacts/504"] = first_meta
    scan_job = data[prefix + "jobs/302"]
    scan_job["steps"].append(
        {
            **scan_job["steps"][-1],
            "number": 4,
            "name": "Preserve raw rejection and original checkpoint on every outcome",
        }
    )
    if fault == "rejected-scan":
        scan_job["conclusion"] = "failure"
        scan_job["steps"][1]["conclusion"] = "failure"
        data[prefix + "runs/202"]["conclusion"] = "failure"
    if fault == "scan-branch":
        data[prefix + "runs/202"]["head_branch"] = "other"
    if fault == "scan-download":
        scan_job["steps"][0]["conclusion"] = "skipped"
    if fault == "scan-runner":
        scan_job["labels"].append("self-hosted")
    if fault == "scan-code":
        (control / m.SOURCES[0]).write_text("foreign scanner source")
    scan_zip = tmp_path / "original-scan.zip"
    with zipfile.ZipFile(scan_zip, "w") as bundle:
        bundle.writestr(
            "grype/server-arm64-grype.json",
            json.dumps(
                {
                    "source": {
                        "target": {
                            "manifestDigest": "other" if fault == "report-target" else "manifest",
                            "imageID": "config",
                        }
                    },
                    "matches": [],
                }
            ),
        )
    scan_meta = {
        **copy.deepcopy(data[prefix + "artifacts/502"]),
        "id": 505,
        "name": "compat018-same-oci-scan-202",
        "size_in_bytes": scan_zip.stat().st_size,
        "digest": "sha256:" + hashlib.sha256(scan_zip.read_bytes()).hexdigest(),
    }
    data[prefix + "artifacts/505"] = scan_meta
    data[prefix + "runs/202/artifacts?per_page=100"] = {
        "total_count": 2,
        "artifacts": [data[prefix + "artifacts/502"], scan_meta],
    }
    downloaded = []

    def download(artifact, path, *, expected_size, expected_sha256):
        source = {504: first, 505: scan_zip}[artifact]
        assert source.stat().st_size == expected_size
        assert hashlib.sha256(source.read_bytes()).hexdigest() == expected_sha256
        downloaded.append(artifact)
        shutil.copyfile(source, path)

    monkeypatch.setattr(inputs, "download_artifact_bytes", download)

    def payload(archive, output, actual_profile, bindings):
        assert actual_profile == profile and bindings == BINDINGS
        image = output / "server-1.tar"
        image.write_bytes(b"actual first payload validator is exercised independently")
        return image

    monkeypatch.setattr(inputs, "first_payload", payload)
    monkeypatch.setattr(
        inputs,
        "inspect_oci_archive",
        lambda *_a, **_kw: {
            "platforms": {
                "linux/arm64": {"manifest_digest": "manifest", "config_digest": "config"}
            }
        },
    )
    kwargs = {
        "source_revision": profile["product_revision"],
        "raw_run_id": 101,
        "first_artifact_id": 504,
        "scan_run_id": 202,
        "output": tmp_path / "native-input",
    }
    if fault not in {None, "rejected-scan"}:
        with pytest.raises(ValueError):
            inputs.prepare_startup_input(control, **kwargs)
    else:
        bindings, run, artifact, sha, image, raw, actual_support = inputs.prepare_startup_input(
            control, **kwargs
        )
        assert bindings == BINDINGS and run["id"] == 101 and artifact["id"] == 504
        assert downloaded == [504, 505] and sha == first_meta["digest"][7:]
        assert actual_support == support and image.exists()
        assert hashlib.sha256(raw).hexdigest() == recovery.sha256(
            kwargs["output"] / "original-arm64-grype.PUBLIC.json"
        )
        receipt = json.loads((kwargs["output"] / "native-input-origin.PUBLIC.json").read_text())
        assert receipt["startup_only"] is True
        assert receipt["High_disposition"] is receipt["full_image_or_lifecycle_qualified"] is False
