"""Local bytes/refusal tests; synthetic layers are not a qualified C2 image."""

import copy
import hashlib
import importlib
import importlib.util
import io
import json
import tarfile
from contextlib import contextmanager
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT


def load(name, filename):
    import sys

    spec = importlib.util.spec_from_file_location(name, ROOT / "saas/scripts" / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    setattr(importlib.import_module("saas.scripts"), name.rsplit(".", 1)[1], module)
    return module


recovery = load("saas.scripts.compat018_oci_recovery", "compat018_oci_recovery.py")
m = load("saas.scripts.compat018_clean_context", "compat018_clean_context.py")


def layer(mutation=None):
    entries = [
        ("build/source.py", b"print('fixed')\n", 0o755, None),
        ("build/alias", b"", 0o777, "source.py"),
    ]
    for base in ("build/", "build/build/lib/"):
        for prefix, names in (
            ("omnigent/server/static/web-ui/", ["index.html", "assets/main.js"]),
            (
                "saas/login_ui/static/",
                [
                    "login.html",
                    "signup.html",
                    "signup-verify.html",
                    "signup-status.html",
                ],
            ),
        ):
            for name in names:
                entries.append((base + prefix + name, name.encode(), 0o644, None))
    if mutation == "source":
        entries[0] = (entries[0][0], b"different", 0o755, None)
    elif mutation == "mode":
        entries[0] = (entries[0][0], entries[0][1], 0o644, None)
    elif mutation == "missing":
        entries = entries[1:]
    elif mutation == "link":
        entries[1] = (entries[1][0], b"", 0o777, "other.py")
    elif mutation == "duplicate":
        entries.append(entries[0])
    elif mutation == "ui-copy":
        name, _, mode, link = entries[-1]
        entries[-1] = (name, b"different UI", mode, link)
    elif mutation == "ui-special":
        name, _, mode, _ = entries[-1]
        entries[-1] = (name, b"", mode, "unexpected")
    elif mutation == "ui-entrypoint":
        entries = [row for row in entries if not row[0].endswith("/login.html")]
    return archive_entries(entries)


def archive_entries(entries):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w") as archive:
        for name, body, mode, link in entries:
            info = tarfile.TarInfo(name)
            info.mode = mode
            if link is not None:
                info.type = tarfile.SYMTYPE
                info.linkname = link
                archive.addfile(info)
            else:
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
    result.seek(0)
    return result


EXPECTED = {
    "source.py": ("100755", b"print('fixed')\n"),
    "alias": ("120000", b"source.py"),
}


@pytest.mark.parametrize("fault", [None, "caller", "libc", "labels", "manifest", "architecture"])
def test_registered_first_binds_own_four_targets_and_refuses_changed_installed_bytes(
    tmp_path, monkeypatch, fault
):
    import saas.scripts.issue_evidence_receipt as issuer
    import saas.scripts.oci_promotion as promotion
    import saas.scripts.protected_legacy_initial_build as profiles
    import saas.scripts.sqlite_component_disposition as components

    profile = {"product_revision": "8" * 40, "product_tree": "9" * 40, "source_date_epoch": 123}
    expected = {path: ("100644", (path + "\n").encode()) for path in m._NATIVE_BOUNDARIES}
    prefix = "opt/venv/lib/python3.12/site-packages/"
    inventory = [
        {"path": prefix + path, "type": "0", "sha256": hashlib.sha256(body).hexdigest()}
        for path, (_, body) in expected.items()
    ] + [{"path": "usr/lib/libc.so.6", "type": "0", "sha256": "a" * 64}]
    if fault == "caller":
        inventory[0]["sha256"] = "f" * 64
    elif fault == "libc":
        inventory.pop()
    labels = {"revision": profile["product_revision"]}
    platforms = {
        p: {"labels": labels, "manifest_digest": "manifest", "config_digest": "config"}
        for p in ("linux/amd64", "linux/arm64")
    }
    if fault == "labels":
        platforms["linux/amd64"]["labels"] = {"revision": recovery.PRODUCT}
    elif fault == "manifest":
        platforms["linux/amd64"]["manifest_digest"] = "another"
    elif fault == "architecture":
        platforms.pop("linux/arm64")

    class Blobs:
        def platform(self, platform):
            return "manifest", {
                "config": {"digest": "config"},
                "layers": [{"digest": "layer"}] * 15,
            }

        @contextmanager
        def blob(self, digest):
            yield io.BytesIO(b"existing audit boundary")

    @contextmanager
    def blobs(_archive):
        yield Blobs()

    from saas.scripts.protected_legacy_initial_build import load_profile

    monkeypatch.setitem(load_profile.__globals__, "load_profile", lambda *_: profile)
    monkeypatch.setattr(profiles, "load_profile", lambda *_: profile)
    verified = []
    monkeypatch.setattr(
        issuer,
        "registered_compatibility_receipt_repo",
        lambda control, repo, **kw: verified.append((control, repo, kw)),
    )
    monkeypatch.setattr(m, "source_inputs", lambda repo, **kw: expected)
    monkeypatch.setattr(promotion, "expected_labels", lambda *_: labels)
    monkeypatch.setattr(m, "inspect_oci_archive", lambda *_a, **_kw: {"platforms": platforms})
    monkeypatch.setattr(components, "image_blobs", blobs)
    monkeypatch.setattr(components, "component_inventory", lambda *_a, **_kw: inventory)
    monkeypatch.setattr(
        m, "verify_context_layer", lambda *_a, **_k: {"existing_Source_audit": True}
    )
    monkeypatch.setattr(m, "verify_host_install_layer", lambda *_a, **kw: kw)
    for role in ("server", "host"):
        (tmp_path / f"{role}-1.tar").write_bytes(b"synthetic unit fixture")
    if fault:
        with pytest.raises(ValueError):
            m.registered_first(tmp_path, REPO, ROOT)
        assert not (tmp_path / "reviewed-subject-image-facts.json").exists()
    else:
        result = m.registered_first(tmp_path, REPO, ROOT)
        assert verified == [(ROOT, REPO, {"product_revision": "8" * 40})]
        assert result["product_revision"] == profile["product_revision"]
        assert result["historical_4e_byte_identity_claimed"] is False
        assert result["independent_rebuild_or_runtime_or_High_or_signature_qualified"] is False
        assert all(len(row["targets"]) == 2 for row in result["images"].values())
        assert result["images"]["host"]["targets"]["linux/arm64"]["source_proof"] == {
            "revision": "8" * 40,
            "epoch": 123,
        }
        proof = tmp_path / "reviewed-subject-image-facts.json"
        proof.write_bytes(b"retained original producer proof")
        assert m.registered_first(tmp_path, REPO, ROOT, write=False) == result
        assert proof.read_bytes() == b"retained original producer proof"


@pytest.mark.parametrize(
    "fault", [None, "host", "runtime-layer", "labels", "history", "architecture", "host-layer"]
)
@pytest.mark.parametrize("paired_host", [False, True])
def test_first_requires_original_Host_and_only_Source_copy_layer_changes(
    tmp_path, monkeypatch, fault, paired_host
):
    platform = {
        "manifest_digest": "old-manifest",
        "config_digest": "old-config",
        "layers": [{"digest": "old"} for _ in range(15)],
        "rootfs_diff_ids": ["old"] * 15,
        "labels": copy.deepcopy(recovery.LABELS),
        "history": [{"created": "fixed"}],
    }
    architectures = {"linux/amd64", "linux/arm64"}
    facts = {
        "platforms": {arch: copy.deepcopy(platform) for arch in architectures},
        "attestations": dict.fromkeys(architectures, True),
        "attestation_descriptor_count": 2,
    }
    pair = {
        "first": copy.deepcopy(facts),
        "second": copy.deepcopy(facts),
        "matching_platform_manifest_and_config": True,
        "history_created_by_equal": True,
    }
    original = {
        "images": {f"omnigent-saas-{role}": copy.deepcopy(pair) for role in ("server", "host")}
    }
    actual = {role: copy.deepcopy(facts) for role in ("server", "host")}
    for value in actual["server"]["platforms"].values():
        value.update(manifest_digest="new-manifest", config_digest="new-config")
        value["layers"][3] = {"digest": "sha256:" + "a" * 64}
        value["rootfs_diff_ids"][3] = "new-source"
    if paired_host:
        for value in actual["host"]["platforms"].values():
            value.update(manifest_digest="new-host-manifest", config_digest="new-host-config")
            value["layers"][14] = {"digest": "sha256:" + "a" * 64}
            value["rootfs_diff_ids"][14] = "new-installed-source"
    server = actual["server"]["platforms"]["linux/amd64"]
    if fault == "host":
        actual["host"]["attestations"] = {}
    elif fault == "runtime-layer":
        server["layers"][0] = {"digest": "different-runtime"}
    elif fault == "labels":
        server["labels"] = {"source": "other"}
    elif fault == "history":
        server["history"] = []
    elif fault == "architecture":
        actual["server"]["platforms"].pop("linux/arm64")
    elif fault == "host-layer":
        actual["host"]["platforms"]["linux/amd64"]["layers"][0] = {"digest": "wrong-base"}
    monkeypatch.setattr(
        recovery, "original_evidence", lambda _path: (copy.deepcopy(original), {}, b"")
    )
    monkeypatch.setattr(
        m, "inspect_oci_archive", lambda path, **kwargs: actual[path.name.split("-")[0]]
    )
    monkeypatch.setattr(m, "source_inputs", lambda _repo: {})
    monkeypatch.setattr(
        m, "verify_context_layer", lambda _stream, _inputs: {"tracked_inputs": 1772}
    )
    monkeypatch.setattr(
        m, "verify_host_install_layer", lambda _stream, _inputs: {"runtime_Python_files": 1275}
    )
    for role in ("server", "host"):
        with tarfile.open(tmp_path / f"{role}-1.tar", "w") as bundle:
            member = tarfile.TarInfo("blobs/sha256/" + "a" * 64)
            member.size = 5
            bundle.addfile(member, io.BytesIO(b"layer"))
    if fault:
        with pytest.raises(ValueError):
            m.verify_first(tmp_path, REPO, paired_host=paired_host)
    else:
        result = m.verify_first(tmp_path, REPO, paired_host=paired_host)
        assert result["new_Host_matches_historical_independent_pair"] is (not paired_host)
        assert result["historical_Server_facts_equal"] is False
        assert set(result["source_proofs"]) == architectures
        if paired_host:
            assert set(result["Host_source_proofs"]) == architectures


def test_source_modes_symlink_and_actual_UI_copies():
    proof = m.verify_context_layer(layer(), EXPECTED)
    assert proof["tracked_inputs"] == 2
    assert proof["generated_UI"]["saas/login_ui/static/"]["files"] == 4


@pytest.mark.parametrize(
    "mutation",
    [
        "source",
        "mode",
        "missing",
        "link",
        "duplicate",
        "ui-copy",
        "ui-special",
        "ui-entrypoint",
    ],
)
def test_context_refuses_real_byte_mode_link_or_UI_mutation(mutation):
    with pytest.raises(ValueError):
        m.verify_context_layer(layer(mutation), EXPECTED)


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "source",
        "missing",
        "extra",
        "identity",
        "identity-code",
        "duplicate",
        "resource",
        "symlink",
    ],
)
def test_installed_Host_audit_binds_Git_and_rejects_code_or_identity_drift(fault):
    prefix = "opt/venv/lib/python3.12/site-packages/"
    identity = (
        '"""Auto-generated for an immutable Omnigent runtime image; do not edit."""\n'
        "from __future__ import annotations\n\n"
        f"BUILD_TIME_EPOCH: int = {recovery.EPOCH}\n"
        f"COMMIT_SHA: str = {recovery.PRODUCT!r}\n"
    ).encode()
    expected = {
        "omnigent/main.py": ("100644", b"fixed = True\n"),
        "saas/runtime.py": ("100644", b"binding = True\n"),
        "omnigent/data.json": ("100644", b"{}"),
        "saas/login_web/scripts/preview.py": ("100644", b"excluded by setuptools"),
    }
    entries = [
        (prefix + name, body, 0o644, None)
        for name, (_, body) in expected.items()
        if not name.startswith("saas/login_web/")
    ]
    entries.append((prefix + "omnigent/_build_info.py", identity, 0o644, None))
    if fault == "source":
        entries[0] = (entries[0][0], b"different = True", 0o644, None)
    elif fault == "missing":
        entries.pop(0)
    elif fault == "extra":
        entries.append((prefix + "saas/unregistered.py", b"unexpected", 0o644, None))
    elif fault in {"identity", "identity-code"}:
        body = (
            identity.replace(recovery.PRODUCT.encode(), b"a" * 40)
            if fault == "identity"
            else identity + b"raise RuntimeError('extra code')\n"
        )
        entries[-1] = (entries[-1][0], body, 0o644, None)
    elif fault == "duplicate":
        entries.append(entries[0])
    elif fault == "resource":
        entries[2] = (entries[2][0], b"changed", 0o644, None)
    elif fault == "symlink":
        entries[0] = (entries[0][0], b"", 0o777, "elsewhere.py")
    if fault:
        with pytest.raises(ValueError):
            m.verify_host_install_layer(archive_entries(entries), expected)
    else:
        result = m.verify_host_install_layer(archive_entries(entries), expected)
        assert result["runtime_Python_files"] == 2
        assert result["tracked_resources"] == 1
        assert result["build_identity"]["COMMIT_SHA"] == recovery.PRODUCT


@pytest.mark.parametrize(
    "fault", [None, "host-match", "host-history", "host-facts", "origin", "second-missing"]
)
def test_new_pair_requires_real_Host_second_and_retains_historical_record(
    first, monkeypatch, fault
):
    root, value, repeated = first
    value.update(kind=m.PAIR_KIND, new_Host_matches_historical_independent_pair=False)
    value["facts"]["host"] = {"test_fact": "new-Host"}
    monkeypatch.setattr(m, "first_for_profile", lambda *_a: copy.deepcopy(value))
    m.audit(root, REPO, m.PAIR_PROFILE)
    (root / "host-2.tar").write_bytes(b"actual fixture second Host, not an image")
    (root / "retained-first-native.json").write_text(json.dumps(recovery.RETAINED_FIRST))
    host = {
        "first": copy.deepcopy(value["facts"]["host"]),
        "matching_platform_manifest_and_config": True,
        "history_created_by_equal": True,
    }

    def compare(left, right, **kwargs):
        right.read_bytes()
        return copy.deepcopy(host if left.name.startswith("host-") else repeated)

    monkeypatch.setattr(m, "compare_archives", compare)
    if fault == "host-match":
        host["matching_platform_manifest_and_config"] = False
    elif fault == "host-history":
        host["history_created_by_equal"] = False
    elif fault == "host-facts":
        host["first"] = {"historical": "forged"}
    elif fault == "origin":
        (root / "retained-first-native.json").write_text("{}")
    elif fault == "second-missing":
        (root / "host-2.tar").unlink()
    if fault:
        with pytest.raises((ValueError, FileNotFoundError)):
            m.comparison(root, REPO, m.PAIR_PROFILE)
    else:
        report = m.confirm(root, REPO, m.PAIR_PROFILE)
        proof = report["clean_context_reproducibility"]
        assert proof["old_Host_byte_identity_claimed"] is False
        assert proof["new_Host_matches_historical_independent_pair"] is False
        assert proof["historical_Host_facts"] == {"historical": "host"}
        assert proof["retained_first_input"] == recovery.RETAINED_FIRST
        assert len(proof["independent_Host_archive_sha256"]) == 64
        assert report["images"]["omnigent-saas-host"] == host
        m.verify_complete(root, REPO, m.PAIR_PROFILE)


@pytest.fixture
def first(tmp_path, monkeypatch):
    value = {
        "kind": m.KIND,
        "facts": {"server": {"test_fact": "server"}},
        "historical_Server_facts_equal": False,
        "new_Host_matches_historical_independent_pair": True,
        "historical_comparison": {"artifact_id": recovery.REPORT_ID},
    }
    monkeypatch.setattr(m, "verify_first", lambda root, repo: copy.deepcopy(value))
    for key, text in {
        "GITHUB_WORKFLOW_SHA": "a" * 40,
        "GITHUB_RUN_ID": "101",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_JOB": "build-compat018-product",
        "GITHUB_ACTOR": "test-fixture-actor",
    }.items():
        monkeypatch.setenv(key, text)
    m.audit(tmp_path, REPO)
    report = {
        "images": {
            "omnigent-saas-server": {"historical": True},
            "omnigent-saas-host": {"historical": "host"},
        }
    }
    monkeypatch.setattr(recovery, "original_evidence", lambda archive: (report, {}, b""))
    (tmp_path / "server-2.tar").write_bytes(b"synthetic unit fixture, not OCI qualification")
    repeated = {
        "matching_platform_manifest_and_config": True,
        "history_created_by_equal": True,
        "first": copy.deepcopy(value["facts"]["server"]),
    }
    monkeypatch.setattr(m, "compare_archives", lambda *args, **kwargs: copy.deepcopy(repeated))
    return tmp_path, value, repeated


def test_clean_pair_has_new_origin_and_no_historical_Server_byte_claim(first):
    root, _, _ = first
    result = m.confirm(root, REPO, "clean-C2-server")
    proof = result["clean_context_reproducibility"]
    assert proof["old_Server_byte_identity_claimed"] is False
    assert proof["native_builder"]["run_id"] == 101
    assert len(proof["independent_Server_archive_sha256"]) == 64
    m.verify_complete(root, REPO, "clean-C2-server")


def test_historical_mode_refuses_new_Server_bytes(first):
    root, _, _ = first
    with pytest.raises(ValueError, match="historical C2"):
        m.comparison(root, REPO, "historical")


def test_historical_fast_path_requires_actual_old_pair_equality(first):
    root, value, _ = first
    value["historical_Server_facts_equal"] = True
    retained = json.loads((root / "clean-context-first.json").read_text())
    retained["historical_Server_facts_equal"] = True
    (root / "clean-context-first.json").write_text(json.dumps(retained))
    result = m.comparison(root, REPO, "historical")
    assert result["clean_context_reproducibility"]["old_Server_byte_identity_claimed"] is True


def test_independent_comparison_failure_refuses(first):
    root, _, repeated = first
    repeated["matching_platform_manifest_and_config"] = False
    with pytest.raises(ValueError, match="independent clean"):
        m.comparison(root, REPO, "clean-C2-server")


def test_first_source_proof_tampering_refuses(first):
    root, _, _ = first
    p = root / "clean-context-first.json"
    data = json.loads(p.read_text())
    data["unexpected"] = True
    p.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="proof changed"):
        m.comparison(root, REPO, "clean-C2-server")


def test_audit_requires_native_attempt_one_identity(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "verify_first", lambda *args: {})
    monkeypatch.delenv("GITHUB_WORKFLOW_SHA", raising=False)
    with pytest.raises(ValueError, match="actual native builder"):
        m.audit(tmp_path, REPO)


def test_clean_raw_stays_unadmitted_and_executes_the_real_comparison_guard(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(m, "verify_complete", lambda root, repo, profile: called.append(profile))
    (tmp_path / "clean-context-first.json").write_text("{}")
    report = {
        "images": {
            f"omnigent-saas-{role}": {"first": {"fixture": role}} for role in ("server", "host")
        }
    }
    (tmp_path / "saas-image-candidate.json").write_text(json.dumps(report))
    for role in ("server", "host"):
        (tmp_path / f"{role}-1.tar").write_bytes(b"local synthetic raw fixture")
    result = recovery.verify_raw(tmp_path, comparison_profile="clean-C2-server")
    assert called == ["clean-C2-server"]
    assert result["raw_checkpoint_only"] is True
    assert result["fresh_scans_passed"] is False
    assert result["source_and_pg_same_final_run_qualified"] is False
    assert result["signed_or_production_admitted"] is False


def test_clean_raw_refuses_stale_scan_payload(tmp_path, monkeypatch):
    (tmp_path / "grype").mkdir()
    with pytest.raises(ValueError, match="admission reports"):
        recovery.verify_raw(tmp_path, comparison_profile="clean-C2-server")


def test_workflow_preserves_original_export_and_only_adds_Host_second_for_pair():
    import yaml

    text = (ROOT / ".github/workflows/saas-compat018-oci-recovery.yml").read_text()
    workflow = yaml.load(text, Loader=yaml.BaseLoader)
    steps = workflow["jobs"]["build-compat018-product"]["steps"]
    names = [step.get("name") for step in steps]
    assert (
        names.count(
            "Build the original locked React18 login export before the original OCI action"
        )
        == 1
    )
    second = [
        s
        for s in steps
        if s.get("uses") == "./saas/actions/build-oci-candidate"
        and s.get("with", {}).get("attempt") == "2"
    ]
    assert [s["with"]["artifact"] for s in second] == ["server", "host"]
    assert second[1]["if"] == (
        "inputs.comparison_profile == 'clean-C2-pair' && inputs.phase != 'repair-reviewed-server'"
    )
    assert "clean-C2-server" in second[0]["if"]
    first_builds = [
        s
        for s in steps
        if s.get("uses") == "./saas/actions/build-oci-candidate" and s["with"]["attempt"] == "1"
    ]
    assert all(s["if"] == "inputs.phase == 'build'" for s in first_builds)
    retained = next(s for s in steps if s.get("id") == "retained")
    assert retained["if"] == "inputs.phase == 'complete-retained'"
    assert "retained-first --root" in retained["run"]
    assert (
        names.index("Audit actual fixed C2 source, UI, and historical Host")
        < names.index("Independently build only C2 Server without cache")
        < names.index("Confirm exact C2 comparison profile")
    )
    sealed = workflow["jobs"]["scan-and-seal-same-oci"]["steps"]
    payload = next(s for s in sealed if s.get("name") == "Retain actually admitted immutable OCI")
    assert "clean-context-first.json" in payload["with"]["path"]
    assert "original-report.zip" in payload["with"]["path"]
    assert 'git archive "$GITHUB_SHA" saas' in text
