"""Unsigned validation exports preserve the protected publication boundary."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/saas-image-candidate.yml"


def workflow():
    return yaml.safe_load(WORKFLOW.read_text())


def export_step(document):
    return next(
        step
        for step in document["jobs"]["build-candidate"]["steps"]
        if step.get("name") == "Upload unsigned OCI bytes for isolated validation"
    )


def test_manual_unsigned_export_is_explicit_and_default_off():
    events = yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)["on"]
    field = events["workflow_dispatch"]["inputs"]["retain_unsigned_oci"]
    assert field["type"] == "boolean" and field["default"] == "false"
    assert field["required"] == "true"
    assert "retain_unsigned_oci" not in events["pull_request"]


def test_unsigned_export_excludes_forks_and_signed_publication_dispatch():
    condition = " ".join(export_step(workflow())["if"].split())
    assert condition == (
        "(github.event_name == 'pull_request' && "
        "github.event.pull_request.head.repo.full_name == github.repository) || "
        "(github.event_name == 'workflow_dispatch' && "
        "inputs.retain_unsigned_oci && !inputs.publish_signed)"
    )


def test_unsigned_export_only_retains_sealed_successful_bytes_with_short_retention():
    document = workflow()
    steps = document["jobs"]["build-candidate"]["steps"]
    names = [step.get("name") for step in steps]
    assert (
        names.index("Compare repeated executable image facts")
        < names.index("Scan exact OCI candidates on both architectures")
        < names.index("Seal exact admitted OCI archives and raw scan evidence")
        < names.index("Upload unsigned OCI bytes for isolated validation")
    )
    export = export_step(document)
    assert "always()" not in export["if"]
    assert export["with"] == {
        "name": "saas-oci-validation-${{ env.CANDIDATE_REVISION }}",
        "path": "artifacts/promotion/",
        "compression-level": 0,
        "if-no-files-found": "error",
        "retention-days": 3,
    }
    assert document["env"]["CANDIDATE_REVISION"] == (
        "${{ github.event.pull_request.head.sha || github.sha }}"
    )


def test_validation_export_never_grants_publication_authority():
    document = workflow()
    build = document["jobs"]["build-candidate"]
    assert build.get("permissions", document["permissions"]) == {"contents": "read"}
    for name in ("publish-signed", "verify-published-source"):
        job = document["jobs"][name]
        assert "retain_unsigned_oci" not in yaml.safe_dump(job)
        condition = " ".join(job["if"].split())
        assert "inputs.publish_signed" in condition
        assert "github.ref == 'refs/heads/main'" in condition
    publisher = document["jobs"]["publish-signed"]
    assert publisher["environment"] == "production-image"


def test_source_and_export_contracts_run_before_expensive_image_builds():
    document = workflow()
    build = document["jobs"]["build-candidate"]
    assert "verify-candidate-preflight" in build["needs"]
    preflight = document["jobs"]["verify-candidate-preflight"]
    command = next(
        step["run"]
        for step in preflight["steps"]
        if step.get("name") == "Verify image supply-chain policy contracts"
    )
    assert "tests/saas/test_oci_candidate_validation_export.py" in command
    assert "tests/saas/test_download_oci_validation.py" in command
    assert (
        "tests/saas/test_legacy_domain_discovery.py::"
        "test_existing_source_qualifier_hard_closure_and_generic_parser_are_unchanged"
    ) in command
