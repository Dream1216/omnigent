"""Keep cross-platform execution on the admitted child and retain original bytes."""

from pathlib import Path

import yaml

from saas.scripts import resume_oci_promotion as resume

ROOT = Path(__file__).resolve().parents[2]


def test_model_renewal_resume_retains_verified_security_candidate(monkeypatch):
    for name in ("LOCK_PATH", "WORKFLOW", "_SELECTED_PRODUCT_REVISION"):
        monkeypatch.setattr(resume, name, getattr(resume, name))
    resume.configure_release_profile("model-renewal-7cea0940")
    binding = resume.lock()
    assert binding["product_revision"] == "7cea09404d49fc965ce053e51803688a5be5fe53"
    assert binding["candidate_run_id"] == 39578869162
    assert binding["candidate_run_conclusion"] == "failure"
    assert binding["candidate_build_job_id"] == 119152199178
    assert binding["oci_artifact_id"] == 12344292161
    assert (
        binding["oci_artifact_sha256"]
        == "057b0b7a77d2103ba1cc23789ea956469148cf51032efee5a17fcab3e3b05fcb"
    )
    assert (
        binding["wheel_sha256"]
        == "47957617e0ffc6a34ec027d2db606116b420a03aa0e3fa8c340cd6b51eaae772"
    )
    assert binding["rebuilt"] is binding["production_authority"] is False
    text = (ROOT / resume.WORKFLOW).read_text()
    workflow = yaml.load(text, Loader=yaml.BaseLoader)
    assert workflow["env"]["PRODUCT_REVISION"] == binding["product_revision"]
    assert workflow["env"]["SOURCE_DATE_EPOCH"] == str(binding["source_date_epoch"])
    assert workflow["env"]["ORIGINAL_CANDIDATE_RUN_ID"] == str(binding["candidate_run_id"])
    assert workflow["jobs"]["admit-original"]["outputs"] == {
        "manifest-sha256": binding["candidate_manifest_sha256"],
        "oci-artifact-id": str(binding["oci_artifact_id"]),
        "oci-artifact-sha256": binding["oci_artifact_sha256"],
    }
    helper = "python -m saas.scripts.resume_oci_promotion"
    assert text.count(helper) == text.count(helper + " --release model-renewal-7cea0940 ")
    assert "docker build" not in text and "uv build" not in text
    for name in ("admit-original", "publish-signed", "verify-published-source"):
        assert "inputs.policy_revision == github.sha" in workflow["jobs"][name]["if"]
        assert "github.ref == 'refs/heads/main'" in workflow["jobs"][name]["if"]
    publish = workflow["jobs"]["publish-signed"]
    assert publish["environment"] == "production-image"
    steps = {s.get("name"): s for s in publish["steps"]}
    scans = steps["Generate per-architecture SBOMs and check raw findings"]["run"]
    assert helper + " --release model-renewal-7cea0940 child" in scans
    assert "for arch in amd64 arm64; do" in scans
    assert "(.ignoredMatches // []) == []" in scans
    assert (
        steps["Record signed candidate facts"]["env"]["WHEEL_ATTESTATION"]
        == "https://github.com/Dream1216/omnigent/attestations/58194115"
    )
    assert (
        "original_candidate_run_id: 39578869162" in steps["Record signed candidate facts"]["run"]
    )


def test_canonical_runtime_probes_do_not_reuse_one_index_for_two_architectures():
    workflow = yaml.load(
        (ROOT / ".github/workflows/saas-image-candidate.yml").read_text(), Loader=yaml.BaseLoader
    )
    steps = {s.get("name"): s for s in workflow["jobs"]["publish-signed"]["steps"]}
    scans = steps["Generate per-architecture SBOMs and check raw findings"]["run"]
    assert ".images[$role].facts.platforms[$platform].manifest_digest" in scans
    assert '"${RUNNER_TEMP}/admitted-oci/oci-promotion-manifest.json"' in scans
    assert 'child_image="${image%@*}@${child_digest}"' in scans
    assert scans.count('"$child_image"') == 4
    assert '"$image"' not in scans
    assert "for arch in amd64 arm64; do" in scans
    assert "(.ignoredMatches // []) == []" in scans
