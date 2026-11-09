"""Replay actual fixed-runner bootstrap cancellations without source-proof credit."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path

import pytest

from saas.scripts import legacy_domain_non_execution as audit

_CASES = json.loads(
    (
        Path(__file__).parent / "resources/legacy_compatibility_fixed_runner_bootstrap_native.json"
    ).read_text()
)


@pytest.fixture(params=range(len(_CASES)))
def fixed_bootstrap(request):
    case = copy.deepcopy(_CASES[request.param])
    case["logs"] = base64.b64decode(case.pop("logs_base64"), validate=True)
    return case


def verify(case, **kwargs):
    return audit.verify_bootstrap_cancellation(
        *(
            case[key]
            for key in (
                "profile",
                "identity",
                "policy",
                "run",
                "job",
                "check",
                "annotations",
                "logs",
            )
        ),
        attachment_workflow_sha256=kwargs.get(
            "workflow", audit.native.FIXED_RUNNER_WORKFLOW_SHA256
        ),
    )


def test_actual_fixed_bootstrap_retains_unknown_and_original_cancellation(fixed_bootstrap):
    case = fixed_bootstrap
    result = verify(case)
    assert isinstance(result, audit.UnattributedBootstrapCancellationObservation)
    receipt = result.receipt
    assert receipt["source_classification"] == "UNKNOWN"
    assert receipt["execution"] == "native-bootstrap-only-cancelled"
    assert receipt["original_conclusion"] == "cancelled"
    assert receipt["attachment_workflow_sha256"] == audit.native.FIXED_RUNNER_WORKFLOW_SHA256
    assert receipt["git_executed"] is (len(case["job"]["steps"]) != 1)
    assert receipt["run_logs_sha256"] == hashlib.sha256(case["logs"]).hexdigest()
    assert all(
        receipt[key] is False
        for key in (
            "source_proof",
            "guard_refusal",
            "technical_gate_waiver",
            "production_admission",
        )
    )
    assert receipt.get("source_ci_pass") is not True
    from saas.scripts.protected_legacy_initial_build import load_profile, validate_profile

    with pytest.raises(ValueError, match="exact reviewed source contract"):
        validate_profile(case["profile"], "Compatibility018")
    current = load_profile(Path(__file__).resolve().parents[2], "Compatibility018")
    assert current["product_revision"] == "27503d14973b751a2031c6febf12a581b42b06d1"
    with pytest.raises(ValueError):
        verify({**case, "profile": current})
    assert receipt["original_event_source_revision"] is None
    assert receipt["trusted_checkout_revision"] is None


@pytest.mark.parametrize(
    "fault",
    [
        "component",
        "profile",
        "runner",
        "step",
        "annotation",
        "extra_annotation",
        "log",
        "workflow",
        "head",
    ],
)
def test_fixed_bootstrap_rejects_changed_identity_steps_or_original_bytes(fixed_bootstrap, fault):
    case = fixed_bootstrap
    kwargs = {}
    if fault == "component":
        case["profile"]["component"] = "Core"
    elif fault == "profile":
        case["profile"]["product_revision"] = "0" * 40
    elif fault == "runner":
        case["job"]["labels"] = ["ubuntu-latest"]
    elif fault == "step":
        case["job"]["steps"][0]["name"] = "Run application code"
    elif fault == "annotation":
        case["annotations"][1]["message"] += " altered"
    elif fault == "extra_annotation":
        case["annotations"].append(copy.deepcopy(case["annotations"][1]))
    elif fault == "log":
        case["logs"] += b"extra"
    elif fault == "workflow":
        kwargs["workflow"] = "0" * 64
    else:
        case["job"]["head_sha"] = "0" * 40
    with pytest.raises(ValueError):
        verify(case, **kwargs)


def test_original_collector_routes_fixed_bootstrap_through_same_typed_verifier(
    fixed_bootstrap, monkeypatch, tmp_path
):
    case = fixed_bootstrap
    workflow = Path(__file__).parents[2] / audit.native.MAIN_WORKFLOW
    original = workflow.read_bytes()
    assert hashlib.sha256(original).hexdigest() == audit.native.FIXED_RUNNER_WORKFLOW_SHA256
    monkeypatch.setattr(audit.native, "_native_file", lambda path, revision: original)
    monkeypatch.setattr(audit, "api", lambda endpoint: copy.deepcopy(case["check"]))
    monkeypatch.setattr(
        audit, "annotations_for", lambda check_id: copy.deepcopy(case["annotations"])
    )
    monkeypatch.setattr(
        audit,
        "download_infrastructure_run_logs",
        lambda run, attempt, path: path.write_bytes(case["logs"]),
    )
    proof = audit.collect_unattributed_audit(
        case["profile"],
        case["identity"],
        None,
        case["policy"],
        case["run"],
        [case["job"]],
        tmp_path,
    )
    assert proof.receipt == verify(case).receipt


def replace_original_log_text(case, old, new):
    import io
    import struct
    import zipfile

    output = io.BytesIO()
    with (
        zipfile.ZipFile(io.BytesIO(case["logs"])) as original,
        zipfile.ZipFile(output, "w") as target,
    ):
        for info in original.infolist():
            target.writestr(info, original.read(info).replace(old.encode(), new.encode()))
    raw = bytearray(output.getvalue())
    offset = 0
    while True:
        offset = raw.find(b"PK\x01\x02", offset)
        if offset < 0:
            break
        struct.pack_into("<I", raw, offset + 38, 0)
        offset += 46
    case["logs"] = bytes(raw)


def test_only_authenticated_runner_and_attachment_values_may_vary(fixed_bootstrap):
    case = fixed_bootstrap
    old = case["run"]["head_sha"]
    fresh = "f" * 40
    case["run"]["head_sha"] = fresh
    case["job"]["head_sha"] = fresh
    case["check"]["head_sha"] = fresh
    for annotation in case["annotations"]:
        annotation["blob_href"] = annotation["blob_href"].replace(old, fresh)
        annotation["message"] = annotation["message"].replace(old, fresh)
    replace_original_log_text(case, old, fresh)
    old_runner = case["job"]["runner_name"]
    case["job"]["runner_id"] += 1000
    case["job"]["runner_name"] = f"GitHub Actions {case['job']['runner_id']}"
    replace_original_log_text(case, old_runner, case["job"]["runner_name"])
    receipt = verify(case).receipt
    assert receipt["source_classification"] == "UNKNOWN"
    assert receipt["source_proof"] is False
    assert receipt["production_admission"] is False


def test_unknown_noncommand_metadata_is_still_rejected(fixed_bootstrap):
    case = fixed_bootstrap
    import io
    import re
    import zipfile

    with zipfile.ZipFile(io.BytesIO(case["logs"])) as archive:
        text = archive.read("0_evaluate.txt").decode()
    region = re.search(r"Region: (\S+)", text)
    assert region is not None
    replace_original_log_text(case, "Region: " + region[1], "Region: unreviewed-region")
    with pytest.raises(ValueError, match="unknown shape"):
        verify(case)
