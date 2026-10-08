import json
from pathlib import Path


def test_pyexpat_lock_binds_same_python_version_and_shared_fixed_expat() -> None:
    directory = Path(__file__).resolve().parents[2] / "saas/supply_chain"
    lock = json.loads((directory / "python312-pyexpat-source-lock.json").read_text())
    assert lock["production_admission"] is True
    assert lock["source_authentication"]["primary_fingerprint"] == (
        "7169605F62C751356D054A26A821E680E5FA6305"
    )
    assert {item["role"] for item in lock["artifacts"]} == {
        "upstream",
        "signature",
        "keyring",
    }
    runtime = lock["runtime_contract"]
    assert runtime["python_version"] == lock["source_version"] == "3.12.15"
    assert runtime["linkage"] == "shared-system-expat; no bundled-expat fallback"
    expat = json.loads((directory / runtime["expat_material_lock"]).read_text())
    assert expat["source_version"].split("-")[0] == runtime["expat_version"] == "2.9.0"
    assert len(runtime["supported_soabi"]) == 2
    assert "both-architectures-complete-runtime-SBOM-and-scans" in lock["required_followup"]
