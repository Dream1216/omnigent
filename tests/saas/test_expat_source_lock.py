import json
from pathlib import Path


def test_expat_lock_records_completed_embedded_python_remediation() -> None:
    lock = json.loads(
        (
            Path(__file__).resolve().parents[2]
            / "saas/supply_chain/debian13-expat-source-lock.json"
        ).read_text()
    )
    assert lock["production_admission"] is True
    assert lock["source_version"] == "2.9.0-1"
    assert lock["source_suite"] == "sid"
    assert lock["build_dependency_suite"] == lock["codename"] == "sid"
    assert "--require-valid-signature" in lock["extraction_contract"]
    assert "--require-strong-checksums" in lock["extraction_contract"]
    assert lock["source_authentication"]["primary_fingerprint"] == (
        "A0DF7E0D3851E0EE45C00BC8ACE1F33CB933BBBB"
    )
    assert lock["source_authentication"]["signing_fingerprint"] == (
        "7D887DC8BA7BBBA7B835E3BADCE310E7864CC8BF"
    )
    assert {item["role"] for item in lock["artifacts"]} == {
        "dsc",
        "upstream",
        "debian",
        "keyring",
    }
    assert "CVE-2026-77214" in lock["addresses"]
    assert (
        "Python-bundled-expat-remediation-and-extension-ABI-verification"
        in lock["required_followup"]
    )
